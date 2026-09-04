import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const vxs = require('verify-xrpl-signature');
const rbc = require('ripple-binary-codec');            // 2.10.0
const pre = require('xrpl-binary-codec-prerelease');   // 9.2.0 (vxs dep)
const kp = require('ripple-keypairs');                  // 3.0.0
const { sha512 } = require('@noble/hashes/sha2.js');
const fixtures = require('./verify-xrpl-signature-src/test/fixtures.json');
const testDefsJson = require('./verify-xrpl-signature-src/test/definitions.json');
const xrpl = require('xrpl');

const hex = b => Buffer.from(b).toString('hex').toUpperCase();
const memoText = m => m?.Memo?.MemoData ? Buffer.from(m.Memo.MemoData,'hex').toString('utf8') : null;
const trunc = s => (typeof s==='string' && s.length>120) ? s.slice(0,60)+'…('+s.length+' hex chars)…'+s.slice(-40) : s;

console.log('== (1) exports of verify-xrpl-signature@9.2.0:', Object.keys(vxs), 'verifySignature.length=', vxs.verifySignature.length);

console.log('\n== (4) every fixture blob');
const flat = { valid: fixtures.valid, memoetc: fixtures.memoetc, xls20: fixtures.xls20, multisign: fixtures.multisign, invalid: fixtures.invalid, validhook: fixtures.validhook, 'xahau.importtx': fixtures.xahau.importtx };
for (const [name, fx] of Object.entries(flat)) {
  const out = { name, expectedAccount: fx.account ?? null, blobLen: fx.blob.length };
  for (const [label, defs] of [['defaultDefs', undefined], ['testDefinitions.json', new pre.XrplDefinitions(testDefsJson)]]) {
    try {
      const tx = pre.decode(fx.blob, defs);
      out['decode@'+label] = { TransactionType: tx.TransactionType, Account: tx.Account, SigningPubKey: tx.SigningPubKey, Signers: tx.Signers?.map(s=>({Account:s.Signer.Account, SigningPubKey:s.Signer.SigningPubKey})), Memos: tx.Memos?.map(memoText), NetworkID: tx.NetworkID };
    } catch (e) { out['decode@'+label] = 'ERR: '+e.message.slice(0,140); }
    try { out['verify@'+label] = vxs.verifySignature(fx.blob, undefined, defs); } catch (e) { out['verify@'+label] = 'THROW: '+e.message.slice(0,160); }
  }
  console.log(JSON.stringify(out, null, 1));
}

console.log('\n== (2) ripple-binary-codec@2.10.0 default definitions and SignIn');
const base = { TransactionType: 'SignIn', Account: 'rwiETSee2wMz3SBnAG8hkMsCgvGy9LWbZ1', SigningPubKey: '0333C718C9CB716E0575454F4A343D46B284ED51151B9C7383524B82C10B262095' };
try { console.log('rbc.encode SignIn default =>', rbc.encode(base)); } catch (e) { console.log('rbc.encode SignIn default THROWS:', e.constructor.name, e.message); }
try { console.log('pre.encode SignIn default =>', pre.encode(base)); } catch (e) { console.log('pre.encode SignIn default THROWS:', e.message); }
console.log('rbc DEFAULT_DEFINITIONS.transactionType.from("SignIn") =', rbc.DEFAULT_DEFINITIONS.transactionType.from('SignIn'));
console.log('pre DEFAULT_DEFINITIONS.transactionType.from("SignIn") =', String(pre.DEFAULT_DEFINITIONS.transactionType.from('SignIn')), 'ordinal', pre.DEFAULT_DEFINITIONS.transactionType.from('SignIn')?.ordinal);

// Custom definitions for rbc 2.10.0: clone default json + SignIn:999
const defJson = JSON.parse(JSON.stringify(require('ripple-binary-codec/dist/enums/definitions.json')));
defJson.TRANSACTION_TYPES.SignIn = 999;
const customDefs = new rbc.XrplDefinitions(defJson);
console.log('custom rbc defs from("SignIn") =', String(customDefs.transactionType.from('SignIn')));

console.log('\n== (5) synthesize SignIn blobs (secp256k1 + ed25519) w/ ripple-keypairs@3 and verify independently');
const challenge = 'xrp-wallet-verification challenge 12345';
const results = {};
for (const algorithm of ['ecdsa-secp256k1', 'ed25519']) {
  const seed = kp.generateSeed({ algorithm, entropy: new Uint8Array(16).fill(algorithm==='ed25519'?7:9) });
  const { publicKey, privateKey } = kp.deriveKeypair(seed);
  const account = kp.deriveAddress(publicKey);
  const tx = { TransactionType: 'SignIn', Account: account, SigningPubKey: publicKey, Memos: [{ Memo: { MemoData: hex(Buffer.from(challenge,'utf8')) } }] };
  const signingData = rbc.encodeForSigning(tx, customDefs);
  console.log(algorithm, 'encodeForSigning prefix =', signingData.slice(0,8), '(STX\\0 = 53545800)', 'ok?', signingData.slice(0,8)==='53545800');
  const TxnSignature = kp.sign(signingData, privateKey);
  const blob = rbc.encode({ ...tx, TxnSignature }, customDefs);
  // independent verify (no vxs): decode w/ custom defs, encodeForSigning, sha512half, verify, deriveAddress==Account
  const decoded = rbc.decode(blob, customDefs);
  const sd = rbc.encodeForSigning(decoded, customDefs);
  const digest = hex(sha512(Buffer.from(sd,'hex')).slice(0,32));
  const sigOk = kp.verify(sd, decoded.TxnSignature, decoded.SigningPubKey);
  const addrOk = kp.deriveAddress(decoded.SigningPubKey) === decoded.Account;
  let viaVxsDefault, viaVxsPreDefs, viaRbcDefault;
  try { viaVxsDefault = vxs.verifySignature(blob); } catch (e) { viaVxsDefault = 'THROW: '+e.message; }
  try { viaVxsPreDefs = vxs.verifySignature(blob, undefined, undefined); } catch (e) { viaVxsPreDefs = 'THROW: '+e.message; }
  try { viaRbcDefault = rbc.decode(blob); } catch (e) { viaRbcDefault = 'rbc.decode default THROWS: '+e.constructor.name+': '+e.message; }
  results[algorithm] = { seed, publicKey, account, blob, decoded: { TransactionType: decoded.TransactionType, Account: decoded.Account, Memo: memoText(decoded.Memos[0]) }, sha512half: digest, independent: { sigOk, addrOk }, vxsDefault: viaVxsDefault, rbcDefaultDecode: viaRbcDefault };
}
console.log(JSON.stringify(results, null, 1));

// Tamper test: flip memo, signature should fail
const t = rbc.decode(results['ecdsa-secp256k1'].blob, customDefs);
t.Memos[0].Memo.MemoData = hex(Buffer.from('tampered'));
const tamperedBlob = rbc.encode(t, customDefs);
console.log('tampered memo -> vxs:', JSON.stringify(vxs.verifySignature(tamperedBlob)));
// Account-swap test: change Account (not signed by that key) - vxs signedBy comes from pubkey, so mismatch is caller's job
const a = rbc.decode(results['ecdsa-secp256k1'].blob, customDefs);
a.Account = 'rwiETSee2wMz3SBnAG8hkMsCgvGy9LWbZ1';
console.log('account-swapped (still sig over new body invalid) -> vxs:', JSON.stringify(vxs.verifySignature(rbc.encode(a, customDefs))));

console.log('\n== (3) HashPrefix in ripple-binary-codec 2.10.0 handled via grep (see shell). encodeForSigning typeof =', typeof rbc.encodeForSigning, 'encodeForMultisigning typeof =', typeof rbc.encodeForMultisigning);
// multisign prefix check on the fixture
const ms = rbc.decode(fixtures.multisign.blob);
const msData = rbc.encodeForMultisigning(ms, fixtures.multisign.account);
console.log('encodeForMultisigning prefix =', msData.slice(0,8), '(SMT\\0 = 534D5400) suffix(accountID 20B) =', msData.slice(-40), 'fixture signer AccountID =', hex(require('ripple-address-codec').decodeAccountID(fixtures.multisign.account)));

console.log('\n== (6) xrpl@5.1.0 with SignIn');
const w = xrpl.Wallet.fromSeed(results['ecdsa-secp256k1'].seed);
try { const s = w.sign({ TransactionType: 'SignIn', Account: w.classicAddress }); console.log('Wallet.sign SignIn =>', s); } catch (e) { console.log('Wallet.sign SignIn THROWS:', e.constructor.name, e.message); }
try { console.log('xrpl.verifySignature(syntheticSignInBlob) =>', xrpl.verifySignature(results['ecdsa-secp256k1'].blob)); } catch (e) { console.log('xrpl.verifySignature(syntheticSignInBlob) THROWS:', e.constructor.name, e.message); }
try { console.log('xrpl.verifySignature(fixtures.valid.blob) =>', xrpl.verifySignature(fixtures.valid.blob)); } catch (e) { console.log('xrpl.verifySignature(valid) THROWS:', e.message); }
try { console.log('xrpl.verifySignature(fixtures.multisign.blob) =>', xrpl.verifySignature(fixtures.multisign.blob)); } catch (e) { console.log('xrpl.verifySignature(multisign) THROWS:', e.constructor.name, e.message); }
// does xrpl expose definitions param?
console.log('xrpl.verifySignature.length =', xrpl.verifySignature.length, '; xrpl.encodeForSigning?', typeof xrpl.encodeForSigning, '; xrpl.XrplDefinitions?', typeof xrpl.XrplDefinitions);
