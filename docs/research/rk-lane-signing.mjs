import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const rk = require('ripple-keypairs');
const { secp256k1 } = require('@noble/curves/secp256k1.js');
const { ed25519 } = require('@noble/curves/ed25519.js');
const { sha512 } = require('@noble/hashes/sha2.js');
const { bytesToHex, hexToBytes, numberToBytesBE, bytesToNumberBE } = require('@noble/curves/utils.js');

const out = (k, v) => console.log(`${k}: ${typeof v === 'string' ? v : JSON.stringify(v)}`);
const hexU = (b) => bytesToHex(b).toUpperCase();
const utf8hex = (s) => hexU(new TextEncoder().encode(s));

out('(7) exports', Object.keys(rk).sort());
out('(7) typeof', Object.fromEntries(Object.keys(rk).map(k => [k, typeof rk[k]])));

// fixed seeds (deterministic)
const secpSeed = rk.generateSeed({ entropy: new Uint8Array(16).fill(1), algorithm: 'ecdsa-secp256k1' });
const edSeed = rk.generateSeed({ entropy: new Uint8Array(16).fill(2), algorithm: 'ed25519' });
const kpS = rk.deriveKeypair(secpSeed);
const kpE = rk.deriveKeypair(edSeed);
out('secp seed', secpSeed); out('secp keypair', kpS); out('secp address', rk.deriveAddress(kpS.publicKey));
out('ed seed', edSeed); out('ed keypair', kpE); out('ed address', rk.deriveAddress(kpE.publicKey));

const msg = 'Sign in to example.com\nnonce: 0123456789abcdef';
const msgHex = utf8hex(msg);
out('message utf8', JSON.stringify(msg)); out('message hex', msgHex);

// (1) API shape / non-hex
const sigS = rk.sign(msgHex, kpS.privateKey);
const sigE = rk.sign(msgHex, kpE.privateKey);
out('(1) secp sig (DER hex)', sigS); out('(1) secp sig bytes', sigS.length / 2);
out('(1) ed sig hex', sigE); out('(1) ed sig bytes', sigE.length / 2);
out('(1) verify secp', rk.verify(msgHex, sigS, kpS.publicKey));
out('(1) verify ed', rk.verify(msgHex, sigE, kpE.publicKey));
for (const bad of [msg, 'ABC', 'zz', '']) {
  try { const r = rk.sign(bad, kpS.privateKey); out(`(1) sign(non-hex ${JSON.stringify(bad)}) ->`, r); }
  catch (e) { out(`(1) sign(non-hex ${JSON.stringify(bad)}) THROWS`, e.message.split('\n')[0]); }
  try { const r = rk.verify(bad, sigS, kpS.publicKey); out(`(1) verify(non-hex ${JSON.stringify(bad)}) ->`, r); }
  catch (e) { out(`(1) verify(non-hex ${JSON.stringify(bad)}) THROWS`, e.message.split('\n')[0]); }
}
// lowercase hex accepted?
out('(1) verify lowercase msgHex', rk.verify(msgHex.toLowerCase(), sigS, kpS.publicKey));
out('(1) verify lowercase sig', rk.verify(msgHex, sigS.toLowerCase(), kpS.publicKey));
out('(1) verify lowercase pub', rk.verify(msgHex, sigS, kpS.publicKey.toLowerCase()));

// (2) reproduce secp with noble directly
const msgBytes = hexToBytes(msgHex);
const digest = sha512(msgBytes).slice(0, 32);
const priv = hexToBytes(kpS.privateKey.slice(2));
const nobleSig = secp256k1.sign(digest, priv, { lowS: true, prehash: false, format: 'der' });
out('(2) sha512half digest', hexU(digest));
out('(2) noble DER sig', hexU(nobleSig));
out('(2) byte-equal to ripple-keypairs', hexU(nobleSig) === sigS);
// negative: sha256 digest / raw message would NOT match
const wrongSig = secp256k1.sign(msgBytes, priv, { lowS: true, prehash: true, format: 'der' });
out('(2) noble sha256-prehash sig equals rk?', hexU(wrongSig) === sigS);
out('(2) noble pubkey from priv equals rk pub', hexU(secp256k1.getPublicKey(priv, true)) === kpS.publicKey);

// (3) ed25519 reproduce
const edPriv = hexToBytes(kpE.privateKey.slice(2));
const edPub = ed25519.getPublicKey(edPriv);
out('(3) noble ed pub (no prefix)', hexU(edPub));
out('(3) rk pub = ED + noble pub', kpE.publicKey === 'ED' + hexU(edPub));
const nobleEdSig = ed25519.sign(msgBytes, edPriv);
out('(3) noble ed sig equals rk', hexU(nobleEdSig) === sigE);
out('(3) noble ed verify raw msg', ed25519.verify(hexToBytes(sigE), msgBytes, edPub));
out('(3) noble ed verify sha512half(msg) (should be false)', ed25519.verify(hexToBytes(sigE), digest, edPub));
// ed priv derivation: rk ed private = sha512half(entropy)
const edEntropy = rk.decodeSeed(edSeed);
out('(3) decodeSeed(ed)', { type: edEntropy.type, bytes: hexU(edEntropy.bytes) });
out('(3) ed priv == sha512half(entropy)', hexU(sha512(edEntropy.bytes).slice(0, 32)) === kpE.privateKey.slice(2));

// (4) HIGH-S
const sigObj = secp256k1.Signature.fromHex(sigS, 'der');
const n = secp256k1.Point.CURVE().n ?? secp256k1.Point.Fn.ORDER;
out('(4) orig s < n/2 (lowS)', sigObj.s < n / 2n);
const highS = new secp256k1.Signature(sigObj.r, n - sigObj.s, sigObj.recovery);
const highDer = hexU(highS.toBytes('der'));
out('(4) highS DER', highDer);
out('(4) highS DER len bytes', highDer.length / 2);
out('(4) rk.verify(highS)', rk.verify(msgHex, highDer, kpS.publicKey));
const pub = hexToBytes(kpS.publicKey);
const compactHigh = highS.toBytes('compact');
const compactLow = sigObj.toBytes('compact');
out('(4) noble verify(low, default opts)', secp256k1.verify(compactLow, digest, pub, { prehash: false }));
out('(4) noble verify(high, default opts {prehash:false})', secp256k1.verify(compactHigh, digest, pub, { prehash: false }));
out('(4) noble verify(high, lowS:false)', secp256k1.verify(compactHigh, digest, pub, { prehash: false, lowS: false }));
out('(4) noble verify(high, lowS:true)', secp256k1.verify(compactHigh, digest, pub, { prehash: false, lowS: true }));
out('(4) noble verify(high, DER format direct)', secp256k1.verify(highS.toBytes('der'), digest, pub, { prehash: false, format: 'der' }));
out('(4) noble verify(high, DER format, lowS:false)', secp256k1.verify(highS.toBytes('der'), digest, pub, { prehash: false, format: 'der', lowS: false }));
// Does Signature.fromHex(der) itself reject highS?
try { secp256k1.Signature.fromHex(highDer, 'der'); out('(4) Signature.fromHex(highS der)', 'parses OK (no lowS check at parse)'); } catch (e) { out('(4) Signature.fromHex(highS der) THROWS', e.message); }

// DER malleability: non-canonical DER (leading zero / long form)? Check what fromHex does with a padded r
const derBytes = hexToBytes(sigS);
// insert extra 0x00 into r integer
const rLen = derBytes[3];
const padded = new Uint8Array(derBytes.length + 1);
padded[0] = 0x30; padded[1] = derBytes[1] + 1; padded[2] = 0x02; padded[3] = rLen + 1; padded[4] = 0x00;
padded.set(derBytes.slice(4), 5);
try { out('(4b) rk.verify(non-minimal DER r padding)', rk.verify(msgHex, hexU(padded), kpS.publicKey)); } catch (e) { out('(4b) rk.verify(non-minimal DER) THROWS', e.message); }

// (5) cross algorithm
try { out('(5) rk.verify(ED pub, DER sig)', rk.verify(msgHex, sigS, kpE.publicKey)); } catch (e) { out('(5) rk.verify(ED pub, DER sig) THROWS', e.constructor.name + ': ' + e.message.split('\n')[0]); }
try { out('(5) rk.verify(secp pub, 64B ed sig)', rk.verify(msgHex, sigE, kpS.publicKey)); } catch (e) { out('(5) rk.verify(secp pub, 64B ed sig) THROWS', e.constructor.name + ': ' + e.message.split('\n')[0]); }
try { out('(5) rk.verify(garbage pub 0x05..)', rk.verify(msgHex, sigS, '05' + kpS.publicKey.slice(2))); } catch (e) { out('(5) rk.verify(garbage pub) THROWS', e.message.split('\n')[0]); }
try { out('(5) rk.verify(uncompressed 04 pub)', rk.verify(msgHex, sigS, hexU(secp256k1.getPublicKey(priv, false)))); } catch (e) { out('(5) rk.verify(04 pub) THROWS', e.message.split('\n')[0]); }
try { out('(5) rk.verify(secp pub, truncated sig)', rk.verify(msgHex, sigS.slice(0, 20), kpS.publicKey)); } catch (e) { out('(5) rk.verify(secp, truncated sig) THROWS', e.constructor.name + ': ' + e.message.split('\n')[0]); }
try { out('(5) rk.verify(ed pub, 63B sig)', rk.verify(msgHex, sigE.slice(0, 126), kpE.publicKey)); } catch (e) { out('(5) rk.verify(ed, 63B sig) THROWS', e.constructor.name + ': ' + e.message.split('\n')[0]); }
try { out('(5) rk.verify(ed pub, wrong msg)', rk.verify(utf8hex(msg + 'x'), sigE, kpE.publicKey)); } catch (e) { out('THROWS', e.message); }
try { out('(5) rk.verify(secp pub, wrong msg)', rk.verify(utf8hex(msg + 'x'), sigS, kpS.publicKey)); } catch (e) { out('THROWS', e.message); }
// ed sig with non-canonical S (s + L)? RFC8032 rejects
const Lord = ed25519.Point.Fn.ORDER;
const eS = hexToBytes(sigE);
const sNum = bytesToNumberBE(eS.slice(32).reverse());
const sPlusL = sNum + Lord;
const sPlusLBytes = numberToBytesBE(sPlusL, 32).reverse();
const malEd = new Uint8Array(64); malEd.set(eS.slice(0, 32), 0); malEd.set(sPlusLBytes, 32);
try { out('(5b) rk.verify(ed, s+L malleated)', rk.verify(msgHex, hexU(malEd), kpE.publicKey)); } catch (e) { out('(5b) rk.verify(ed s+L) THROWS', e.message); }
try { out('(5b) noble ed.verify(s+L, zip215:true)', ed25519.verify(malEd, msgBytes, edPub, { zip215: true })); } catch (e) { out('(5b) noble zip215 THROWS', e.message); }

// (6) noble version resolved
out('(6) @noble/curves resolved', require.resolve('@noble/curves/secp256k1.js', { paths: [require.resolve('ripple-keypairs')] }));
out('(6) @noble/curves version', JSON.parse(require('node:fs').readFileSync(require.resolve('@noble/curves/secp256k1.js', { paths: [require.resolve('ripple-keypairs')] }).replace(/secp256k1\.js$/, 'package.json'))).version);
out('(6) @noble/hashes version', JSON.parse(require('node:fs').readFileSync(require.resolve('@noble/hashes/sha2.js').replace(/sha2\.js$/, 'package.json'))).version);
out('(6) @xrplf/isomorphic version', require('@xrplf/isomorphic/package.json').version);

// FIXTURES
console.log('\n=== FIXTURES ===');
console.log(JSON.stringify({
  message: msg, messageHex: msgHex,
  secp256k1: { seed: secpSeed, privateKey: kpS.privateKey, publicKey: kpS.publicKey, address: rk.deriveAddress(kpS.publicKey), sha512half: hexU(digest), signatureDER: sigS, signatureHighS_DER_mustReject: highDer },
  ed25519: { seed: edSeed, privateKey: kpE.privateKey, publicKey: kpE.publicKey, address: rk.deriveAddress(kpE.publicKey), signature: sigE, signature_sPlusL_mustReject: hexU(malEd) },
}, null, 2));
