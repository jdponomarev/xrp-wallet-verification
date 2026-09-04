// Reproduce what xrpl-connect LedgerAdapter.signMessage sends to hw-app-xrp.signTransaction
// (packages/adapters/ledger/src/ledger-adapter.ts:488-495): hex(UTF-8 message) as `rawTxHex`.
import { decode, encodeForSigning } from 'ripple-binary-codec';
import * as kp from 'ripple-keypairs';

const message = 'Sign in to Example nonce=abc123';
const messageHex = Array.from(new TextEncoder().encode(message)).map(b => b.toString(16).padStart(2,'0')).join('');
console.log('messageHex (what LedgerAdapter passes as rawTxHex):', messageHex);
try { console.log('ripple-binary-codec decode(messageHex) =>', JSON.stringify(decode(messageHex))); }
catch (e) { console.log('ripple-binary-codec decode(messageHex) THROWS:', e.constructor.name, '-', String(e.message).slice(0,120)); }
for (const m of ['hello', 'a', 'Sign in']) {
  const h = Buffer.from(m,'utf8').toString('hex');
  try { console.log(`decode(hex("${m}")) =>`, JSON.stringify(decode(h))); } catch (e) { console.log(`decode(hex("${m}")) THROWS:`, String(e.message).slice(0,100)); }
}
const tx = { TransactionType: 'Payment', Account: 'rrrrrrrrrrrrrrrrrrrrrhoLvTp', Destination: 'rrrrrrrrrrrrrrrrrrrrBZbvji', Amount: '1', Fee: '10', Sequence: 1, SigningPubKey: '' };
console.log('encodeForSigning() prefix (first 8 hex):', encodeForSigning(tx).slice(0,8), '= "STX\\0" (0x53545800)');

const seed = kp.generateSeed({ entropy: new Uint8Array(16).fill(7), algorithm: 'ecdsa-secp256k1' });
const { privateKey, publicKey } = kp.deriveKeypair(seed);
const sigRaw = kp.sign(messageHex, privateKey);
console.log('ripple-keypairs sign(messageHex) -> verify(messageHex):', kp.verify(messageHex, sigRaw, publicKey));
// Emulate a device that (like app-xrp for a transaction) hashes sha512half("STX\0" || bytes) and returns DER
const sigDevice = kp.sign('53545800' + messageHex, privateKey);
console.log('device-style sig over STX||msg -> ripple-keypairs verify(messageHex):', kp.verify(messageHex, sigDevice, publicKey));
console.log('device-style sig over STX||msg -> verify("53545800"+messageHex):', kp.verify('53545800' + messageHex, sigDevice, publicKey));
console.log('DER length bytes:', sigDevice.length/2);
