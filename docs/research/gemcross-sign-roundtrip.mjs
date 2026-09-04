// Emulate GemWallet's LedgerContext.signMessage exactly:
//   const messageHex = isHex ? message : Buffer.from(message,'utf8').toString('hex');
//   return sign(messageHex, wallet.wallet.privateKey);   // ripple-keypairs
import { sign, verify, deriveKeypair, deriveAddress } from 'ripple-keypairs';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
console.log('ripple-keypairs', require('ripple-keypairs/package.json').version);

const message = 'Hello, XRPL! nonce=1234';
const messageHex = Buffer.from(message, 'utf8').toString('hex');

for (const [label, seed] of [
  ['secp256k1', 'sn3nxiW7v8KXzPzAqzyHXbSSKNuN9'],   // known test seed (xrpl docs)
  ['ed25519',   'sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r'],  // known ed25519 test seed
]) {
  const kp = deriveKeypair(seed);
  const address = deriveAddress(kp.publicKey);
  const signedMessage = sign(messageHex, kp.privateKey);
  const ok = verify(messageHex, signedMessage, kp.publicKey);
  // negative checks: verify raw utf8 (not hex) fails / different message fails
  let rawUtf8Ok = null; try { rawUtf8Ok = verify(message, signedMessage, kp.publicKey); } catch (e) { rawUtf8Ok = 'throws: ' + e.message; }
  const tampered = verify(Buffer.from(message + 'x','utf8').toString('hex'), signedMessage, kp.publicKey);
  console.log(JSON.stringify({ label, address, publicKey: kp.publicKey, message, messageHex, signedMessage,
    sigLenHex: signedMessage.length, derPrefix: signedMessage.slice(0,2), verify_hexUtf8: ok, verify_rawUtf8: rawUtf8Ok, verify_tampered: tampered }, null, 1));
}
// isHex=true path: message already hex -> signed as-is
const hexMsg = 'deadbeef';
const kp = deriveKeypair('sn3nxiW7v8KXzPzAqzyHXbSSKNuN9');
const s2 = sign(hexMsg, kp.privateKey);
console.log('isHex path: verify(hexMsg)=', verify(hexMsg, s2, kp.publicKey), ' verify(hex(utf8("deadbeef")))=', verify(Buffer.from(hexMsg,'utf8').toString('hex'), s2, kp.publicKey));
// what does sign() do with a NON-hex string (Crossmark adapter passes raw utf8 as `hex`)?
try { console.log('sign(non-hex "Hello") ->', sign('Hello, XRPL!', kp.privateKey)); } catch (e) { console.log('sign(non-hex) throws:', e.message); }
try { console.log('sign(odd-length hex "abc") ->', sign('abc', kp.privateKey)); } catch (e) { console.log('sign(odd hex) throws:', e.message); }
