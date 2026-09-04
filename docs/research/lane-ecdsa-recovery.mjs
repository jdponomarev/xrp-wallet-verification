import * as rk from 'ripple-keypairs';
import * as rac from 'ripple-address-codec';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const seed = rk.generateSeed({ algorithm: 'ecdsa-secp256k1' });
const kp = rk.deriveKeypair(seed);
const msg = new TextEncoder().encode('hello xrpl ' + Date.now());
const msgHex = bytesToHex(msg);
const sigHex = rk.sign(msgHex, kp.privateKey);
console.log('pubkey       ', kp.publicKey);
console.log('sig DER hex  ', sigHex, 'len', sigHex.length / 2);
console.log('rk.verify    ', rk.verify(msgHex, sigHex, kp.publicKey));
const msgHash = sha512(msg).slice(0, 32);
const sig = secp256k1.Signature.fromHex(sigHex, 'der');
console.log('hasHighS     ', sig.hasHighS());
const expectedAddr = rk.deriveAddress(kp.publicKey);
for (let rec = 0; rec < 4; rec++) {
  try {
    const pt = sig.addRecoveryBit(rec).recoverPublicKey(msgHash);
    const pub = pt.toHex(true).toUpperCase();
    const acct = ripemd160(sha256(pt.toBytes(true)));
    const addr = rac.encodeAccountID(acct);
    console.log(`rec=${rec} pub=${pub} match=${pub === kp.publicKey} addr=${addr} addrMatch=${addr === expectedAddr}`);
  } catch (e) {
    console.log(`rec=${rec} threw: ${e.message}`);
  }
}
console.log('rk.deriveAddress', expectedAddr);
