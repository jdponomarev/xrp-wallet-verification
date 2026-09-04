import { sha256, sha512 } from '@noble/hashes/sha2.js';
import { ripemd160 } from '@noble/hashes/legacy.js';

/** First 32 bytes of SHA-512: the XRPL signing digest. */
export function sha512Half(bytes: Uint8Array): Uint8Array {
  return sha512(bytes).slice(0, 32);
}

/** RIPEMD160(SHA256(bytes)): the XRPL AccountID of a 33-byte public key. */
export function accountIdOf(publicKey33: Uint8Array): Uint8Array {
  return ripemd160(sha256(publicKey33));
}
