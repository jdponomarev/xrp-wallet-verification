import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { MalformedInputError } from './errors.js';
import { bytesToHex, hexToBytes } from './hex.js';
import type { Algorithm } from './types.js';

export interface ParsedPublicKey {
  algorithm: Algorithm;
  /** 33 bytes, including the algorithm prefix byte. */
  bytes: Uint8Array;
  /** Uppercase hex of `bytes`. */
  hex: string;
}

/**
 * Parse and validate a 33-byte XRPL public key. Rejects wrong lengths, the uncompressed `04`
 * form (ripple-keypairs accepts it but derives an address no account can have) and points that
 * are not on the curve (ripple-keypairs derives an address from those without complaint).
 */
export function parsePublicKey(publicKeyHex: string): ParsedPublicKey {
  const bytes = hexToBytes(publicKeyHex, 'publicKey');
  if (bytes.length !== 33) {
    throw new MalformedInputError(`publicKey: expected 33 bytes, got ${bytes.length}`);
  }
  const prefix = bytes[0];
  if (prefix === 0xed) {
    try {
      ed25519.Point.fromBytes(bytes.slice(1));
    } catch {
      throw new MalformedInputError('publicKey: not a valid ed25519 point');
    }
    return { algorithm: 'ed25519', bytes, hex: bytesToHex(bytes) };
  }
  if (prefix === 0x02 || prefix === 0x03) {
    try {
      secp256k1.Point.fromBytes(bytes);
    } catch {
      throw new MalformedInputError('publicKey: not a point on secp256k1');
    }
    return { algorithm: 'secp256k1', bytes, hex: bytesToHex(bytes) };
  }
  throw new MalformedInputError(
    `publicKey: unknown prefix ${bytesToHex(bytes.slice(0, 1))} (expected 02, 03 or ED)`,
  );
}
