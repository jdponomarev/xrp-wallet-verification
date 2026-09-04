import { bytesToHex as nobleBytesToHex } from '@noble/hashes/utils.js';
import { MalformedInputError } from './errors.js';

const HEX_RE = /^[0-9a-fA-F]*$/;

/** Strict hex parse: even length, hex digits only. Case-insensitive. Empty string gives empty bytes. */
export function hexToBytes(hex: string, what = 'hex'): Uint8Array {
  if (typeof hex !== 'string') throw new MalformedInputError(`${what}: expected a string`);
  if (!HEX_RE.test(hex)) throw new MalformedInputError(`${what}: not hexadecimal`);
  if (hex.length % 2 !== 0) throw new MalformedInputError(`${what}: odd-length hex`);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** Uppercase hex, the XRPL convention. */
export function bytesToHex(bytes: Uint8Array): string {
  return nobleBytesToHex(bytes).toUpperCase();
}

export function utf8ToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Returns undefined when the bytes are not valid UTF-8. */
export function bytesToUtf8(bytes: Uint8Array): string | undefined {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
