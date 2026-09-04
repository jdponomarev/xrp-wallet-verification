import {
  encodeAccountID,
  isValidClassicAddress,
  isValidXAddress,
  xAddressToClassicAddress,
} from 'ripple-address-codec';
import { MalformedInputError } from './errors.js';
import { accountIdOf } from './hash.js';
import { parsePublicKey } from './keys.js';
import type { NormalizedAddress } from './types.js';

/** Classic r-address of a 33-byte public key (hex). Throws MalformedInputError on a bad key. */
export function deriveAddress(publicKey: string): string {
  return encodeAccountID(accountIdOf(parsePublicKey(publicKey).bytes));
}

/** Accepts a classic or X-address; returns the classic form plus tag. Throws MalformedInputError. */
export function normalizeAddress(addr: string): NormalizedAddress {
  if (typeof addr !== 'string') throw new MalformedInputError('address: expected a string');
  const trimmed = addr.trim();
  if (isValidClassicAddress(trimmed)) return { classic: trimmed, isXAddress: false };
  if (isValidXAddress(trimmed)) {
    const { classicAddress, tag, test } = xAddressToClassicAddress(trimmed);
    const out: NormalizedAddress = { classic: classicAddress, isXAddress: true, test };
    if (tag !== false) out.tag = tag;
    return out;
  }
  throw new MalformedInputError('address: not a valid classic or X-address');
}
