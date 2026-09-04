import { normalizeAddress } from './address.js';
import { MalformedInputError } from './errors.js';
import type { AccountState } from './types.js';

export interface NormalizedAccountState {
  classic: string;
  regularKey?: string;
  exists: boolean;
  masterDisabled: boolean;
  hasSignerList: boolean;
}

/**
 * Validates a caller-supplied AccountState and normalises its addresses. A missing or non-boolean
 * policy field is rejected rather than read as false, so a hand-built object cannot fail open.
 * Throws MalformedInputError; callers map it to `malformed_input`.
 */
export function normalizeAccountState(state: AccountState): NormalizedAccountState {
  if (typeof state !== 'object' || state === null) {
    throw new MalformedInputError('account: expected an object');
  }
  for (const field of ['exists', 'masterDisabled', 'hasSignerList'] as const) {
    if (typeof state[field] !== 'boolean') {
      throw new MalformedInputError(`account.${field}: expected a boolean`);
    }
  }
  const out: NormalizedAccountState = {
    classic: normalizeAddress(state.address).classic,
    exists: state.exists,
    masterDisabled: state.masterDisabled,
    hasSignerList: state.hasSignerList,
  };
  if (state.regularKey !== undefined) out.regularKey = normalizeAddress(state.regularKey).classic;
  return out;
}
