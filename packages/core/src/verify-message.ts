import type { VerifyMessageInput, VerifyResult } from './types.js';

export function verifyMessage(_input: VerifyMessageInput): VerifyResult {
  throw new Error('not implemented');
}

export function verifyMessageByAddress(
  _input: Omit<VerifyMessageInput, 'publicKey'> & { address: string },
): VerifyResult {
  throw new Error('not implemented');
}
