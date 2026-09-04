import type {
  ChallengeFields,
  ValidateChallengeContext,
  ValidateChallengeResult,
} from './types.js';

export function formatChallenge(_fields: ChallengeFields): string {
  throw new Error('not implemented');
}

export function parseChallenge(_text: string): ChallengeFields {
  throw new Error('not implemented');
}

export async function validateChallenge(
  _fields: ChallengeFields,
  _ctx: ValidateChallengeContext,
): Promise<ValidateChallengeResult> {
  throw new Error('not implemented');
}
