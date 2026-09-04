/**
 * Thrown by internal helpers on malformed caller data. Public verification functions catch it and
 * return `{ valid: false, reason: 'malformed_input' }`; it only escapes from helpers that are
 * documented to throw (deriveAddress, normalizeAddress, parseChallenge).
 */
export class MalformedInputError extends Error {
  override readonly name = 'MalformedInputError';
  constructor(message: string) {
    super(message);
  }
}

/** Thrown by parseChallenge with the line where parsing failed. */
export class ParseError extends Error {
  override readonly name = 'ParseError';
  constructor(
    message: string,
    readonly line: number,
  ) {
    super(`${message} (line ${line})`);
  }
}
