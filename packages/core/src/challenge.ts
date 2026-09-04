import { normalizeAddress } from './address.js';
import { MalformedInputError, ParseError } from './errors.js';
import type {
  ChallengeFailure,
  ChallengeFields,
  ChallengeNetwork,
  ValidateChallengeContext,
  ValidateChallengeResult,
} from './types.js';

const HEADER_SUFFIX = ' wants you to prove control of XRP Ledger account:';
const NETWORK_NAMES = ['mainnet', 'testnet', 'devnet', 'xahau'] as const;
const CLOCK_SKEW_MS = 60_000;
const MAX_CHALLENGE_CHARS = 8192;
const MAX_UINT32 = 0xffff_ffff;

const LABEL = '[a-z0-9](?:[a-z0-9-]*[a-z0-9])?';
const DOMAIN_RE = new RegExp(`^${LABEL}(?:\\.${LABEL})*(?::([0-9]{1,5}))?$`);
const NONCE_RE = /^[A-Za-z0-9]{16,}$/;
const TIME_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const NETWORK_ID_RE = /^(?:0|[1-9][0-9]*)$/;
const DEFAULT_PORTS: Record<string, string> = {
  'http:': '80',
  'https:': '443',
  'ws:': '80',
  'wss:': '443',
};

/** Splits `host[:port]`; `undefined` when the string is not a valid authority. */
function splitDomain(domain: string): { host: string; port?: string } | undefined {
  const match = DOMAIN_RE.exec(domain);
  if (!match) return undefined;
  const port = match[1];
  if (port === undefined) return { host: domain };
  const n = Number(port);
  if (n < 1 || n > 65535) return undefined;
  return { host: domain.slice(0, -port.length - 1), port };
}

/** Milliseconds since epoch for an RFC 3339 UTC timestamp; `undefined` when it is not one. */
function parseTime(value: string): number | undefined {
  if (!TIME_RE.test(value)) return undefined;
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return undefined;
  // Date.parse rolls over impossible dates such as 02-30 or 24:00; require an exact match.
  if (new Date(ms).toISOString().slice(0, 19) !== value.slice(0, 19)) return undefined;
  return ms;
}

function parseUrl(value: string): URL | undefined {
  if (!/^\S+$/.test(value)) return undefined;
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function parseNetworkId(value: string): number | undefined {
  if (!NETWORK_ID_RE.test(value)) return undefined;
  const n = Number(value);
  return n <= MAX_UINT32 ? n : undefined;
}

function isNetwork(value: unknown): value is ChallengeNetwork {
  if (typeof value === 'number')
    return Number.isInteger(value) && value >= 0 && value <= MAX_UINT32;
  return (NETWORK_NAMES as readonly string[]).includes(value as string);
}

/** A single line of free text: non-empty, no control characters, no surrounding whitespace. */
function isLine(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    value !== '' &&
    value === value.trim() &&
    // eslint-disable-next-line no-control-regex
    !/[\x00-\x1F\x7F]/.test(value)
  );
}

function isClassicAddress(value: unknown): boolean {
  if (typeof value !== 'string' || value !== value.trim()) return false;
  try {
    return !normalizeAddress(value).isXAddress;
  } catch {
    return false;
  }
}

/** Returns a description of the first invalid field, or `undefined` when every field is valid. */
function checkFields(f: ChallengeFields): string | undefined {
  if (typeof f.domain !== 'string' || !splitDomain(f.domain)) return 'domain: expected host[:port]';
  if (!isClassicAddress(f.address)) return 'address: expected a classic address';
  if (f.statement !== undefined && !isLine(f.statement)) return 'statement: expected a single line';
  if (typeof f.uri !== 'string' || !parseUrl(f.uri)) return 'uri: expected an absolute URI';
  if (f.version !== '1') return 'version: expected "1"';
  if (!isNetwork(f.network)) return 'network: expected a network name or a uint32 NetworkID';
  if (typeof f.nonce !== 'string' || !NONCE_RE.test(f.nonce))
    return 'nonce: expected [A-Za-z0-9]{16,}';
  if (typeof f.issuedAt !== 'string' || parseTime(f.issuedAt) === undefined)
    return 'issuedAt: expected an RFC 3339 UTC timestamp';
  if (typeof f.expirationTime !== 'string' || parseTime(f.expirationTime) === undefined)
    return 'expirationTime: expected an RFC 3339 UTC timestamp';
  if (f.requestId !== undefined && !isLine(f.requestId)) return 'requestId: expected a single line';
  return undefined;
}

/**
 * Renders challenge fields as the canonical v1 envelope text (LF line endings, no trailing newline).
 * Throws MalformedInputError when a field cannot round-trip through {@link parseChallenge}.
 */
export function formatChallenge(fields: ChallengeFields): string {
  const problem = checkFields(fields);
  if (problem) throw new MalformedInputError(problem);
  const lines = [`${fields.domain}${HEADER_SUFFIX}`, fields.address, ''];
  if (fields.statement !== undefined) lines.push(fields.statement, '');
  lines.push(
    `URI: ${fields.uri}`,
    `Version: ${fields.version}`,
    `Network: ${fields.network}`,
    `Nonce: ${fields.nonce}`,
    `Issued At: ${fields.issuedAt}`,
    `Expiration Time: ${fields.expirationTime}`,
  );
  if (fields.requestId !== undefined) lines.push(`Request ID: ${fields.requestId}`);
  return lines.join('\n');
}

/**
 * Parses envelope text into fields. Strict: exact line order, no unknown fields, no surrounding
 * whitespace, no trailing newline; CRLF is normalised to LF. Throws ParseError on the first violation.
 */
export function parseChallenge(text: string): ChallengeFields {
  if (typeof text !== 'string') throw new MalformedInputError('challenge: expected a string');
  if (text === '') throw new ParseError('empty challenge', 1);
  if (text.charCodeAt(0) === 0xfeff) throw new ParseError('unexpected byte order mark', 1);
  if (text.length > MAX_CHALLENGE_CHARS) throw new ParseError('challenge too long', 1);

  const lines = text.replace(/\r\n/g, '\n').split('\n');
  if (lines.length > 1 && lines[lines.length - 1] === '')
    throw new ParseError('trailing newline', lines.length);
  lines.forEach((line, i) => {
    if (line !== line.trim()) throw new ParseError('leading or trailing whitespace', i + 1);
  });

  const at = (i: number): string => {
    const line = lines[i];
    if (line === undefined) throw new ParseError('unexpected end of challenge', i + 1);
    return line;
  };
  const field = (i: number, name: string): string => {
    const line = at(i);
    if (!line.startsWith(`${name}: `)) throw new ParseError(`expected "${name}:"`, i + 1);
    return line.slice(name.length + 2);
  };
  const fail = (i: number, message: string): never => {
    throw new ParseError(message, i + 1);
  };

  const header = at(0);
  if (!header.endsWith(HEADER_SUFFIX))
    fail(0, 'expected "<domain> wants you to prove control of XRP Ledger account:"');
  const domain = header.slice(0, -HEADER_SUFFIX.length);
  if (!splitDomain(domain)) fail(0, 'domain: expected host[:port]');

  const address = at(1);
  if (!isClassicAddress(address)) fail(1, 'address: expected a classic address');
  if (at(2) !== '') fail(2, 'expected a blank line');

  let i = 3;
  let statement: string | undefined;
  if (!at(3).startsWith('URI: ')) {
    statement = at(3);
    if (!isLine(statement)) fail(3, 'statement: expected a single line');
    if (at(4) !== '') fail(4, 'expected a blank line after the statement');
    i = 5;
  }

  const uri = field(i, 'URI');
  if (!parseUrl(uri)) fail(i, 'uri: expected an absolute URI');
  const version = field(i + 1, 'Version');
  if (version !== '1') fail(i + 1, 'version: expected "1"');
  const networkText = field(i + 2, 'Network');
  const network = (NETWORK_NAMES as readonly string[]).includes(networkText)
    ? (networkText as ChallengeNetwork)
    : parseNetworkId(networkText);
  if (network === undefined) fail(i + 2, 'network: expected a network name or a uint32 NetworkID');
  const nonce = field(i + 3, 'Nonce');
  if (!NONCE_RE.test(nonce)) fail(i + 3, 'nonce: expected [A-Za-z0-9]{16,}');
  const issuedAt = field(i + 4, 'Issued At');
  if (parseTime(issuedAt) === undefined)
    fail(i + 4, 'issuedAt: expected an RFC 3339 UTC timestamp');
  const expirationTime = field(i + 5, 'Expiration Time');
  if (parseTime(expirationTime) === undefined)
    fail(i + 5, 'expirationTime: expected an RFC 3339 UTC timestamp');

  const fields: ChallengeFields = {
    domain,
    address,
    uri,
    version: '1',
    network: network as ChallengeNetwork,
    nonce,
    issuedAt,
    expirationTime,
  };
  if (statement !== undefined) fields.statement = statement;

  i += 6;
  if (i < lines.length) {
    const requestId = field(i, 'Request ID');
    if (!isLine(requestId)) fail(i, 'requestId: expected a single line');
    fields.requestId = requestId;
    i += 1;
  }
  if (i < lines.length) fail(i, 'unexpected content after the last field');
  return fields;
}

function uriMatchesDomain(uri: string, domain: string): boolean {
  const url = parseUrl(uri);
  const authority = splitDomain(domain.toLowerCase());
  if (!url || !authority) return false;
  if (url.hostname.toLowerCase() !== authority.host) return false;
  if (authority.port === undefined) return true;
  return (url.port || DEFAULT_PORTS[url.protocol]) === authority.port;
}

/**
 * Checks fields against the verifier's expectations. Checks run in this order and the first
 * failure is returned: domain, address, network, nonce length, timestamp syntax, not-yet-valid
 * (60 s skew), expired, expiration before issue, URI host, fields round-trip through format/parse
 * (`malformed_fields`, for hand-built objects), nonce reuse. Never throws for bad field values;
 * throws TypeError when `ctx` is malformed and propagates errors from `ctx.isNonceUnused`.
 */
export async function validateChallenge(
  fields: ChallengeFields,
  ctx: ValidateChallengeContext,
): Promise<ValidateChallengeResult> {
  if (
    !(ctx.now instanceof Date) ||
    Number.isNaN(ctx.now.getTime()) ||
    typeof ctx.expectedDomain !== 'string' ||
    typeof ctx.isNonceUnused !== 'function'
  ) {
    throw new TypeError('validateChallenge: ctx needs now, expectedDomain and isNonceUnused');
  }
  const fail = (reason: ChallengeFailure): ValidateChallengeResult => ({ ok: false, reason });

  if (
    typeof fields.domain !== 'string' ||
    fields.domain.toLowerCase() !== ctx.expectedDomain.toLowerCase()
  ) {
    return fail('domain_mismatch');
  }
  if (
    ctx.expectedAddress !== undefined &&
    normalizeAddress(ctx.expectedAddress).classic !== fields.address
  ) {
    return fail('address_mismatch');
  }
  if (ctx.expectedNetwork !== undefined && ctx.expectedNetwork !== fields.network) {
    return fail('network_mismatch');
  }
  if (typeof fields.nonce !== 'string' || fields.nonce.length < 16) return fail('nonce_too_short');

  const issued = typeof fields.issuedAt === 'string' ? parseTime(fields.issuedAt) : undefined;
  const expires =
    typeof fields.expirationTime === 'string' ? parseTime(fields.expirationTime) : undefined;
  if (issued === undefined || expires === undefined) return fail('invalid_time');
  const now = ctx.now.getTime();
  if (issued > now + CLOCK_SKEW_MS) return fail('not_yet_valid');
  if (expires <= now) return fail('expired');
  if (expires <= issued) return fail('invalid_time');

  if (typeof fields.uri !== 'string' || !uriMatchesDomain(fields.uri, fields.domain)) {
    return fail('invalid_uri');
  }
  try {
    parseChallenge(formatChallenge(fields));
  } catch {
    return fail('malformed_fields');
  }
  if (!(await ctx.isNonceUnused(fields.nonce))) return fail('nonce_used');
  return { ok: true };
}
