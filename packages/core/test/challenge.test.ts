import { encodeAccountID } from 'ripple-address-codec';
import { describe, expect, it, vi } from 'vitest';
import { formatChallenge, parseChallenge, validateChallenge } from '../src/challenge.js';
import { MalformedInputError, ParseError } from '../src/errors.js';
import type { ChallengeFields, ValidateChallengeContext } from '../src/types.js';

const ADDRESS = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const X_ADDRESS = 'XVPcpSm47b1CZkf5AkKM9a84dQHe3m4sBhsrA4XtnBECTAc';

const base: ChallengeFields = {
  domain: 'example.com',
  address: ADDRESS,
  uri: 'https://example.com/login',
  version: '1',
  network: 'mainnet',
  nonce: 'k3Jf9sLq2ZxW8vBn',
  issuedAt: '2026-09-04T08:00:00Z',
  expirationTime: '2026-09-04T08:10:00Z',
};

const CANONICAL = [
  'example.com wants you to prove control of XRP Ledger account:',
  ADDRESS,
  '',
  'URI: https://example.com/login',
  'Version: 1',
  'Network: mainnet',
  'Nonce: k3Jf9sLq2ZxW8vBn',
  'Issued At: 2026-09-04T08:00:00Z',
  'Expiration Time: 2026-09-04T08:10:00Z',
].join('\n');

const lines = (text: string) => text.split('\n');

function expectParseError(text: string, line: number) {
  let caught: unknown;
  try {
    parseChallenge(text);
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(ParseError);
  expect((caught as ParseError).line).toBe(line);
}

// Deterministic generator: a 32-bit LCG so the property test never depends on Math.random.
function lcg(seed: number) {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s;
  };
}
const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
function pick<T>(next: () => number, items: readonly T[]): T {
  return items[next() % items.length] as T;
}
function alnum(next: () => number, length: number): string {
  let out = '';
  for (let i = 0; i < length; i++) out += ALNUM[next() % ALNUM.length];
  return out;
}
function randomFields(next: () => number): ChallengeFields {
  const id = new Uint8Array(20);
  for (let i = 0; i < 20; i++) id[i] = next() & 0xff;
  const host = pick(next, ['example.com', 'login.example.org', 'localhost:3000', 'a-b.c1.io']);
  const f: ChallengeFields = {
    domain: host,
    address: encodeAccountID(id),
    uri: `https://${host}/${alnum(next, 1 + (next() % 12))}?s=${alnum(next, 4)}`,
    version: '1',
    network: pick(next, ['mainnet', 'testnet', 'devnet', 'xahau', 0, 1, 21337, 4294967295]),
    nonce: alnum(next, 16 + (next() % 24)),
    issuedAt: `2026-09-${String(1 + (next() % 28)).padStart(2, '0')}T08:00:00Z`,
    expirationTime: `2026-10-01T${String(next() % 24).padStart(2, '0')}:30:15.${next() % 1000}Z`,
  };
  if (next() % 2) f.statement = `Sign in to ${host} ${alnum(next, 6)}`;
  if (next() % 2) f.requestId = alnum(next, 8);
  return f;
}

describe('formatChallenge', () => {
  it('renders the canonical envelope with LF endings and no trailing newline', () => {
    expect(formatChallenge(base)).toBe(CANONICAL);
  });

  it('renders the optional statement and Request ID in their places', () => {
    const text = formatChallenge({ ...base, statement: 'Sign in to Example', requestId: 'req-42' });
    const out = lines(text);
    expect(out[3]).toBe('Sign in to Example');
    expect(out[4]).toBe('');
    expect(out[5]).toBe('URI: https://example.com/login');
    expect(out[out.length - 1]).toBe('Request ID: req-42');
  });

  it('renders a numeric network as decimal', () => {
    expect(lines(formatChallenge({ ...base, network: 21337 }))[5]).toBe('Network: 21337');
  });

  it.each<[string, Partial<ChallengeFields>]>([
    ['uppercase domain', { domain: 'Example.com' }],
    ['domain with path', { domain: 'example.com/x' }],
    ['domain with bad port', { domain: 'example.com:70000' }],
    ['X-address', { address: X_ADDRESS }],
    ['garbage address', { address: 'rNotAnAddress' }],
    ['multi-line statement', { statement: 'line one\nline two' }],
    ['empty statement', { statement: '' }],
    ['padded statement', { statement: ' padded' }],
    ['relative uri', { uri: '/login' }],
    ['uri with whitespace', { uri: 'https://example.com/a b' }],
    ['version 2', { version: '2' as '1' }],
    ['negative network', { network: -1 }],
    ['fractional network', { network: 1.5 }],
    ['network above uint32', { network: 4294967296 }],
    ['unknown network name', { network: 'ripplenet' as 'mainnet' }],
    ['short nonce', { nonce: 'abc123' }],
    ['nonce with symbols', { nonce: 'abcdefghijklmnop-' }],
    ['non-UTC issuedAt', { issuedAt: '2026-09-04T08:00:00+10:00' }],
    ['rolled-over date', { issuedAt: '2026-02-30T00:00:00Z' }],
    ['hour 24', { expirationTime: '2026-09-04T24:00:00Z' }],
    ['request id with newline', { requestId: 'a\nb' }],
  ])('throws MalformedInputError on %s', (_name, patch) => {
    expect(() => formatChallenge({ ...base, ...patch })).toThrow(MalformedInputError);
  });
});

describe('parseChallenge', () => {
  it('parses the canonical envelope', () => {
    expect(parseChallenge(CANONICAL)).toEqual(base);
  });

  it('round-trips 200 generated field sets', () => {
    const next = lcg(20260904);
    for (let i = 0; i < 200; i++) {
      const f = randomFields(next);
      expect(parseChallenge(formatChallenge(f))).toEqual(f);
    }
  });

  it('accepts CRLF line endings', () => {
    expect(parseChallenge(CANONICAL.replace(/\n/g, '\r\n'))).toEqual(base);
  });

  it('parses a statement and Request ID when present', () => {
    const f = { ...base, statement: 'Sign in to Example', requestId: 'req-42' };
    const parsed = parseChallenge(formatChallenge(f));
    expect(parsed).toEqual(f);
    expect(parsed.statement).toBe('Sign in to Example');
    expect(parsed.requestId).toBe('req-42');
  });

  it('leaves statement and requestId absent when not present', () => {
    const parsed = parseChallenge(CANONICAL);
    expect('statement' in parsed).toBe(false);
    expect('requestId' in parsed).toBe(false);
  });

  it('parses a numeric network as a number', () => {
    expect(parseChallenge(CANONICAL.replace('Network: mainnet', 'Network: 21337')).network).toBe(
      21337,
    );
    expect(parseChallenge(CANONICAL.replace('Network: mainnet', 'Network: 0')).network).toBe(0);
  });

  it('rejects empty text and a BOM', () => {
    expectParseError('', 1);
    expectParseError(`\uFEFF${CANONICAL}`, 1);
  });

  it('rejects an unknown field', () => {
    const out = lines(CANONICAL);
    out.splice(6, 0, 'Chain ID: 1');
    expectParseError(out.join('\n'), 7);
  });

  it('rejects reordered fields', () => {
    const out = lines(CANONICAL);
    [out[5], out[6]] = [out[6] as string, out[5] as string];
    expectParseError(out.join('\n'), 6);
  });

  it('rejects a trailing newline', () => {
    expectParseError(`${CANONICAL}\n`, 10);
    expectParseError(`${CANONICAL}\r\n`, 10);
  });

  it('rejects leading or trailing whitespace on a line', () => {
    expectParseError(CANONICAL.replace('Network: mainnet', 'Network: mainnet '), 6);
    expectParseError(CANONICAL.replace('Version: 1', ' Version: 1'), 5);
    expectParseError(CANONICAL.replace('Version: 1', 'Version: 1\t'), 5);
  });

  it('rejects a missing blank line after the address', () => {
    const out = lines(CANONICAL);
    out.splice(2, 1);
    expectParseError(out.join('\n'), 3);
  });

  it('rejects a multi-line statement', () => {
    const out = lines(CANONICAL);
    out.splice(3, 0, 'Statement one', 'Statement two', '');
    expectParseError(out.join('\n'), 5);
  });

  it('rejects a statement without a following blank line', () => {
    const out = lines(CANONICAL);
    out.splice(3, 0, 'Statement one');
    expectParseError(out.join('\n'), 5);
  });

  it('rejects a bad header, domain or address', () => {
    expectParseError(CANONICAL.replace('wants you to prove', 'wants you to sign'), 1);
    expectParseError(CANONICAL.replace('example.com wants', 'Example.com wants'), 1);
    expectParseError(CANONICAL.replace(ADDRESS, X_ADDRESS), 2);
    expectParseError(CANONICAL.replace(ADDRESS, 'rNotAnAddress'), 2);
  });

  it('rejects bad URI, version and network values', () => {
    expectParseError(CANONICAL.replace('https://example.com/login', 'login'), 4);
    expectParseError(CANONICAL.replace('Version: 1', 'Version: 2'), 5);
    expectParseError(CANONICAL.replace('Network: mainnet', 'Network: ripplenet'), 6);
    expectParseError(CANONICAL.replace('Network: mainnet', 'Network: 01'), 6);
    expectParseError(CANONICAL.replace('Network: mainnet', 'Network: 4294967296'), 6);
  });

  it('rejects a bad nonce', () => {
    expectParseError(CANONICAL.replace('k3Jf9sLq2ZxW8vBn', 'short'), 7);
    expectParseError(CANONICAL.replace('k3Jf9sLq2ZxW8vBn', 'k3Jf9sLq2ZxW8vB_'), 7);
  });

  it('rejects a bad date', () => {
    expectParseError(CANONICAL.replace('2026-09-04T08:00:00Z', '2026-09-04 08:00:00'), 8);
    expectParseError(CANONICAL.replace('2026-09-04T08:10:00Z', '2026-09-04T08:10:00+00:00'), 9);
    expectParseError(CANONICAL.replace('2026-09-04T08:10:00Z', '2026-02-30T08:10:00Z'), 9);
  });

  it('rejects a truncated envelope', () => {
    expectParseError(lines(CANONICAL).slice(0, 8).join('\n'), 9);
    expectParseError(lines(CANONICAL).slice(0, 2).join('\n'), 3);
  });

  it('rejects content after Request ID and a second Request ID', () => {
    expectParseError(`${CANONICAL}\nRequest ID: a\nRequest ID: b`, 11);
    expectParseError(`${CANONICAL}\nRequest ID: a\nfoo`, 11);
    expectParseError(`${CANONICAL}\nRequest ID: `, 10);
  });
});

describe('validateChallenge', () => {
  const now = new Date('2026-09-04T08:05:00Z');
  const ctx = (patch: Partial<ValidateChallengeContext> = {}): ValidateChallengeContext => ({
    now,
    expectedDomain: 'example.com',
    isNonceUnused: () => true,
    ...patch,
  });

  it('accepts a fresh, matching challenge', async () => {
    await expect(validateChallenge(base, ctx())).resolves.toEqual({ ok: true });
  });

  it('returns malformed_fields for hand-built fields the parser would reject', async () => {
    const isNonceUnused = vi.fn(() => true);
    const result = await validateChallenge(
      { ...base, statement: 'two\nlines' },
      ctx({ isNonceUnused }),
    );
    expect(result).toEqual({ ok: false, reason: 'malformed_fields' });
    expect(isNonceUnused).not.toHaveBeenCalled();
  });

  it('accepts when every expectation is given and matches, with an async nonce store', async () => {
    const isNonceUnused = vi.fn(async (nonce: string) => nonce === base.nonce);
    const result = await validateChallenge(
      base,
      ctx({ expectedAddress: ADDRESS, expectedNetwork: 'mainnet', isNonceUnused }),
    );
    expect(result).toEqual({ ok: true });
    expect(isNonceUnused).toHaveBeenCalledWith(base.nonce);
  });

  it('compares the domain case-insensitively', async () => {
    await expect(validateChallenge(base, ctx({ expectedDomain: 'EXAMPLE.com' }))).resolves.toEqual({
      ok: true,
    });
    await expect(validateChallenge(base, ctx({ expectedDomain: 'example.org' }))).resolves.toEqual({
      ok: false,
      reason: 'domain_mismatch',
    });
  });

  it('returns address_mismatch and normalises an expected X-address', async () => {
    await expect(
      validateChallenge(base, ctx({ expectedAddress: 'rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH' })),
    ).resolves.toEqual({ ok: false, reason: 'address_mismatch' });
    await expect(validateChallenge(base, ctx({ expectedAddress: X_ADDRESS }))).resolves.toEqual({
      ok: true,
    });
  });

  it('returns network_mismatch, treating names and numbers as distinct', async () => {
    await expect(validateChallenge(base, ctx({ expectedNetwork: 'testnet' }))).resolves.toEqual({
      ok: false,
      reason: 'network_mismatch',
    });
    await expect(validateChallenge(base, ctx({ expectedNetwork: 0 }))).resolves.toEqual({
      ok: false,
      reason: 'network_mismatch',
    });
    await expect(
      validateChallenge({ ...base, network: 21337 }, ctx({ expectedNetwork: 21337 })),
    ).resolves.toEqual({ ok: true });
  });

  it('returns nonce_too_short', async () => {
    await expect(validateChallenge({ ...base, nonce: 'abcdefghijklmno' }, ctx())).resolves.toEqual({
      ok: false,
      reason: 'nonce_too_short',
    });
  });

  it('returns invalid_time for unparsable timestamps', async () => {
    await expect(validateChallenge({ ...base, issuedAt: 'yesterday' }, ctx())).resolves.toEqual({
      ok: false,
      reason: 'invalid_time',
    });
    await expect(
      validateChallenge({ ...base, expirationTime: '2026-09-04T08:10:00+00:00' }, ctx()),
    ).resolves.toEqual({ ok: false, reason: 'invalid_time' });
  });

  it('returns not_yet_valid beyond 60 s of skew and accepts within it', async () => {
    await expect(
      validateChallenge(
        { ...base, issuedAt: '2026-09-04T08:06:01Z', expirationTime: '2026-09-04T08:16:00Z' },
        ctx(),
      ),
    ).resolves.toEqual({ ok: false, reason: 'not_yet_valid' });
    await expect(
      validateChallenge(
        { ...base, issuedAt: '2026-09-04T08:06:00Z', expirationTime: '2026-09-04T08:16:00Z' },
        ctx(),
      ),
    ).resolves.toEqual({ ok: true });
  });

  it('returns expired at or after the expiration time', async () => {
    await expect(
      validateChallenge({ ...base, expirationTime: '2026-09-04T08:05:00Z' }, ctx()),
    ).resolves.toEqual({ ok: false, reason: 'expired' });
    await expect(
      validateChallenge({ ...base, expirationTime: '2026-09-04T08:04:59Z' }, ctx()),
    ).resolves.toEqual({ ok: false, reason: 'expired' });
  });

  it('returns invalid_time when the expiration is not after issue', async () => {
    await expect(
      validateChallenge(
        { ...base, issuedAt: '2026-09-04T08:06:00Z', expirationTime: '2026-09-04T08:06:00Z' },
        ctx(),
      ),
    ).resolves.toEqual({ ok: false, reason: 'invalid_time' });
  });

  it('returns invalid_uri when the URI host differs from the domain', async () => {
    await expect(
      validateChallenge({ ...base, uri: 'https://evil.example.org/login' }, ctx()),
    ).resolves.toEqual({ ok: false, reason: 'invalid_uri' });
    await expect(validateChallenge({ ...base, uri: 'not a url' }, ctx())).resolves.toEqual({
      ok: false,
      reason: 'invalid_uri',
    });
  });

  it('ignores the URI port only when the domain has none', async () => {
    await expect(
      validateChallenge({ ...base, uri: 'https://example.com:8443/login' }, ctx()),
    ).resolves.toEqual({ ok: true });
    const withPort = {
      ...base,
      domain: 'example.com:8443',
      uri: 'https://example.com/login',
    };
    await expect(
      validateChallenge(withPort, ctx({ expectedDomain: 'example.com:8443' })),
    ).resolves.toEqual({ ok: false, reason: 'invalid_uri' });
    await expect(
      validateChallenge(
        { ...withPort, uri: 'https://example.com:8443/login' },
        ctx({ expectedDomain: 'example.com:8443' }),
      ),
    ).resolves.toEqual({ ok: true });
    await expect(
      validateChallenge(
        { ...base, domain: 'example.com:443' },
        ctx({ expectedDomain: 'example.com:443' }),
      ),
    ).resolves.toEqual({ ok: true });
  });

  it('returns nonce_used when the store reports the nonce as seen', async () => {
    await expect(
      validateChallenge(base, ctx({ isNonceUnused: async () => false })),
    ).resolves.toEqual({ ok: false, reason: 'nonce_used' });
    await expect(validateChallenge(base, ctx({ isNonceUnused: () => false }))).resolves.toEqual({
      ok: false,
      reason: 'nonce_used',
    });
  });

  it('checks in the documented order and consults the nonce store last', async () => {
    const isNonceUnused = vi.fn(() => false);
    const result = await validateChallenge(
      { ...base, expirationTime: '2026-09-04T08:00:00Z' },
      ctx({ expectedDomain: 'other.com', isNonceUnused }),
    );
    expect(result).toEqual({ ok: false, reason: 'domain_mismatch' });
    expect(isNonceUnused).not.toHaveBeenCalled();
  });

  it('propagates a nonce store failure instead of accepting', async () => {
    await expect(
      validateChallenge(
        base,
        ctx({
          isNonceUnused: async () => {
            throw new Error('store down');
          },
        }),
      ),
    ).rejects.toThrow('store down');
  });

  it('throws on a malformed ctx', async () => {
    await expect(
      validateChallenge(base, { ...ctx(), now: 'now' as unknown as Date }),
    ).rejects.toThrow(TypeError);
    await expect(
      validateChallenge(base, { ...ctx(), isNonceUnused: undefined as unknown as () => boolean }),
    ).rejects.toThrow(TypeError);
  });
});
