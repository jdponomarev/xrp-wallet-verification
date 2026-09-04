import { readdirSync, readFileSync } from 'node:fs';
import { verify as rippleKeypairsVerify } from 'ripple-keypairs';
import { verifySignature } from 'verify-xrpl-signature';
import { describe, expect, it } from 'vitest';
import { verifyMessage, verifySignInBlob } from '../src/index.js';
import type {
  Reason,
  VerifyMessageInput,
  VerifyResult,
  VerifySignInOptions,
} from '../src/index.js';
import { PENDING_DIR_URL, loadVectors, type Vector } from './helpers.js';

// Kept in sync with the Reason union in src/types.ts by hand: a new reason without a vector fails here.
const REASONS: Reason[] = [
  'bad_signature',
  'algorithm_mismatch',
  'address_mismatch',
  'master_disabled',
  'unsupported_multisig',
  'account_not_found',
  'malformed_input',
  'message_too_large',
  'non_canonical_signature',
  'unexpected_transaction_type',
  'challenge_mismatch',
];

const SCHEMA_KEYS = ['id', 'source', 'kind', 'algorithm', 'encoding', 'expect', 'notes'];

const vectors = loadVectors();

function messageInput(v: Vector): VerifyMessageInput {
  const message = v.encoding === 'hex' ? v.messageHex : v.message;
  if (message === undefined || v.publicKey === undefined || v.signature === undefined) {
    throw new Error(`vector ${v.id}: message, publicKey and signature are required`);
  }
  return {
    message,
    signature: v.signature,
    publicKey: v.publicKey,
    ...(v.encoding === 'hex' ? { encoding: 'hex' as const } : {}),
    ...(v.address !== undefined ? { address: v.address } : {}),
    ...(v.account ? { account: v.account } : {}),
    ...(v.policy ? { policy: v.policy } : {}),
  };
}

function signInOptions(v: Vector): VerifySignInOptions {
  const o = v.options ?? {};
  return {
    ...(o.expectedAccount !== undefined ? { expectedAccount: o.expectedAccount } : {}),
    ...(o.expectedMemo !== undefined ? { expectedMemo: o.expectedMemo } : {}),
    ...(o.allowMissingTransactionType !== undefined
      ? { allowMissingTransactionType: o.allowMissingTransactionType }
      : {}),
    ...(v.account ? { account: v.account } : {}),
    ...(v.policy ? { policy: v.policy } : {}),
  };
}

function run(v: Vector): VerifyResult {
  if (v.kind === 'message') return verifyMessage(messageInput(v));
  if (v.blobHex === undefined) throw new Error(`vector ${v.id}: blobHex is required`);
  return verifySignInBlob(v.blobHex, signInOptions(v));
}

describe('fixtures/vectors.json', () => {
  it('has unique ids', () => {
    expect(new Set(vectors.map((v) => v.id)).size).toBe(vectors.length);
    expect(vectors.length).toBeGreaterThan(0);
  });

  it('produces every Reason at least once', () => {
    const seen = new Set(vectors.map((v) => v.expect.reason));
    for (const reason of REASONS) expect(seen.has(reason), `no vector yields ${reason}`).toBe(true);
    expect(seen.has(null), 'no valid vector').toBe(true);
  });

  for (const v of vectors) {
    it(v.id, () => {
      const result = run(v);
      expect(result.valid).toBe(v.expect.valid);
      expect(result.reason ?? null).toBe(v.expect.reason);
      expect(result.signer).toBe(v.expect.signer);
      if (v.expect.derivedAddress !== undefined) {
        expect(result.derivedAddress).toBe(v.expect.derivedAddress);
      }
      if (v.expect.valid && v.algorithm !== null) expect(result.algorithm).toBe(v.algorithm);
    });
  }
});

describe('cross-check against reference implementations', () => {
  for (const v of vectors.filter((x) => x.kind === 'message' && x.expect.valid)) {
    it(`${v.id} verifies with ripple-keypairs`, () => {
      if (v.messageHex === undefined || v.signature === undefined || v.publicKey === undefined) {
        throw new Error(`vector ${v.id}: messageHex, signature and publicKey are required`);
      }
      expect(rippleKeypairsVerify(v.messageHex, v.signature, v.publicKey)).toBe(true);
    });
  }

  for (const v of vectors.filter((x) => x.kind === 'signin' && x.expect.valid)) {
    it(`${v.id} verifies with verify-xrpl-signature`, () => {
      if (v.blobHex === undefined) throw new Error(`vector ${v.id}: blobHex is required`);
      expect(verifySignature(v.blobHex).signatureValid).toBe(true);
    });
  }
});

describe('fixtures/pending', () => {
  const files = readdirSync(PENDING_DIR_URL)
    .filter((f) => f.endsWith('.json'))
    .sort();

  it('has placeholders', () => expect(files.length).toBeGreaterThan(0));

  for (const file of files) {
    const record = JSON.parse(readFileSync(new URL(file, PENDING_DIR_URL), 'utf8')) as Record<
      string,
      unknown
    >;
    it(`${file} has the vector schema`, () => {
      for (const key of SCHEMA_KEYS) expect(record, `${file} lacks ${key}`).toHaveProperty(key);
      expect(record.expect).toBeTypeOf('object');
    });
    it.skip(`${String(record.id)}: awaiting real-wallet capture`, () => {});
  }
});
