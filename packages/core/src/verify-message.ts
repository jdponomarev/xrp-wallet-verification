import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import type { ECDSASignature } from '@noble/curves/abstract/weierstrass.js';
import { addressOfKeyBytes, normalizeAddress } from './address.js';
import { normalizeAccountState, type NormalizedAccountState } from './account-state.js';
import { sha512Half } from './hash.js';
import { hexToBytes, utf8ToBytes } from './hex.js';
import { parsePublicKey, type ParsedPublicKey } from './keys.js';
import type {
  AccountState,
  Algorithm,
  Encoding,
  Policy,
  Reason,
  Signer,
  VerifyMessageInput,
  VerifyResult,
} from './types.js';

const DEFAULT_MAX_MESSAGE_BYTES = 65536;

interface ResolvedPolicy {
  allowMasterDisabled: boolean;
  requireLowS: boolean;
  maxMessageBytes: number;
}

/** Fields of the result that are known before the verdict; filled in as parsing progresses. */
interface Ctx {
  algorithm?: Algorithm;
  derivedAddress?: string;
}

interface Failure {
  reason: Reason;
  details?: Record<string, unknown>;
}

/** Addresses the signer is compared against, all in classic form. */
interface Target {
  classic?: string;
  regularKey?: string;
  account?: NormalizedAccountState;
  conflict: boolean;
}

type Decoded = { ok: true; bytes: Uint8Array } | { ok: false; failure: Failure };

function resolvePolicy(policy: Policy | undefined): ResolvedPolicy {
  const maxMessageBytes = policy?.maxMessageBytes ?? DEFAULT_MAX_MESSAGE_BYTES;
  if (!Number.isInteger(maxMessageBytes) || maxMessageBytes <= 0) {
    throw new RangeError('policy.maxMessageBytes must be a positive integer');
  }
  return {
    allowMasterDisabled: policy?.allowMasterDisabled ?? false,
    requireLowS: policy?.requireLowS ?? true,
    maxMessageBytes,
  };
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

function fail(ctx: Ctx, failure: Failure, signer: Signer = 'unknown'): VerifyResult {
  const out: VerifyResult = { valid: false, reason: failure.reason, signer };
  if (ctx.algorithm) out.algorithm = ctx.algorithm;
  if (ctx.derivedAddress) out.derivedAddress = ctx.derivedAddress;
  if (failure.details) out.details = failure.details;
  return out;
}

function malformed(error: string): Failure {
  return { reason: 'malformed_input', details: { error } };
}

/** Message bytes to verify. Empty messages are rejected in both encodings. */
function decodeMessage(message: unknown, encoding: Encoding | undefined, max: number): Decoded {
  if (typeof message !== 'string')
    return { ok: false, failure: malformed('message: expected a string') };
  let bytes: Uint8Array;
  if (encoding === undefined || encoding === 'utf8') {
    bytes = utf8ToBytes(message);
  } else if (encoding === 'hex') {
    try {
      bytes = hexToBytes(message, 'message');
    } catch (e) {
      return { ok: false, failure: malformed(errorMessage(e)) };
    }
  } else {
    return { ok: false, failure: malformed(`encoding: unknown value ${String(encoding)}`) };
  }
  if (bytes.length === 0) return { ok: false, failure: malformed('message: empty') };
  if (bytes.length > max) {
    return {
      ok: false,
      failure: { reason: 'message_too_large', details: { bytes: bytes.length, max } },
    };
  }
  return { ok: true, bytes };
}

function parseDer(bytes: Uint8Array): ECDSASignature | undefined {
  try {
    return secp256k1.Signature.fromBytes(bytes, 'der');
  } catch {
    return undefined;
  }
}

function secpVerify(
  sig: ECDSASignature,
  msgHash: Uint8Array,
  pub33: Uint8Array,
  lowS: boolean,
): boolean {
  try {
    return secp256k1.verify(sig.toBytes('compact'), msgHash, pub33, { prehash: false, lowS });
  } catch {
    return false;
  }
}

function ed25519Verify(sig: Uint8Array, msg: Uint8Array, pub32: Uint8Array): boolean {
  try {
    return ed25519.verify(sig, msg, pub32, { zip215: false });
  } catch {
    return false;
  }
}

/**
 * Normalises the address and account the caller wants the signer bound to. `conflict` is set when
 * both are given and disagree. Throws MalformedInputError; the callers map it to `malformed_input`.
 */
function resolveTarget(address: string | undefined, account: AccountState | undefined): Target {
  const target: Target = { conflict: false };
  if (address !== undefined) target.classic = normalizeAddress(address).classic;
  if (account !== undefined && account !== null) {
    const state = normalizeAccountState(account);
    if (target.classic === undefined) target.classic = state.classic;
    else if (target.classic !== state.classic) target.conflict = true;
    if (state.regularKey !== undefined) target.regularKey = state.regularKey;
    target.account = state;
  }
  return target;
}

function bindSigner(derived: string | undefined, target: Target): Signer {
  if (derived === undefined) return 'unknown';
  if (derived === target.classic) return 'master';
  if (target.regularKey !== undefined && derived === target.regularKey) return 'regular';
  return 'unknown';
}

/** Address binding and account policy, applied only after the signature itself has verified. */
function finish(ctx: Ctx, signer: Signer, target: Target, policy: ResolvedPolicy): VerifyResult {
  if (target.conflict) {
    return fail(ctx, {
      reason: 'address_mismatch',
      details: { error: 'address and account.address differ' },
    });
  }
  const account = target.account;
  if (account && !account.exists) {
    const derivedMatches =
      ctx.derivedAddress !== undefined && ctx.derivedAddress === target.classic;
    return fail(ctx, { reason: 'account_not_found', details: { derivedMatches } }, signer);
  }
  if (target.classic !== undefined && signer === 'unknown') {
    return fail(ctx, {
      reason: 'address_mismatch',
      details: { expected: target.classic, derived: ctx.derivedAddress },
    });
  }
  if (account?.hasSignerList) return fail(ctx, { reason: 'unsupported_multisig' }, signer);
  if (signer === 'master' && account?.masterDisabled && !policy.allowMasterDisabled) {
    return fail(ctx, { reason: 'master_disabled' }, signer);
  }
  const out: VerifyResult = { valid: true, signer };
  if (ctx.algorithm) out.algorithm = ctx.algorithm;
  if (ctx.derivedAddress) out.derivedAddress = ctx.derivedAddress;
  return out;
}

/**
 * Verify a raw-bytes XRPL message signature (the GemWallet / ripple-keypairs scheme) against a
 * public key, optionally binding the signer to an address and applying account policy.
 * Never throws on caller data; throws only on an invalid `policy`.
 */
export function verifyMessage(input: VerifyMessageInput): VerifyResult {
  const policy = resolvePolicy(input.policy);
  const ctx: Ctx = {};

  const msg = decodeMessage(input.message, input.encoding, policy.maxMessageBytes);
  if (!msg.ok) return fail(ctx, msg.failure);

  let key: ParsedPublicKey;
  try {
    key = parsePublicKey(input.publicKey);
  } catch (e) {
    return fail(ctx, malformed(errorMessage(e)));
  }
  ctx.algorithm = key.algorithm;
  ctx.derivedAddress = addressOfKeyBytes(key.bytes);

  let sigBytes: Uint8Array;
  try {
    sigBytes = hexToBytes(input.signature, 'signature');
  } catch (e) {
    return fail(ctx, malformed(errorMessage(e)));
  }

  let target: Target;
  try {
    target = resolveTarget(input.address, input.account);
  } catch (e) {
    return fail(ctx, malformed(errorMessage(e)));
  }

  if (key.algorithm === 'ed25519') {
    if (sigBytes.length !== 64) {
      if (parseDer(sigBytes)) {
        return fail(ctx, {
          reason: 'algorithm_mismatch',
          details: { error: 'DER (secp256k1) signature supplied with an ed25519 key' },
        });
      }
      return fail(ctx, malformed(`signature: expected 64 bytes, got ${sigBytes.length}`));
    }
    if (!ed25519Verify(sigBytes, msg.bytes, key.bytes.slice(1))) {
      return fail(ctx, { reason: 'bad_signature' });
    }
  } else {
    const sig = parseDer(sigBytes);
    if (!sig) {
      if (sigBytes.length === 64) {
        return fail(ctx, {
          reason: 'algorithm_mismatch',
          details: { error: '64-byte (ed25519) signature supplied with a secp256k1 key' },
        });
      }
      return fail(ctx, malformed('signature: not canonical DER'));
    }
    if (policy.requireLowS && sig.hasHighS()) {
      return fail(ctx, { reason: 'non_canonical_signature' });
    }
    if (!secpVerify(sig, sha512Half(msg.bytes), key.bytes, policy.requireLowS)) {
      return fail(ctx, { reason: 'bad_signature' });
    }
  }

  return finish(ctx, bindSigner(ctx.derivedAddress, target), target, policy);
}

/**
 * Verify a secp256k1 message signature when only the signer's address is known: the public key is
 * recovered from the signature and accepted if it derives to `address` (or the account's
 * RegularKey). Ed25519 signatures cannot be verified this way and return `algorithm_mismatch`.
 */
export function verifyMessageByAddress(
  input: Omit<VerifyMessageInput, 'publicKey'> & { address: string },
): VerifyResult {
  const policy = resolvePolicy(input.policy);
  const ctx: Ctx = {};

  const msg = decodeMessage(input.message, input.encoding, policy.maxMessageBytes);
  if (!msg.ok) return fail(ctx, msg.failure);

  if (typeof input.address !== 'string') return fail(ctx, malformed('address: required'));
  let target: Target;
  try {
    target = resolveTarget(input.address, input.account);
  } catch (e) {
    return fail(ctx, malformed(errorMessage(e)));
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = hexToBytes(input.signature, 'signature');
  } catch (e) {
    return fail(ctx, malformed(errorMessage(e)));
  }

  const sig = parseDer(sigBytes);
  if (!sig) {
    if (sigBytes.length === 64) {
      return fail(ctx, {
        reason: 'algorithm_mismatch',
        details: {
          error: '64-byte signature is not DER',
          hint: 'ed25519 signatures cannot be verified by address alone; supply the public key to verifyMessage',
        },
      });
    }
    return fail(ctx, malformed('signature: not canonical DER'));
  }
  ctx.algorithm = 'secp256k1';
  if (policy.requireLowS && sig.hasHighS()) {
    return fail(ctx, { reason: 'non_canonical_signature' });
  }

  const msgHash = sha512Half(msg.bytes);
  const candidates: string[] = [];
  let signer: Signer = 'unknown';
  for (let rec = 0; rec < 4 && signer === 'unknown'; rec++) {
    let pub33: Uint8Array;
    try {
      pub33 = sig.addRecoveryBit(rec).recoverPublicKey(msgHash).toBytes(true);
    } catch {
      continue;
    }
    const derived = addressOfKeyBytes(pub33);
    candidates.push(derived);
    signer = bindSigner(derived, target);
    if (signer !== 'unknown') ctx.derivedAddress = derived;
  }
  if (signer === 'unknown') {
    return fail(ctx, {
      reason: 'address_mismatch',
      details: { expected: target.classic, candidates },
    });
  }
  return finish(ctx, signer, target, policy);
}
