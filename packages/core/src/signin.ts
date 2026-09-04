import { secp256k1 } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { decode, encodeForSigning } from 'ripple-binary-codec';
import { addressOfKeyBytes, normalizeAddress } from './address.js';
import { normalizeAccountState, type NormalizedAccountState } from './account-state.js';
import { signInDefinitions } from './definitions.js';
import { sha512Half } from './hash.js';
import { bytesToHex, bytesToUtf8, hexToBytes } from './hex.js';
import { parsePublicKey } from './keys.js';
import type {
  DecodedMemo,
  DecodedTx,
  Reason,
  VerifySignInOptions,
  VerifySignInResult,
} from './types.js';

/**
 * Verify a signed Xaman SignIn blob (TransactionType 999): decode, check the single signature
 * over the signing data, bind SigningPubKey to Account (or the RegularKey), then apply account
 * policy and the optional expected account / memo. Never throws on bad blobs.
 */
export function verifySignInBlob(
  blobHex: string,
  opts: VerifySignInOptions = {},
): VerifySignInResult {
  const details: Record<string, unknown> = {};
  const out: VerifySignInResult = { valid: false, signer: 'unknown', tx: {}, memos: [], details };
  const fail = (reason: Reason, extra?: Record<string, unknown>): VerifySignInResult => {
    out.reason = reason;
    if (extra) Object.assign(details, extra);
    return out;
  };

  let blobBytes: Uint8Array;
  try {
    blobBytes = hexToBytes(blobHex, 'blob');
  } catch (e) {
    return fail('malformed_input', { error: errorMessage(e) });
  }
  if (blobBytes.length === 0) return fail('malformed_input', { error: 'blob: empty' });
  if (blobBytes.length > (opts.policy?.maxMessageBytes ?? 65536)) return fail('message_too_large');

  let state: NormalizedAccountState | undefined;
  try {
    if (opts.account !== undefined && opts.account !== null) {
      state = normalizeAccountState(opts.account);
    }
  } catch (e) {
    return fail('malformed_input', { error: errorMessage(e) });
  }

  let tx: DecodedTx;
  try {
    tx = decode(blobHex, signInDefinitions());
  } catch (e) {
    return fail('malformed_input', { error: errorMessage(e) });
  }
  out.tx = tx;
  out.memos = decodeMemos(tx.Memos);
  details.transactionType = tx.TransactionType;
  details.account = tx.Account;

  const account = tx.Account;
  if (typeof account !== 'string')
    return fail('malformed_input', { error: 'blob: Account missing' });
  if (tx.Signers !== undefined || tx.SigningPubKey === '') return fail('unsupported_multisig');

  const type = tx.TransactionType;
  const typeOk =
    type === 'SignIn' || (type === undefined && opts.allowMissingTransactionType === true);
  if (!typeOk || tx.Destination !== undefined || tx.Amount !== undefined) {
    return fail('unexpected_transaction_type');
  }

  const pubHex = tx.SigningPubKey;
  const sigHex = tx.TxnSignature;
  if (typeof pubHex !== 'string' || typeof sigHex !== 'string') {
    return fail('malformed_input', { error: 'blob: SigningPubKey or TxnSignature missing' });
  }
  let key: ReturnType<typeof parsePublicKey>;
  let sigBytes: Uint8Array;
  try {
    key = parsePublicKey(pubHex);
    sigBytes = hexToBytes(sigHex, 'TxnSignature');
  } catch (e) {
    return fail('malformed_input', { error: errorMessage(e) });
  }
  out.algorithm = key.algorithm;
  out.derivedAddress = addressOfKeyBytes(key.bytes);

  let signingBytes: Uint8Array;
  try {
    signingBytes = hexToBytes(encodeForSigning(tx, signInDefinitions()));
  } catch (e) {
    return fail('malformed_input', { error: errorMessage(e) });
  }

  const requireLowS = opts.policy?.requireLowS ?? true;
  let signatureOk: boolean;
  if (key.algorithm === 'secp256k1') {
    let sig: ReturnType<typeof secp256k1.Signature.fromBytes>;
    try {
      sig = secp256k1.Signature.fromBytes(sigBytes, 'der');
    } catch (e) {
      if (sigBytes.length === 64) {
        return fail('algorithm_mismatch', { error: 'secp256k1 key with a 64-byte signature' });
      }
      return fail('malformed_input', { error: `TxnSignature: ${errorMessage(e)}` });
    }
    if (requireLowS && sig.hasHighS()) return fail('non_canonical_signature');
    try {
      signatureOk = secp256k1.verify(sig.toBytes('compact'), sha512Half(signingBytes), key.bytes, {
        prehash: false,
        lowS: requireLowS,
      });
    } catch {
      signatureOk = false;
    }
  } else {
    if (sigBytes.length !== 64) {
      return sigBytes[0] === 0x30
        ? fail('algorithm_mismatch', { error: 'ed25519 key with a DER signature' })
        : fail('malformed_input', {
            error: `TxnSignature: expected 64 bytes, got ${sigBytes.length}`,
          });
    }
    try {
      signatureOk = ed25519.verify(sigBytes, signingBytes, key.bytes.slice(1), { zip215: false });
    } catch {
      signatureOk = false;
    }
  }
  if (!signatureOk) return fail('bad_signature');

  const derived = out.derivedAddress;
  if (derived === account) {
    out.signer = 'master';
  } else if (state && state.classic === account && state.regularKey === derived) {
    out.signer = 'regular';
  } else {
    return fail('address_mismatch');
  }

  if (opts.expectedAccount !== undefined) {
    let expected: string;
    try {
      expected = normalizeAddress(opts.expectedAccount).classic;
    } catch (e) {
      return fail('malformed_input', { error: `expectedAccount: ${errorMessage(e)}` });
    }
    if (expected !== account) return fail('address_mismatch', { expectedAccount: expected });
  }

  if (state) {
    if (state.classic !== account) return fail('address_mismatch', { accountState: state.classic });
    if (!state.exists) return fail('account_not_found');
    if (state.hasSignerList) return fail('unsupported_multisig');
    if (
      out.signer === 'master' &&
      state.masterDisabled &&
      opts.policy?.allowMasterDisabled !== true
    ) {
      return fail('master_disabled');
    }
  }

  const expectedMemo = opts.expectedMemo;
  if (typeof expectedMemo === 'string') {
    if (!out.memos.some((m) => m.data === expectedMemo)) return fail('challenge_mismatch');
  } else if (typeof expectedMemo === 'function') {
    let accepted: boolean;
    try {
      accepted = expectedMemo(out.memos) === true;
    } catch (e) {
      return fail('challenge_mismatch', { error: errorMessage(e) });
    }
    if (!accepted) return fail('challenge_mismatch');
  }

  out.valid = true;
  return out;
}

function decodeMemos(raw: unknown): DecodedMemo[] {
  if (!Array.isArray(raw)) return [];
  const memos: DecodedMemo[] = [];
  for (const entry of raw) {
    const memo = (entry as { Memo?: Record<string, unknown> } | null)?.Memo;
    if (!memo || typeof memo !== 'object') continue;
    const decoded: DecodedMemo = {};
    putMemoField(decoded, 'type', memo.MemoType);
    putMemoField(decoded, 'data', memo.MemoData);
    putMemoField(decoded, 'format', memo.MemoFormat);
    memos.push(decoded);
  }
  return memos;
}

function putMemoField(memo: DecodedMemo, key: 'type' | 'data' | 'format', value: unknown): void {
  if (typeof value !== 'string') return;
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(value);
  } catch {
    return;
  }
  memo[`${key}Hex`] = bytesToHex(bytes);
  const text = bytesToUtf8(bytes);
  if (text !== undefined) memo[key] = text;
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
