/** Signature algorithm, determined by the public key prefix (`02`/`03` or `ED`). */
export type Algorithm = 'secp256k1' | 'ed25519';

/** How `message` is supplied to verification functions. */
export type Encoding = 'utf8' | 'hex';

export interface Policy {
  /** Accept a signature from the master key even when `lsfDisableMaster` is set. Default false. */
  allowMasterDisabled?: boolean;
  /** Reject secp256k1 signatures with high S. Default true. */
  requireLowS?: boolean;
  /** Maximum message size in bytes. Default 65536. */
  maxMessageBytes?: number;
}

/** Ledger state for an account, as returned by {@link resolveAccount}. */
export interface AccountState {
  address: string;
  exists: boolean;
  regularKey?: string;
  masterDisabled: boolean;
  hasSignerList: boolean;
  ledgerIndex?: number;
}

export interface VerifyMessageInput {
  message: string;
  /** Default 'utf8'. */
  encoding?: Encoding;
  /** Hex. DER for secp256k1, 64 bytes for ed25519. */
  signature: string;
  /** Hex, 33 bytes: `02`/`03` + x for secp256k1, `ED` + 32 bytes for ed25519. */
  publicKey: string;
  /** Classic or X-address. When given it must match the derived address (or the RegularKey when `account` is given). */
  address?: string;
  account?: AccountState;
  policy?: Policy;
}

export type Reason =
  | 'bad_signature'
  | 'algorithm_mismatch'
  | 'address_mismatch'
  | 'master_disabled'
  | 'unsupported_multisig'
  | 'account_not_found'
  | 'malformed_input'
  | 'message_too_large'
  | 'non_canonical_signature'
  | 'unexpected_transaction_type'
  | 'challenge_mismatch';

export type Signer = 'master' | 'regular' | 'unknown';

export interface VerifyResult {
  valid: boolean;
  reason?: Reason;
  /** Absent when the public key could not be parsed. */
  algorithm?: Algorithm;
  /** Classic address derived from the public key. Absent when the key could not be parsed. */
  derivedAddress?: string;
  signer: Signer;
  /** Free-form diagnostics (never needed to interpret `valid`). */
  details?: Record<string, unknown>;
}

/** One decoded Memo from a transaction. Text fields are present when the hex decodes as UTF-8. */
export interface DecodedMemo {
  typeHex?: string;
  dataHex?: string;
  formatHex?: string;
  type?: string;
  data?: string;
  format?: string;
}

/** Decoded transaction JSON as produced by ripple-binary-codec. */
export type DecodedTx = Record<string, unknown>;

export interface VerifySignInOptions {
  /** Classic or X-address the blob's Account must equal. */
  expectedAccount?: string;
  /** Text expected in a MemoData, or a predicate over all decoded memos. */
  expectedMemo?: string | ((memos: DecodedMemo[]) => boolean);
  account?: AccountState;
  policy?: Policy;
  /** Accept a blob whose TransactionType is absent (legacy Xaman pseudo-tx). Default false. */
  allowMissingTransactionType?: boolean;
}

export interface VerifySignInResult extends VerifyResult {
  tx: DecodedTx;
  memos: DecodedMemo[];
}

export interface NormalizedAddress {
  classic: string;
  tag?: number;
  isXAddress: boolean;
  /** True for a T... X-address (test network prefix). */
  test?: boolean;
}

/** Minimal JSON-RPC adapter: wraps an xrpl.js Client or a plain fetch. */
export interface RpcClient {
  request(method: string, params: Record<string, unknown>): Promise<unknown>;
}

export type ChallengeNetwork = 'mainnet' | 'testnet' | 'devnet' | 'xahau' | number;

export interface ChallengeFields {
  domain: string;
  address: string;
  statement?: string;
  uri: string;
  version: '1';
  network: ChallengeNetwork;
  nonce: string;
  issuedAt: string;
  expirationTime: string;
  requestId?: string;
}

export interface ValidateChallengeContext {
  now: Date;
  expectedDomain: string;
  expectedAddress?: string;
  expectedNetwork?: ChallengeNetwork;
  isNonceUnused: (nonce: string) => boolean | Promise<boolean>;
}

export type ChallengeFailure =
  | 'malformed_fields'
  | 'domain_mismatch'
  | 'address_mismatch'
  | 'network_mismatch'
  | 'not_yet_valid'
  | 'expired'
  | 'nonce_used'
  | 'nonce_too_short'
  | 'invalid_uri'
  | 'invalid_time';

export interface ValidateChallengeResult {
  ok: boolean;
  reason?: ChallengeFailure;
}
