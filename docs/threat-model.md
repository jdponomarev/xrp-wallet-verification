# Threat model

Scope: the `xrpl-message-verify` package (`packages/core`) and the static verify page that wraps
it. Applications that call the library are in scope only where the library's contract shapes what
they can get wrong.

## Assets

1. **The message–account binding.** The claim "the holder of account `r…` signed exactly these
   bytes". Everything else exists to make this claim true or to refuse it.
2. **The account's current key set.** Master key, RegularKey, SignerList and the `lsfDisableMaster`
   flag as of the latest validated ledger.
3. **The challenge.** Domain, address, network, nonce and validity window that turn a signature
   into a one-time sign-in.
4. **The published artefact.** What `npm install xrpl-message-verify` actually delivers.

## Actors

- **Legitimate user** with a wallet that signs what it displays.
- **Network attacker** who observes or replays signatures and challenges.
- **Malicious or buggy wallet** returning a different `message`, `publicKey` or `signature` than
  the app requested, or signing with a prefix or encoding the app did not expect.
- **Attacker with a signature from another context** (another site, another network, a past
  session, a transaction blob).
- **Attacker who compromised a key that no longer controls the account** (rotated RegularKey,
  disabled master).
- **Supply-chain attacker** targeting the package, its dependencies or the release pipeline.

## The failure that matters

A **false `valid`**: the library returns `valid: true` (or `validateChallenge` returns `ok: true`)
for a message the account holder did not sign, or for an account the signer does not currently
control. A false `invalid` costs a retry; a false `valid` costs the account. Every design decision
below trades convenience for the absence of false valids.

Corollaries that shape the code:

- No verification function throws on caller data. An exception in the middle of a check is an
  unexamined code path; the library catches every primitive and returns `valid: false`.
- The algorithm comes from the public key prefix, never from the signature or a caller hint.
- The address is derived from the key and compared, never trusted from input.
- Defaults are strict; every relaxation is an explicit `Policy` field the caller has to write.

## Reason codes as mitigations

| Reason                        | Threat mitigated                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `malformed_input`             | Ambiguous bytes reaching a primitive. Odd-length hex is silently truncated by upstream hex parsers (`ABC` becomes one byte); uncompressed `04` keys derive to an address no account can have; off-curve 33-byte keys still derive an address; non-canonical DER throws. All rejected before any crypto.                                                        |
| `message_too_large`           | Memory or CPU exhaustion via multi-megabyte "messages"; also a sanity bound on what a wallet would plausibly display.                                                                                                                                                                                                                                          |
| `algorithm_mismatch`          | Cross-algorithm confusion: a DER signature presented with an `ED` key or a 64-byte signature with a secp key. Upstream libraries throw `RangeError` / `DERErr` here; the gate returns a typed reason instead.                                                                                                                                                  |
| `non_canonical_signature`     | Signature malleability. For secp256k1 a high-S twin of any valid signature verifies mathematically; for ed25519 `s + L` does too under permissive verifiers. High-S is refused explicitly with `hasHighS()` so a library default change cannot re-admit it; ed25519 `s >= L` is rejected inside the strict (`zip215: false`) verifier and pinned by a fixture. |
| `bad_signature`               | Forgery, tampering with the message after signing, or a wallet that signed different bytes (a prefixed or transaction-wrapped message, for example Ledger).                                                                                                                                                                                                    |
| `address_mismatch`            | A valid signature by the wrong key: attacker's key with the victim's address, or the wrong recovery id in `verifyMessageByAddress` (recovery yields a plausible key for every id; the address comparison is what rejects it).                                                                                                                                  |
| `account_not_found`           | Sign-in to an address that does not exist on the ledger; also catches wrong-network lookups.                                                                                                                                                                                                                                                                   |
| `master_disabled`             | A key that proves history, not control. With `lsfDisableMaster` set the master key cannot move funds; accepting it lets a leaked old key sign in forever.                                                                                                                                                                                                      |
| `unsupported_multisig`        | Accounts governed by a SignerList and blobs carrying `Signers`. A single signature is not authorisation for such an account, and multisig quorum semantics are not something a message verifier should guess.                                                                                                                                                  |
| `unexpected_transaction_type` | A SignIn verifier fed a real transaction (or a SignIn carrying `Destination`/`Amount`). Otherwise a signed Payment captured elsewhere would double as a login, and a login could be replayed as a transaction.                                                                                                                                                 |
| `challenge_mismatch`          | The memo or challenge text in the signed bytes is not what the server issued.                                                                                                                                                                                                                                                                                  |

## Replay and domain binding

A signature over a bare nonce is a bearer credential for whoever sees it. The challenge envelope
([envelope.md](envelope.md)) puts the following inside the signed bytes:

- **domain** and **uri**: a signature obtained by phishing site A cannot be presented to site B;
  `validateChallenge` rejects `domain_mismatch`.
- **address**: the text names the account that is expected to sign; a signature by another key is
  `address_mismatch` even if the attacker controls that other key.
- **network**: a testnet signature is not a mainnet login (`network_mismatch`).
- **nonce**, **issuedAt**, **expirationTime**: one attempt, one window. The library checks
  format, length and the window; single use is enforced by the caller's `isNonceUnused`, which
  must consume the nonce atomically.

For Xaman SignIn the envelope travels in `MemoData`. Whether Xaman preserves Memos on SignIn is
unverified (FINDINGS F-2.9); if it does not, binding falls back to the payload's server-side
`custom_meta.identifier`, which is authenticated by the Xaman API, not by the signature. The
README states this limitation rather than hiding it.

## Key and algorithm confusion

- The 33-byte key prefix decides the algorithm: `ED` is ed25519, `02`/`03` is secp256k1, anything
  else is `malformed_input`. The signature is never used to infer the algorithm.
- Ed25519 verification uses strict (non-ZIP215) semantics with the raw message, no prehash.
- Secp256k1 verification uses SHA-512Half of the message and DER parsing with a single canonical
  encoding.
- `verifyMessageByAddress` exists only for secp256k1; ed25519 cannot recover keys and the function
  refuses `ED` inputs rather than guessing.

## Malleability

- **High S** (secp256k1): rejected by an explicit `hasHighS()` check even though the underlying
  library also rejects it by default. A committed high-S fixture must fail in CI, so a dependency
  bump that changes the default is caught.
- **ed25519 `s + L`**: the 64-byte signature with `s` outside `[0, L)` is rejected before
  verification.
- **DER**: leading-zero padding, negative integers, trailing bytes and long-form lengths are
  refused; only the shortest canonical encoding is accepted.

## Uncompressed keys and hex truncation

- **Uncompressed `04` keys** (65 bytes) are refused. `ripple-keypairs.deriveAddress` would hash
  all 65 bytes and produce an address that no account can have; a verifier that accepted it would
  bind the signature to a phantom address.
- **Odd-length hex** is refused everywhere (`hexToBytes` is the only parser). Upstream code
  truncates `ABC` to `AB`, which would let an attacker sign one byte and have the verifier accept
  it as the intended message.
- **Empty messages** and **empty hex** are refused at the gate.

## Account-state races

Ledger state is fetched separately from signing, so two windows exist:

1. **Key rotated after signing.** The user signs with key K; before the server verifies, the
   account sets a RegularKey or disables the master. `resolveAccount` is called at verification
   time, so the newer state wins and the signature is refused. The reverse order (server caches
   state, then the account rotates) is why callers must not cache `AccountState` across attempts.
2. **RegularKey reassigned.** The RegularKey is a property of the account, not the key: the same
   key can be RegularKey of many accounts. `address_mismatch` compares the derived address with the
   supplied `address` first and with `account.regularKey` second, and the caller must supply the
   `address` the user claims, never derive it from the key alone.

`resolveAccount` reads `ledger_index: 'validated'` so a proposed but unvalidated key change is not
trusted. It reports `ledgerIndex` so callers who care can enforce freshness.

## Supply chain

- **Exact pins** for `ripple-*`, `@noble/*` and the codec; Renovate delivers them as a separate
  `crypto-deps` group, labelled `manual-review`, never auto-merged, with a seven-day minimum release
  age.
- **Frozen lockfile** in CI; `pnpm install --frozen-lockfile` fails on drift.
- **Trusted publishing** from `release.yml` via OIDC. No npm tokens exist for this package;
  provenance attestations link the tarball to the workflow run and commit.
- **Cross-check tests** run the reference implementations (`ripple-keypairs.verify`,
  `verify-xrpl-signature`) against every fixture, so a divergence in either stack fails CI.
- **Browser bundle** uses `@noble/*` directly; the `ripple-*` packages are test oracles and codec
  only, keeping a second ECDSA implementation out of the shipped bundle.
- **CODEOWNERS** on `packages/core/src`, `fixtures/`, the lockfile and the core `package.json`.

## Out of scope

- Nonce storage and single-use enforcement (callback provided, storage is the application's).
- Session issuance, cookies, JWTs and everything after `valid: true`.
- Wallet UI security: a wallet that shows one text and signs another defeats any verifier.
- Multisig authorisation semantics (quorum evaluation). Such accounts are refused.
- Transaction verification and submission. The SignIn path refuses submittable transactions.
- Key custody, seed handling and signing. The library has no private-key code paths.
- Timing side channels on public data. Inputs and keys are public; only `bytesEqual` is
  constant-time, as a courtesy, not a security boundary.
