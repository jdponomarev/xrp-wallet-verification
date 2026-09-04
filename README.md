# xrpl-message-verify

[![CI](https://github.com/jdponomarev/xrp-wallet-verification/actions/workflows/ci.yml/badge.svg)](https://github.com/jdponomarev/xrp-wallet-verification/actions/workflows/ci.yml)

Verify XRP Ledger signed messages and Xaman SignIn blobs on the server, in the browser or in a
worker. secp256k1 and ed25519, address derivation, RegularKey and master-key policy, and a
challenge envelope for sign-in flows.

Try it without installing anything: <https://jdponomarev.github.io/xrp-wallet-verification/>

## Why

Ethereum has EIP-191 and `ecrecover`; every wallet signs a personal message the same way and
every backend verifies it with one call. The XRP Ledger has neither. Wallets that can sign a free
text message (GemWallet) sign the raw UTF-8 bytes with the account key and return a DER or 64-byte
signature; Xaman does not sign messages at all and offers a `SignIn` pseudo-transaction instead;
Ledger devices cannot do either. Verifying any of this correctly means knowing the digest rule per
algorithm, rejecting malformed and non-canonical inputs before they reach a library that throws or
silently truncates, deriving the address from the key, and checking the account's current keys on
the ledger.

This package does that verification and nothing else. A false `valid` is the failure it is
designed against.

## Install

```sh
pnpm add xrpl-message-verify
```

ESM and CommonJS builds ship with types. Node 20+ and evergreen browsers are supported; the only
network call in the library is behind an injected client (see `resolveAccount`).

## Quick start

### Verify a signed message

```ts
import { verifyMessage } from 'xrpl-message-verify';

const result = verifyMessage({
  message: 'Sign in to example.com\nnonce: 0123456789abcdef',
  publicKey: '035A7FA22521397BE0FFE9CD7C35DDE0FB0C8EA96E48FF84E0C6309D0D4D70D9EA',
  signature:
    '30440220072BCE65E506246C591AD415313F091B89A3212C5EDA9E0205FC088C9A53FEA1022037FE519459B5FD6EEA039E15237755268646108639917618D51BE02724202A59',
  address: 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA',
});

result.valid; // true
result.algorithm; // 'secp256k1'
result.derivedAddress; // 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA'
```

`message` is UTF-8 text by default; pass `encoding: 'hex'` for raw bytes. `publicKey` is the
33-byte XRPL key (`02`/`03` + x for secp256k1, `ED` + 32 bytes for ed25519). `signature` is DER for
secp256k1 or 64 raw bytes for ed25519. `address` is optional; when present it must match the
address derived from the key, or the account's RegularKey when account state is supplied.

Never branch on anything but `result.valid`. `reason` and `details` are for logs and error
messages.

### Verify when you only have the address (secp256k1)

```ts
import { verifyMessageByAddress } from 'xrpl-message-verify';

const result = verifyMessageByAddress({
  message: 'Sign in to example.com\nnonce: 0123456789abcdef',
  signature: '3044...2A59',
  address: 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA',
});
```

ECDSA public keys can be recovered from a signature; ed25519 keys cannot. Prefer asking the wallet
for its public key and using `verifyMessage`.

### Check the account on the ledger

A signature proves control of a key. Whether that key still controls the account is ledger state:
the account may have set a RegularKey, disabled its master key or installed a SignerList.
`resolveAccount` fetches that state through any JSON-RPC-shaped client you inject.

```ts
import { jsonRpcClient, resolveAccount, verifyMessage } from 'xrpl-message-verify';

const account = await resolveAccount(address, jsonRpcClient('https://xrplcluster.com/'));

const result = verifyMessage({ message, publicKey, signature, address, account });
// account.exists === false          -> reason 'account_not_found'
// master key disabled, signed by it -> reason 'master_disabled' (policy.allowMasterDisabled)
// SignerList present                -> reason 'unsupported_multisig'
// signed by the RegularKey          -> valid, result.signer === 'regular'
```

`jsonRpcClient` is a ten-line `fetch` wrapper. To reuse an xrpl.js `Client`, adapt it:

```ts
const rpc = {
  request: (method: string, params: Record<string, unknown>) =>
    client.request({ command: method, ...params } as never).catch((err: { data?: unknown }) => {
      if (err.data) return err.data; // rippled error response, e.g. actNotFound
      throw err;
    }),
};
```

### Verify a Xaman SignIn blob

Xaman returns a signed pseudo-transaction (`TransactionType` 999) as `response.hex`. The library
decodes it with a custom definitions table, recomputes the signing digest, verifies the signature
against `SigningPubKey`, and checks that the signer is the `Account` (or its RegularKey when
account state is given).

```ts
import { verifySignInBlob } from 'xrpl-message-verify';

const result = verifySignInBlob(payload.response.hex, {
  expectedAccount: payload.response.account,
  expectedMemo: challengeText, // the text you asked the user to sign, carried in MemoData
});

result.valid;
result.tx; // decoded transaction JSON
result.memos; // decoded memos, text fields when the hex is UTF-8
```

Multisigned blobs are rejected with `unsupported_multisig`. Blobs carrying submittable fields
such as `Destination` or `Amount` are rejected with `unexpected_transaction_type`. The
TransactionType is required by default; `allowMissingTransactionType` accepts the legacy
TransactionType-less form.

### Challenge envelope

Sign-in needs more than a signature over a nonce: the text should bind the domain, the address,
the network and a validity window so it cannot be replayed elsewhere. `formatChallenge` produces
the canonical text (grammar in [docs/envelope.md](docs/envelope.md)), `parseChallenge` reads it
back strictly, `validateChallenge` checks it against your expectations.

```ts
import { formatChallenge, parseChallenge, validateChallenge } from 'xrpl-message-verify';

const text = formatChallenge({
  domain: 'example.com',
  address: 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA',
  statement: 'Sign in to Example',
  uri: 'https://example.com/login',
  version: '1',
  network: 'mainnet',
  nonce: crypto.randomUUID().replaceAll('-', ''),
  issuedAt: new Date().toISOString(),
  expirationTime: new Date(Date.now() + 5 * 60_000).toISOString(),
});

// Remember every nonce you issue; mark it accepted only after the signature verifies.
const issued = new Set([parseChallenge(text).nonce]);

// The wallet signs `text`. Later, on the server:
const fields = parseChallenge(text);
const check = await validateChallenge(fields, {
  now: new Date(),
  expectedDomain: 'example.com',
  expectedAddress: 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA',
  expectedNetwork: 'mainnet',
  isNonceUnused: (nonce) => issued.has(nonce),
});
check.ok; // false with check.reason on domain_mismatch, expired, nonce_used, ...
```

## Reason codes

`valid: false` always comes with one `reason`:

| Reason                        | Meaning                                                                                                                            |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `malformed_input`             | Hex is odd-length or not hex, the key is not 33 bytes with prefix `02`/`03`/`ED`, is off-curve, DER is invalid                     |
| `message_too_large`           | Message exceeds `policy.maxMessageBytes` (default 65536)                                                                           |
| `algorithm_mismatch`          | Signature shape does not match the key's algorithm (DER with an `ED` key, 64 bytes with a secp key)                                |
| `non_canonical_signature`     | secp256k1 signature has high S (or ed25519 `s` not reduced); rejected because it is malleable (`policy.requireLowS`, default true) |
| `bad_signature`               | Well-formed signature that does not verify for this key and message                                                                |
| `address_mismatch`            | Derived address differs from the supplied `address` (and from the RegularKey when account state is given)                          |
| `account_not_found`           | `account` says the address is not on the ledger                                                                                    |
| `master_disabled`             | Signed by the master key while `lsfDisableMaster` is set and `policy.allowMasterDisabled` is false                                 |
| `unsupported_multisig`        | The account has a SignerList, or the blob carries `Signers`                                                                        |
| `unexpected_transaction_type` | SignIn blob is not TransactionType 999, or carries submittable fields                                                              |
| `challenge_mismatch`          | The expected memo or challenge text is not what was signed                                                                         |

## Wallet support

Statuses reflect what has been verified against wallet source code or a real capture, not vendor
documentation. Details and evidence are in [docs/FINDINGS.md](docs/FINDINGS.md) §3; the capture
procedure is in [fixtures/CAPTURE.md](fixtures/CAPTURE.md).

| Wallet             | Message signing                                              | Status                                                                                                    |
| ------------------ | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| GemWallet          | `signMessage(message, isHex)`, raw bytes, no prefix          | Confirmed from extension source; verify with `verifyMessage`                                              |
| Xaman              | No message signing; `SignIn` pseudo-transaction              | Supported via `verifySignInBlob`; a real mainnet/testnet capture is pending, memo preservation unverified |
| Crossmark          | SDK has no `signMessage`; adapters emulate via `signIn`      | Unverified: what bytes are signed is unknown without a live extension                                     |
| Ledger             | None; the XRP app only signs transactions                    | Unsupported                                                                                               |
| MetaMask XRPL Snap | `xrpl_signMessage {message}` → `{signature}`                 | Pending capture                                                                                           |
| Xyra               | `signMessage({message})` → `{message, signature, publicKey}` | Pending capture; compare the returned `message` with what you requested                                   |
| Otsu               | `window.xrpl.signMessage(str)` → `{signature}`               | Pending capture                                                                                           |
| WalletConnect      | Declares `signMessage: false`                                | Unsupported                                                                                               |

## What this library does NOT do

- **Store or check nonces.** `validateChallenge` calls your `isNonceUnused`; single use, expiry and
  storage are yours. Without a fresh nonce per attempt, a captured signature is a permanent
  credential.
- **Prevent replay across services.** Bind the domain and the network in the challenge and check
  them; a signature over a bare nonce is valid for anyone who sees it.
- **Bind sessions.** Issuing a session, JWT or cookie after `valid: true` is your application.
- **Talk to the network on its own.** Only `resolveAccount` performs I/O, through the client you
  pass. Everything else is pure and synchronous.
- **Handle private keys, seeds or signing.** There is no `sign` function. Test vectors are
  generated from throwaway seeds under `scripts/`.
- **Prove current control without ledger state.** A valid signature proves the signer held the
  key at signing time. Pass `account` from `resolveAccount` (fetched at verification time) to
  reject disabled master keys, rotated RegularKeys and multisig accounts.

## Threat model in short

The asset is the binding between "this message" and "this account". The failure that matters is a
`valid: true` for a message the account holder did not sign. Mitigations, in the order the code
applies them: a strict input gate (even-length hex, 33-byte key with a known prefix, on-curve
check, signature length by algorithm) so no primitive ever sees ambiguous bytes; explicit
canonicality checks (low S, reduced ed25519 `s`) independent of library defaults; algorithm chosen
from the key, never from the signature; address derived, never trusted; ledger state consulted at
verification time; every primitive wrapped so an exception becomes `valid: false`, never an
unhandled path. Replay and domain binding live in the challenge envelope; nonce storage is the
caller's. The full model, including account-state races and supply-chain controls, is in
[docs/threat-model.md](docs/threat-model.md).

## Documentation

- [docs/envelope.md](docs/envelope.md): challenge envelope grammar (ABNF) and rationale
- [docs/threat-model.md](docs/threat-model.md): assets, actors, failure modes, mitigations
- [docs/FINDINGS.md](docs/FINDINGS.md): every belief about wallets and libraries, checked against
  executed code
- [fixtures/CAPTURE.md](fixtures/CAPTURE.md): how to capture a real-wallet vector on testnet
- [SECURITY.md](SECURITY.md): reporting a vulnerability
- [CONTRIBUTING.md](CONTRIBUTING.md): how changes land

## Development

```sh
pnpm install
pnpm test          # vitest, packages/core
pnpm typecheck
pnpm lint && pnpm format
pnpm build         # tsup: ESM + CJS + types
pnpm gen-fixtures  # regenerate fixtures/vectors.json from deterministic seeds
```

Any change under `packages/core/src/verify*` or `signin*` needs a fixture and a changeset; see
[CONTRIBUTING.md](CONTRIBUTING.md).

## Credits and licence

Initially developed by engineers at Coinstash; not affiliated with Ripple, the XRPL Foundation or
XRPL Labs.

[MIT](LICENSE).
