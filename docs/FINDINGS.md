# FINDINGS — VERIFY items from the handover

Every "VERIFY" belief in the handover, checked on 2026-09-04 against installed library code, not docs from memory.
Lab: Node 26.8.1, ripple-keypairs 3.0.0, ripple-address-codec 5.0.1, ripple-binary-codec 2.10.0, verify-xrpl-signature 9.2.0, xrpl 5.1.0, @noble/curves 2.4.0, @noble/hashes 2.4.0, @gemwallet/api 3.8.0, @crossmarkio/sdk 0.4.0, xrpl-connect HEAD 3df40d19 (2026-09-02), verify-xrpl-signature source at master.
Scripts that produced the evidence are in `docs/research/` and re-run with `node <script>` after `npm i` of the packages above.

Status legend: **confirmed** = executed code agrees; **refuted** = executed code disagrees; **partial** = part executed, part inferred; **unverified** = needs a live wallet or account.

## 1. Raw message signatures (handover §4.2)

| # | Belief | Status | Finding |
|---|--------|--------|---------|
| F-1.1 | `sign(messageHex, priv)` / `verify(messageHex, sig, pub)`; message is hex of bytes | confirmed | Non-hex input throws `Invalid hex string`. Case-insensitive. **Footguns:** odd-length hex is silently truncated (`ABC` signs one byte `0xAB`) in both Node and browser builds of `@xrplf/isomorphic` 1.0.2; empty string is accepted. The verifier must enforce even-length, non-empty hex before any library call. |
| F-1.2 | secp256k1 digest = SHA-512Half, RFC 6979, DER, low-S | confirmed | Byte-identical reproduction with noble: `secp256k1.sign(sha512(msg).slice(0,32), priv32, {lowS:true, format:'der', prehash:false})`. Private key hex is `00`-prefixed 33 bytes. |
| F-1.3 | ed25519 signs raw bytes, pubkey `ED` + 32 bytes | confirmed | `ed25519.sign(msgBytes, priv32)`, no prehash; verify uses `{zip215:false}`. 64-byte signature. |
| F-1.4 | Do ripple-keypairs / noble reject high-S? | confirmed (they do) | Built `s' = n - s`: ripple-keypairs `verify` → false; noble `verify` → false by default, true only with `{lowS:false}`. The DER parser accepts high-S, the check is inside `verify`. Keep the high-S must-reject fixture so a future noble default change is caught; also call `sig.hasHighS()` explicitly and return `non_canonical_signature`. |
| F-1.5 | Cross-algorithm inputs | confirmed (throws) | ED pubkey + DER sig → `RangeError`; 02/03 pubkey + 64-byte sig → `DERErr`; truncated DER → `DERErr`; unknown prefix → `invalid_key`. Nothing returns false. Verifier must gate on length/prefix first and wrap every primitive in try/catch. |
| F-1.6 | Uncompressed `04` keys | new finding | ripple-keypairs `verify` accepts a 65-byte `04` key and `deriveAddress` hashes all 65 bytes, yielding an address that matches no real account. Reject `04` keys as `malformed_input` (or compress before deriving). |
| F-1.7 | Off-curve 33-byte key | confirmed | noble `verify` and ripple-keypairs `verify` return false, but `deriveAddress` still produces an address. Validate with `secp256k1.Point.fromHex` before deriving. |
| F-1.8 | Non-canonical DER | confirmed | Leading-zero pad, negative integer, trailing bytes, long-form length all throw `DERErr` from noble; ripple-keypairs does not catch. Map to `malformed_input`. |
| F-1.9 | Browser safety | partial | ripple-keypairs and ripple-address-codec dist have zero `Buffer` references. `@xrplf/isomorphic` uses `Buffer`/`node:crypto` on its Node path and a pure `Uint8Array` path via per-subpath `browser` fields. Vite honours that; the CI Playwright smoke test is the guard. Runtime code should use noble directly and keep ripple-* as test oracles. |
| F-1.10 | ripple-keypairs exports | confirmed | Exactly `decodeSeed, deriveAddress, deriveKeypair, deriveNodeAddress, generateSeed, sign, verify`. No hash or algorithm-detection helpers are exported. |

## 2. Xaman SignIn blobs (handover §4.3)

| # | Belief | Status | Finding |
|---|--------|--------|---------|
| F-2.1 | `verify-xrpl-signature` returns `{signedBy, signatureValid, signatureMultiSign}` | confirmed | Exact. Signature: `verifySignature(txBlob, explicitMultiSigner?, definitions?)`. **It never compares `signedBy` with `Account`**, never checks NetworkID or memos. A blob signed by an attacker's key with `Account = victim` returns `signatureValid: true`. Our wrapper must add the Account/RegularKey comparison. |
| F-2.2 | SignIn is not in ripple-binary-codec definitions | confirmed | `encode({TransactionType:'SignIn'})` throws `Unable to interpret "TransactionType: SignIn"`. verify-xrpl-signature avoids this by depending on XRPL Labs' fork `xrpl-binary-codec-prerelease`, whose bundled definitions contain `"SignIn": 999`. Workaround on mainstream codec verified: clone `definitions.json`, add `TRANSACTION_TYPES.SignIn = 999`, wrap in `new XrplDefinitions(json)`. A SignIn blob starts with `1203E7` (UInt16 999). |
| F-2.3 | Prefixes `0x53545800` / `0x534D5400`, `encodeForSigning` / `encodeForMultisigning` | confirmed | Constants and function names match ripple-binary-codec 2.10.0 source. |
| F-2.4 | Independent verification without verify-xrpl-signature | confirmed | Synthetic SignIn blobs (secp256k1 and ed25519, with a Memo) verify via decode → `encodeForSigning` → sha512half → `ripple-keypairs.verify` → `deriveAddress === Account`; verify-xrpl-signature agrees; tampered Memo fails. |
| F-2.5 | xrpl.js can verify SignIn | refuted | `Wallet.sign` throws `Unknown TransactionType SignIn`; `xrpl.verifySignature` throws on SignIn and on multisigned blobs. Do not route SignIn through xrpl.js. |
| F-2.6 | verify-xrpl-signature as a runtime dependency | partial | Pulls a nested ripple-keypairs 1.3.1 (elliptic/bn.js stack) and the codec fork: a second ECDSA implementation in the bundle. Fine as a dev-only oracle. |
| F-2.7 | Real Xaman SignIn blob available anywhere | unverified | verify-xrpl-signature's own fixtures contain **no** SignIn (999) blob. Its `valid` fixture is a TransactionType-less pseudo-tx. A real Xaman capture is still required (see CAPTURE plan). |
| F-2.8 | Payload response field names `response.hex`, `response.account`, `response.signer` | confirmed (types) | xumm-sdk 1.11.2 `XummGetPayloadResponse`: `response.hex`, `response.txid`, `response.account`, `response.signer`, `response.signer_pubkey`, `response.user`; `meta.signed`. The webhook body has no hex; a GET is required. |
| F-2.9 | Memos on SignIn carry the challenge | unverified | No documentation or example shows Memos on SignIn; xumm-sdk types allow any field. Needs one live payload. Fallback binding: `custom_meta.identifier` (unique per app, echoed on GET) is server-side only, not inside the signed bytes. |
| F-2.10 | Xaman has no arbitrary-message signing (2026) | unverified (negative evidence only) | Release notes 4.2 to 5.0 and a code search of Xaman-App show nothing. OAuth2/xApp flows return an HS256 JWT, not a blob. |

## 3. Wallet encodings (handover §4.4)

| Wallet | Status | Finding |
|--------|--------|---------|
| GemWallet | confirmed (source) | Extension `LedgerContext.signMessage(message, isHex)`: `messageHex = isHex ? message : hex(utf8(message))`, then `ripple-keypairs.sign`. No prefix. `@gemwallet/api` 3.8.0 forwards `{message, isHex}`; `getPublicKey()` → `{address, publicKey}`. xrpl-connect adapter never sets `isHex` and takes `publicKey` from the connect-time cache. Verify with `verify(hex(utf8(msg)), signedMessage, publicKey)`. Emulated round trip passes for both algorithms. |
| Crossmark | unverified | SDK 0.4.0 has **no** `signMessage`. xrpl-connect emulates it with `signInAndWait(hex)` and passes the raw UTF-8 text into the `hex` slot; docs say the argument should be "a hex message prepared using ripple-keypairs". Response `signature` is optional in the typings. What bytes the extension signs is unknown without a live extension. Likely upstream bug in xrpl-connect. |
| Ledger | refuted as "Yes" | xrpl-connect passes `hex(utf8(message))` straight into `hw-app-xrp.signTransaction(path, rawTxHex)`. The XRP app has no message-signing command and parses the bytes as a transaction; every sample fails `ripple-binary-codec.decode`. Only test is the rejection path. Even if it signed, the device prepends `STX\0`. Treat Ledger raw messages as unsupported until a hardware run proves otherwise. |
| MetaMask XRPL Snap | partial | Adapter sends the UTF-8 string as `xrpl_signMessage {message}` and expects `{signature}`; `publicKey` from cache. Snap internals not inspected. |
| Xyra | partial | `sdk.signMessage({message})` returns `{message, signature, publicKey}` from the wallet. The wallet controls `message`; verifier must compare it with the requested text. Scheme unverified. |
| Otsu | partial | `window.xrpl.signMessage(str)` → `{signature}`. Scheme unverified. |
| WalletConnect | confirmed | Throws `UNSUPPORTED_METHOD`, declares `signMessage:false`. |
| All adapters | confirmed | Inputs are normalised to UTF-8 strings (`TextDecoder`, mostly non-fatal). Binary messages never originate from xrpl-connect. |

## 4. Keys, addresses, recovery (handover §4.1, §5)

| # | Belief | Status | Finding |
|---|--------|--------|---------|
| F-4.1 | ripple-address-codec exports | confirmed | All six names exist plus `decodeAccountID`, `encodeXAddress`, `decodeXAddress`, seed and node-public codecs. |
| F-4.2 | Alphabet | confirmed | Lives in `@scure/base` (`base58xrp`), identical string. Pin `@scure/base` transitively. |
| F-4.3 | Genesis derivation | confirmed | `0330E7…FD020` → AccountID `b5f762…37e8` → `rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh`. X-address round trips with tags 0, 12345 (testnet), 4294967295; tag 2^32 throws. |
| F-4.4 | noble recovery API `Signature.addRecoveryBit(rec).recoverPublicKey(hash)` | confirmed | v2 API: `secp256k1.Signature.fromHex(hex, 'der')` (no `fromDER`), then `addRecoveryBit(rec).recoverPublicKey(msgHash).toBytes(true)`. Exactly one rec in {0,1} matches; rec 2 and 3 throw for ordinary r, so try/catch per rec. The wrong rec yields a plausible key, so always compare against the expected address. |

## 5. Tooling and release (handover §9)

| # | Topic | Status | Finding |
|---|-------|--------|---------|
| F-5.1 | npm provenance | confirmed | Trusted publishing (OIDC) is GA; provenance is automatic, `--provenance` flag unnecessary. Needs npm ≥ 11.5.1, Node ≥ 22.14, `id-token: write`, public repo, `repository.url` exactly matching, workflow filename registered on npmjs.com. Classic tokens were revoked 2025-12-09. Open: whether the first publish of a new name needs a one-off manual publish. |
| F-5.2 | GitHub Pages | confirmed | Project page at `jdponomarev.github.io/xrp-wallet-verification/`; Vite `base: '/xrp-wallet-verification/'`; `configure-pages@v6`, `upload-pages-artifact@v5`, `deploy-pages@v5`; Pages source must be set to "GitHub Actions" once by hand. |
| F-5.3 | Bundler | confirmed | tsup 8.5.1 (stable) vs tsdown 0.23.0 (Rolldown successor, pre-1.0). Recommend tsup for a security library; add `attw --pack` to CI. Exports block with separate `.d.ts` / `.d.cts`. |
| F-5.4 | changesets | partial | `@changesets/cli` 3.0.1; keep publish out of the changesets action so the OIDC job stays the single registered publisher. |
| F-5.5 | Renovate | confirmed | Two rules: group everything, then a later rule pulls `ripple-*`, `@noble/**`, `verify-xrpl-signature`, `xrpl` into a labelled `crypto-deps` group with `automerge: false` and `minimumReleaseAge: 7 days`. Dependabot cannot label one group differently. |
| F-5.6 | Browser smoke test | recommendation | Plain `@playwright/test` against `vite preview` of the built dist (real base path, real bundle) beats vitest browser mode, which re-transforms source. |
| F-5.7 | Versions (2026-09-04) | confirmed | Node 24 Active LTS (26 becomes LTS Oct 2026), pnpm 11.25.0 (`latest`), TypeScript 7.0.2 (native port; verify tool compat or pin 6.x), Vitest 5.0.0, Vite 8.2.2, Playwright 1.62.1. |

## 6. Fixture candidates (deterministic, regenerate from `docs/research/`)

- **secp256k1** seed `sp5fV4UGhZhfCvcDRuY3dyyh5PjHf`, pubkey `035A7FA22521397BE0FFE9CD7C35DDE0FB0C8EA96E48FF84E0C6309D0D4D70D9EA`, address `rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA`, message `Sign in to example.com\nnonce: 0123456789abcdef`, signature `30440220072BCE65E506246C591AD415313F091B89A3212C5EDA9E0205FC088C9A53FEA1022037FE519459B5FD6EEA039E15237755268646108639917618D51BE02724202A59` (valid); high-S variant `30450220072BCE65…C801AE6BA64A029115FC61EADC88AAD83468CC6075B72A22EAB67E65AC1616E8` (must reject).
- **ed25519** seed `sEdSKuYwxeL4JM1LBJcGmpLw9fbF8JN`, pubkey `ED26D54D80051A116166CF76FEA87330D546680B875827B87AF1B1D58B9EB464E1`, address `rpjfAeE3DeeHPFnN2PgGFW5YxnZFAjrEyN`, same message, signature `0FE0FACA05B234667E44A926553E1D06F93CCE82ECCD182233F1E420A8256229A01B28719C35B95CDAA2311609DB56F6B60C3F21CF10A5FC39A695775A63C300` (valid); s+L malleated variant must reject.
- **GemWallet-emulated** seeds `sn3nxiW7v8KXzPzAqzyHXbSSKNuN9` (secp) and `sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r` (ed), message `Hello, XRPL! nonce=1234`; plus the `isHex=true` negative.
- **SignIn synthetic** blobs (entropy fill(9) secp, fill(7) ed) with Memo `xrp-wallet-verification challenge 12345`; tampered-Memo negative regenerated at test time.
- **verify-xrpl-signature fixtures** (real XRPL Labs blobs): TransactionType-less single-sign, Payment with memo, two multisign blobs (→ `unsupported_multisig`), undecodable blob, Xahau ClaimReward (unknown type with default definitions).
- **Ledger-emulation negative**: signature over `53545800` + messageHex must fail `verify(messageHex)`.
- **Address vectors**: genesis key and X-address round trips above; off-curve key `02000…0005`; wrong-shape keys `04`+32 bytes and `02`+31 bytes.

## 7. Still open (need a live wallet or account)

1. A real Xaman SignIn blob: does it carry TransactionType 999, which fields (Sequence, Fee, Flags), and does it preserve Memos.
2. Crossmark: what bytes `signInAndWait(hex)` signs, and whether `signature` is ever omitted.
3. Ledger XRP app: status word for non-transaction bytes (one device run settles it).
4. MetaMask Snap, Xyra, Otsu signing schemes (source read, not yet done).
5. Whether Xaman 4.x/5.x added message signing (release notes on help.xaman.app not fetched).
6. First-publish behaviour under npm trusted publishing.
