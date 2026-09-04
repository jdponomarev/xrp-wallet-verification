# PLAN — XRPL signed-message verifier

Status: 2026-09-04. Decisions taken (§0). Phases 0, 1 and 2 implemented on `feat/phase-1`; Phase 1b human captures, Phase 3 and Phase 4 remain. See §6 for the current state.
Source brief: the handover doc (Claude chat, 4 Sep 2026). Section numbers below refer to it.

## 0. Decisions (handover §11)

Decided by Dmitrii on 2026-09-04: 1 → `xrpl-message-verify`, 2 → MIT, 3 → verify-only first, 4 → replicate with `verify-xrpl-signature` as a test oracle. Items 5 to 9 take the recommendation below unless overruled. Scaffolding (Phase 0) is unblocked.

1. **Names.** GitHub repo is already `jdponomarev/xrp-wallet-verification`. npm name `xrpl-message-verify` is free (registry returned 404 on 2026-09-04; also free: `xrpl-verify`, `xrpl-signed-message`, `xrp-wallet-verification`). The `@coinstash` npm scope has zero packages and would put a vendor name on a spec that is meant to be neutral (§3). **Recommend unscoped `xrpl-message-verify`**, repo name unchanged. Pages URL becomes `https://jdponomarev.github.io/xrp-wallet-verification/`.
2. **Licence.** **Recommend MIT.** Apache-2.0 only if a patent grant matters to Coinstash legal; for crypto glue it does not.
3. **Sign tab in Phase 2.** **Recommend verify-only first (Phase 2), Sign tab as 2b** once at least one real-wallet capture exists, because the Sign tab is the only part that pulls wallet SDKs into the bundle and widens the CSP.
4. **SignIn blobs: depend on `verify-xrpl-signature` or replicate.** See FINDINGS F-2.1, F-2.2, F-2.6. **Recommend replicate** (the reference implementation is small: decode with a custom `SignIn` definition, `encodeForSigning`, `sha512half`, `ripple-keypairs.verify`) and keep `verify-xrpl-signature` as a **dev-only** equivalence oracle in tests. Reason: one fewer runtime dependency in a browser bundle, and we control the multisig rejection and RegularKey policy.
5. **Strict `master_disabled` rejection by default.** **Recommend yes.** A disabled master key cannot move funds, so a signature from it proves history, not control. `policy.allowMasterDisabled` stays available.
6. **.NET port location.** **Recommend same repo, `dotnet/`, sharing `fixtures/vectors.json`.** Separate repo means two fixture copies that drift.
7. **XLS draft.** Engineering prepares `docs/envelope.md` in XLS shape; **Dmitrii signs off and posts** under his own GitHub identity. No action until Phase 1 fixtures pass.

Not in §11 but needs a call:

8. **Branch model.** Public greenfield repo: `main` protected, squash-merge PRs, no `develop`/`staging`. This PLAN commit is the only direct push to `main`.
9. **SECURITY.md contact.** Placeholder `security@<domain>`; needs a real mailbox before the first npm publish.

## 1. What the research confirmed (summary)

Full detail with evidence is in `docs/FINDINGS.md`. Items that change the plan:

- **The handover's crypto beliefs hold** (F-1.2, F-1.3, F-2.3, F-4.x): SHA-512Half + DER low-S for secp256k1, raw-bytes ed25519, the `STX\0` prefix, the alphabet, the genesis derivation and the noble recovery API all reproduce byte for byte.
- **The libraries throw where the handover assumed `false`** (F-1.5, F-1.8, F-4.4): cross-algorithm inputs, malformed DER and wrong-shape keys raise exceptions; odd-length hex is silently truncated and `04` uncompressed keys derive to a wrong address (F-1.1, F-1.6). Task 1.2 therefore starts with a strict input gate before any primitive is called.
- **SignIn: replicate, do not depend** (F-2.1, F-2.2, F-2.6): `verify-xrpl-signature` never compares signer with `Account`, and it ships a second ECDSA stack via a codec fork. A ten-line custom `XrplDefinitions` (SignIn = 999) on mainstream `ripple-binary-codec` was verified end to end. This settles decision 4.
- **No real Xaman SignIn blob exists in any public fixture set** (F-2.7, F-2.9); whether Xaman preserves Memos on SignIn is unverified. The human capture in Phase 1b is on the critical path for the Xaman half of the DoD, and the envelope must also work through `custom_meta.identifier` if Memos turn out to be stripped.
- **Wallet matrix corrections** (F-3): GemWallet confirmed from extension source; Crossmark has no message-signing API and xrpl-connect's emulation is probably broken; Ledger's "Yes" is refuted (bytes go to the transaction parser). Only GemWallet is a safe launch target; Crossmark, Snap, Xyra and Otsu stay in `fixtures/pending/`.
- **Tooling** (F-5): npm trusted publishing makes provenance automatic and token-free; Pages is straightforward with `base: '/xrp-wallet-verification/'`; tsup over pre-1.0 tsdown; Playwright against the built dist for the smoke test; TypeScript 7 may need pinning to 6.x.

## 2. Phases and tasks

Estimates are focused engineering hours including review, assuming Claude Code executes and a human reviews each PR.

### Phase 0 — Scaffold (≈3 h)

| #   | Task                                                                                                                                                                      | Est.  |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| 0.1 | pnpm 11 workspace, TypeScript strict (6.x if 7 breaks tooling), ESLint + Prettier, Vitest 5, tsup 8.5; `packages/core` with ESM/CJS/types exports and `attw --pack` check | 1.0 h |
| 0.2 | `ci.yml`: install --frozen-lockfile → lint → typecheck → test → build; Node 20 and 22 matrix                                                                              | 0.5 h |
| 0.3 | LICENSE, README stub, SECURITY.md, CONTRIBUTING.md, CODEOWNERS, Renovate config (grouped, crypto deps labelled)                                                           | 0.5 h |
| 0.4 | Pin exact versions of `ripple-keypairs`, `ripple-address-codec`, `ripple-binary-codec`, `@noble/*`; `verify-xrpl-signature` as devDependency                              | 0.5 h |
| 0.5 | Branch protection on `main` (required CI, no force push) documented in CONTRIBUTING                                                                                       | 0.5 h |

### Phase 1 — Core library (≈14 h)

| #   | Task                                                                                                                                                                                                                                                                                                                                                   | Est.  |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| 1.1 | `hex.ts`, `address.ts`: strict hex parsing, `deriveAddress`, `normalizeAddress` (X-address → classic + tag)                                                                                                                                                                                                                                            | 1.0 h |
| 1.2 | Input gate first: even-length non-empty hex, 33-byte key with prefix in {02,03,ED}, on-curve check, signature length by algorithm, every primitive in try/catch (F-1.1, F-1.5 to F-1.8). Then `verifyMessage`: DER canonical + explicit `hasHighS()`, secp/ed25519 verify via noble, address compare, RegularKey / master-disabled / SignerList policy | 3.5 h |
| 1.3 | `verifyMessageByAddress` (secp256k1 only): DER → noble Signature, try recovery ids, derive, compare                                                                                                                                                                                                                                                    | 1.5 h |
| 1.4 | `verifySignInBlob`: custom `XrplDefinitions` with SignIn = 999, `1203E7` pre-check, decode, reject Signers as `unsupported_multisig`, reject submittable fields, `encodeForSigning` + sha512half, verify, `signedBy` vs `Account`/RegularKey (F-2.1), memo decode, optional challenge parse                                                            | 2.5 h |
| 1.5 | Challenge envelope: `formatChallenge` / `parseChallenge` (strict grammar, CRLF→LF) / `validateChallenge`; `docs/envelope.md` with ABNF                                                                                                                                                                                                                 | 2.5 h |
| 1.6 | `resolveAccount(address, client)`: `account_info` → `AccountState`; injected RPC adapter, no network in tests                                                                                                                                                                                                                                          | 1.0 h |
| 1.7 | `scripts/gen-fixtures.ts`: deterministic vectors for every Reason value, both algorithms, SignIn blobs incl. tampered memo / account / signature                                                                                                                                                                                                       | 2.0 h |
| 1.8 | Cross-check test: `ripple-keypairs.verify` agrees with `verifyMessage` on every generated vector; `verify-xrpl-signature` agrees on every SignIn vector                                                                                                                                                                                                | 0.5 h |

### Phase 1b — Real-wallet fixtures (≈3 h engineering + human capture)

| #    | Task                                                                                                                                                    | Est.        |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| 1b.1 | `fixtures/CAPTURE.md`: per-wallet steps (testnet only), `fixtures/pending/` placeholders, non-blocking CI job that reports pending captures             | 1.5 h       |
| 1b.2 | Import the XRPL Labs reference blobs (single-sign, memo, two multisign, undecodable, unknown type) as regression vectors; none is a real SignIn (F-2.7) | 0.5 h       |
| 1b.3 | Human capture: GemWallet and Xaman (required for DoD), Crossmark if available                                                                           | human, ~1 h |
| 1b.4 | Docs: README quick start (must run as written), threat model, FINDINGS closed out                                                                       | 1.0 h       |

### Phase 1 release (≈1.5 h)

| #   | Task                                                                                                                                                                      | Est.  |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| R.1 | changesets (version PR only); `release.yml` on `v*` tags using npm trusted publishing (OIDC, provenance automatic, no token); register the workflow filename on npmjs.com | 1.0 h |
| R.2 | `npm publish --dry-run --provenance` proof, then `v0.1.0`                                                                                                                 | 0.5 h |

### Phase 2 — Static verify page (≈10 h)

| #   | Task                                                                                                                                                                                                          | Est.  |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| 2.1 | `packages/web`: Vite + TypeScript, no framework (two forms and a result panel do not need one); `base` set to the repo path                                                                                   | 2.0 h |
| 2.2 | Verify-message tab: text/hex toggle, pubkey, signature, optional address → verdict, derived address, plain-language reason                                                                                    | 2.5 h |
| 2.3 | Verify-SignIn tab: paste blob → decoded tx, memos, parsed challenge, verdict                                                                                                                                  | 2.0 h |
| 2.4 | Optional user-initiated `account_info` lookup (off by default, endpoint selectable)                                                                                                                           | 1.0 h |
| 2.5 | Strict CSP via meta tag, no inline scripts, footer with version + commit, mobile layout, a11y pass                                                                                                            | 1.5 h |
| 2.6 | `pages.yml`: build → `upload-pages-artifact@v5` → `deploy-pages@v5` on `main`; Playwright smoke spec against `vite preview` of the built dist, asserting VALID/INVALID on a fixture pair and zero page errors | 1.5 h |

GitHub Pages is possible for this repo: it is public, so Pages is free; the workflow deploys the built `dist/` on every merge to `main`. One manual step: set Pages source to "GitHub Actions" in repo settings.

### Phase 2b — Sign tab (only if decision 3 says yes) (≈6 h)

GemWallet and Crossmark via their SDKs, Xaman via a hosted payload flow that needs an API key and a backend, so Xaman signing stays out of the static page.

### Phase 3 — .NET port (separate go/no-go, ≈12 h)

`dotnet/` with `Xrpl.MessageVerify` NuGet, passing `fixtures/vectors.json` byte for byte. Depends on a maintained C# secp256k1/ed25519 stack; assess before committing.

### Phase 4 — XLS draft (human)

`docs/envelope.md` reformatted as an XLS discussion post. Dmitrii posts.

## 3. Risks and open questions

| Risk / question                                                                       | Impact                                                      | Mitigation                                                                                                                                                    |
| ------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Xaman strips Memos on SignIn (unverified)                                             | Challenge cannot be bound inside the signed bytes for Xaman | Capture one live payload in Phase 1b before finalising `docs/envelope.md`; fall back to `custom_meta.identifier` plus payload GET, documented as server-bound |
| Real Xaman blob differs from the synthetic one (TransactionType absent, extra fields) | `verifySignInBlob` too strict or too loose                  | Policy: require TransactionType 999 by default, `policy.allowLegacySignIn` for TransactionType-less blobs; reject blobs carrying `Destination`/`Amount`       |
| Crossmark encoding unknown                                                            | Advertising Crossmark support would be a false claim        | Ship as pending; file an upstream xrpl-connect issue about raw text in the `hex` slot                                                                         |
| Ledger cannot sign messages                                                           | Same                                                        | List as unsupported with evidence; one hardware run can reopen it                                                                                             |
| noble changes its `lowS` default                                                      | Silent acceptance of high-S                                 | Explicit `hasHighS()` check plus the committed high-S must-reject fixture; exact pins                                                                         |
| `@xrplf/isomorphic` Node path leaks `Buffer` into the browser bundle                  | Page breaks at runtime                                      | Runtime code uses noble directly; Playwright smoke test asserts zero page errors                                                                              |
| TypeScript 7 / tsup / vitest 5 compatibility                                          | Scaffold churn                                              | Pin TS 6.x if any tool balks; revisit via Renovate                                                                                                            |
| First npm publish under trusted publishing may need a manual publish                  | Release day surprise                                        | Do the `v0.1.0` dry run early; keep a 2FA session ready                                                                                                       |
| Uncompressed `04` keys or odd-length hex from a wallet                                | Wrong address binding or altered message                    | Reject both at the input gate (`malformed_input`); fixtures for each                                                                                          |

## 4. Definition of done for Phase 1 (handover §12)

- `verifyMessage` and `verifySignInBlob` pass every generated fixture; real-wallet vectors captured for GemWallet and Xaman.
- Cross-check test agrees with `ripple-keypairs.verify` on every vector.
- Browser bundle passes the CI smoke test.
- README quick start runs exactly as written.
- CI green; `npm publish --dry-run --provenance` succeeds.
- `docs/FINDINGS.md` lists every VERIFY item with outcome and evidence.

## 5. Notes on the handover itself

- The handover points at `/Users/jedi/Documents/c/claude-skills/` for repo-convention, release and frontend skills. The real folder is `/Users/dmitrii/Documents/c/claude-skills/` and it holds only Coinstash ops skills (Datadog, Sumsub, backend release ceremony, PR review). None apply to a public greenfield npm package; repo conventions therefore come from this plan.

## 6. Status (2026-09-04)

Done: workspace, `packages/core` (all five modules), 85 generated fixtures plus the XRPL Labs reference blobs, cross-check tests against ripple-keypairs and verify-xrpl-signature, docs (README, SECURITY, CONTRIBUTING, envelope, threat model, FINDINGS), CI, release and Pages workflows, `packages/web` verify page with a Playwright smoke test.

Open, needs a human:

1. Real-wallet captures (`fixtures/CAPTURE.md`): GemWallet and Xaman are required for the Phase 1 DoD; all seven wallets sit in `fixtures/pending/`.
2. `SECURITY.md` disclosure mailbox.
3. npm: register the trusted publisher for `xrpl-message-verify` (repo `jdponomarev/xrp-wallet-verification`, workflow `release.yml`) before tagging `v0.1.0`; the first publish of a new name may need a manual `npm publish`.
4. GitHub repo settings: branch protection on `main`, Pages source set to "GitHub Actions" (done by the integrator if the API allowed it).
5. Phase 3 (.NET port) and Phase 4 (XLS draft) go/no-go.
