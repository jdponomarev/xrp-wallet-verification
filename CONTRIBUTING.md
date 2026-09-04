# Contributing

Thanks for helping keep XRPL message verification boring and correct. This document covers how a
change lands; the design constraints are in [docs/threat-model.md](docs/threat-model.md).

## Ground rules

- **Branch and pull request only.** Nobody pushes to `main`, including maintainers. Squash-merge.
- **CI must be green** on every PR: lint, format, typecheck, tests, build and the package export
  check (`attw`). The `pending-captures` job is informational and never blocks.
- **A false `valid` is a release blocker.** If you find one, follow [SECURITY.md](SECURITY.md)
  instead of opening a PR.
- **Never commit a private key, seed or mnemonic that has ever held funds.** Fixture seeds are
  deterministic throwaways generated in `packages/core/scripts/gen-fixtures.ts`.

## Setup

```sh
pnpm install
pnpm test
```

Node 22.13 or newer for development (pnpm 11 needs it; the published library itself runs on Node 20+), pnpm 11 (`corepack enable` picks the pinned version from `package.json`).

## Changes to verification code need fixtures

Any change under `packages/core/src/verify*` or `packages/core/src/signin*` must come with:

1. a fixture in `fixtures/vectors.json` (regenerate with `pnpm gen-fixtures`, never edit by hand) or
   a real-wallet capture under `fixtures/`, covering the new behaviour, including the negative case;
2. the cross-check test still agreeing with `ripple-keypairs` / `verify-xrpl-signature` on every
   vector.

A PR that changes verification behaviour without a fixture will be asked to add one. This is how
the repository stays honest about what it verifies.

## Changesets

Every user-visible change needs a changeset:

```sh
pnpm changeset
```

Pick `patch` for fixes, `minor` for new options or Reason codes, `major` for anything that changes
what an existing input returns. Release PRs are generated from the accumulated changesets; publish
happens from a `v*` tag through `release.yml` (npm trusted publishing, no tokens).

## Commit style

Short imperative subject, at most 72 characters, body explains **why**. Prefix with the area when
it helps: `core:`, `signin:`, `challenge:`, `fixtures:`, `web:`, `ci:`, `docs:`. Do not put
incident narratives or reviewer conversation into code comments; that belongs in the commit
message and the PR description.

## Adding a wallet capture

Real-wallet vectors are the only way a wallet moves from "pending" to "confirmed" in the README
matrix. The procedure, per wallet, is in [fixtures/CAPTURE.md](fixtures/CAPTURE.md). In short:

1. Use a **testnet** account created for the capture; never a funded mainnet account.
2. Record the exact request the app made (message text or SignIn payload) and the exact response
   fields the wallet returned (`publicKey`, `signature`, `hex`, `account`, `signer`).
3. Save it as the capture format described in `fixtures/CAPTURE.md`, note the wallet version, the
   network and the date, and move the placeholder out of `fixtures/pending/`.
4. Add the corresponding test, update the README matrix row and `docs/FINDINGS.md` §3, and open a
   PR.

## Branch protection (what maintainers configure on `main`)

- Require a pull request before merging; at least one review from a code owner
  ([CODEOWNERS](CODEOWNERS) covers `packages/core/src`, `fixtures/`, the lockfile and the core
  `package.json`).
- Require the `core` CI job to pass on the latest commit.
- Require branches to be up to date before merging.
- No force pushes, no deletions, no bypass for administrators.
- Tags `v*` are created by maintainers only, after the changeset release PR is merged.

## Review focus

Reviewers look first at anything that could widen what is accepted: a relaxed regex, a removed
check, a new default in `Policy`, a new dependency in `packages/core/package.json`. Dependency
bumps to `ripple-*`, `@noble/*`, `verify-xrpl-signature` and `xrpl` arrive as a separate Renovate
group labelled `crypto-deps` and are never auto-merged.
