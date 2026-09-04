# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories: open the repository's **Security** tab and
choose **Report a vulnerability**. Do not open a public issue or pull request for anything that
could be a vulnerability.

Email: TODO (maintainer to fill before first release)

Include the inputs that reproduce the problem (message, public key, signature or blob, and any
account state), the version of `xrpl-message-verify`, and what the library returned versus what it
should have returned. A failing Vitest case is the most useful form.

## What counts as a vulnerability

Any input that makes `verifyMessage`, `verifyMessageByAddress`, `verifySignInBlob` or
`validateChallenge` return `valid: true` / `ok: true` when it should not. In particular:

- a signature that verifies for a key, address or message it was not made over
- a non-canonical or malleated signature accepted as valid
- an uncompressed, off-curve or wrong-length key accepted or derived to an address
- hex, memo or challenge text that is truncated or reinterpreted before verification
- a SignIn blob accepted where the signer is not the `Account` (or its RegularKey)
- account-state checks (`master_disabled`, `unsupported_multisig`, `account_not_found`) bypassed
- an exception escaping a `verify*` function on caller data (a crash is a denial-of-service path
  and a sign that a check was skipped)

Also in scope: incorrect `resolveAccount` mapping that hides a disabled master key or a signer
list, and supply-chain problems in the published package (files not built from this repository,
missing provenance).

Not in scope: nonce storage, session handling and replay protection in applications that use the
library (documented as the caller's responsibility), and issues in wallets themselves. Wallet
findings are still welcome as ordinary issues so the support matrix stays honest.

## Coordinated disclosure

- Acknowledgement within 5 working days.
- Assessment and, when confirmed, a fix and a regression fixture as soon as practical.
- Public disclosure 90 days after the report, or earlier once a fixed version is published and
  reporters agree. We credit reporters in the advisory unless they prefer otherwise.

## Supported versions

| Version | Supported                                                 |
| ------- | --------------------------------------------------------- |
| 0.x     | Latest minor only; fixes ship as a new 0.x release        |
| < 0.1.0 | Not supported (pre-release; nothing was published to npm) |

Once 1.0.0 ships, the latest major and the previous major receive security fixes for six months
after the newer major's release.
