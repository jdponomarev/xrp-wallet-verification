# XRPL message-verification challenge envelope, version 1

Status: draft, 2026-09-04. Written in the shape of an XLS discussion post so it can be submitted
without a rewrite. Reference implementation: `formatChallenge`, `parseChallenge` and
`validateChallenge` in `packages/core/src/challenge.ts`.

## 1. Purpose

A service that wants a user to prove control of an XRP Ledger account asks the wallet to sign a
short piece of text. Without structure, a harvested signature over "Sign in" is replayable against
any service that accepts the same words. The envelope makes every signed challenge:

- **single-use** — a random nonce the verifier remembers until the challenge expires;
- **domain-bound** — the requesting domain is the first token of the text, and the URI must belong
  to it, so a signature collected by one site proves nothing to another;
- **expiring** — an explicit issue and expiration time;
- **human-readable** — a wallet shows the plain text; nothing is hidden in encoded fields.

The layout is modelled on EIP-4361 (Sign-In with Ethereum). Section 9 lists the differences.

## 2. Template

Lines are separated by LF (`\n`). There is no trailing newline after the last line. Braces mark
fields; the two lines marked optional are omitted entirely when unused.

```text
{domain} wants you to prove control of XRP Ledger account:
{address}

{statement}                       ← optional; when present it is followed by one blank line

URI: {uri}
Version: 1
Network: {network}
Nonce: {nonce}
Issued At: {issued-at}
Expiration Time: {expiration-time}
Request ID: {request-id}          ← optional, always the last line
```

Without a statement, line 4 is the `URI:` line. Without a Request ID, the `Expiration Time:` line
is the last line.

## 3. Grammar (ABNF, RFC 5234)

```abnf
challenge        = domain " wants you to prove control of XRP Ledger account:" LF
                   address LF
                   LF
                   [ statement LF LF ]
                   "URI: " uri LF
                   "Version: " version LF
                   "Network: " network LF
                   "Nonce: " nonce LF
                   "Issued At: " issued-at LF
                   "Expiration Time: " expiration-time
                   [ LF "Request ID: " request-id ]

domain           = host [ ":" port ]
host             = label *( "." label )
label            = alnum-lc [ *( alnum-lc / "-" ) alnum-lc ]
alnum-lc         = %x30-39 / %x61-7A                 ; 0-9 a-z, lowercase only
port             = 1*5DIGIT                          ; 1..65535

address          = "r" 24*34base58                   ; classic address, checksum verified
base58           = ALPHA / DIGIT                     ; the XRPL base58 alphabet, no 0 O I l

statement        = visible *( visible / SP ) visible / visible
                                                     ; one line, no leading/trailing space
visible          = %x21-7E / %x80-10FFFF             ; any non-control, non-space character

uri              = 1*visible                         ; absolute URI per RFC 3986
version          = "1"
network          = "mainnet" / "testnet" / "devnet" / "xahau" / network-id
network-id       = "0" / ( %x31-39 *DIGIT )          ; decimal uint32, no leading zeros
nonce            = 16*( ALPHA / DIGIT )
issued-at        = date-time                         ; RFC 3339, "Z" suffix only
expiration-time  = date-time
date-time        = 4DIGIT "-" 2DIGIT "-" 2DIGIT "T" 2DIGIT ":" 2DIGIT ":" 2DIGIT
                   [ "." 1*9DIGIT ] "Z"
request-id       = statement                         ; one line, no leading/trailing space
```

Parsers MUST normalise CRLF to LF before matching and MUST reject everything else the grammar
does not produce: a byte-order mark, a trailing newline, leading or trailing whitespace on any
line, unknown or reordered fields, lowercase-violating domains, a `Version` other than `1`, a
`Network` with leading zeros or above 2^32-1, a nonce shorter than 16 characters, and a timestamp
that Date-parses only by rolling over (for example `02-30` or `24:00`). The first violation is
reported with its line number.

## 4. Field semantics

| Field            | Meaning                                                                                                                                                                                                                          |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `domain`         | The authority (`host[:port]`) of the service requesting the signature. Lowercase. It is the first token of the text so a wallet can show it prominently.                                                                         |
| `address`        | The classic `r...` address the signature must resolve to. X-addresses are not allowed in the envelope; a verifier that accepts X-addresses from its own users converts them to classic form before formatting.                   |
| `statement`      | Optional human-readable sentence, one line. Not interpreted by verifiers.                                                                                                                                                        |
| `uri`            | Absolute URI of the resource the signature authorises. Its host MUST equal the domain host; when the domain carries a port, the URI port (explicit or scheme default) MUST match too.                                            |
| `version`        | Envelope version. Always `1` for this document.                                                                                                                                                                                  |
| `network`        | The ledger the account lives on: one of the four names or a decimal `NetworkID` (mainnet 0, testnet 1, devnet 2, Xahau 21337). A name and its number are **not** interchangeable; the service and its clients agree on one form. |
| `nonce`          | At least 16 characters from `[A-Za-z0-9]` (16 base62 characters ≈ 95 bits; 22 characters ≈ 131 bits). Generated by the verifier from a CSPRNG, never by the client.                                                              |
| `issuedAt`       | When the challenge was issued, RFC 3339 in UTC with a `Z` suffix. Re-emitted exactly as received.                                                                                                                                |
| `expirationTime` | After this instant the challenge is invalid. Must be later than `issuedAt`. Short windows (5–10 minutes) are recommended.                                                                                                        |
| `requestId`      | Optional opaque correlation value chosen by the service, one line. Not interpreted.                                                                                                                                              |

## 5. Signing rule for raw-signature wallets

Wallets that sign arbitrary messages sign **the UTF-8 bytes of the exact envelope text**: LF line
endings, no trailing newline, no prefix, no length framing, no hashing beyond what the signature
algorithm itself does. When the wallet API takes hexadecimal, hex-encode those bytes (uppercase or
lowercase; the bytes are what is signed).

The verifier recomputes the same bytes from the text it issued (or parses the text it receives,
re-formats it and checks that the result is byte-identical) and verifies the signature against the
account's public key with the normal XRPL rules: secp256k1 over SHA-512Half with a canonical low-S
DER signature, or ed25519 over the raw bytes. It then derives the address from the public key and
compares it with the `address` line (or with the account's RegularKey when ledger state is
available).

## 6. Signing rule for SignIn pseudo-transactions

Some wallets do not expose raw message signing and instead sign a `SignIn` pseudo-transaction
(`TransactionType` 999, never submittable). For those wallets the envelope travels inside the
signed bytes as a Memo:

- `MemoType` = hex of the UTF-8 string `xrpl-message-verify/challenge/v1`, i.e.
  `7872706C2D6D6573736167652D7665726966792F6368616C6C656E67652F7631`;
- `MemoData` = hex of the UTF-8 bytes of the exact envelope text (same bytes as section 5);
- `MemoFormat` omitted.

The verifier decodes the blob, verifies the transaction signature, checks that the signer resolves
to the `Account` field, finds the Memo with that `MemoType`, decodes `MemoData`, and parses and
validates the text. A blob with no such Memo fails with `challenge_mismatch`.

**Open item (FINDINGS F-2.9).** Whether the dominant SignIn wallet preserves Memos on SignIn
payloads is unverified: no public fixture shows one, and its SDK types merely allow any field. If
Memos turn out to be stripped, the fallback is the payload's `custom_meta.identifier`: the service
stores the nonce there when it creates the payload and reads it back from the payload-status
response. That binding is **server-side only** — it is not inside the signed bytes — so a verifier
using it must fetch the payload from the wallet's API itself, over an authenticated channel, and
must not accept an identifier supplied by the client. The verdict then rests on the signed
`Account` plus the server's own record, not on the signed text. Section 6 will be finalised after
one real capture.

## 7. Verifier responsibilities

Parsing accepts the text; validation decides whether to trust it. Checks run in this order and the
first failure wins:

1. `domain_mismatch` — `domain` differs (case-insensitively) from the verifier's own domain.
2. `address_mismatch` — an expected address was given and its classic form differs from `address`.
3. `network_mismatch` — an expected network was given and is not identical to `network`.
4. `nonce_too_short` — fewer than 16 characters.
5. `invalid_time` — either timestamp is not an RFC 3339 UTC instant.
6. `not_yet_valid` — `issuedAt` is more than 60 seconds in the future (clock-skew allowance).
7. `expired` — `expirationTime` is at or before now.
8. `invalid_time` — `expirationTime` is at or before `issuedAt`.
9. `invalid_uri` — `uri` does not parse or its host (and port, when the domain has one) differs from `domain`.
10. `malformed_fields` — the fields do not round-trip through `formatChallenge` and
    `parseChallenge` (hand-built or deserialised objects the parser would have rejected).
11. `nonce_used` — `isNonceUnused(nonce)` returned false. The verifier owns the store: it issues
    each nonce, `isNonceUnused` answers whether that nonce was issued and has not yet been
    accepted, and the verifier marks it accepted only after the signature and every other check
    have passed. `validateChallenge` never writes to the store. This check is last so a forged or
    stale challenge never consumes a store lookup.

Beyond those checks the verifier MUST:

- issue nonces itself from a CSPRNG and remember each one at least until its `expirationTime`
  (a store keyed by nonce with a TTL equal to the challenge lifetime is enough); a nonce is
  consumed on the first successful verification, never on a failed one;
- verify the signature and the address binding **before** trusting anything in the text —
  validation of the envelope is not proof of control;
- treat a thrown nonce-store error as a failure, never as "unused";
- fix `now` from its own clock, never from the client;
- reject the whole request when the parsed text re-formats to different bytes than were signed.

## 8. Worked example

Fields:

```json
{
  "domain": "example.com",
  "address": "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
  "statement": "Sign in to Example. No transaction will be submitted.",
  "uri": "https://example.com/login",
  "version": "1",
  "network": "mainnet",
  "nonce": "k3Jf9sLq2ZxW8vBnT5yHd7Rc",
  "issuedAt": "2026-09-04T08:00:00Z",
  "expirationTime": "2026-09-04T08:10:00Z",
  "requestId": "7c9e6679-7425-40de-944b-e07fc1f90ae7"
}
```

Envelope text (362 bytes of UTF-8, LF line endings, no trailing newline):

```text
example.com wants you to prove control of XRP Ledger account:
rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh

Sign in to Example. No transaction will be submitted.

URI: https://example.com/login
Version: 1
Network: mainnet
Nonce: k3Jf9sLq2ZxW8vBnT5yHd7Rc
Issued At: 2026-09-04T08:00:00Z
Expiration Time: 2026-09-04T08:10:00Z
Request ID: 7c9e6679-7425-40de-944b-e07fc1f90ae7
```

Raw-signature wallet: sign those 362 bytes; as hex the message starts
`6578616D706C652E636F6D2077616E747320796F7520746F2070726F76652063…` and ends
`…3434622D653037666331663930616537`.

SignIn wallet: one Memo with `MemoType`
`7872706C2D6D6573736167652D7665726966792F6368616C6C656E67652F7631` and `MemoData` equal to that
same hex.

Verifier at `2026-09-04T08:05:00Z`, expecting `example.com`, address
`rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh`, network `mainnet`, nonce unseen: every check passes and the
nonce is marked used. The same text presented at `08:10:00Z` fails with `expired`; presented to
`login.example.org` it fails with `domain_mismatch`; presented twice it fails with `nonce_used`.

## 9. Differences from EIP-4361

- **First line.** "wants you to prove control of XRP Ledger account:" instead of "wants you to sign
  in with your Ethereum account:". The wording says what the signature proves and nothing more.
- **Address form.** A classic `r...` address; X-addresses are excluded from the envelope so a single
  account has a single representation.
- **`Network` replaces `Chain ID`.** Names (`mainnet`, `testnet`, `devnet`, `xahau`) or a decimal
  `NetworkID`, because most XRPL tooling identifies networks by name.
- **`Expiration Time` is required**, not optional: a challenge without an expiry never leaves the
  nonce store.
- **No `Not Before` and no `Resources`.** Neither had a consumer in the sign-in use case; fewer
  fields means fewer parsing branches to get wrong. `Request ID` is kept for correlation.
- **Nonce alphabet and length** are fixed (`[A-Za-z0-9]{16,}`, at least ~95 bits) rather than
  EIP-4361's 8-character minimum.
- **Timestamps are UTC with `Z` only.** EIP-4361 allows any RFC 3339 offset; a single form keeps
  the round-trip byte-exact.
- **No signature-scheme prefix.** EIP-191 prepends `\x19Ethereum Signed Message:\n<len>`; XRPL
  message signing has no such convention, so the envelope bytes themselves are signed (section 5),
  or carried in a `SignIn` Memo (section 6).
- **Strict parsing.** CRLF is normalised, but unknown fields, reordering, trailing newlines and
  surrounding whitespace are rejected instead of tolerated.
