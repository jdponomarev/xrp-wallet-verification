# Capturing real-wallet fixtures

Testnet only. Never use an account that holds real funds, and never paste a seed or private key
anywhere in this repository. Each capture is a signature (or a signed SignIn blob) over the exact
text below, recorded with the public key, address and wallet version so it can be replayed by
`packages/core/test/fixtures.test.ts` forever.

Where to paste: `fixtures/pending/<wallet>.json`. Fill the null fields, keep the schema, open a PR.
Once the vector verifies, the reviewer moves it into `fixtures/vectors.json` with
`source: "<wallet>@<version>"` and deletes the placeholder. `node scripts/report-pending.mjs`
lists what is still missing.

## The message to sign

Replace `<address>` with the classic r-address of the testnet account that signs. Lines are joined
with `\n` (LF), no trailing newline. Paste it exactly; a wallet that trims or re-wraps it produces a
different signature, which is itself a finding worth recording in `notes`.

```
example.com wants you to prove control of XRP Ledger account:
<address>

Sign in to example.com

URI: https://example.com/login
Version: 1
Network: testnet
Nonce: 0123456789abcdef0123456789abcdef
Issued At: 2026-09-04T00:00:00Z
Expiration Time: 2026-09-04T00:10:00Z
Request ID: 7c9e6679-7425-40de-944b-e07fc1f90ae7
```

For SignIn wallets (Xaman) the same text goes into `MemoData` as hex, with `MemoType` set to the
hex of `xrpl-message-verify/challenge/v1`.

Get testnet XRP from <https://xrpl.org/resources/dev-tools/xrp-faucets> (or the wallet's own
testnet faucet). Hex of a UTF-8 string in a browser console:

```js
[...new TextEncoder().encode(text)]
  .map((b) => b.toString(16).padStart(2, '0'))
  .join('')
  .toUpperCase();
```

## GemWallet (`fixtures/pending/gemwallet.json`)

1. Install GemWallet from the Chrome Web Store. Create a new wallet, switch the network to Testnet
   (Settings → Network), fund it from the faucet.
2. Note the extension version from `chrome://extensions` (Details → Version).
3. The verify page has no Sign tab yet, so drive `@gemwallet/api` from the browser console on any
   https page where the extension is enabled (the Pages site works):

   ```js
   const gem = await import('https://esm.sh/@gemwallet/api@3.8.0');
   const key = await gem.getPublicKey(); // { result: { address, publicKey } }
   const text = `...envelope with key.result.address...`;
   const sig = await gem.signMessage(text); // { result: { signedMessage } }
   console.log(JSON.stringify({ ...key.result, signedMessage: sig.result.signedMessage, text }));
   ```

4. Record `publicKey`, `signature` (= `signedMessage`), `address`, `message` (= `text`),
   `encoding: "utf8"`, `algorithm` from the key prefix (`ED` → ed25519, `02`/`03` → secp256k1),
   `source: "gemwallet@<version>"`, `expect: { valid: true, reason: null, signer: "master" }`.
5. Repeat once with an ed25519 account if the first one was secp256k1 (GemWallet creates
   ed25519 by default; import a secp256k1 seed for the other).

## Xaman (`fixtures/pending/xaman.json`)

Needs a developer API key: create an app at <https://apps.xaman.dev> and copy the API key and
secret. Xaman must be on Testnet (Settings → Advanced → Node → Testnet).

1. Create a SignIn payload with a Memo carrying the envelope:

   ```sh
   curl -s https://xumm.app/api/v1/platform/payload \
     -H 'X-API-Key: <key>' -H 'X-API-Secret: <secret>' -H 'Content-Type: application/json' \
     -d '{"txjson":{"TransactionType":"SignIn","Memos":[{"Memo":{"MemoType":"<hex of xrpl-message-verify/challenge/v1>","MemoData":"<hex of the envelope>"}}]}}'
   ```

   The response has `uuid` and `refs.qr_png`. Open the QR, scan it with Xaman, sign.

2. Fetch the result:

   ```sh
   curl -s https://xumm.app/api/v1/platform/payload/<uuid> -H 'X-API-Key: <key>' -H 'X-API-Secret: <secret>'
   ```

   Record `response.hex` as `blobHex`, `response.account` as `address`, and put
   `response.signer`, `response.signer_pubkey`, `meta.signed`, plus the Xaman app version
   (Settings → About) into `notes`. `kind: "signin"`, `encoding: "hex"`,
   `source: "xaman@<version>"`, `expect: { valid: true, reason: null, signer: "master" }`.

3. Decode the blob (`ripple-binary-codec` with `TRANSACTION_TYPES.SignIn = 999`, or the verify
   page once it exists) and write into `notes`: does it carry `TransactionType` 999, which other
   fields (`Sequence`, `Fee`, `Flags`, `NetworkID`), and **whether the Memos survived**.
4. Repeat the whole flow WITHOUT `Memos` and record that blob too (a second placeholder record or
   an array in `notes` is fine); the reviewer splits them.
5. If the Memos were stripped, also record `custom_meta.identifier` behaviour: create a payload
   with `"custom_meta":{"identifier":"<nonce>"}` and confirm it is echoed on the GET.

## Crossmark (`fixtures/pending/crossmark.json`)

Crossmark has no message-signing API; xrpl-connect emulates it with `signInAndWait`.

1. Install Crossmark, create a testnet account, fund it.
2. In the browser console on a page where Crossmark is injected:

   ```js
   const sdk = (await import('https://esm.sh/@crossmarkio/sdk@0.4.0')).default;
   const nonce = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
   const res = await sdk.methods.signInAndWait(nonce);
   console.log(JSON.stringify(res, null, 2));
   ```

3. Record the complete response in `notes` verbatim (address, publicKey, whether a `signature`
   field is present at all, and every other field). Put the nonce in `message` and leave `expect`
   as it is: the encoding of what Crossmark signs is unknown, and the reviewer works it out from
   the capture. Also record the extension version.

## Ledger (`fixtures/pending/ledger.json`)

One attempt only; the expected outcome is a rejection.

1. Ledger device with the XRP app installed and open, Ledger Live closed.
2. Using xrpl-connect's `LedgerAdapter`, call `signMessage('hello')` (any text; the envelope is
   not needed).
3. Record the thrown error and the APDU status word (for example `0x6a80`, `0x6985`, `0x6d00`),
   the XRP app version and the device model in `notes`. If the device unexpectedly returns a
   signature, record it together with the exact bytes that were sent so the prefix can be
   established.

## MetaMask XRPL Snap, Xyra, Otsu (`metamask-snap.json`, `xyra.json`, `otsu.json`)

For each wallet, on a testnet account:

1. Call the wallet's `signMessage` with the envelope text (Snap: `xrpl_signMessage { message }`
   via the Snap RPC; Xyra: `sdk.signMessage({ message })`; Otsu: `window.xrpl.signMessage(text)`).
2. Record everything the wallet returns, verbatim, in `notes`, plus the public key and address the
   wallet reports and its version. For Xyra also record the `message` field it returns and note
   whether it equals the text that was requested.
3. Fill `publicKey`, `signature`, `address`, `message` when present. The signing scheme is
   unverified for all three, so `expect` stays as it is until the reviewer confirms which bytes
   were signed.

## After the capture

- Run `node scripts/report-pending.mjs` to see the placeholder recognised as captured.
- Open a PR. The reviewer verifies the vector with `verifyMessage` / `verifySignInBlob`, sets
  `expect`, moves the record into `fixtures/vectors.json` and resets the placeholder.
- Anything unexpected (trimmed text, missing Memos, a prefix, an uncompressed key) goes into
  `docs/FINDINGS.md` §3 with the capture as evidence.
