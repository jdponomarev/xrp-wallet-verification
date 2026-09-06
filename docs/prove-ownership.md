# Proving you control an XRP Ledger account

Someone has asked you to show that an XRP address is yours. This takes about two minutes, moves
no funds, and reveals nothing secret. You sign a short piece of text with your wallet; the
signature can only have come from the account's owner.

## What you need

- A computer with Chrome, Brave or Edge.
- The **GemWallet** browser extension (<https://gemwallet.app>) with the account in question
  imported or created. Other wallets: see the last section.
- The link the requester sent you. It starts with
  `https://jdponomarev.github.io/xrp-wallet-verification/#sign?`.

## Steps

1. **Open the link.** A page titled _XRPL Message Verify_ opens on the _Prove ownership_ tab and
   shows the request text. Read it. It names who is asking (their domain), your account address,
   and an expiry time. If anything looks wrong, stop and ask the requester.
2. **Click "Sign with GemWallet".** The extension pops up and shows the same text. Approve it.
   If GemWallet asks which account to use, pick the one named in the request.
3. **Send the proof back.** The page now shows _Signed and verified_ with two buttons:
   _Copy verification link_ and _Copy proof as text_. Copy either one and send it to the requester
   the same way they sent you the link (email, chat). Both contain the same information and
   nothing private.

That is all. You can close the page.

## If the page says "Not verified"

- **"Your wallet signed as r… but the request is for r…"**: GemWallet used a different account.
  Switch to the right account in the extension (click the extension icon, choose the account) and
  sign again.
- **"GemWallet is not installed in this browser"**: install it from <https://gemwallet.app>,
  import your account, reload the page.
- **The request has expired**: ask the requester for a new link.

## What you are signing, and what you are not

The text you sign says, in plain words, that the requester wants proof of control of your account,
with a random one-time code and an expiry. It is not a transaction. It cannot move funds, change
settings or authorise anything on the ledger. Because it names the requester and expires, someone
who intercepts it cannot reuse it elsewhere.

Never enter your secret key, seed phrase or password on this page. It never asks for them.

## Other wallets

- **Xaman (phone app).** Xaman cannot sign from this page. The requester has to send you a Xaman
  sign-in request instead; you approve it in the app like a normal sign-in. If they only sent you a
  page link, tell them you use Xaman.
- **Crossmark.** There is a _Sign with Crossmark_ button, but it is experimental and may fail.
- **Ledger.** The Ledger XRP app cannot sign messages. Use a software wallet for the same account
  if you have one, or ask the requester for another way.

## For the requester

Open the same page, _Prove ownership_ tab, fill in your domain and the address, and send the
generated link. When the proof comes back, open the verification link (or paste the proof into the
_Signed message_ tab). The page shows **VALID** with the derived address and the request details.
Check that the nonce shown is the one you issued and that the request has not expired. The page
cannot know which requests you sent, so that comparison is yours.
