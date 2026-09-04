import { getPublicKey, isInstalled, signMessage } from '@gemwallet/api';
import crossmark from '@crossmarkio/sdk';
import {
  formatChallenge,
  normalizeAddress,
  parseChallenge,
  verifyMessage,
  type ChallengeFields,
  type ChallengeNetwork,
} from 'xrpl-message-verify';
import { $, b64urlDecode, b64urlEncode, copyText, esc, pageUrl } from './dom.js';

/** Signature plus everything a verifier needs; also what the proof link carries. */
export interface Proof {
  message: string;
  publicKey: string;
  signature: string;
  address: string;
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

function nonce(length = 24): string {
  let out = '';
  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    for (const b of bytes) if (b < 248 && out.length < length) out += ALNUM[b % 62];
  }
  return out;
}

export function requestLink(text: string): string {
  return `${pageUrl()}#sign?c=${b64urlEncode(text)}`;
}

export function proofLink(p: Proof): string {
  return `${pageUrl()}#verify?p=${b64urlEncode(JSON.stringify(p))}`;
}

function showRequest(text: string): void {
  const link = requestLink(text);
  $('request-out').innerHTML =
    `<p><strong>Request text</strong></p><pre id="request-text">${esc(text)}</pre>` +
    `<div class="linkbox"><input id="request-link" readonly value="${esc(link)}" /><button type="button" id="copy-request">Copy link</button></div>` +
    `<p class="muted">Send the link to the wallet owner. When they open it, this page shows the text and the sign buttons. Keep the nonce (<code>${esc(parseChallenge(text).nonce)}</code>) so you can recognise the proof that comes back.</p>`;
  $<HTMLButtonElement>('copy-request').addEventListener('click', (e) =>
    copyText(link, e.currentTarget as HTMLButtonElement),
  );
  showSign(text);
}

function showSign(text: string): void {
  $<HTMLTextAreaElement>('sign-text').value = text;
  $('sign-block').hidden = false;
  $('sign-out').innerHTML = '';
}

function currentText(): string {
  return $<HTMLTextAreaElement>('sign-text').value;
}

function renderProof(p: Proof): void {
  let fields: ChallengeFields | undefined;
  try {
    fields = parseChallenge(p.message);
  } catch {
    fields = undefined;
  }
  const input = {
    message: p.message,
    publicKey: p.publicKey,
    signature: p.signature,
    address: fields?.address ?? p.address,
  };
  const r = verifyMessage(input);
  const out = $('sign-out');
  if (!r.valid) {
    const why =
      r.reason === 'address_mismatch'
        ? `Your wallet signed as <code>${esc(r.derivedAddress)}</code> but the request is for <code>${esc(input.address)}</code>. Switch to that account in the wallet and sign again.`
        : `The wallet returned a signature this page could not verify (<code>${esc(r.reason)}</code>). ${esc(String(r.details?.error ?? ''))}`;
    out.innerHTML = `<div class="verdict bad" data-valid="false">Not verified<small>${why}</small></div>`;
    return;
  }
  const link = proofLink(p);
  const json = JSON.stringify(p, null, 2);
  out.innerHTML =
    `<div class="verdict ok" data-valid="true">Signed and verified<small>Send the proof below to whoever asked for it. It contains no secrets.</small></div>` +
    `<div class="proof"><div class="linkbox"><input id="proof-link" readonly value="${esc(link)}" /><button type="button" id="copy-proof-link">Copy verification link</button></div>` +
    `<pre id="proof-json">${esc(json)}</pre><div class="actions"><button type="button" id="copy-proof-json">Copy proof as text</button></div></div>`;
  $<HTMLButtonElement>('copy-proof-link').addEventListener('click', (e) =>
    copyText(link, e.currentTarget as HTMLButtonElement),
  );
  $<HTMLButtonElement>('copy-proof-json').addEventListener('click', (e) =>
    copyText(json, e.currentTarget as HTMLButtonElement),
  );
}

function renderSignError(e: unknown): void {
  $('sign-out').innerHTML = `<div class="verdict bad" data-valid="error">Could not sign<small>${esc(
    e instanceof Error ? e.message : String(e),
  )}</small></div>`;
}

async function signWithGemWallet(text: string): Promise<Proof> {
  const installed = await isInstalled();
  if (!installed.result?.isInstalled) {
    throw new Error(
      'GemWallet is not installed in this browser. Install it from gemwallet.app, then reload this page.',
    );
  }
  const key = await getPublicKey();
  if (!key.result) throw new Error('GemWallet did not share the public key (request declined).');
  const sig = await signMessage(text);
  if (!sig.result) throw new Error('GemWallet did not sign (request declined).');
  return {
    message: text,
    publicKey: key.result.publicKey,
    signature: sig.result.signedMessage,
    address: key.result.address,
  };
}

async function signWithCrossmark(text: string): Promise<Proof> {
  if (!crossmark.methods.isInstalled()) {
    throw new Error(
      'Crossmark is not installed in this browser. Install it from crossmark.io, then reload this page.',
    );
  }
  const hex = Array.from(new TextEncoder().encode(text), (b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  const res = await crossmark.methods.signInAndWait(hex);
  const data = res.response.data;
  if (!data.signature) throw new Error('Crossmark returned no signature.');
  return {
    message: text,
    publicKey: data.publicKey,
    signature: data.signature,
    address: data.address,
  };
}

function bind(id: string, signer: (text: string) => Promise<Proof>): void {
  const button = $<HTMLButtonElement>(id);
  button.addEventListener('click', async () => {
    button.disabled = true;
    $('sign-out').innerHTML = '<p class="muted">Waiting for the wallet…</p>';
    try {
      renderProof(await signer(currentText()));
    } catch (e) {
      renderSignError(e);
    } finally {
      button.disabled = false;
    }
  });
}

export function initSign(opts: { selectTab: (id: string) => void }): void {
  $<HTMLFormElement>('form-request').addEventListener('submit', (e) => {
    e.preventDefault();
    try {
      const now = new Date();
      const minutes = Number($<HTMLInputElement>('rq-minutes').value) || 30;
      const statement = $<HTMLInputElement>('rq-statement').value.trim();
      const fields: ChallengeFields = {
        domain: $<HTMLInputElement>('rq-domain').value.trim().toLowerCase(),
        address: normalizeAddress($<HTMLInputElement>('rq-address').value).classic,
        uri: `https://${$<HTMLInputElement>('rq-domain').value.trim().toLowerCase()}/`,
        version: '1',
        network: $<HTMLSelectElement>('rq-network').value as ChallengeNetwork,
        nonce: nonce(),
        issuedAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
        expirationTime: new Date(now.getTime() + minutes * 60_000)
          .toISOString()
          .replace(/\.\d{3}Z$/, 'Z'),
      };
      if (statement) fields.statement = statement;
      showRequest(formatChallenge(fields));
    } catch (err) {
      $('request-out').innerHTML =
        `<div class="verdict bad" data-valid="error">Could not create the request<small>${esc(
          err instanceof Error ? err.message : String(err),
        )}</small></div>`;
    }
  });
  bind('sign-gem', signWithGemWallet);
  bind('sign-crossmark', signWithCrossmark);

  // A request link opens straight on the sign step.
  if (location.hash.startsWith('#sign?')) {
    const c = new URLSearchParams(location.hash.slice('#sign?'.length)).get('c');
    if (c) {
      try {
        const text = b64urlDecode(c);
        parseChallenge(text); // refuse to show anything that is not a well-formed request
        showSign(text);
        $('request-block').hidden = true;
        opts.selectTab('tab-sign');
      } catch {
        opts.selectTab('tab-sign');
        $('sign-block').hidden = false;
        renderSignError(new Error('This link does not contain a valid request.'));
      }
    }
  }
}

/** Decodes a `#verify?p=` proof link; undefined when absent or malformed. */
export function proofFromHash(): Proof | undefined {
  if (!location.hash.startsWith('#verify?')) return undefined;
  const p = new URLSearchParams(location.hash.slice('#verify?'.length)).get('p');
  if (!p) return undefined;
  try {
    const parsed = JSON.parse(b64urlDecode(p)) as Partial<Proof>;
    if (
      typeof parsed.message === 'string' &&
      typeof parsed.publicKey === 'string' &&
      typeof parsed.signature === 'string' &&
      typeof parsed.address === 'string'
    ) {
      return parsed as Proof;
    }
  } catch {
    // fall through
  }
  return undefined;
}
