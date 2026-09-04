import {
  parseChallenge,
  resolveAccount,
  verifyMessage,
  verifySignInBlob,
  type AccountState,
  type DecodedMemo,
  type Reason,
  type RpcClient,
  type VerifyMessageInput,
  type VerifyResult,
  type VerifySignInOptions,
} from 'xrpl-message-verify';

const REASONS: Record<Reason, string> = {
  bad_signature: 'The signature does not match this message and public key.',
  algorithm_mismatch:
    'The signature format does not belong to the key type (secp256k1 keys need a DER signature, ED keys a 64-byte one).',
  address_mismatch: 'The key that signed derives to a different address than the one given.',
  master_disabled:
    'The signing key is the account master key, but the master key is disabled on the ledger.',
  unsupported_multisig:
    'This account or blob uses multi-signing; a single-key ownership proof is not possible.',
  account_not_found:
    'The account does not exist on the ledger (unfunded or deleted). The key still derives to the address shown.',
  malformed_input:
    'Something could not be parsed. Check hex characters, even length and the key prefix.',
  message_too_large: 'The message exceeds the size limit.',
  non_canonical_signature:
    'The secp256k1 signature uses a high S value and is rejected as non-canonical.',
  unexpected_transaction_type:
    'The blob is not a SignIn pseudo-transaction. Real transactions are not ownership proofs.',
  challenge_mismatch: 'No memo in the blob equals the expected challenge text.',
};

const $ = <T extends HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing #${id}`);
  return el as T;
};

// Tabs
const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
function selectTab(tab: HTMLButtonElement): void {
  for (const t of tabs) {
    const selected = t === tab;
    t.setAttribute('aria-selected', String(selected));
    t.tabIndex = selected ? 0 : -1;
    $(t.getAttribute('aria-controls') as string).hidden = !selected;
  }
  tab.focus();
}
tabs.forEach((t, i) => {
  t.addEventListener('click', () => selectTab(t));
  t.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
      e.preventDefault();
      const next = (i + (e.key === 'ArrowRight' ? 1 : tabs.length - 1)) % tabs.length;
      selectTab(tabs[next] as HTMLButtonElement);
    }
  });
});

// Node selectors
for (const prefix of ['msg', 'si']) {
  const select = $<HTMLSelectElement>(`${prefix}-node`);
  const custom = $<HTMLInputElement>(`${prefix}-node-custom`);
  select.addEventListener('change', () => {
    custom.hidden = select.value !== 'custom';
  });
}

function nodeUrl(prefix: string): string {
  const select = $<HTMLSelectElement>(`${prefix}-node`);
  return select.value === 'custom'
    ? $<HTMLInputElement>(`${prefix}-node-custom`).value.trim()
    : select.value;
}

function fetchClient(url: string): RpcClient {
  return {
    async request(method, params) {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method, params: [params] }),
      });
      if (!res.ok) throw new Error(`node returned HTTP ${res.status}`);
      return res.json();
    },
  };
}

async function maybeResolve(
  prefix: string,
  address: string | undefined,
): Promise<AccountState | undefined> {
  if (!$<HTMLInputElement>(`${prefix}-lookup`).checked || !address) return undefined;
  return resolveAccount(address, fetchClient(nodeUrl(prefix)));
}

function esc(s: unknown): string {
  return String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function renderResult(out: HTMLElement, r: VerifyResult, extra = ''): void {
  const rows: Array<[string, unknown]> = [];
  if (r.algorithm) rows.push(['Algorithm', r.algorithm]);
  if (r.derivedAddress) rows.push(['Derived address', r.derivedAddress]);
  rows.push(['Signer', r.signer]);
  if (r.reason) rows.push(['Reason code', r.reason]);
  if (r.details?.error) rows.push(['Detail', r.details.error]);
  out.innerHTML =
    `<div class="verdict ${r.valid ? 'ok' : 'bad'}" data-valid="${r.valid}">${r.valid ? 'VALID' : 'INVALID'}` +
    (r.reason ? `<small>${esc(REASONS[r.reason] ?? r.reason)}</small>` : '') +
    `</div><dl>${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>${extra}`;
}

function renderError(out: HTMLElement, e: unknown): void {
  out.innerHTML = `<div class="verdict bad" data-valid="error">Could not verify<small>${esc(
    e instanceof Error ? e.message : String(e),
  )}</small></div>`;
}

// Signed message
const EXAMPLE = {
  message: 'Sign in to example.com\nnonce: 0123456789abcdef',
  publicKey: '035A7FA22521397BE0FFE9CD7C35DDE0FB0C8EA96E48FF84E0C6309D0D4D70D9EA',
  signature:
    '30440220072BCE65E506246C591AD415313F091B89A3212C5EDA9E0205FC088C9A53FEA1022037FE519459B5FD6EEA039E15237755268646108639917618D51BE02724202A59',
  address: 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA',
};
$('msg-example').addEventListener('click', () => {
  $<HTMLTextAreaElement>('msg-text').value = EXAMPLE.message;
  $<HTMLInputElement>('msg-pubkey').value = EXAMPLE.publicKey;
  $<HTMLInputElement>('msg-sig').value = EXAMPLE.signature;
  $<HTMLInputElement>('msg-address').value = EXAMPLE.address;
  (document.querySelector('input[name="msg-encoding"][value="utf8"]') as HTMLInputElement).checked =
    true;
});

$<HTMLFormElement>('form-message').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = $('result-message');
  try {
    const encoding = (
      document.querySelector('input[name="msg-encoding"]:checked') as HTMLInputElement
    ).value as 'utf8' | 'hex';
    const address = $<HTMLInputElement>('msg-address').value.trim() || undefined;
    const input: VerifyMessageInput = {
      message: $<HTMLTextAreaElement>('msg-text').value,
      encoding,
      signature: $<HTMLInputElement>('msg-sig').value.trim(),
      publicKey: $<HTMLInputElement>('msg-pubkey').value.trim(),
    };
    if (address) input.address = address;
    const account = await maybeResolve('msg', address);
    if (account) input.account = account;
    renderResult(out, verifyMessage(input), account ? accountHtml(account) : '');
  } catch (err) {
    renderError(out, err);
  }
});

function accountHtml(a: AccountState): string {
  return (
    `<dl><dt>Ledger account</dt><dd>${esc(a.address)}</dd><dt>Exists</dt><dd>${a.exists}</dd>` +
    (a.regularKey ? `<dt>RegularKey</dt><dd>${esc(a.regularKey)}</dd>` : '') +
    `<dt>Master disabled</dt><dd>${a.masterDisabled}</dd><dt>Signer list</dt><dd>${a.hasSignerList}</dd>` +
    (a.ledgerIndex ? `<dt>Ledger index</dt><dd>${a.ledgerIndex}</dd>` : '') +
    `</dl>`
  );
}

// Xaman SignIn
function memosHtml(memos: DecodedMemo[]): string {
  if (memos.length === 0) return '<p class="muted">No memos.</p>';
  return memos
    .map((m, i) => {
      let challenge = '';
      if (m.data) {
        try {
          const c = parseChallenge(m.data);
          challenge = `<p><strong>Parsed challenge</strong></p><pre>${esc(JSON.stringify(c, null, 2))}</pre>`;
        } catch {
          challenge = '';
        }
      }
      return `<p><strong>Memo ${i + 1}</strong>${m.type ? ` · type <code>${esc(m.type)}</code>` : ''}</p><pre>${esc(
        m.data ?? m.dataHex ?? '',
      )}</pre>${challenge}`;
    })
    .join('');
}

$<HTMLFormElement>('form-signin').addEventListener('submit', async (e) => {
  e.preventDefault();
  const out = $('result-signin');
  try {
    const blob = $<HTMLTextAreaElement>('si-blob').value.replace(/\s+/g, '');
    const expectedAccount = $<HTMLInputElement>('si-account').value.trim() || undefined;
    const expectedMemo = $<HTMLTextAreaElement>('si-memo').value || undefined;
    const opts: VerifySignInOptions = {};
    if (expectedAccount) opts.expectedAccount = expectedAccount;
    if (expectedMemo) opts.expectedMemo = expectedMemo;
    if ($<HTMLInputElement>('si-legacy').checked) opts.allowMissingTransactionType = true;
    // Look up the account named in the blob (or the expected one) only when asked.
    const first = verifySignInBlob(blob, opts);
    const account = await maybeResolve(
      'si',
      expectedAccount ?? (first.tx.Account as string | undefined),
    );
    const r = account ? verifySignInBlob(blob, { ...opts, account }) : first;
    renderResult(
      out,
      r,
      `<p><strong>Decoded transaction</strong></p><pre>${esc(JSON.stringify(r.tx, null, 2))}</pre>` +
        `<p><strong>Memos</strong></p>${memosHtml(r.memos)}` +
        (account ? accountHtml(account) : ''),
    );
  } catch (err) {
    renderError(out, err);
  }
});

$('build-info').textContent = `xrpl-message-verify v${__CORE_VERSION__} · build ${__COMMIT__}`;
