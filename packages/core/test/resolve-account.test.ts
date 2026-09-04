import { describe, expect, it } from 'vitest';
import { MalformedInputError } from '../src/errors.js';
import { jsonRpcClient, resolveAccount } from '../src/resolve-account.js';
import type { RpcClient } from '../src/types.js';

const GENESIS = 'rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh';
const GENESIS_X_TAG_12345 = 'XVPcpSm47b1CZkf5AkKM9a84dQHe3mTAxgxfLw2qYoe7Boa';
const REGULAR = 'rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA';
const LSF_DISABLE_MASTER = 0x00100000;

interface Call {
  method: string;
  params: Record<string, unknown>;
}

function fakeClient(response: unknown): RpcClient & { calls: Call[] } {
  const calls: Call[] = [];
  return {
    calls,
    request(method, params) {
      calls.push({ method, params });
      return Promise.resolve(response);
    },
  };
}

function accountInfo(accountData: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  return {
    result: {
      account_data: { Account: GENESIS, Balance: '1000000', Flags: 0, ...accountData },
      ledger_hash: '00'.repeat(32),
      ledger_index: 95000000,
      validated: true,
      ...extra,
    },
  };
}

describe('resolveAccount', () => {
  it('requests account_info for the validated ledger with signer lists', async () => {
    const client = fakeClient(accountInfo({}));
    await resolveAccount(GENESIS, client);
    expect(client.calls).toEqual([
      {
        method: 'account_info',
        params: { account: GENESIS, ledger_index: 'validated', signer_lists: true },
      },
    ]);
  });

  it('maps a plain account with no RegularKey', async () => {
    const state = await resolveAccount(GENESIS, fakeClient(accountInfo({})));
    expect(state).toEqual({
      address: GENESIS,
      exists: true,
      masterDisabled: false,
      hasSignerList: false,
      ledgerIndex: 95000000,
    });
    expect('regularKey' in state).toBe(false);
  });

  it('exposes the RegularKey', async () => {
    const state = await resolveAccount(GENESIS, fakeClient(accountInfo({ RegularKey: REGULAR })));
    expect(state.regularKey).toBe(REGULAR);
    expect(state.masterDisabled).toBe(false);
  });

  it('reads lsfDisableMaster from Flags', async () => {
    const flags = LSF_DISABLE_MASTER | 0x00800000;
    const state = await resolveAccount(GENESIS, fakeClient(accountInfo({ Flags: flags })));
    expect(state.masterDisabled).toBe(true);
  });

  it('ignores other flag bits', async () => {
    const state = await resolveAccount(GENESIS, fakeClient(accountInfo({ Flags: 0x00800000 })));
    expect(state.masterDisabled).toBe(false);
  });

  it('detects a signer list under account_data (rippled >= 1.8)', async () => {
    const list = { SignerEntries: [], SignerQuorum: 2 };
    const state = await resolveAccount(GENESIS, fakeClient(accountInfo({ signer_lists: [list] })));
    expect(state.hasSignerList).toBe(true);
  });

  it('detects a signer list at the result level (older rippled)', async () => {
    const list = { SignerEntries: [], SignerQuorum: 2 };
    const state = await resolveAccount(
      GENESIS,
      fakeClient(accountInfo({}, { signer_lists: [list] })),
    );
    expect(state.hasSignerList).toBe(true);
  });

  it('treats an empty signer_lists array as no signer list', async () => {
    const state = await resolveAccount(GENESIS, fakeClient(accountInfo({ signer_lists: [] })));
    expect(state.hasSignerList).toBe(false);
  });

  it('falls back to ledger_current_index', async () => {
    const response = accountInfo({});
    delete (response.result as Record<string, unknown>).ledger_index;
    (response.result as Record<string, unknown>).ledger_current_index = 42;
    const state = await resolveAccount(GENESIS, fakeClient(response));
    expect(state.ledgerIndex).toBe(42);
  });

  it('accepts an adapter that returns the inner result without the envelope', async () => {
    const state = await resolveAccount(GENESIS, fakeClient(accountInfo({}).result));
    expect(state.exists).toBe(true);
    expect(state.ledgerIndex).toBe(95000000);
  });

  it('maps actNotFound to exists: false', async () => {
    const client = fakeClient({
      result: { error: 'actNotFound', error_code: 19, status: 'error', validated: true },
    });
    const state = await resolveAccount(GENESIS, client);
    expect(state).toEqual({
      address: GENESIS,
      exists: false,
      masterDisabled: false,
      hasSignerList: false,
    });
  });

  it('throws on any other rippled error', async () => {
    const client = fakeClient({ result: { error: 'lgrNotFound', status: 'error' } });
    await expect(resolveAccount(GENESIS, client)).rejects.toThrow(
      'account_info failed: lgrNotFound',
    );
  });

  it('throws when the response has no account_data', async () => {
    await expect(resolveAccount(GENESIS, fakeClient({ result: {} }))).rejects.toThrow(
      'account_info failed',
    );
    await expect(resolveAccount(GENESIS, fakeClient('nope'))).rejects.toThrow(
      'account_info failed',
    );
  });

  it('normalises an X-address to its classic form before the lookup', async () => {
    const client = fakeClient(accountInfo({}));
    const state = await resolveAccount(GENESIS_X_TAG_12345, client);
    expect(client.calls[0]?.params.account).toBe(GENESIS);
    expect(state.address).toBe(GENESIS);
  });

  it('throws MalformedInputError on a bad address without calling the client', async () => {
    const client = fakeClient(accountInfo({}));
    await expect(resolveAccount('not-an-address', client)).rejects.toBeInstanceOf(
      MalformedInputError,
    );
    await expect(resolveAccount('', client)).rejects.toBeInstanceOf(MalformedInputError);
    expect(client.calls).toEqual([]);
  });
});

describe('jsonRpcClient', () => {
  it('POSTs a JSON-RPC body and returns the parsed JSON', async () => {
    const seen: { url: string; init: RequestInit }[] = [];
    const fetchImpl: typeof fetch = (input, init) => {
      seen.push({ url: String(input), init: init ?? {} });
      return Promise.resolve(new Response(JSON.stringify({ result: { ok: 1 } }), { status: 200 }));
    };
    const client = jsonRpcClient('https://rpc.example/', fetchImpl);
    const out = await client.request('account_info', { account: GENESIS, signer_lists: true });

    expect(out).toEqual({ result: { ok: 1 } });
    expect(seen).toHaveLength(1);
    expect(seen[0]?.url).toBe('https://rpc.example/');
    expect(seen[0]?.init.method).toBe('POST');
    expect(seen[0]?.init.headers).toEqual({ 'content-type': 'application/json' });
    expect(JSON.parse(String(seen[0]?.init.body))).toEqual({
      method: 'account_info',
      params: [{ account: GENESIS, signer_lists: true }],
    });
  });

  it('throws on a non-2xx status', async () => {
    const fetchImpl: typeof fetch = () => Promise.resolve(new Response('busy', { status: 503 }));
    const client = jsonRpcClient('https://rpc.example/', fetchImpl);
    await expect(client.request('account_info', {})).rejects.toThrow(
      'account_info failed: HTTP 503',
    );
  });

  it('works end to end with resolveAccount', async () => {
    const fetchImpl: typeof fetch = () =>
      Promise.resolve(
        new Response(JSON.stringify(accountInfo({ RegularKey: REGULAR })), { status: 200 }),
      );
    const state = await resolveAccount(GENESIS, jsonRpcClient('https://rpc.example/', fetchImpl));
    expect(state.regularKey).toBe(REGULAR);
  });
});
