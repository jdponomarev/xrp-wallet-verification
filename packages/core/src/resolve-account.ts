import { normalizeAddress } from './address.js';
import type { AccountState, RpcClient } from './types.js';

/** `lsfDisableMaster` in `AccountRoot.Flags`. */
const LSF_DISABLE_MASTER = 0x00100000;

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Accepts the `{ result }` envelope of xrpl.js and JSON-RPC, or an adapter that already unwrapped it. */
function unwrapResult(response: unknown): Json {
  if (!isRecord(response)) throw new Error('account_info failed: response is not an object');
  if ('result' in response) {
    if (!isRecord(response.result)) throw new Error('account_info failed: result is not an object');
    return response.result;
  }
  return response;
}

/**
 * Fetch the ledger state a verifier needs for `address`: existence, RegularKey, whether the master
 * key is disabled and whether a SignerList is set. Reads the latest validated ledger.
 *
 * Throws MalformedInputError on an address that is neither classic nor X-address, and Error when
 * `account_info` returns any error other than `actNotFound`.
 */
export async function resolveAccount(address: string, client: RpcClient): Promise<AccountState> {
  const { classic } = normalizeAddress(address);
  const response = await client.request('account_info', {
    account: classic,
    ledger_index: 'validated',
    signer_lists: true,
  });
  const result = unwrapResult(response);

  if (result.error === 'actNotFound') {
    return { address: classic, exists: false, masterDisabled: false, hasSignerList: false };
  }
  if (result.error !== undefined) {
    throw new Error(`account_info failed: ${String(result.error)}`);
  }
  const data = result.account_data;
  if (!isRecord(data)) throw new Error('account_info failed: response has no account_data');

  if (typeof data.Flags !== 'number') {
    throw new Error('account_info failed: account_data.Flags missing');
  }
  const flags = data.Flags;
  const signerLists = data.signer_lists ?? result.signer_lists;
  const ledgerIndex = result.ledger_index ?? result.ledger_current_index;

  const state: AccountState = {
    address: classic,
    exists: true,
    masterDisabled: (flags & LSF_DISABLE_MASTER) !== 0,
    hasSignerList: Array.isArray(signerLists) && signerLists.length > 0,
  };
  if (typeof data.RegularKey === 'string') state.regularKey = data.RegularKey;
  if (typeof ledgerIndex === 'number') state.ledgerIndex = ledgerIndex;
  return state;
}

/**
 * Minimal JSON-RPC adapter over `fetch` for a rippled or Clio HTTP endpoint. This is the only code
 * in the library that touches the network; it exists for {@link resolveAccount} and nothing else.
 */
export function jsonRpcClient(url: string, fetchImpl: typeof fetch = globalThis.fetch): RpcClient {
  return {
    async request(method, params) {
      const res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method, params: [params] }),
      });
      if (!res.ok) throw new Error(`${method} failed: HTTP ${res.status}`);
      return (await res.json()) as unknown;
    },
  };
}
