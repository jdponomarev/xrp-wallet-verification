import type { AccountState, RpcClient } from './types.js';

export async function resolveAccount(_address: string, _client: RpcClient): Promise<AccountState> {
  throw new Error('not implemented');
}
