import { XrplDefinitions } from 'ripple-binary-codec';
import definitionsJson from 'ripple-binary-codec/dist/enums/definitions.json' with { type: 'json' };

/** TransactionType ordinal Xaman uses for SignIn pseudo-transactions. Not in rippled. */
export const SIGNIN_TRANSACTION_TYPE = 999;

let cached: XrplDefinitions | undefined;

/** Mainnet definitions plus `TransactionType: SignIn = 999`. Built once, on first use. */
export function signInDefinitions(): XrplDefinitions {
  if (!cached) {
    const json = structuredClone(definitionsJson);
    const transactionTypes: Record<string, number> = json.TRANSACTION_TYPES;
    transactionTypes.SignIn = SIGNIN_TRANSACTION_TYPE;
    cached = new XrplDefinitions(json);
  }
  return cached;
}
