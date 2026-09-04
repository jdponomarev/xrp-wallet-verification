import { describe, expect, it } from 'vitest';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { classicAddressToXAddress } from 'ripple-address-codec';
import { decode, encode, encodeForSigning } from 'ripple-binary-codec';
import { deriveKeypair, generateSeed, sign } from 'ripple-keypairs';
import { verifySignature } from 'verify-xrpl-signature';
import { deriveAddress } from '../src/address.js';
import { SIGNIN_TRANSACTION_TYPE, signInDefinitions } from '../src/definitions.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../src/hex.js';
import { verifySignInBlob } from '../src/signin.js';
import type { AccountState, DecodedMemo, DecodedTx } from '../src/types.js';

const CHALLENGE = 'xrp-wallet-verification challenge 12345';

interface TestSigner {
  publicKey: string;
  privateKey: string;
  address: string;
}

function keypair(algorithm: 'ecdsa-secp256k1' | 'ed25519', fill: number): TestSigner {
  const seed = generateSeed({ algorithm, entropy: new Uint8Array(16).fill(fill) });
  const { publicKey, privateKey } = deriveKeypair(seed);
  return { publicKey, privateKey, address: deriveAddress(publicKey) };
}

const secp = keypair('ecdsa-secp256k1', 9);
const ed = keypair('ed25519', 7);
const other = keypair('ecdsa-secp256k1', 3);

const hexOf = (text: string) => bytesToHex(utf8ToBytes(text));
const memo = (data: string) => ({ Memo: { MemoData: hexOf(data) } });

function signInTx(signer: TestSigner, fields: DecodedTx = {}): DecodedTx {
  return {
    TransactionType: 'SignIn',
    Account: signer.address,
    SigningPubKey: signer.publicKey,
    Memos: [memo(CHALLENGE)],
    ...fields,
  };
}

function signBlob(tx: DecodedTx, privateKey: string): string {
  const defs = signInDefinitions();
  const TxnSignature = sign(encodeForSigning(tx, defs), privateKey);
  return encode({ ...tx, TxnSignature }, defs);
}

const decodeBlob = (blob: string): DecodedTx => decode(blob, signInDefinitions());
const reencode = (tx: DecodedTx): string => encode(tx, signInDefinitions());

function withSignature(blob: string, txnSignatureHex: string): string {
  return reencode({ ...decodeBlob(blob), TxnSignature: txnSignatureHex });
}

function highSVariant(blob: string): string {
  const tx = decodeBlob(blob);
  const sig = secp256k1.Signature.fromBytes(hexToBytes(tx.TxnSignature as string), 'der');
  const flipped = new secp256k1.Signature(sig.r, secp256k1.Point.Fn.ORDER - sig.s);
  return withSignature(blob, bytesToHex(flipped.toBytes('der')));
}

function state(address: string, over: Partial<AccountState> = {}): AccountState {
  return { address, exists: true, masterDisabled: false, hasSignerList: false, ...over };
}

/** verify-xrpl-signature is the equivalence oracle (FINDINGS F-2.4). */
function crossCheck(blob: string) {
  const ours = verifySignInBlob(blob);
  const theirs = verifySignature(blob);
  expect(theirs.signatureValid).toBe(ours.valid);
  expect(theirs.signedBy).toBe(ours.derivedAddress);
  expect(theirs.signatureMultiSign).toBe(false);
  return ours;
}

// Real XRPL Labs blobs from verify-xrpl-signature/test/fixtures.json. None is a SignIn.
const FIXTURES = {
  // Single-signed pseudo-transaction without a TransactionType.
  valid: {
    blob: '2280000000240000000268400000000000000C73210333C718C9CB716E0575454F4A343D46B284ED51151B9C7383524B82C10B262095744730450221009A4D99017F8FD6881D888047E2F9F90C068C09EC9308BC8526116B539D6DD44102207FAA7E8756F67FE7EE1A88884F120A00A8EC37E7D3E5ED3E02FEA7B1D97AA05581146C0994D3FCB140CAB36BAE9465137448883FA487',
    account: 'rwiETSee2wMz3SBnAG8hkMsCgvGy9LWbZ1',
  },
  // Payment with a memo.
  memoetc:
    '120000230098C1822405062D212E00000309201B05076FDA6140000000002DC6C068400000000000000F7321037AE7410E85C615B703D3484D5674F73936E968B671E7790C79B82EA582D8333D744630440220704D644BF883CE7484C2CE7DCF8D54E6BF4163DCCB22C8513CC84771BCC3CF0302203A8F67BB473114E6731FCC7124784EAA84C87D249109C6D313F770E0AEDF856E81143EFF5DB71D74ED511141CBB078E067D2009953ED8314842BDB20FD28150302B81618B77B1DB190B61D57F9EA7D1B4A4A57524E554E45435748504D55424F534A5651505145415F3437E1F1',
  // Multi-signed Payment.
  multisign:
    '1200002400000003201B00503A406140000000000000016840000000000000677300811461D46A8DE4DAE4F72196C87995D9390BA82BA9F18314F84E8A80D08854F3621F9214D58F04D41A07EE10F3E01073210217241703CBC4D52C04D59269DE634B388E57C1E72F9462EEF4B435E041ED88367446304402204789F8AA9625D65FD65F43A7AC9FBFAEF64026A4BD1421B0F87ADE24B15F477302207241FDC7B31E15FDB121CA64623B6AC84475A30992E092F56656A731743B9FF781146B07151AAEC3405E3D83CEE654456B621EBF0007E1F1F9EA7C08536F6D65547970657D08536F6D6544617461E1EA7C09446576656C6F7065727D0B4057696574736557696E64E1F1',
  // Multi-signed NFTokenMint.
  xls20:
    '120019141770220000000824047E70A8201B0480EDCA202A00000032684000000000000C807300811472631AFCCECFF285A11CDC6159CE3E5AB34920B9F3E0107321EDFC78FE5C5F474985678DD821FCDD7F65F2F7CC5029E3D0BEB46C9B0D90C622FF7440EFF305AF335C59180B81E5A0FC860F1F3CF5B2242269B9A8C61534A87F08E50DFF77B9D2487FA80D97290E0808BE220CCF8A7F6026B7FDE2D1C64B2A4AE2AB0F8114112DE2804BD473EB8A77E01E1C43A9CDC79A6EBFE1F1',
  // Undecodable.
  invalid:
    '12000022800000002400000003614000000002F0000000000000C8730081146C1D22888CF2CC88579D71FE0BE6890FE2268BF38314F84E8A80D08854F3621F9214D58F04D41A07EE10F3E010732103858452B639D34041FAC9C6CA4F46A5DF5528C2E9BBBBD750EB4FEAB2AE8B2E22744630440220333BC823D9F3F048FD01BA6CEE41187928FDE59E358F4A65AE5054C9446E8D5D022043C9CA3C2C70589628E2B7E88C0827E67B1CE8D6850854541D447449715107A08114F4A5239106E24D5E4ABBC82AD870AB2D22B7E082E1F1F9EA7C08536F6D65547970657D08536F6D6544617461E1EA7C09446576656C6F7065727D0B4057696574736557696E64E1F1',
  // Xahau ClaimReward: TransactionType unknown to mainnet definitions.
  validhook:
    '120062210000535A2200000000240013948A201B00200F366840000000000007D07321030FF7159D7474E352231C119CB23CEA8E78A41DCB8DDC1554356BF9ED9766710E744630440220574E1AC9FEA83E37857C9CDCA38D99EDD60AAAD499B6D21F537FB91C641F3360022039DC8173E861195BE794A4321038F046F932F188823197DCEC5CBF9374D4E3F281144E59DE4FE68A3BF3D729FD2AFB61F109DF5BC99E8414B5F762798A53D543A014CAF8B297CFF8F2F937E8',
};

describe('signInDefinitions', () => {
  it('adds SignIn = 999 without touching the codec defaults', async () => {
    const { DEFAULT_DEFINITIONS } = await import('ripple-binary-codec');
    expect(SIGNIN_TRANSACTION_TYPE).toBe(999);
    const signIn = signInDefinitions().transactionType.from('SignIn');
    expect(signIn.name).toBe('SignIn');
    expect(signIn.ordinal).toBe(999);
    expect(DEFAULT_DEFINITIONS.transactionType.from('SignIn')).toBeUndefined();
    expect(() => encode({ TransactionType: 'SignIn', Account: secp.address })).toThrow();
  });

  it('is a singleton', () => {
    expect(signInDefinitions()).toBe(signInDefinitions());
  });
});

describe('verifySignInBlob', () => {
  describe.each([
    ['secp256k1', secp],
    ['ed25519', ed],
  ] as const)('%s', (algorithm, signer) => {
    const blob = signBlob(signInTx(signer), signer.privateKey);

    it('encodes TransactionType 999 first', () => {
      expect(blob.startsWith('1203E7')).toBe(true);
    });

    it('accepts a freshly signed SignIn with a memo', () => {
      const r = crossCheck(blob);
      expect(r).toMatchObject({
        valid: true,
        algorithm,
        derivedAddress: signer.address,
        signer: 'master',
      });
      expect(r.reason).toBeUndefined();
      expect(r.tx.TransactionType).toBe('SignIn');
      expect(r.tx.Account).toBe(signer.address);
      expect(r.memos).toEqual([{ dataHex: hexOf(CHALLENGE), data: CHALLENGE }]);
      expect(r.details).toMatchObject({ transactionType: 'SignIn', account: signer.address });
    });

    it('accepts a SignIn without memos', () => {
      const tx: DecodedTx = {
        TransactionType: 'SignIn',
        Account: signer.address,
        SigningPubKey: signer.publicKey,
      };
      const r = crossCheck(signBlob(tx, signer.privateKey));
      expect(r.valid).toBe(true);
      expect(r.memos).toEqual([]);
    });

    it('accepts lowercase hex', () => {
      expect(verifySignInBlob(blob.toLowerCase()).valid).toBe(true);
    });

    it('rejects a tampered memo: bad_signature', () => {
      const tx = decodeBlob(blob);
      tx.Memos = [memo('tampered')];
      const r = crossCheck(reencode(tx));
      expect(r).toMatchObject({
        valid: false,
        reason: 'bad_signature',
        algorithm,
        derivedAddress: signer.address,
        signer: 'unknown',
      });
      expect(r.memos[0]?.data).toBe('tampered');
    });

    it('rejects a swapped Account under the old signature: bad_signature', () => {
      const r = crossCheck(reencode({ ...decodeBlob(blob), Account: other.address }));
      expect(r).toMatchObject({ valid: false, reason: 'bad_signature' });
    });

    it('rejects Account != signer even with a valid signature: address_mismatch', () => {
      const fresh = signBlob(signInTx(signer, { Account: other.address }), signer.privateKey);
      const r = verifySignInBlob(fresh);
      expect(r).toMatchObject({
        valid: false,
        reason: 'address_mismatch',
        derivedAddress: signer.address,
        signer: 'unknown',
      });
      // F-2.1: the oracle only checks the signature, never the Account binding.
      expect(verifySignature(fresh)).toMatchObject({
        signatureValid: true,
        signedBy: signer.address,
      });
    });

    it('accepts the RegularKey signer when the account state names it', () => {
      const fresh = signBlob(signInTx(signer, { Account: other.address }), signer.privateKey);
      const r = verifySignInBlob(fresh, {
        account: state(other.address, { regularKey: signer.address }),
      });
      expect(r).toMatchObject({ valid: true, signer: 'regular', derivedAddress: signer.address });
    });

    it('rejects a wrong-length signature: malformed_input', () => {
      const sigHex = decodeBlob(blob).TxnSignature as string;
      const r = verifySignInBlob(withSignature(blob, sigHex.slice(0, -2)));
      expect(r).toMatchObject({ valid: false, reason: 'malformed_input' });
    });
  });

  describe('expected memo', () => {
    const blob = signBlob(signInTx(secp), secp.privateKey);

    it('matches a memo by text', () => {
      expect(verifySignInBlob(blob, { expectedMemo: CHALLENGE }).valid).toBe(true);
    });

    it('rejects a missing text: challenge_mismatch', () => {
      const r = verifySignInBlob(blob, { expectedMemo: 'another challenge' });
      expect(r).toMatchObject({ valid: false, reason: 'challenge_mismatch', signer: 'master' });
    });

    it('calls a predicate with the decoded memos', () => {
      let seen: DecodedMemo[] | undefined;
      const r = verifySignInBlob(blob, {
        expectedMemo: (memos) => {
          seen = memos;
          return memos.some((m) => m.data?.endsWith('12345') ?? false);
        },
      });
      expect(r.valid).toBe(true);
      expect(seen).toEqual([{ dataHex: hexOf(CHALLENGE), data: CHALLENGE }]);
    });

    it('rejects when the predicate is false or not exactly true', () => {
      expect(verifySignInBlob(blob, { expectedMemo: () => false }).reason).toBe(
        'challenge_mismatch',
      );
      const truthy = (() => 'yes') as unknown as (memos: DecodedMemo[]) => boolean;
      expect(verifySignInBlob(blob, { expectedMemo: truthy }).reason).toBe('challenge_mismatch');
    });

    it('rejects an expected memo when the blob has none', () => {
      const tx: DecodedTx = {
        TransactionType: 'SignIn',
        Account: secp.address,
        SigningPubKey: secp.publicKey,
      };
      const r = verifySignInBlob(signBlob(tx, secp.privateKey), { expectedMemo: CHALLENGE });
      expect(r.reason).toBe('challenge_mismatch');
    });

    it('decodes type, format and data; keeps non-UTF-8 data as hex only', () => {
      const tx = signInTx(secp, {
        Memos: [
          {
            Memo: {
              MemoType: hexOf('xrp-wallet-verification'),
              MemoFormat: hexOf('text/plain'),
              MemoData: 'FFFE',
            },
          },
          memo(CHALLENGE),
        ],
      });
      const r = verifySignInBlob(signBlob(tx, secp.privateKey), { expectedMemo: CHALLENGE });
      expect(r.valid).toBe(true);
      expect(r.memos).toEqual([
        {
          typeHex: hexOf('xrp-wallet-verification'),
          type: 'xrp-wallet-verification',
          formatHex: hexOf('text/plain'),
          format: 'text/plain',
          dataHex: 'FFFE',
        },
        { dataHex: hexOf(CHALLENGE), data: CHALLENGE },
      ]);
      expect(r.memos[0]).not.toHaveProperty('data');
    });
  });

  describe('expected account', () => {
    const blob = signBlob(signInTx(ed), ed.privateKey);

    it('accepts the matching classic address', () => {
      expect(verifySignInBlob(blob, { expectedAccount: ed.address }).valid).toBe(true);
    });

    it('accepts the matching X-address', () => {
      const x = classicAddressToXAddress(ed.address, 7, false);
      expect(verifySignInBlob(blob, { expectedAccount: x }).valid).toBe(true);
    });

    it('rejects a different account: address_mismatch', () => {
      const r = verifySignInBlob(blob, { expectedAccount: other.address });
      expect(r).toMatchObject({ valid: false, reason: 'address_mismatch', signer: 'master' });
      expect(r.details).toMatchObject({ expectedAccount: other.address });
    });

    it('rejects an unparseable expected account: malformed_input', () => {
      const r = verifySignInBlob(blob, { expectedAccount: 'not-an-address' });
      expect(r).toMatchObject({ valid: false, reason: 'malformed_input' });
    });
  });

  describe('transaction type', () => {
    it('rejects a real Payment: unexpected_transaction_type', () => {
      const r = verifySignInBlob(FIXTURES.memoetc);
      expect(r).toMatchObject({ valid: false, reason: 'unexpected_transaction_type' });
      expect(r.details).toMatchObject({ transactionType: 'Payment' });
      expect(r.tx.TransactionType).toBe('Payment');
    });

    it('rejects a SignIn carrying Destination or Amount', () => {
      const withDest = signBlob(signInTx(secp, { Destination: other.address }), secp.privateKey);
      expect(verifySignInBlob(withDest).reason).toBe('unexpected_transaction_type');
      const withAmount = signBlob(signInTx(secp, { Amount: '1000000' }), secp.privateKey);
      expect(verifySignInBlob(withAmount).reason).toBe('unexpected_transaction_type');
    });

    it('rejects a TransactionType-less blob by default', () => {
      const r = verifySignInBlob(FIXTURES.valid.blob);
      expect(r).toMatchObject({ valid: false, reason: 'unexpected_transaction_type' });
      expect(r.details?.transactionType).toBeUndefined();
      expect(r.tx.Account).toBe(FIXTURES.valid.account);
    });

    it('accepts a TransactionType-less blob with allowMissingTransactionType', () => {
      const r = verifySignInBlob(FIXTURES.valid.blob, { allowMissingTransactionType: true });
      expect(r).toMatchObject({
        valid: true,
        algorithm: 'secp256k1',
        derivedAddress: FIXTURES.valid.account,
        signer: 'master',
      });
      expect(verifySignature(FIXTURES.valid.blob)).toMatchObject({
        signatureValid: true,
        signedBy: FIXTURES.valid.account,
      });
    });

    it('still rejects a TransactionType-less Payment-shaped blob', () => {
      const tx = decodeBlob(FIXTURES.valid.blob);
      const r = verifySignInBlob(reencode({ ...tx, Destination: other.address }), {
        allowMissingTransactionType: true,
      });
      expect(r.reason).toBe('unexpected_transaction_type');
    });
  });

  describe('multisig', () => {
    it.each([
      ['multisign', FIXTURES.multisign],
      ['xls20', FIXTURES.xls20],
    ])('rejects the %s fixture: unsupported_multisig', (_name, blob) => {
      const r = verifySignInBlob(blob);
      expect(r).toMatchObject({ valid: false, reason: 'unsupported_multisig', signer: 'unknown' });
      expect(r.algorithm).toBeUndefined();
      expect(r.derivedAddress).toBeUndefined();
    });

    it('rejects an empty SigningPubKey on a SignIn', () => {
      const blob = reencode({
        TransactionType: 'SignIn',
        Account: secp.address,
        SigningPubKey: '',
      });
      expect(verifySignInBlob(blob).reason).toBe('unsupported_multisig');
    });
  });

  describe('malformed input', () => {
    it.each([
      ['undecodable fixture', FIXTURES.invalid],
      ['unknown transaction type', FIXTURES.validhook],
      ['random hex', 'DEADBEEFDEADBEEF'],
      ['odd length', '1203E7'.slice(0, 5)],
      ['non-hex', '1203E7zz'],
      ['empty', ''],
    ])('%s: malformed_input', (_name, blob) => {
      const r = verifySignInBlob(blob);
      expect(r).toMatchObject({ valid: false, reason: 'malformed_input', signer: 'unknown' });
      expect(r.memos).toEqual([]);
      expect(typeof r.details?.error).toBe('string');
    });

    it('rejects a SignIn without SigningPubKey', () => {
      const blob = reencode({
        TransactionType: 'SignIn',
        Account: secp.address,
        TxnSignature: '00',
      });
      expect(verifySignInBlob(blob).reason).toBe('malformed_input');
    });

    it('rejects a SignIn without Account', () => {
      const blob = reencode({ TransactionType: 'SignIn', SigningPubKey: secp.publicKey });
      expect(verifySignInBlob(blob).reason).toBe('malformed_input');
    });

    it('rejects an off-curve SigningPubKey', () => {
      const tx = signInTx(secp, { SigningPubKey: '02' + '00'.repeat(31) + '05' });
      expect(verifySignInBlob(reencode({ ...tx, TxnSignature: '3006020101020101' })).reason).toBe(
        'malformed_input',
      );
    });

    it('rejects a signature in the other algorithm format: algorithm_mismatch', () => {
      const secpBlob = signBlob(signInTx(secp), secp.privateKey);
      const edBlob = signBlob(signInTx(ed), ed.privateKey);
      const derSig = decodeBlob(secpBlob).TxnSignature as string;
      const rawSig = decodeBlob(edBlob).TxnSignature as string;
      expect(verifySignInBlob(withSignature(edBlob, derSig)).reason).toBe('algorithm_mismatch');
      expect(verifySignInBlob(withSignature(secpBlob, rawSig)).reason).toBe('algorithm_mismatch');
    });

    it('never throws', () => {
      for (const input of [undefined, null, 42, {}, 'zz', '1203E7']) {
        expect(() => verifySignInBlob(input as unknown as string)).not.toThrow();
        expect(verifySignInBlob(input as unknown as string).valid).toBe(false);
      }
    });
  });

  describe('low-S policy', () => {
    const blob = signBlob(signInTx(secp), secp.privateKey);
    const highS = highSVariant(blob);

    it('rejects a high-S signature: non_canonical_signature', () => {
      const r = verifySignInBlob(highS);
      expect(r).toMatchObject({
        valid: false,
        reason: 'non_canonical_signature',
        derivedAddress: secp.address,
      });
      // The oracle's nested ripple-keypairs 1.3.1 (elliptic) does not enforce low-S; F-1.4 only
      // holds for ripple-keypairs 3. Equivalence with the oracle therefore excludes this vector.
      expect(verifySignature(highS)).toMatchObject({
        signatureValid: true,
        signedBy: secp.address,
      });
    });

    it('accepts it only when requireLowS is false', () => {
      expect(verifySignInBlob(highS, { policy: { requireLowS: false } }).valid).toBe(true);
      expect(verifySignInBlob(blob, { policy: { requireLowS: false } }).valid).toBe(true);
    });
  });

  describe('account policy', () => {
    const blob = signBlob(signInTx(secp), secp.privateKey);

    it('passes with a plain existing account', () => {
      const r = verifySignInBlob(blob, { account: state(secp.address) });
      expect(r).toMatchObject({ valid: true, signer: 'master' });
    });

    it('rejects a disabled master key by default: master_disabled', () => {
      const r = verifySignInBlob(blob, { account: state(secp.address, { masterDisabled: true }) });
      expect(r).toMatchObject({ valid: false, reason: 'master_disabled', signer: 'master' });
    });

    it('accepts a disabled master key with allowMasterDisabled', () => {
      const r = verifySignInBlob(blob, {
        account: state(secp.address, { masterDisabled: true }),
        policy: { allowMasterDisabled: true },
      });
      expect(r.valid).toBe(true);
    });

    it('does not apply master_disabled to a RegularKey signer', () => {
      const fresh = signBlob(signInTx(ed, { Account: other.address }), ed.privateKey);
      const r = verifySignInBlob(fresh, {
        account: state(other.address, { masterDisabled: true, regularKey: ed.address }),
      });
      expect(r).toMatchObject({ valid: true, signer: 'regular' });
    });

    it('rejects a missing account: account_not_found', () => {
      const r = verifySignInBlob(blob, { account: state(secp.address, { exists: false }) });
      expect(r).toMatchObject({ valid: false, reason: 'account_not_found' });
    });

    it('rejects an account with a SignerList: unsupported_multisig', () => {
      const r = verifySignInBlob(blob, { account: state(secp.address, { hasSignerList: true }) });
      expect(r).toMatchObject({ valid: false, reason: 'unsupported_multisig' });
    });

    it('rejects an account state for a different address: address_mismatch', () => {
      const r = verifySignInBlob(blob, { account: state(other.address) });
      expect(r).toMatchObject({ valid: false, reason: 'address_mismatch' });
    });

    it('ignores a RegularKey that does not match the signer', () => {
      const fresh = signBlob(signInTx(secp, { Account: other.address }), secp.privateKey);
      const r = verifySignInBlob(fresh, {
        account: state(other.address, { regularKey: ed.address }),
      });
      expect(r).toMatchObject({ valid: false, reason: 'address_mismatch' });
    });
  });
});
