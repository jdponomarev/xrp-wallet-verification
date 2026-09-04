// Deterministic fixture generator: fixed seeds, no clock, no randomness. Uses only the reference
// libraries (ripple-keypairs, ripple-binary-codec, ripple-address-codec, @noble/*) so the vectors
// are independent of the library under test. Run from the repo root with `pnpm gen-fixtures`.
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { classicAddressToXAddress } from 'ripple-address-codec';
import { XrplDefinitions, decode, encode, encodeForSigning } from 'ripple-binary-codec';
import definitionsJson from 'ripple-binary-codec/dist/enums/definitions.json' with { type: 'json' };
import { deriveAddress, deriveKeypair, generateSeed, sign } from 'ripple-keypairs';
import type { AccountState, Algorithm, Policy, Reason, Signer } from '../src/types.js';

type Encoding = 'utf8' | 'hex';

interface Expect {
  valid: boolean;
  reason: Reason | null;
  signer: Signer;
  derivedAddress?: string;
}

interface SignInOptions {
  expectedAccount?: string;
  expectedMemo?: string;
  allowMissingTransactionType?: boolean;
}

interface Vector {
  id: string;
  source: string;
  kind: 'message' | 'signin';
  algorithm: Algorithm | null;
  encoding: Encoding;
  message?: string;
  messageHex?: string;
  publicKey?: string;
  signature?: string;
  address?: string;
  blobHex?: string;
  options?: SignInOptions;
  account?: AccountState;
  policy?: Policy;
  expect: Expect;
  notes: string;
}

interface Key {
  algorithm: Algorithm;
  publicKey: string;
  privateKey: string;
  address: string;
}

const RK_ALGORITHM = { secp256k1: 'ecdsa-secp256k1', ed25519: 'ed25519' } as const;

const hex = (bytes: Uint8Array): string => bytesToHex(bytes).toUpperCase();
const utf8Hex = (text: string): string => hex(new TextEncoder().encode(text));
const byte = (bytes: Uint8Array, i: number): number => bytes[i] as number;

function keyFromSeed(seed: string): Key {
  const { publicKey, privateKey } = deriveKeypair(seed);
  const algorithm: Algorithm = publicKey.startsWith('ED') ? 'ed25519' : 'secp256k1';
  return { algorithm, publicKey, privateKey, address: deriveAddress(publicKey) };
}

function seedFromEntropy(fill: number, algorithm: Algorithm): string {
  return generateSeed({
    entropy: new Uint8Array(16).fill(fill),
    algorithm: RK_ALGORITHM[algorithm],
  });
}

// FINDINGS §6 seeds.
const SECP = keyFromSeed('sp5fV4UGhZhfCvcDRuY3dyyh5PjHf');
const ED = keyFromSeed('sEdSKuYwxeL4JM1LBJcGmpLw9fbF8JN');
const GEM_SECP = keyFromSeed('sn3nxiW7v8KXzPzAqzyHXbSSKNuN9');
const GEM_ED = keyFromSeed('sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r');
const SIGNIN_SECP = keyFromSeed(seedFromEntropy(9, 'secp256k1'));
const SIGNIN_ED = keyFromSeed(seedFromEntropy(7, 'ed25519'));
// A third account that never signs anything: used as "some other address".
const OTHER = keyFromSeed(seedFromEntropy(3, 'secp256k1'));

const ASCII = 'Hello, XRPL! nonce=1234';
const MEMO_TYPE = 'xrpl-message-verify/challenge/v1';

/** Hand-written v1 envelope (SIWE shape). verifyMessage treats it as opaque bytes. */
function envelope(address: string): string {
  return [
    'example.com wants you to prove control of XRP Ledger account:',
    address,
    '',
    'Sign in to example.com',
    '',
    'URI: https://example.com/login',
    'Version: 1',
    'Network: testnet',
    'Nonce: 0123456789abcdef0123456789abcdef',
    'Issued At: 2026-09-04T00:00:00Z',
    'Expiration Time: 2026-09-04T00:10:00Z',
    'Request ID: 7c9e6679-7425-40de-944b-e07fc1f90ae7',
  ].join('\n');
}

function flipByte(hexString: string, index: number): string {
  const bytes = hexToBytes(hexString);
  bytes[index] = byte(bytes, index) ^ 0x01;
  return hex(bytes);
}

/** Index of the byte to tamper: last byte of s for DER, a low-order byte of S for ed25519. */
function tamperIndex(algorithm: Algorithm, signatureHex: string): number {
  return algorithm === 'secp256k1' ? signatureHex.length / 2 - 1 : 40;
}

function highS(derHex: string): string {
  const sig = secp256k1.Signature.fromBytes(hexToBytes(derHex), 'der');
  const flipped = new secp256k1.Signature(sig.r, secp256k1.Point.Fn.ORDER - sig.s);
  return hex(flipped.toBytes('der'));
}

/** Same r and s, but r carries a redundant leading 0x00 (valid BER, invalid DER). */
function nonMinimalDer(derHex: string): string {
  const der = hexToBytes(derHex);
  const out = new Uint8Array(der.length + 1);
  out[0] = 0x30;
  out[1] = byte(der, 1) + 1;
  out[2] = 0x02;
  out[3] = byte(der, 3) + 1;
  out[4] = 0x00;
  out.set(der.slice(4), 5);
  return hex(out);
}

function accountState(address: string, patch: Partial<AccountState> = {}): AccountState {
  return { address, exists: true, masterDisabled: false, hasSignerList: false, ...patch };
}

const ok = (derivedAddress: string, signer: Signer = 'master'): Expect => ({
  valid: true,
  reason: null,
  signer,
  derivedAddress,
});
/** `signer` is set when the key was bound to the account before the check that failed. */
const fail = (reason: Reason, derivedAddress?: string, signer: Signer = 'unknown'): Expect =>
  derivedAddress === undefined
    ? { valid: false, reason, signer }
    : { valid: false, reason, signer, derivedAddress };

interface MessageSpec {
  id: string;
  key: Key;
  message?: string;
  messageHex?: string;
  encoding?: Encoding;
  publicKey?: string;
  signature?: string;
  address?: string;
  omitAddress?: boolean;
  omitMessageHex?: boolean;
  algorithm?: Algorithm | null;
  account?: AccountState;
  policy?: Policy;
  expect: Expect;
  notes: string;
}

function messageVector(spec: MessageSpec): Vector {
  const encoding = spec.encoding ?? 'utf8';
  const messageHex = spec.messageHex ?? utf8Hex(spec.message ?? '');
  return {
    id: spec.id,
    source: 'generated',
    kind: 'message',
    algorithm: spec.algorithm === undefined ? spec.key.algorithm : spec.algorithm,
    encoding,
    ...(encoding === 'utf8' && spec.message !== undefined ? { message: spec.message } : {}),
    ...(spec.omitMessageHex ? {} : { messageHex }),
    publicKey: spec.publicKey ?? spec.key.publicKey,
    signature: spec.signature ?? sign(messageHex, spec.key.privateKey),
    ...(spec.omitAddress ? {} : { address: spec.address ?? spec.key.address }),
    ...(spec.account ? { account: spec.account } : {}),
    ...(spec.policy ? { policy: spec.policy } : {}),
    expect: spec.expect,
    notes: spec.notes,
  };
}

function messageVectorsFor(key: Key): Vector[] {
  const alg = key.algorithm;
  const id = (name: string): string => `message-${alg}-${name}`;
  const asciiHex = utf8Hex(ASCII);
  const asciiSig = sign(asciiHex, key.privateKey);
  const otherKey = key === SECP ? ED : SECP;
  const crossSig = sign(asciiHex, otherKey.privateKey);
  const gemKey = alg === 'secp256k1' ? GEM_SECP : GEM_ED;

  const vectors: Vector[] = [
    messageVector({
      id: id('empty'),
      key,
      message: '',
      expect: fail('malformed_input'),
      notes: 'Empty message. ripple-keypairs signs it happily; the verifier must refuse it.',
    }),
    messageVector({
      id: id('one-byte'),
      key,
      message: 'a',
      expect: ok(key.address),
      notes: 'One byte.',
    }),
    messageVector({
      id: id('ascii'),
      key,
      message: ASCII,
      expect: ok(key.address),
      notes: 'Plain ASCII.',
    }),
    messageVector({
      id: id('unicode'),
      key,
      message: 'Zdravo 👋 ünïcödé ✓ 日本語',
      expect: ok(key.address),
      notes: 'Multi-byte UTF-8 including an emoji (surrogate pair in JS).',
    }),
    messageVector({
      id: id('lf'),
      key,
      message: 'Sign in to example.com\nnonce: 0123456789abcdef',
      expect: ok(key.address),
      notes: 'Embedded LF. FINDINGS §6 reference vector.',
    }),
    messageVector({
      id: id('crlf'),
      key,
      message: 'Sign in to example.com\r\nnonce: 0123456789abcdef',
      expect: ok(key.address),
      notes: 'Embedded CRLF; bytes differ from the LF vector so the signatures differ.',
    }),
    messageVector({
      id: id('10kb'),
      key,
      message: '0123456789abcdef'.repeat(640),
      expect: ok(key.address),
      notes: 'Exactly 10240 bytes.',
    }),
    messageVector({
      id: id('65537-bytes'),
      key,
      message: 'a'.repeat(65537),
      omitMessageHex: true,
      expect: fail('message_too_large'),
      notes: 'One byte over the default 65536 limit. Signature is genuine; size alone must reject.',
    }),
    messageVector({
      id: id('envelope'),
      key,
      message: envelope(key.address),
      expect: ok(key.address),
      notes: 'Challenge envelope text (v1 shape, domain example.com) signed as a raw message.',
    }),
    messageVector({
      id: id('hex-encoding'),
      key,
      encoding: 'hex',
      messageHex: asciiHex,
      signature: asciiSig,
      expect: ok(key.address),
      notes: "encoding 'hex': message is supplied as the hex of the signed bytes.",
    }),
    messageVector({
      id: id('lowercase-hex'),
      key,
      encoding: 'hex',
      messageHex: asciiHex.toLowerCase(),
      publicKey: key.publicKey.toLowerCase(),
      signature: asciiSig.toLowerCase(),
      expect: ok(key.address),
      notes: 'All hex inputs lowercase.',
    }),
    messageVector({
      id: id('x-address'),
      key,
      message: ASCII,
      address: classicAddressToXAddress(key.address, false, false),
      expect: ok(key.address),
      notes: 'Address given as a mainnet X-address without tag; derivedAddress stays classic.',
    }),
    messageVector({
      id: id('regular-key'),
      key,
      message: ASCII,
      address: OTHER.address,
      account: accountState(OTHER.address, { regularKey: key.address }),
      expect: ok(key.address, 'regular'),
      notes: 'Account OTHER has this key as its RegularKey; address differs from derivedAddress.',
    }),
    messageVector({
      id: id('master-disabled'),
      key,
      message: ASCII,
      account: accountState(key.address, { masterDisabled: true }),
      expect: fail('master_disabled', key.address, 'master'),
      notes: 'lsfDisableMaster set and no policy override.',
    }),
    messageVector({
      id: id('master-disabled-allowed'),
      key,
      message: ASCII,
      account: accountState(key.address, { masterDisabled: true }),
      policy: { allowMasterDisabled: true },
      expect: ok(key.address),
      notes: 'Same account state, policy.allowMasterDisabled true.',
    }),
    messageVector({
      id: id('signer-list'),
      key,
      message: ASCII,
      account: accountState(key.address, { hasSignerList: true }),
      expect: fail('unsupported_multisig', key.address, 'master'),
      notes: 'Account has a SignerList; single-key proof is refused.',
    }),
    messageVector({
      id: id('account-not-found'),
      key,
      message: ASCII,
      account: accountState(key.address, { exists: false }),
      expect: fail('account_not_found', key.address, 'master'),
      notes: 'account_info reported the account as missing.',
    }),
    messageVector({
      id: id('tampered-message'),
      key,
      message: `${ASCII}.`,
      signature: asciiSig,
      expect: fail('bad_signature'),
      notes: 'Signature over ASCII presented with one extra character.',
    }),
    messageVector({
      id: id('tampered-signature'),
      key,
      message: ASCII,
      signature: flipByte(asciiSig, tamperIndex(alg, asciiSig)),
      expect: fail('bad_signature'),
      notes: 'One bit flipped in the signature; still well-formed.',
    }),
    messageVector({
      id: id('truncated-signature'),
      key,
      message: ASCII,
      signature: asciiSig.slice(0, alg === 'secp256k1' ? 20 : 126),
      expect: fail('malformed_input'),
      notes: 'Signature cut short (10 bytes of DER / 63 bytes for ed25519).',
    }),
    messageVector({
      id: id('cross-algorithm'),
      key,
      message: ASCII,
      signature: crossSig,
      expect: fail('algorithm_mismatch'),
      notes: `Signature produced by the ${otherKey.algorithm} key over the same message.`,
    }),
    messageVector({
      id: id('wrong-address'),
      key,
      message: ASCII,
      address: OTHER.address,
      expect: fail('address_mismatch', key.address),
      notes: 'Address of an unrelated account, no account state.',
    }),
    messageVector({
      id: id('malformed-hex-signature'),
      key,
      message: ASCII,
      signature: `zz${asciiSig.slice(2)}`,
      expect: fail('malformed_input'),
      notes: 'Non-hex characters in the signature.',
    }),
    messageVector({
      id: id('odd-length-hex-message'),
      key,
      encoding: 'hex',
      messageHex: `${asciiHex}A`,
      signature: asciiSig,
      expect: fail('malformed_input'),
      notes: 'Odd-length hex message. ripple-keypairs would silently drop the last nibble.',
    }),
    messageVector({
      id: id('ledger-prefix'),
      key,
      message: ASCII,
      signature: sign(`53545800${asciiHex}`, key.privateKey),
      expect: fail('bad_signature'),
      notes:
        'Signature over STX\\0 + message (transaction-style prefix) must not verify as a raw message.',
    }),
    messageVector({
      id: id('gemwallet-emulated'),
      key: gemKey,
      message: ASCII,
      expect: ok(gemKey.address),
      notes: 'GemWallet signMessage(message) emulation: hex(utf8(message)) signed, no prefix.',
    }),
    messageVector({
      id: id('gemwallet-ishex-as-utf8'),
      key: gemKey,
      message: 'DEADBEEF',
      signature: sign('DEADBEEF', gemKey.privateKey),
      expect: fail('bad_signature'),
      notes:
        'GemWallet signMessage("DEADBEEF", isHex=true) signed the 4 bytes; verifying the text as UTF-8 fails.',
    }),
    messageVector({
      id: id('gemwallet-ishex-as-hex'),
      key: gemKey,
      encoding: 'hex',
      messageHex: 'DEADBEEF',
      signature: sign('DEADBEEF', gemKey.privateKey),
      expect: ok(gemKey.address),
      notes: "Same signature as gemwallet-ishex-as-utf8, verified with encoding 'hex'.",
    }),
  ];

  if (alg === 'secp256k1') {
    const uncompressed = hex(secp256k1.getPublicKey(hexToBytes(key.privateKey.slice(2)), false));
    vectors.push(
      messageVector({
        id: id('high-s'),
        key,
        message: 'Sign in to example.com\nnonce: 0123456789abcdef',
        signature: highS(
          sign(utf8Hex('Sign in to example.com\nnonce: 0123456789abcdef'), key.privateKey),
        ),
        expect: fail('non_canonical_signature'),
        notes: "s' = n - s of the FINDINGS §6 vector. Mathematically valid, must be rejected.",
      }),
      messageVector({
        id: id('non-minimal-der'),
        key,
        message: ASCII,
        signature: nonMinimalDer(asciiSig),
        expect: fail('malformed_input'),
        notes: 'Redundant 0x00 pad on r: BER, not DER.',
      }),
      messageVector({
        id: id('off-curve-pubkey'),
        key,
        message: ASCII,
        publicKey: `02${'00'.repeat(31)}05`,
        omitAddress: true,
        algorithm: null,
        expect: fail('malformed_input'),
        notes: '33-byte key whose x has no square root on secp256k1.',
      }),
      messageVector({
        id: id('uncompressed-pubkey'),
        key,
        message: ASCII,
        publicKey: uncompressed,
        omitAddress: true,
        algorithm: null,
        expect: fail('malformed_input'),
        notes:
          '65-byte 04 key of the same private key. ripple-keypairs derives a bogus address from it.',
      }),
      messageVector({
        id: id('short-pubkey'),
        key,
        message: ASCII,
        publicKey: key.publicKey.slice(0, 64),
        omitAddress: true,
        algorithm: null,
        expect: fail('malformed_input'),
        notes: '32-byte key (prefix 02 + 31 bytes).',
      }),
    );
  }
  return vectors;
}

// ---- SignIn -------------------------------------------------------------------------------------

const definitions = new XrplDefinitions({
  ...definitionsJson,
  TRANSACTION_TYPES: { ...definitionsJson.TRANSACTION_TYPES, SignIn: 999 },
});

type Tx = Record<string, unknown>;

function signInTx(key: Key, account: string, memoData?: string): Tx {
  const tx: Tx = { TransactionType: 'SignIn', Account: account, SigningPubKey: key.publicKey };
  if (memoData !== undefined) {
    tx.Memos = [{ Memo: { MemoType: utf8Hex(MEMO_TYPE), MemoData: utf8Hex(memoData) } }];
  }
  return tx;
}

function signTx(tx: Tx, key: Key): string {
  const TxnSignature = sign(encodeForSigning(tx, definitions), key.privateKey);
  return encode({ ...tx, TxnSignature }, definitions);
}

interface SignInSpec {
  id: string;
  source?: string;
  algorithm: Algorithm | null;
  blobHex: string;
  options?: SignInOptions;
  account?: AccountState;
  expect: Expect;
  notes: string;
}

function signInVector(spec: SignInSpec): Vector {
  return {
    id: spec.id,
    source: spec.source ?? 'generated',
    kind: 'signin',
    algorithm: spec.algorithm,
    encoding: 'hex',
    blobHex: spec.blobHex,
    ...(spec.options ? { options: spec.options } : {}),
    ...(spec.account ? { account: spec.account } : {}),
    expect: spec.expect,
    notes: spec.notes,
  };
}

function signInVectorsFor(key: Key): Vector[] {
  const alg = key.algorithm;
  const id = (name: string): string => `signin-${alg}-${name}`;
  const challenge = envelope(key.address);
  const withMemo = signTx(signInTx(key, key.address, challenge), key);
  const decoded = decode(withMemo, definitions) as Tx;

  const tamperedMemo = { ...decoded } as Tx;
  tamperedMemo.Memos = [{ Memo: { MemoType: utf8Hex(MEMO_TYPE), MemoData: utf8Hex('tampered') } }];
  const tamperedSignature = {
    ...decoded,
    TxnSignature: flipByte(
      decoded.TxnSignature as string,
      tamperIndex(alg, decoded.TxnSignature as string),
    ),
  };

  const vectors: Vector[] = [
    signInVector({
      id: id('memo'),
      algorithm: alg,
      blobHex: withMemo,
      expect: ok(key.address),
      notes: `SignIn (TransactionType 999) with MemoType "${MEMO_TYPE}" and the envelope as MemoData.`,
    }),
    signInVector({
      id: id('no-memo'),
      algorithm: alg,
      blobHex: signTx(signInTx(key, key.address), key),
      expect: ok(key.address),
      notes: 'SignIn without Memos.',
    }),
    signInVector({
      id: id('expected-memo-match'),
      algorithm: alg,
      blobHex: withMemo,
      options: { expectedMemo: challenge },
      expect: ok(key.address),
      notes: 'options.expectedMemo equals the MemoData text.',
    }),
    signInVector({
      id: id('expected-memo-mismatch'),
      algorithm: alg,
      blobHex: withMemo,
      options: { expectedMemo: 'not the challenge that was issued' },
      expect: fail('challenge_mismatch', key.address, 'master'),
      notes: 'Genuine blob, but the server expected a different challenge.',
    }),
    signInVector({
      id: id('tampered-memo'),
      algorithm: alg,
      blobHex: encode(tamperedMemo, definitions),
      expect: fail('bad_signature', key.address),
      notes: 'MemoData replaced after signing; TxnSignature unchanged.',
    }),
    signInVector({
      id: id('tampered-signature'),
      algorithm: alg,
      blobHex: encode(tamperedSignature, definitions),
      expect: fail('bad_signature', key.address),
      notes: 'One bit flipped in TxnSignature.',
    }),
    signInVector({
      id: id('account-mismatch'),
      algorithm: alg,
      blobHex: signTx(signInTx(key, OTHER.address, challenge), key),
      expect: fail('address_mismatch', key.address),
      notes:
        'Freshly signed by this key over a body whose Account is another address (the verify-xrpl-signature gap).',
    }),
    signInVector({
      id: id('expected-account-mismatch'),
      algorithm: alg,
      blobHex: withMemo,
      options: { expectedAccount: OTHER.address },
      expect: fail('address_mismatch', key.address, 'master'),
      notes: 'Genuine blob, options.expectedAccount names another account.',
    }),
  ];

  if (alg === 'secp256k1') {
    vectors.push(
      signInVector({
        id: id('expected-account-x-address'),
        algorithm: alg,
        blobHex: withMemo,
        options: { expectedAccount: classicAddressToXAddress(key.address, false, false) },
        expect: ok(key.address),
        notes: 'options.expectedAccount given as an X-address of the same account.',
      }),
      signInVector({
        id: id('regular-key'),
        algorithm: alg,
        blobHex: signTx(signInTx(key, OTHER.address, challenge), key),
        account: accountState(OTHER.address, { regularKey: key.address }),
        expect: ok(key.address, 'regular'),
        notes: 'Account is OTHER, signed by its RegularKey.',
      }),
    );
  }
  return vectors;
}

// XRPL Labs reference blobs, copied verbatim from verify-xrpl-signature test/fixtures.json.
const XRPL_LABS = {
  valid:
    '2280000000240000000268400000000000000C73210333C718C9CB716E0575454F4A343D46B284ED51151B9C7383524B82C10B262095744730450221009A4D99017F8FD6881D888047E2F9F90C068C09EC9308BC8526116B539D6DD44102207FAA7E8756F67FE7EE1A88884F120A00A8EC37E7D3E5ED3E02FEA7B1D97AA05581146C0994D3FCB140CAB36BAE9465137448883FA487',
  memoetc:
    '120000230098C1822405062D212E00000309201B05076FDA6140000000002DC6C068400000000000000F7321037AE7410E85C615B703D3484D5674F73936E968B671E7790C79B82EA582D8333D744630440220704D644BF883CE7484C2CE7DCF8D54E6BF4163DCCB22C8513CC84771BCC3CF0302203A8F67BB473114E6731FCC7124784EAA84C87D249109C6D313F770E0AEDF856E81143EFF5DB71D74ED511141CBB078E067D2009953ED8314842BDB20FD28150302B81618B77B1DB190B61D57F9EA7D1B4A4A57524E554E45435748504D55424F534A5651505145415F3437E1F1',
  xls20:
    '120019141770220000000824047E70A8201B0480EDCA202A00000032684000000000000C807300811472631AFCCECFF285A11CDC6159CE3E5AB34920B9F3E0107321EDFC78FE5C5F474985678DD821FCDD7F65F2F7CC5029E3D0BEB46C9B0D90C622FF7440EFF305AF335C59180B81E5A0FC860F1F3CF5B2242269B9A8C61534A87F08E50DFF77B9D2487FA80D97290E0808BE220CCF8A7F6026B7FDE2D1C64B2A4AE2AB0F8114112DE2804BD473EB8A77E01E1C43A9CDC79A6EBFE1F1',
  multisign:
    '1200002400000003201B00503A406140000000000000016840000000000000677300811461D46A8DE4DAE4F72196C87995D9390BA82BA9F18314F84E8A80D08854F3621F9214D58F04D41A07EE10F3E01073210217241703CBC4D52C04D59269DE634B388E57C1E72F9462EEF4B435E041ED88367446304402204789F8AA9625D65FD65F43A7AC9FBFAEF64026A4BD1421B0F87ADE24B15F477302207241FDC7B31E15FDB121CA64623B6AC84475A30992E092F56656A731743B9FF781146B07151AAEC3405E3D83CEE654456B621EBF0007E1F1F9EA7C08536F6D65547970657D08536F6D6544617461E1EA7C09446576656C6F7065727D0B4057696574736557696E64E1F1',
  invalid:
    '12000022800000002400000003614000000002F0000000000000C8730081146C1D22888CF2CC88579D71FE0BE6890FE2268BF38314F84E8A80D08854F3621F9214D58F04D41A07EE10F3E010732103858452B639D34041FAC9C6CA4F46A5DF5528C2E9BBBBD750EB4FEAB2AE8B2E22744630440220333BC823D9F3F048FD01BA6CEE41187928FDE59E358F4A65AE5054C9446E8D5D022043C9CA3C2C70589628E2B7E88C0827E67B1CE8D6850854541D447449715107A08114F4A5239106E24D5E4ABBC82AD870AB2D22B7E082E1F1F9EA7C08536F6D65547970657D08536F6D6544617461E1EA7C09446576656C6F7065727D0B4057696574736557696E64E1F1',
};
const XRPL_LABS_VALID_ACCOUNT = 'rwiETSee2wMz3SBnAG8hkMsCgvGy9LWbZ1';

function xrplLabsVectors(): Vector[] {
  const labs = (spec: Omit<SignInSpec, 'source'>): Vector =>
    signInVector({ ...spec, source: 'xrpl-labs-fixture' });
  return [
    labs({
      id: 'xrpl-labs-valid',
      algorithm: 'secp256k1',
      blobHex: XRPL_LABS.valid,
      expect: fail('unexpected_transaction_type'),
      notes: 'Legacy Xaman pseudo-transaction: no TransactionType field. Refused by default.',
    }),
    labs({
      id: 'xrpl-labs-valid-allow-missing-type',
      algorithm: 'secp256k1',
      blobHex: XRPL_LABS.valid,
      options: { allowMissingTransactionType: true },
      expect: ok(XRPL_LABS_VALID_ACCOUNT),
      notes: 'Same blob with options.allowMissingTransactionType. Signer key derives to Account.',
    }),
    labs({
      id: 'xrpl-labs-memoetc',
      algorithm: 'secp256k1',
      blobHex: XRPL_LABS.memoetc,
      expect: fail('unexpected_transaction_type'),
      notes: 'A real signed Payment with a Memo. Valid signature, wrong transaction type.',
    }),
    labs({
      id: 'xrpl-labs-xls20',
      algorithm: null,
      blobHex: XRPL_LABS.xls20,
      expect: fail('unsupported_multisig'),
      notes: 'Multisigned NFTokenMint (Signers array, empty SigningPubKey).',
    }),
    labs({
      id: 'xrpl-labs-multisign',
      algorithm: null,
      blobHex: XRPL_LABS.multisign,
      expect: fail('unsupported_multisig'),
      notes: 'Multisigned Payment with Memos.',
    }),
    labs({
      id: 'xrpl-labs-invalid',
      algorithm: null,
      blobHex: XRPL_LABS.invalid,
      expect: fail('malformed_input'),
      notes: 'Undecodable blob.',
    }),
  ];
}

// ---- output -------------------------------------------------------------------------------------

const vectors = [
  ...messageVectorsFor(SECP),
  ...messageVectorsFor(ED),
  ...signInVectorsFor(SIGNIN_SECP),
  ...signInVectorsFor(SIGNIN_ED),
  ...xrplLabsVectors(),
].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

const ids = new Set<string>();
for (const v of vectors) {
  if (ids.has(v.id)) throw new Error(`duplicate vector id ${v.id}`);
  ids.add(v.id);
}

const out = { version: 1, generatedBy: 'scripts/gen-fixtures.ts', vectors };
const target = fileURLToPath(new URL('../../../fixtures/vectors.json', import.meta.url));
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`);

const counts = new Map<string, number>();
for (const v of vectors) {
  const k = v.expect.reason ?? 'valid';
  counts.set(k, (counts.get(k) ?? 0) + 1);
}
console.log(`wrote ${vectors.length} vectors to ${target}`);
for (const [k, n] of [...counts].sort()) console.log(`  ${k.padEnd(28)} ${n}`);
