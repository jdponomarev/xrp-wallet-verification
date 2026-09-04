import { secp256k1 } from '@noble/curves/secp256k1.js';
import { classicAddressToXAddress } from 'ripple-address-codec';
import * as rk from 'ripple-keypairs';
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../src/hex.js';
import type { AccountState, VerifyMessageInput } from '../src/types.js';
import { verifyMessage, verifyMessageByAddress } from '../src/verify-message.js';

// Fixed vectors from docs/FINDINGS.md §6.
const SECP_SEED = 'sp5fV4UGhZhfCvcDRuY3dyyh5PjHf';
const ED_SEED = 'sEdSKuYwxeL4JM1LBJcGmpLw9fbF8JN';
const MESSAGE = 'Sign in to example.com\nnonce: 0123456789abcdef';
const SECP_SIG =
  '30440220072BCE65E506246C591AD415313F091B89A3212C5EDA9E0205FC088C9A53FEA1022037FE519459B5FD6EEA039E15237755268646108639917618D51BE02724202A59';
const ED_SIG =
  '0FE0FACA05B234667E44A926553E1D06F93CCE82ECCD182233F1E420A8256229A01B28719C35B95CDAA2311609DB56F6B60C3F21CF10A5FC39A695775A63C300';

const secp = rk.deriveKeypair(SECP_SEED);
const ed = rk.deriveKeypair(ED_SEED);
const SECP_ADDRESS = rk.deriveAddress(secp.publicKey);
const ED_ADDRESS = rk.deriveAddress(ed.publicKey);

const hexOf = (text: string): string => bytesToHex(utf8ToBytes(text));
const signText = (text: string, privateKey: string): string => rk.sign(hexOf(text), privateKey);

const secpInput = (over: Partial<VerifyMessageInput> = {}): VerifyMessageInput => ({
  message: MESSAGE,
  signature: SECP_SIG,
  publicKey: secp.publicKey,
  ...over,
});
const edInput = (over: Partial<VerifyMessageInput> = {}): VerifyMessageInput => ({
  message: MESSAGE,
  signature: ED_SIG,
  publicKey: ed.publicKey,
  ...over,
});

const liveAccount = (address: string, over: Partial<AccountState> = {}): AccountState => ({
  address,
  exists: true,
  masterDisabled: false,
  hasSignerList: false,
  ...over,
});

/** DER SEQUENCE of two INTEGERs built from the given byte arrays verbatim (no normalisation). */
function der(r: Uint8Array, s: Uint8Array): string {
  const int = (b: Uint8Array) => Uint8Array.from([0x02, b.length, ...b]);
  const ri = int(r);
  const si = int(s);
  return bytesToHex(Uint8Array.from([0x30, ri.length + si.length, ...ri, ...si]));
}

/** Minimal positive DER INTEGER content for a bigint. */
function minimal(n: bigint): Uint8Array {
  let h = n.toString(16);
  if (h.length % 2) h = '0' + h;
  const b = hexToBytes(h);
  return (b[0] as number) & 0x80 ? Uint8Array.from([0, ...b]) : b;
}

function rkVerifyOrFalse(msgHex: string, sig: string, pub: string): boolean {
  try {
    return rk.verify(msgHex, sig, pub);
  } catch {
    return false;
  }
}

function highS(derHex: string): string {
  const sig = secp256k1.Signature.fromHex(derHex, 'der');
  return new secp256k1.Signature(sig.r, secp256k1.Point.Fn.ORDER - sig.s)
    .toHex('der')
    .toUpperCase();
}

describe('fixed vectors reproduce FINDINGS §6', () => {
  it('ripple-keypairs signs the fixed vectors byte for byte', () => {
    expect(secp.publicKey).toBe(
      '035A7FA22521397BE0FFE9CD7C35DDE0FB0C8EA96E48FF84E0C6309D0D4D70D9EA',
    );
    expect(SECP_ADDRESS).toBe('rMPrYipfRHJryWfwYARAwhsVGvHwpUDjgA');
    expect(signText(MESSAGE, secp.privateKey)).toBe(SECP_SIG);
    expect(ed.publicKey).toBe('ED26D54D80051A116166CF76FEA87330D546680B875827B87AF1B1D58B9EB464E1');
    expect(ED_ADDRESS).toBe('rpjfAeE3DeeHPFnN2PgGFW5YxnZFAjrEyN');
    expect(signText(MESSAGE, ed.privateKey)).toBe(ED_SIG);
  });
});

describe('verifyMessage: valid signatures', () => {
  it('secp256k1 without an address: valid, signer unknown', () => {
    expect(verifyMessage(secpInput())).toEqual({
      valid: true,
      signer: 'unknown',
      algorithm: 'secp256k1',
      derivedAddress: SECP_ADDRESS,
    });
  });

  it('secp256k1 with the matching address: signer master', () => {
    const r = verifyMessage(secpInput({ address: SECP_ADDRESS }));
    expect(r.valid).toBe(true);
    expect(r.signer).toBe('master');
    expect(r.reason).toBeUndefined();
  });

  it('ed25519 without and with the matching address', () => {
    expect(verifyMessage(edInput())).toEqual({
      valid: true,
      signer: 'unknown',
      algorithm: 'ed25519',
      derivedAddress: ED_ADDRESS,
    });
    expect(verifyMessage(edInput({ address: ED_ADDRESS })).signer).toBe('master');
  });

  it('hex-encoded message agrees with the utf8 form, lowercase hex accepted everywhere', () => {
    const r = verifyMessage({
      message: hexOf(MESSAGE).toLowerCase(),
      encoding: 'hex',
      signature: SECP_SIG.toLowerCase(),
      publicKey: secp.publicKey.toLowerCase(),
      address: SECP_ADDRESS,
    });
    expect(r.valid).toBe(true);
    expect(r.derivedAddress).toBe(SECP_ADDRESS);
    const e = verifyMessage(
      edInput({ signature: ED_SIG.toLowerCase(), publicKey: ed.publicKey.toLowerCase() }),
    );
    expect(e.valid).toBe(true);
  });

  it('X-address input binds to the classic address', () => {
    const x = classicAddressToXAddress(SECP_ADDRESS, 12345, false);
    const r = verifyMessage(secpInput({ address: x }));
    expect(r).toMatchObject({ valid: true, signer: 'master', derivedAddress: SECP_ADDRESS });
  });

  it('CRLF is signed as-is and does not verify against the LF form', () => {
    const crlf = 'line one\r\nline two\r\n';
    const sig = signText(crlf, secp.privateKey);
    expect(verifyMessage(secpInput({ message: crlf, signature: sig })).valid).toBe(true);
    const lf = verifyMessage(secpInput({ message: crlf.replaceAll('\r\n', '\n'), signature: sig }));
    expect(lf).toMatchObject({ valid: false, reason: 'bad_signature' });
  });

  it('unicode and emoji messages', () => {
    const text = 'Привет, XRPL! 🚀 日本語 nonce=ü';
    const sig = signText(text, ed.privateKey);
    expect(verifyMessage(edInput({ message: text, signature: sig })).valid).toBe(true);
    expect(verifyMessage(edInput({ message: text.normalize('NFD'), signature: sig })).reason).toBe(
      'bad_signature',
    );
  });

  it('10 KB message', () => {
    const text = 'x'.repeat(10 * 1024);
    const sig = signText(text, secp.privateKey);
    expect(verifyMessage(secpInput({ message: text, signature: sig })).valid).toBe(true);
  });

  it('exactly maxMessageBytes is accepted, one more byte is not', () => {
    const text = 'y'.repeat(65536);
    const sig = signText(text, ed.privateKey);
    expect(verifyMessage(edInput({ message: text, signature: sig })).valid).toBe(true);
    const r = verifyMessage(edInput({ message: text + 'y', signature: sig }));
    expect(r).toMatchObject({ valid: false, reason: 'message_too_large', signer: 'unknown' });
    expect(r.algorithm).toBeUndefined();
  });
});

describe('verifyMessage: bad and mismatched signatures', () => {
  it('bad_signature when the message differs (both algorithms)', () => {
    const s = verifyMessage(secpInput({ message: MESSAGE + ' ' }));
    expect(s).toEqual({
      valid: false,
      reason: 'bad_signature',
      signer: 'unknown',
      algorithm: 'secp256k1',
      derivedAddress: SECP_ADDRESS,
    });
    const e = verifyMessage(edInput({ message: MESSAGE + ' ' }));
    expect(e).toMatchObject({ valid: false, reason: 'bad_signature', derivedAddress: ED_ADDRESS });
  });

  it('bad_signature is reported before address policy', () => {
    const r = verifyMessage(secpInput({ message: 'other', address: ED_ADDRESS }));
    expect(r.reason).toBe('bad_signature');
  });

  it('bad_signature when the key belongs to another account', () => {
    const other = rk.deriveKeypair(
      rk.generateSeed({ entropy: new Uint8Array(16).fill(0x42), algorithm: 'ecdsa-secp256k1' }),
    );
    const r = verifyMessage(secpInput({ publicKey: other.publicKey }));
    expect(r).toMatchObject({ valid: false, reason: 'bad_signature' });
  });

  it('algorithm_mismatch: ed25519 key with a DER signature', () => {
    const r = verifyMessage(edInput({ signature: SECP_SIG }));
    expect(r).toMatchObject({ valid: false, reason: 'algorithm_mismatch', algorithm: 'ed25519' });
  });

  it('algorithm_mismatch: secp256k1 key with a 64-byte signature', () => {
    const r = verifyMessage(secpInput({ signature: ED_SIG }));
    expect(r).toMatchObject({ valid: false, reason: 'algorithm_mismatch', algorithm: 'secp256k1' });
  });

  it('non_canonical_signature: high-S DER is rejected by default and accepted only by policy', () => {
    const hs = highS(SECP_SIG);
    expect(hs).not.toBe(SECP_SIG);
    expect(rk.verify(hexOf(MESSAGE), hs, secp.publicKey)).toBe(false);
    expect(verifyMessage(secpInput({ signature: hs }))).toMatchObject({
      valid: false,
      reason: 'non_canonical_signature',
      derivedAddress: SECP_ADDRESS,
    });
    expect(verifyMessage(secpInput({ signature: hs, policy: { requireLowS: false } })).valid).toBe(
      true,
    );
  });

  it('ed25519 s + L malleation is rejected', () => {
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    const bytes = hexToBytes(ED_SIG);
    const sLE = bytes.slice(32);
    let s = 0n;
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(sLE[i] as number);
    s += L;
    const out = Uint8Array.from(bytes);
    for (let i = 0; i < 32; i++) out[32 + i] = Number((s >> BigInt(8 * i)) & 0xffn);
    const r = verifyMessage(edInput({ signature: bytesToHex(out) }));
    expect(r).toMatchObject({ valid: false, reason: 'bad_signature' });
  });
});

describe('verifyMessage: malformed input', () => {
  const secpOffCurveKey = '02' + '00'.repeat(31) + '05';

  it.each([
    ['odd-length hex message', { message: 'ABC', encoding: 'hex' as const }],
    ['non-hex message', { message: 'zz', encoding: 'hex' as const }],
    ['empty utf8 message', { message: '' }],
    ['empty hex message', { message: '', encoding: 'hex' as const }],
    ['odd-length signature', { signature: SECP_SIG + 'A' }],
    ['non-hex signature', { signature: 'not hex' }],
    ['empty signature', { signature: '' }],
    ['unknown encoding', { encoding: 'base64' as unknown as 'hex' }],
    ['non-string message', { message: 123 as unknown as string }],
    ['malformed address', { address: 'rNotAnAddress' }],
  ])('%s', (_name, over) => {
    const r = verifyMessage(secpInput(over));
    expect(r.valid).toBe(false);
    expect(r.reason).toBe('malformed_input');
    expect(r.signer).toBe('unknown');
    expect(typeof r.details?.error).toBe('string');
  });

  it.each([
    ['uncompressed 04 key', bytesToHex(secp256k1.Point.fromHex(secp.publicKey).toBytes(false))],
    ['off-curve 02 key', secpOffCurveKey],
    ['32-byte key', secp.publicKey.slice(0, 64)],
    ['unknown prefix', '05' + secp.publicKey.slice(2)],
    ['odd-length key', secp.publicKey + 'A'],
    ['invalid ed25519 point', 'ED' + 'FF'.repeat(32)],
  ])('%s', (_name, publicKey) => {
    const r = verifyMessage(secpInput({ publicKey }));
    expect(r).toMatchObject({ valid: false, reason: 'malformed_input', signer: 'unknown' });
    expect(r.algorithm).toBeUndefined();
    expect(r.derivedAddress).toBeUndefined();
    expect(typeof r.details?.error).toBe('string');
  });

  it('non-canonical DER variants', () => {
    const sig = secp256k1.Signature.fromHex(SECP_SIG, 'der');
    const rB = minimal(sig.r);
    const sB = minimal(sig.s);
    expect(der(rB, sB)).toBe(SECP_SIG);
    const variants: Record<string, string> = {
      truncated: SECP_SIG.slice(0, -8),
      leadingZeroPad: der(Uint8Array.from([0, ...rB]), sB),
      negativeInteger: der(Uint8Array.from([0x80 | (rB[0] as number), ...rB.slice(1)]), sB),
      trailingByte: SECP_SIG + '00',
      longFormLength: '3081' + SECP_SIG.slice(2),
      rOutOfRange: der(minimal(secp256k1.Point.Fn.ORDER), sB),
    };
    for (const [name, signature] of Object.entries(variants)) {
      const r = verifyMessage(secpInput({ signature }));
      expect(r, name).toMatchObject({
        valid: false,
        reason: 'malformed_input',
        algorithm: 'secp256k1',
      });
      // ripple-keypairs throws on malformed DER instead of returning false (FINDINGS F-1.8).
      expect(rkVerifyOrFalse(hexOf(MESSAGE), signature, secp.publicKey), name).toBe(false);
    }
  });

  it('ed25519 key with a wrong-length non-DER signature', () => {
    const r = verifyMessage(edInput({ signature: ED_SIG.slice(0, -2) }));
    expect(r).toMatchObject({ valid: false, reason: 'malformed_input', algorithm: 'ed25519' });
  });

  it('message_too_large honours policy.maxMessageBytes', () => {
    const r = verifyMessage(secpInput({ policy: { maxMessageBytes: 10 } }));
    expect(r).toMatchObject({ valid: false, reason: 'message_too_large' });
    expect(r.details).toEqual({ bytes: utf8ToBytes(MESSAGE).length, max: 10 });
  });

  it('invalid policy is a programmer error and throws', () => {
    expect(() => verifyMessage(secpInput({ policy: { maxMessageBytes: 0 } }))).toThrow(RangeError);
    expect(() => verifyMessage(secpInput({ policy: { maxMessageBytes: 1.5 } }))).toThrow(
      RangeError,
    );
  });
});

describe('verifyMessage: address and account policy', () => {
  it('address_mismatch when the derived address differs', () => {
    const r = verifyMessage(secpInput({ address: ED_ADDRESS }));
    expect(r).toEqual({
      valid: false,
      reason: 'address_mismatch',
      signer: 'unknown',
      algorithm: 'secp256k1',
      derivedAddress: SECP_ADDRESS,
      details: { expected: ED_ADDRESS, derived: SECP_ADDRESS },
    });
  });

  it('address_mismatch when address and account.address disagree', () => {
    const r = verifyMessage(secpInput({ address: SECP_ADDRESS, account: liveAccount(ED_ADDRESS) }));
    expect(r).toMatchObject({ valid: false, reason: 'address_mismatch' });
  });

  it('account alone binds the signer', () => {
    expect(verifyMessage(secpInput({ account: liveAccount(SECP_ADDRESS) }))).toMatchObject({
      valid: true,
      signer: 'master',
    });
    expect(verifyMessage(secpInput({ account: liveAccount(ED_ADDRESS) }))).toMatchObject({
      valid: false,
      reason: 'address_mismatch',
    });
  });

  it('RegularKey: signature from the regular key verifies as signer regular', () => {
    const account = liveAccount(ED_ADDRESS, { regularKey: SECP_ADDRESS });
    const r = verifyMessage(secpInput({ address: ED_ADDRESS, account }));
    expect(r).toEqual({
      valid: true,
      signer: 'regular',
      algorithm: 'secp256k1',
      derivedAddress: SECP_ADDRESS,
    });
    // The regular key is still good when the master key is disabled.
    const disabled = liveAccount(ED_ADDRESS, { regularKey: SECP_ADDRESS, masterDisabled: true });
    expect(verifyMessage(secpInput({ account: disabled })).signer).toBe('regular');
  });

  it('RegularKey does not make the master key a regular signer', () => {
    const account = liveAccount(SECP_ADDRESS, { regularKey: ED_ADDRESS });
    expect(verifyMessage(secpInput({ account })).signer).toBe('master');
  });

  it('master_disabled by default, allowed via policy', () => {
    const account = liveAccount(SECP_ADDRESS, { masterDisabled: true });
    expect(verifyMessage(secpInput({ account }))).toMatchObject({
      valid: false,
      reason: 'master_disabled',
      signer: 'master',
      derivedAddress: SECP_ADDRESS,
    });
    expect(
      verifyMessage(secpInput({ account, policy: { allowMasterDisabled: true } })),
    ).toMatchObject({ valid: true, signer: 'master' });
  });

  it('unsupported_multisig when the account has a SignerList', () => {
    const account = liveAccount(SECP_ADDRESS, { hasSignerList: true });
    expect(verifyMessage(secpInput({ account }))).toMatchObject({
      valid: false,
      reason: 'unsupported_multisig',
      signer: 'master',
    });
  });

  it('account_not_found still reports the derived address and whether it matches', () => {
    const missing = liveAccount(SECP_ADDRESS, { exists: false });
    expect(verifyMessage(secpInput({ account: missing }))).toEqual({
      valid: false,
      reason: 'account_not_found',
      signer: 'master',
      algorithm: 'secp256k1',
      derivedAddress: SECP_ADDRESS,
      details: { derivedMatches: true },
    });
    const wrong = liveAccount(ED_ADDRESS, { exists: false });
    expect(verifyMessage(secpInput({ account: wrong }))).toMatchObject({
      reason: 'account_not_found',
      signer: 'unknown',
      details: { derivedMatches: false },
    });
  });
});

describe('verifyMessageByAddress', () => {
  it('recovers the key and binds to the address', () => {
    expect(
      verifyMessageByAddress({ message: MESSAGE, signature: SECP_SIG, address: SECP_ADDRESS }),
    ).toEqual({
      valid: true,
      signer: 'master',
      algorithm: 'secp256k1',
      derivedAddress: SECP_ADDRESS,
    });
  });

  it('accepts an X-address and lowercase hex', () => {
    const x = classicAddressToXAddress(SECP_ADDRESS, false, true);
    const r = verifyMessageByAddress({
      message: hexOf(MESSAGE).toLowerCase(),
      encoding: 'hex',
      signature: SECP_SIG.toLowerCase(),
      address: x,
    });
    expect(r).toMatchObject({ valid: true, signer: 'master', derivedAddress: SECP_ADDRESS });
  });

  it('address_mismatch for the wrong address, listing the recovered candidates', () => {
    const r = verifyMessageByAddress({
      message: MESSAGE,
      signature: SECP_SIG,
      address: ED_ADDRESS,
    });
    expect(r).toMatchObject({
      valid: false,
      reason: 'address_mismatch',
      signer: 'unknown',
      algorithm: 'secp256k1',
    });
    expect(r.derivedAddress).toBeUndefined();
    expect(r.details?.candidates).toContain(SECP_ADDRESS);
  });

  it('address_mismatch when the message was tampered', () => {
    const r = verifyMessageByAddress({
      message: MESSAGE + '!',
      signature: SECP_SIG,
      address: SECP_ADDRESS,
    });
    expect(r).toMatchObject({ valid: false, reason: 'address_mismatch' });
  });

  it('ed25519 signatures cannot be recovered: algorithm_mismatch with a hint', () => {
    const r = verifyMessageByAddress({ message: MESSAGE, signature: ED_SIG, address: ED_ADDRESS });
    expect(r).toMatchObject({ valid: false, reason: 'algorithm_mismatch', signer: 'unknown' });
    expect(r.algorithm).toBeUndefined();
    expect(typeof r.details?.hint).toBe('string');
  });

  it('high-S is rejected before recovery', () => {
    const r = verifyMessageByAddress({
      message: MESSAGE,
      signature: highS(SECP_SIG),
      address: SECP_ADDRESS,
    });
    expect(r).toMatchObject({
      valid: false,
      reason: 'non_canonical_signature',
      algorithm: 'secp256k1',
    });
  });

  it('RegularKey via account: signer regular, and master policy applies', () => {
    const account = liveAccount(ED_ADDRESS, { regularKey: SECP_ADDRESS, masterDisabled: true });
    expect(
      verifyMessageByAddress({
        message: MESSAGE,
        signature: SECP_SIG,
        address: ED_ADDRESS,
        account,
      }),
    ).toMatchObject({ valid: true, signer: 'regular', derivedAddress: SECP_ADDRESS });
    const disabled = liveAccount(SECP_ADDRESS, { masterDisabled: true });
    expect(
      verifyMessageByAddress({
        message: MESSAGE,
        signature: SECP_SIG,
        address: SECP_ADDRESS,
        account: disabled,
      }),
    ).toMatchObject({ valid: false, reason: 'master_disabled', signer: 'master' });
  });

  it.each([
    ['malformed address', { address: 'nope' }],
    ['truncated DER', { signature: SECP_SIG.slice(0, -8) }],
    ['odd hex message', { message: 'ABC', encoding: 'hex' as const }],
    ['empty message', { message: '' }],
  ])('%s is malformed_input', (_name, over) => {
    const r = verifyMessageByAddress({
      message: MESSAGE,
      signature: SECP_SIG,
      address: SECP_ADDRESS,
      ...over,
    });
    expect(r).toMatchObject({ valid: false, reason: 'malformed_input', signer: 'unknown' });
  });
});

describe('cross-check against ripple-keypairs', () => {
  const algorithms = ['ecdsa-secp256k1', 'ed25519'] as const;

  it.each(algorithms)(
    '%s: 20 deterministic vectors agree with ripple-keypairs.verify',
    (algorithm) => {
      for (let i = 1; i <= 20; i++) {
        const seed = rk.generateSeed({ entropy: new Uint8Array(16).fill(i), algorithm });
        const kp = rk.deriveKeypair(seed);
        const text = `vector ${i} for ${algorithm} ${'#'.repeat(i)}`;
        const msgHex = hexOf(text);
        const sig = rk.sign(msgHex, kp.privateKey);
        const address = rk.deriveAddress(kp.publicKey);

        const ok = verifyMessage({
          message: text,
          signature: sig,
          publicKey: kp.publicKey,
          address,
        });
        expect(rk.verify(msgHex, sig, kp.publicKey)).toBe(true);
        expect(ok.valid).toBe(true);
        expect(ok.derivedAddress).toBe(address);

        const tamperedHex = hexOf(text + '.');
        const bad = verifyMessage({ message: text + '.', signature: sig, publicKey: kp.publicKey });
        expect(rk.verify(tamperedHex, sig, kp.publicKey)).toBe(false);
        expect(bad.valid).toBe(false);
        expect(bad.reason).toBe('bad_signature');

        if (algorithm === 'ecdsa-secp256k1') {
          const byAddr = verifyMessageByAddress({ message: text, signature: sig, address });
          expect(byAddr.valid).toBe(true);
          expect(byAddr.derivedAddress).toBe(address);
        }
      }
    },
  );
});
