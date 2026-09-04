import * as rk from 'ripple-keypairs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const kp = rk.deriveKeypair(rk.generateSeed({ algorithm: 'ecdsa-secp256k1' }));
const msg = new TextEncoder().encode('der strictness');
const msgHex = bytesToHex(msg);
const sigHex = rk.sign(msgHex, kp.privateKey);
const sig = secp256k1.Signature.fromHex(sigHex, 'der');
console.log('good sig', sigHex);

// helper: rebuild DER from r,s byte arrays as given (no normalisation)
function der(rBytes, sBytes) {
  const int = (b) => Uint8Array.from([0x02, b.length, ...b]);
  const ri = int(rBytes), si = int(sBytes);
  return bytesToHex(Uint8Array.from([0x30, ri.length + si.length, ...ri, ...si])).toUpperCase();
}
const minimal = (n) => { let h = n.toString(16); if (h.length % 2) h = '0' + h; let b = hexToBytes(h); if (b[0] & 0x80) b = Uint8Array.from([0, ...b]); return b; };
const rB = minimal(sig.r), sB = minimal(sig.s);
console.log('canonical rebuild == original:', der(rB, sB) === sigHex);

const variants = {
  'A: extra leading 0x00 pad on r': der(Uint8Array.from([0, ...rB]), sB),
  'B: negative INTEGER (r high bit set, pad stripped)': (() => { const raw = hexToBytes(sig.r.toString(16).padStart(64, '0')); return der(raw[0] & 0x80 ? raw : Uint8Array.from([0x80 | raw[0], ...raw.slice(1)]), sB); })(),
  'C: high-S (n - s)': (() => { const hs = secp256k1.Point.Fn.ORDER - sig.s; return der(rB, minimal(hs)); })(),
  'D: trailing garbage byte': sigHex + '00',
  'E: BER long-form length 0x81': (() => { const body = sigHex.slice(4); const len = body.length / 2; return '3081' + len.toString(16).padStart(2, '0').toUpperCase() + body; })(),
};
const pub = kp.publicKey;
for (const [name, v] of Object.entries(variants)) {
  let noble, rkv;
  try { const s = secp256k1.Signature.fromHex(v, 'der'); noble = `parsed r==r:${s.r === sig.r} s==s:${s.s === sig.s} highS:${s.hasHighS()}`; 
        try { noble += ` verify(default)=${secp256k1.verify(s.toBytes('compact'), sha512(msg).slice(0,32), hexToBytes(pub), { prehash: false })}`; 
              noble += ` verify(lowS:false)=${secp256k1.verify(s.toBytes('compact'), sha512(msg).slice(0,32), hexToBytes(pub), { prehash: false, lowS: false })}`; } catch (e) { noble += ` verify threw: ${e.message}`; }
  } catch (e) { noble = `THREW ${e.constructor.name}: ${e.message}`; }
  try { rkv = String(rk.verify(msgHex, v, pub)); } catch (e) { rkv = `THREW ${e.constructor.name}: ${e.message}`; }
  console.log(`${name}\n   noble: ${noble}\n   rk.verify: ${rkv}`);
}

console.log('\n---- off-curve pubkey');
// 02 + x where x has no sqrt(x^3+7) -> off curve. Find one by scanning.
let bad;
for (let i = 1n; ; i++) { const cand = '02' + i.toString(16).padStart(64, '0'); try { secp256k1.Point.fromHex(cand); } catch { bad = cand.toUpperCase(); break; } }
console.log('off-curve 33-byte hex:', bad);
try { console.log('noble Point.fromHex ->', secp256k1.Point.fromHex(bad)); } catch (e) { console.log('noble Point.fromHex THREW:', e.message); }
try { console.log('noble verify ->', secp256k1.verify(sig.toBytes('compact'), sha512(msg).slice(0,32), hexToBytes(bad), { prehash: false })); } catch (e) { console.log('noble verify THREW:', e.constructor.name, e.message); }
try { console.log('rk.verify ->', rk.verify(msgHex, sigHex, bad)); } catch (e) { console.log('rk.verify THREW:', e.constructor.name, e.message); }
try { console.log('rk.deriveAddress(off-curve) ->', rk.deriveAddress(bad)); } catch (e) { console.log('rk.deriveAddress THREW:', e.message); }
// x >= p
const bigx = '02' + 'FF'.repeat(32);
try { console.log('rk.verify x>=p ->', rk.verify(msgHex, sigHex, bigx)); } catch (e) { console.log('rk.verify x>=p THREW:', e.constructor.name, e.message); }
// wrong length / bad prefix
for (const k of ['04' + '00'.repeat(32), '02' + '00'.repeat(31), 'ED' + '00'.repeat(32)]) {
  try { console.log(`rk.verify(${k.slice(0,4)}.. len ${k.length/2}) ->`, rk.verify(msgHex, sigHex, k)); } catch (e) { console.log(`rk.verify(${k.slice(0,4)}.. len ${k.length/2}) THREW:`, e.constructor.name, e.message); }
}
