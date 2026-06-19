//! Swappable PQ ring-sig C ABI (mirrors pqc/include/pq_ring_sig.h) + compact packing.
//!
//! All entry points are plain `extern "C"`, panic-guarded (a panic across an FFI boundary is
//! UB), with sizes queried at runtime.  This is the surface the C++11 consensus layer would
//! eventually link against (phase 2 — NOT wired here).
//!
//! Encodings:
//!   public key  = modq-encoded a0           (897 bytes, canonical 14-bit packing)
//!   secret key  = seed (we keep keygen deterministic; sk export = 48-byte seed)
//!   nullifier   = 32-byte hash of aots
//!   signature   = compact packing (see `pack`/`unpack`): per-member comp-encoded (r0,r1) +
//!                 32-byte b, plus modq aots + comp-encoded ots (s0,s1), canonical varints,
//!                 no padding.

use crate::falcon_ffi as fc;
use crate::falcon_ffi::N;
use crate::raptor::{self, Member, OtsSig, RaptorSecretKey, Signature};
use std::panic;
use std::slice;

pub const SCHEME_ID: u32 = 0x52_41_50_54; // "RAPT"
// Raw modq encoding of an n=512 poly at 14 bits/coeff = 512*14/8 = 896 bytes (no header byte;
// PQClean's 897-byte CRYPTO_PUBLICKEYBYTES adds a 1-byte format header which we omit — our
// scheme id provides the framing).
pub const PUBKEY_BYTES: usize = 896;
pub const SECKEY_BYTES: usize = 48;        // the deterministic seed (wallet-restorable)
pub const NULLIFIER_BYTES: usize = raptor::NULLIFIER_BYTES;

const RET_OK: i32 = 0;
const RET_ERR: i32 = -1;

fn guard<F: FnOnce() -> i32>(f: F) -> i32 {
    match panic::catch_unwind(panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => RET_ERR,
    }
}

#[no_mangle]
pub extern "C" fn ccx_pq_scheme_id() -> u32 { SCHEME_ID }
#[no_mangle]
pub extern "C" fn ccx_pq_pubkey_bytes() -> usize { PUBKEY_BYTES }
#[no_mangle]
pub extern "C" fn ccx_pq_seckey_bytes() -> usize { SECKEY_BYTES }
#[no_mangle]
pub extern "C" fn ccx_pq_nullifier_bytes() -> usize { NULLIFIER_BYTES }

/// Canonical pubkey check: a0 must be exactly PUBKEY_BYTES of valid modq encoding (every
/// coeff in [0,q)), and must re-encode to the identical bytes (rejects non-canonical packings).
#[no_mangle]
pub extern "C" fn ccx_pq_pubkey_is_canonical(pk: *const u8, pk_len: usize) -> i32 {
    guard(|| {
        if pk.is_null() || pk_len != PUBKEY_BYTES { return 0; }
        let bytes = unsafe { slice::from_raw_parts(pk, pk_len) };
        // decode: modq_decode returns 0 if any coeff >= q or trailing bits nonzero.
        let decoded = match fc::modq_decode(bytes) { Some(d) => d, None => return 0 };
        // canonical: re-encode must reproduce the exact bytes
        let re = match fc::modq_encode(&decoded) { Some(r) => r, None => return 0 };
        if re.len() == pk_len && re.as_slice() == bytes { 1 } else { 0 }
    })
}

#[no_mangle]
pub extern "C" fn ccx_pq_keygen(
    seed: *const u8, seed_len: usize,
    pk_out: *mut u8, pk_cap: usize,
    sk_out: *mut u8, sk_cap: usize,
) -> i32 {
    guard(|| {
        if seed.is_null() || pk_out.is_null() || sk_out.is_null() { return RET_ERR; }
        if pk_cap < PUBKEY_BYTES || sk_cap < SECKEY_BYTES { return RET_ERR; }
        let seed = unsafe { slice::from_raw_parts(seed, seed_len) };
        // Normalize the wallet seed to exactly SECKEY_BYTES via SHAKE so the exported sk is
        // fixed-size and any-length seed input works.
        let sk_seed = fc::shake256(seed, SECKEY_BYTES);
        let (pk, _sk) = raptor::keygen(&sk_seed);
        let pk_enc = match fc::modq_encode(&pk.a0) { Some(e) => e, None => return RET_ERR };
        if pk_enc.len() != PUBKEY_BYTES { return RET_ERR; }
        unsafe {
            slice::from_raw_parts_mut(pk_out, PUBKEY_BYTES).copy_from_slice(&pk_enc);
            slice::from_raw_parts_mut(sk_out, SECKEY_BYTES).copy_from_slice(&sk_seed);
        }
        RET_OK
    })
}

#[no_mangle]
pub extern "C" fn ccx_pq_nullifier(
    sk: *const u8, sk_len: usize,
    _pk: *const u8, _pk_len: usize,
    nf_out: *mut u8, nf_cap: usize,
) -> i32 {
    guard(|| {
        if sk.is_null() || nf_out.is_null() || nf_cap < NULLIFIER_BYTES { return RET_ERR; }
        let sk_seed = unsafe { slice::from_raw_parts(sk, sk_len) };
        let (_pk, secret) = raptor::keygen(sk_seed);
        let nf = raptor::nullifier(&secret);
        unsafe { slice::from_raw_parts_mut(nf_out, NULLIFIER_BYTES).copy_from_slice(&nf); }
        RET_OK
    })
}

#[no_mangle]
pub extern "C" fn ccx_pq_sign(
    msg: *const u8, msg_len: usize,
    ring: *const u8, ring_count: usize, member_stride: usize,
    sk: *const u8, sk_len: usize, signer_index: usize,
    sig_out: *mut u8, sig_len: *mut usize,
) -> i32 {
    guard(|| {
        if msg.is_null() || ring.is_null() || sk.is_null() || sig_out.is_null() || sig_len.is_null() {
            return RET_ERR;
        }
        if member_stride < PUBKEY_BYTES || ring_count == 0 { return RET_ERR; }
        let msg = unsafe { slice::from_raw_parts(msg, msg_len) };
        let ring_bytes = unsafe { slice::from_raw_parts(ring, ring_count * member_stride) };
        let mut ring_polys: Vec<[u16; N]> = Vec::with_capacity(ring_count);
        for i in 0..ring_count {
            let off = i * member_stride;
            let enc = &ring_bytes[off..off + PUBKEY_BYTES];
            match fc::modq_decode(enc) {
                Some(p) => ring_polys.push(p),
                None => return RET_ERR,
            }
        }
        let sk_seed = unsafe { slice::from_raw_parts(sk, sk_len) };
        let (_pk, secret) = raptor::keygen(sk_seed);
        // deterministic signing seed for the PoC (in production a wallet derives this);
        // bind to sk+msg so verification works and tests reproduce.
        let mut sign_seed = Vec::from(&b"abi-sign"[..]);
        sign_seed.extend_from_slice(sk_seed);
        let sig = match raptor::sign(msg, &ring_polys, &secret, signer_index, &sign_seed) {
            Ok(s) => s, Err(_) => return RET_ERR,
        };
        let packed = match pack(&sig) { Some(p) => p, None => return RET_ERR };
        let cap = unsafe { *sig_len };
        if cap < packed.len() {
            unsafe { *sig_len = packed.len(); } // tell caller required size
            return RET_ERR;
        }
        unsafe {
            slice::from_raw_parts_mut(sig_out, packed.len()).copy_from_slice(&packed);
            *sig_len = packed.len();
        }
        RET_OK
    })
}

#[no_mangle]
pub extern "C" fn ccx_pq_verify(
    msg: *const u8, msg_len: usize,
    ring: *const u8, ring_count: usize, member_stride: usize,
    sig: *const u8, sig_len: usize,
    nf_out: *mut u8, nf_cap: usize,
) -> i32 {
    guard(|| {
        if msg.is_null() || ring.is_null() || sig.is_null() || nf_out.is_null() { return RET_ERR; }
        if nf_cap < NULLIFIER_BYTES || member_stride < PUBKEY_BYTES || ring_count == 0 { return RET_ERR; }
        let msg = unsafe { slice::from_raw_parts(msg, msg_len) };
        let ring_bytes = unsafe { slice::from_raw_parts(ring, ring_count * member_stride) };
        let mut ring_polys: Vec<[u16; N]> = Vec::with_capacity(ring_count);
        for i in 0..ring_count {
            let off = i * member_stride;
            let enc = &ring_bytes[off..off + PUBKEY_BYTES];
            match fc::modq_decode(enc) { Some(p) => ring_polys.push(p), None => return RET_ERR }
        }
        let sig_bytes = unsafe { slice::from_raw_parts(sig, sig_len) };
        let parsed = match unpack(sig_bytes, ring_count) { Some(s) => s, None => return RET_ERR };
        match raptor::verify(msg, &ring_polys, &parsed) {
            Ok(nf) => {
                unsafe { slice::from_raw_parts_mut(nf_out, NULLIFIER_BYTES).copy_from_slice(&nf); }
                RET_OK
            }
            Err(_) => RET_ERR,
        }
    })
}

// ================= compact packing =================
//
// Layout (all integers as canonical LEB128 varints, no padding):
//   varint ring_count
//   for each member:
//     varint len(comp(r0)) || comp(r0)
//     varint len(comp(r1)) || comp(r1)
//     32 bytes b
//   modq(aots)                       [fixed 897 bytes]
//   varint len(comp(s0)) || comp(s0)
//   varint len(comp(s1)) || comp(s1)
//
// comp() is Falcon's native signature compressor (Golomb-style) on each short poly.

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 { byte |= 0x80; }
        out.push(byte);
        if v == 0 { break; }
    }
}
fn get_varint(inp: &[u8], pos: &mut usize) -> Option<u64> {
    let mut v = 0u64; let mut shift = 0;
    loop {
        if *pos >= inp.len() || shift >= 64 { return None; }
        let byte = inp[*pos]; *pos += 1;
        v |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 { break; }
        shift += 7;
    }
    Some(v)
}

fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}
fn get_blob<'a>(inp: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let len = get_varint(inp, pos)? as usize;
    if *pos + len > inp.len() { return None; }
    let b = &inp[*pos..*pos + len];
    *pos += len;
    Some(b)
}

pub fn pack(sig: &Signature) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    put_varint(&mut out, sig.members.len() as u64);
    for m in &sig.members {
        let c0 = fc::comp_encode(&m.r0)?;
        let c1 = fc::comp_encode(&m.r1)?;
        put_blob(&mut out, &c0);
        put_blob(&mut out, &c1);
        out.extend_from_slice(&m.b);
    }
    let aots = fc::modq_encode(&sig.aots)?;
    if aots.len() != PUBKEY_BYTES { return None; }
    out.extend_from_slice(&aots);
    let s0 = fc::comp_encode(&sig.ots_sig.s0)?;
    let s1 = fc::comp_encode(&sig.ots_sig.s1)?;
    put_blob(&mut out, &s0);
    put_blob(&mut out, &s1);
    Some(out)
}

pub fn unpack(inp: &[u8], expect_ring: usize) -> Option<Signature> {
    let mut pos = 0usize;
    let count = get_varint(inp, &mut pos)? as usize;
    if count != expect_ring { return None; }
    let mut members = Vec::with_capacity(count);
    for _ in 0..count {
        let c0 = get_blob(inp, &mut pos)?;
        let r0 = fc::comp_decode(c0)?;
        let c1 = get_blob(inp, &mut pos)?;
        let r1 = fc::comp_decode(c1)?;
        if pos + 32 > inp.len() { return None; }
        let mut b = [0u8; 32];
        b.copy_from_slice(&inp[pos..pos + 32]);
        pos += 32;
        members.push(Member { r0, r1, b });
    }
    if pos + PUBKEY_BYTES > inp.len() { return None; }
    let aots = fc::modq_decode(&inp[pos..pos + PUBKEY_BYTES])?;
    pos += PUBKEY_BYTES;
    let s0b = get_blob(inp, &mut pos)?;
    let s0 = fc::comp_decode(s0b)?;
    let s1b = get_blob(inp, &mut pos)?;
    let s1 = fc::comp_decode(s1b)?;
    // reject trailing garbage (canonical length)
    if pos != inp.len() { return None; }
    Some(Signature { members, aots, ots_sig: OtsSig { s0, s1 } })
}

/// Exposed for the harness: pack a signature and return its byte length.
pub fn packed_len(sig: &Signature) -> usize { pack(sig).map(|p| p.len()).unwrap_or(0) }

// silence unused import warnings for types only used via re-export paths
#[allow(unused_imports)]
use raptor::RaptorSecretKey as _Sk;
#[allow(dead_code)]
fn _touch(_s: &RaptorSecretKey) {}
