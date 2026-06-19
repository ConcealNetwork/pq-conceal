//! Raptor spike validation + measurement harness.
//!
//! Runs: round-trip, deterministic keygen, soundness (tamper rejection), linkability,
//! canonicity, and a compact-size / verify-time table across ring sizes {2,4,6,8,16}.

use raptor_spike::abi;
use raptor_spike::falcon_ffi as fc;
use raptor_spike::raptor::{self, RaptorSecretKey, RaptorPublicKey};
use std::time::Instant;

fn keypair(seed: &[u8]) -> (RaptorPublicKey, RaptorSecretKey) {
    raptor::keygen(&fc::shake256(seed, 48))
}

fn build_ring(secrets: &[RaptorSecretKey]) -> Vec<[u16; fc::N]> {
    secrets.iter().map(|s| s.a0).collect()
}

fn main() {
    let mut pass = 0usize;
    let mut fail = 0usize;
    macro_rules! check {
        ($name:expr, $cond:expr) => {{
            if $cond { println!("  [PASS] {}", $name); pass += 1; }
            else     { println!("  [FAIL] {}", $name); fail += 1; }
        }};
    }

    println!("== Raptor spike validation ==\n");

    // ---------- 0. keygen-determinism KAT tripwire (HIGH-1) ----------
    // Same-platform determinism gate: detects cross-platform Falcon FP-keygen drift.  A failure
    // here means this build would emit incompatible keys/nullifiers (NOT a fix — see raptor.rs).
    println!("0. Keygen determinism KAT (HIGH-1 tripwire)");
    check!("keygen KAT matches pinned reference digest", raptor::keygen_kat_ok());

    // ---------- 1. round-trip + deterministic keygen ----------
    println!("\n1. Round-trip & deterministic keygen");
    let (pk_a, sk_a) = keypair(b"seed-alice");
    let (_pk_a2, sk_a2) = keypair(b"seed-alice");
    check!("det keygen: same seed => identical a0", sk_a.a0 == sk_a2.a0);
    check!("det keygen: same seed => identical aots", sk_a.aots == sk_a2.aots);
    check!("det keygen: same seed => identical main f", sk_a.main.f == sk_a2.main.f);

    let (pk_b, sk_b) = keypair(b"seed-bob");
    let (pk_c, sk_c) = keypair(b"seed-carol");
    let secrets = vec![sk_a.clone(), sk_b.clone(), sk_c.clone()];
    let ring = build_ring(&secrets);
    let _ = (&pk_a, &pk_b, &pk_c);

    let msg = b"transfer 10 CCX to wallet X";
    let sig = raptor::sign(msg, &ring, &sk_b, 1, b"sign-rand-1").expect("sign");
    let v = raptor::verify(msg, &ring, &sig);
    check!("verify accepts a valid signature", v.is_ok());
    check!("verify yields signer B's nullifier",
        v.ok() == Some(raptor::nullifier(&sk_b)));

    // pack/unpack round-trip
    let packed = abi::pack(&sig).expect("pack");
    let unpacked = abi::unpack(&packed, ring.len()).expect("unpack");
    let v2 = raptor::verify(msg, &ring, &unpacked);
    check!("verify accepts after pack->unpack round-trip", v2.is_ok());

    // ---------- 2. soundness ----------
    println!("\n2. Soundness (tamper rejection)");
    // tampered message
    check!("tampered message rejected",
        raptor::verify(b"transfer 9999 CCX", &ring, &sig).is_err());
    // tampered signature (flip a byte in packing)
    let mut bad = packed.clone();
    bad[10] ^= 0xff;
    let rej = match abi::unpack(&bad, ring.len()) {
        Some(s) => raptor::verify(msg, &ring, &s).is_err(),
        None => true, // decode rejected it outright
    };
    check!("tampered signature bytes rejected", rej);
    // tampered ring (swap a ring member for an unrelated key)
    let (_pkx, skx) = keypair(b"seed-mallory");
    let mut bad_ring = ring.clone();
    bad_ring[0] = skx.a0;
    check!("tampered ring rejected", raptor::verify(msg, &bad_ring, &sig).is_err());
    // a non-signer cannot forge: signer_index pointing at a member whose secret we lack.
    // Mallory tries to sign claiming to be index 0 (alice) but holds only her own key.
    let forge = raptor::sign(msg, &ring, &skx, 0, b"forge");
    check!("non-member cannot sign as a ring member (rejected at sign)",
        forge.is_err());
    // Even if Mallory is added to the ring at index 3 and signs honestly there, a signature
    // claiming index 1 with her key must fail (mismatched pk).
    let ring4: Vec<[u16; fc::N]> = {
        let mut r = ring.clone(); r.push(skx.a0); r
    };
    let mforge = raptor::sign(msg, &ring4, &skx, 1, b"forge2");
    check!("signer cannot claim another member's index", mforge.is_err());
    // honest signature by mallory at her real index verifies (sanity that ring4 is usable)
    let msig = raptor::sign(msg, &ring4, &skx, 3, b"ok").expect("mallory honest sign");
    check!("honest sign at correct index in larger ring verifies",
        raptor::verify(msg, &ring4, &msig).is_ok());

    // ---------- 3. linkability ----------
    println!("\n3. Linkability");
    // same signer (B), two DIFFERENT rings/messages => same nullifier
    let ring2 = vec![sk_c.a0, sk_b.a0]; // B at index 1, different ring
    let sig_b1 = raptor::sign(b"msg-one", &ring, &sk_b, 1, b"r1").expect("B sign 1");
    let sig_b2 = raptor::sign(b"msg-two", &ring2, &sk_b, 1, b"r2").expect("B sign 2");
    let nf_b1 = raptor::verify(b"msg-one", &ring, &sig_b1).expect("vB1");
    let nf_b2 = raptor::verify(b"msg-two", &ring2, &sig_b2).expect("vB2");
    check!("same signer, different rings => identical nullifier", nf_b1 == nf_b2);
    check!("link() reports linked for same signer", raptor::link(&sig_b1, &sig_b2));

    // two DISTINCT signers => distinct nullifiers
    let sig_aa = raptor::sign(b"m", &ring, &sk_a, 0, b"ra").expect("A sign");
    let nf_aa = raptor::verify(b"m", &ring, &sig_aa).expect("vA");
    check!("distinct signers => distinct nullifiers", nf_aa != nf_b1);
    check!("link() reports NOT linked for distinct signers", !raptor::link(&sig_aa, &sig_b1));

    // ---------- 4. canonicity ----------
    println!("\n4. Canonicity (pubkey_is_canonical)");
    let pk_enc = fc::modq_encode(&sk_a.a0).expect("encode");
    check!("canonical pubkey accepted",
        abi::ccx_pq_pubkey_is_canonical(pk_enc.as_ptr(), pk_enc.len()) == 1);
    // mangle: force the first coefficient's 14 bits to 0x3FFF (=16383 >= q), which modq_decode
    // must reject as out-of-range / non-canonical.  (At 14 bits/coeff over 896 bytes there are
    // no spare padding bits, so canonicity == every coeff in [0,q).)
    let mut mangled = pk_enc.clone();
    mangled[0] = 0xff;
    mangled[1] |= 0xc0; // top 14 bits now all 1 -> coeff 0 == 16383 >= 12289
    let mangled_rejected = abi::ccx_pq_pubkey_is_canonical(mangled.as_ptr(), mangled.len()) == 0;
    check!("mangled (out-of-range coeff) pubkey rejected", mangled_rejected);
    // wrong length rejected
    check!("wrong-length pubkey rejected",
        abi::ccx_pq_pubkey_is_canonical(pk_enc.as_ptr(), pk_enc.len() - 1) == 0);

    // ---------- 5. size / timing table ----------
    println!("\n5. Compact signature size & verify time vs ring size");
    println!("   ring | sig bytes | sign ms | verify ms");
    println!("   -----+-----------+---------+----------");
    let ring_sizes = [2usize, 4, 6, 8, 16];
    let mut table = Vec::new();
    for &rs in &ring_sizes {
        // build rs keypairs; signer at index rs/2
        let mut secs = Vec::new();
        for i in 0..rs {
            let (_p, s) = keypair(format!("ring-member-{}", i).as_bytes());
            secs.push(s);
        }
        let r = build_ring(&secs);
        let signer = rs / 2;
        let m = b"benchmark message";

        let t0 = Instant::now();
        let s = raptor::sign(m, &r, &secs[signer], signer, b"bench").expect("bench sign");
        let sign_ms = t0.elapsed().as_secs_f64() * 1e3;

        let packed = abi::pack(&s).expect("pack");
        let sz = packed.len();

        // verify timing: average over a few iterations
        let iters = 5;
        let t1 = Instant::now();
        let mut okall = true;
        for _ in 0..iters {
            okall &= raptor::verify(m, &r, &s).is_ok();
        }
        let verify_ms = t1.elapsed().as_secs_f64() * 1e3 / iters as f64;

        println!("   {:>4} | {:>9} | {:>7.1} | {:>8.2}", rs, sz, sign_ms, verify_ms);
        table.push((rs, sz, sign_ms, verify_ms, okall));
        check!(&format!("ring {} verifies", rs), okall);
    }

    println!("\n== SUMMARY: {} passed, {} failed ==", pass, fail);
    if fail == 0 { println!("ALL CHECKS PASSED"); }
    std::process::exit(if fail == 0 { 0 } else { 1 });
}
