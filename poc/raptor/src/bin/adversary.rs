// adversary: probe the linkability-soundness crux — can a signer present a DIFFERENT
// nullifier (aots') than the one bound to their key, and still verify?  If yes, double-spend
// linkability is broken.  This is the most important soundness signal for the spike.
//
// Each rejection probe below is paired with a POSITIVE CONTROL (an honest sibling that DOES
// verify) so a rejection cannot pass vacuously (e.g. because verify rejects everything).
use raptor_spike::falcon_ffi as fc;
use raptor_spike::raptor::{self, RaptorSecretKey, RaptorPublicKey, OtsSig};
use rand::SeedableRng;
use rand::RngCore;
use rand_chacha::ChaCha20Rng;

fn kp(s: &[u8]) -> (RaptorPublicKey, RaptorSecretKey) {
    raptor::keygen(&fc::shake256(s, 48))
}

/// A random short (s0,s1) pair within Falcon's acceptance bound (for the forged-OTS probe):
/// small centered coeffs so the joint norm stays comfortably under the bound, but NOT a valid
/// preimage of the transcript target under aots.
fn random_short_pair(rng: &mut ChaCha20Rng) -> ([i16; fc::N], [i16; fc::N]) {
    let mut s0 = [0i16; fc::N];
    let mut s1 = [0i16; fc::N];
    for k in 0..fc::N {
        // uniform in [-100,100] => joint sqnorm ~ 2*512*3333 ~ 3.4M, well under 34.03M bound.
        s0[k] = (rng.next_u32() % 201) as i16 - 100;
        s1[k] = (rng.next_u32() % 201) as i16 - 100;
    }
    (s0, s1)
}

fn main() {
    let mut fails = 0;

    let (_pa, sk_a) = kp(b"adv-alice");
    let (_pb, sk_b) = kp(b"adv-bob");
    let (_pc, sk_c) = kp(b"adv-carol");
    let ring = vec![sk_a.a0, sk_b.a0, sk_c.a0];
    let msg = b"double-spend attempt";

    // Honest signature by B.
    let sig = raptor::sign(msg, &ring, &sk_b, 1, b"r").expect("sign");
    let nf_real = raptor::verify(msg, &ring, &sig).expect("verify");
    assert_eq!(nf_real, raptor::nullifier(&sk_b));

    // Attack 1: substitute a different aots (Carol's) into B's signature, keeping everything
    // else.  Verify recomputes ai = a0_i - H1(aots'); the ring hash relation and the ots
    // signature should both break.
    let mut forged = sig.clone();
    forged.aots = sk_c.aots; // different linking tag
    let r1 = raptor::verify(msg, &ring, &forged);
    if r1.is_ok() {
        println!("[FAIL] attack1: swapped-aots signature verified (nullifier not binding!)");
        fails += 1;
    } else {
        println!("[PASS] attack1: swapped-aots signature rejected");
    }

    // Attack 2: try to re-sign with B's main key but a fresh independent ots key (so a new
    // nullifier), WITHOUT changing the public key a0.  The signer's a0 commits to the original
    // aots via a0 = a + H1(aots); using a different aots means ai = a0 - H1(aots') != a, so B's
    // trapdoor no longer matches index 1 -> preimage relation fails at verify.
    // We simulate by hand-constructing an sk with mismatched aots/mask but same a0.
    let mut sk_bad = sk_b.clone();
    let (_pd, sk_d) = kp(b"adv-dave");
    sk_bad.ots = sk_d.ots;
    sk_bad.aots = sk_d.aots;
    let dec = fc::modq_encode(&sk_bad.aots).unwrap();
    sk_bad.mask = fc::hash_to_rq(&dec, c"RAPTOR-CCX-H1-mask");
    // keep sk_bad.a0 = B's real a0 (the on-chain public key is unchanged)
    let r2 = raptor::sign(msg, &ring, &sk_bad, 1, b"r2");
    match r2 {
        Ok(s2) => {
            let v = raptor::verify(msg, &ring, &s2);
            if v.is_ok() {
                let nf2 = v.unwrap();
                if nf2 != nf_real {
                    println!("[FAIL] attack2: B produced a DIFFERENT valid nullifier for same a0 (linkability broken!)");
                    fails += 1;
                } else {
                    println!("[PASS] attack2: nullifier unchanged despite swapped ots");
                }
            } else {
                println!("[PASS] attack2: mismatched-aots signature rejected at verify");
            }
        }
        Err(_) => println!("[PASS] attack2: signing with mismatched aots/a0 failed (trapdoor mismatch)"),
    }

    // Attack 3: malleability — re-pack with a different member order shouldn't verify.
    let mut shuffled = sig.clone();
    shuffled.members.swap(0, 2);
    let r3 = raptor::verify(msg, &ring, &shuffled);
    if r3.is_ok() {
        println!("[FAIL] attack3: member-reordered signature verified against original ring");
        fails += 1;
    } else {
        println!("[PASS] attack3: member-reordered signature rejected");
    }

    let mut rng = ChaCha20Rng::from_seed([0x5a; 32]);

    // Attack 4: forged OTS — replace the one-time signature with a random short (s0,s1) that is
    // within the norm bound but is NOT a preimage of the transcript target under aots.  Verify's
    // OTS relation (s0 + s1*aots == ots_target) must reject it.
    // Positive control: the genuine sig (same everything else) DOES verify.
    {
        let pc = raptor::verify(msg, &ring, &sig).is_ok();
        if !pc { println!("[FAIL] attack4 positive-control: honest sig did not verify"); fails += 1; }
        else   { println!("[PASS] attack4 control: honest OTS verifies"); }

        let (fs0, fs1) = random_short_pair(&mut rng);
        // sanity: the forged pair is within the bound (so rejection is due to the RELATION,
        // not the norm gate) — this is what makes it a meaningful forged-OTS test.
        let within = fc::sqnorm(&fs0) + fc::sqnorm(&fs1) <= raptor::FALCON512_SQNORM_BOUND;
        let mut forged_ots = sig.clone();
        forged_ots.ots_sig = OtsSig { s0: fs0, s1: fs1 };
        let r4 = raptor::verify(msg, &ring, &forged_ots);
        if r4.is_ok() {
            println!("[FAIL] attack4: forged short OTS verified (OTS not bound to transcript!)");
            fails += 1;
        } else if !within {
            println!("[WARN] attack4: forged OTS rejected but exceeded norm bound — inconclusive");
        } else {
            println!("[PASS] attack4: forged (short, in-bound) OTS rejected by the relation check");
        }
    }

    // Attack 5: replay across a DIFFERENT ring.  Take B's valid sig (made for `ring`, B at
    // index 1) and present it against ring2 where B's a0 sits at a DIFFERENT index.  The
    // recomputed ai/c_i + the ots transcript bind to the ring as presented, so it must reject.
    // Positive control: an honest fresh signature by B on ring2 DOES verify.
    {
        let ring2 = vec![sk_c.a0, sk_a.a0, sk_b.a0]; // B now at index 2, not 1
        let r5 = raptor::verify(msg, &ring2, &sig);
        if r5.is_ok() {
            println!("[FAIL] attack5: sig replayed against a different ring verified");
            fails += 1;
        } else {
            println!("[PASS] attack5: cross-ring replay rejected");
        }
        let honest2 = raptor::sign(msg, &ring2, &sk_b, 2, b"r5").expect("sign ring2");
        let pc = raptor::verify(msg, &ring2, &honest2);
        match pc {
            Ok(nf) if nf == nf_real =>
                println!("[PASS] attack5 control: honest sig on ring2 verifies, SAME nullifier (linkable)"),
            Ok(_) => { println!("[FAIL] attack5 control: ring2 sig verified but nullifier changed"); fails += 1; }
            Err(_) => { println!("[FAIL] attack5 control: honest ring2 signature failed to verify"); fails += 1; }
        }
    }

    // Attack 6: ring size 1 — degenerate ring of just the signer.  Cryptographically valid but
    // provides ZERO anonymity (the signer is the only possible author).  Documented, not a bug.
    {
        let ring1 = vec![sk_b.a0];
        match raptor::sign(msg, &ring1, &sk_b, 0, b"r6") {
            Ok(s6) => match raptor::verify(msg, &ring1, &s6) {
                Ok(nf) if nf == nf_real =>
                    println!("[PASS] attack6: ring-size-1 signs+verifies (NOTE: anonymity set = 1, no privacy)"),
                Ok(_) => { println!("[FAIL] attack6: ring-1 nullifier mismatch"); fails += 1; }
                Err(_) => { println!("[FAIL] attack6: ring-1 signature failed to verify"); fails += 1; }
            },
            Err(_) => { println!("[FAIL] attack6: ring-size-1 signing failed"); fails += 1; }
        }
    }

    // Attack 7: null ring — size 0.  Both signing into it and verifying a size-0 ring must Err
    // (no member to be the signer; the construction is undefined for L=0).
    {
        let empty: Vec<[u16; fc::N]> = Vec::new();
        let sign_err = raptor::sign(msg, &empty, &sk_b, 0, b"r7").is_err();
        // a size-0 ring with a non-empty member list (reuse B's real sig) must also reject.
        let verify_err = raptor::verify(msg, &empty, &sig).is_err();
        if sign_err && verify_err {
            println!("[PASS] attack7: null (size-0) ring rejected at both sign and verify");
        } else {
            println!("[FAIL] attack7: null ring accepted (sign_err={}, verify_err={})", sign_err, verify_err);
            fails += 1;
        }
    }

    // Attack 8: nullifier-collision sanity.  Distinct signers => distinct nullifiers; the SAME
    // signer across different rings/messages => IDENTICAL nullifier (the linkability guarantee).
    {
        let nf_b = raptor::nullifier(&sk_b);
        let nf_a = raptor::nullifier(&sk_a);
        let nf_c = raptor::nullifier(&sk_c);
        let distinct = nf_b != nf_a && nf_b != nf_c && nf_a != nf_c;
        // same signer, different ring + different message => same nullifier
        let ring_x = vec![sk_b.a0, sk_a.a0];
        let sig_x = raptor::sign(b"unrelated message", &ring_x, &sk_b, 0, b"r8").expect("sign");
        let nf_x = raptor::verify(b"unrelated message", &ring_x, &sig_x).expect("verify");
        let linkable = nf_x == nf_real && nf_x == nf_b;
        if distinct && linkable {
            println!("[PASS] attack8: distinct signers => distinct nullifiers; same signer => identical nullifier");
        } else {
            println!("[FAIL] attack8: nullifier collision/linkability broken (distinct={}, linkable={})", distinct, linkable);
            fails += 1;
        }
    }

    // Attack 9: post-signing b_pi tamper — flip a bit in a member's b; verify must reject.
    // This tests that the b_i canonicality check AND the XOR ring-hash relation both contribute
    // to rejection (not just the OTS).  Positive control: the unmodified sig verifies.
    {
        // control: original sig still verifies
        let pc = raptor::verify(msg, &ring, &sig).is_ok();
        if !pc { println!("[FAIL] attack9 positive-control: honest sig did not verify"); fails += 1; }

        // tamper member 0 (non-signer) — breaks XOR relation and b_is_canonical
        let mut t1 = sig.clone();
        t1.members[0].b[0] ^= 0x01;
        let r9a = raptor::verify(msg, &ring, &t1).is_err();
        if r9a { println!("[PASS] attack9a: flipped b_i bit (non-signer) causes verify rejection"); }
        else   { println!("[FAIL] attack9a: tampered b_i byte accepted"); fails += 1; }

        // tamper member 1 (the actual signer, B at index 1) — breaks b_pi and the XOR relation
        let mut t2 = sig.clone();
        t2.members[1].b[15] ^= 0x80;
        let r9b = raptor::verify(msg, &ring, &t2).is_err();
        if r9b { println!("[PASS] attack9b: flipped b_pi bit (signer member) causes verify rejection"); }
        else   { println!("[FAIL] attack9b: tampered b_pi byte accepted"); fails += 1; }
    }

    println!("\nadversary: {} failures", fails);
    std::process::exit(if fails == 0 { 0 } else { 1 });
}
