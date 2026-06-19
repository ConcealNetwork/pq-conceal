# Raptor Ring-Sig Clean-Room Spike — PROGRESS

Status: IN PROGRESS. Checkpoint written incrementally (prior agents lost state on crash).
Host: WSL Ubuntu 24.04 x86_64 (ssh 100.100.90.103). Workspace: ~/raptor-spike/ (isolated; live conceal-core tree UNTOUCHED).

## Provenance / clean-room rules (CRITICAL)
- Conceal-core is MIT. Upstream Raptor (zhenfeizhang/raptor) is GPLv3 + patent-asserted — NOT read, NOT copied.
  - We only used the GPL repo's README *prose* (high-level description) and may use its built binary as a black-box
    size/timing oracle. NO source line from it is read or reused.
- Raptor *construction* implemented FROM THE PAPER ONLY: eprint 2018/857 ("Raptor: A Practical Lattice-Based
  (Linkable) Ring Signature", Lu/Au/Zhang, ACNS 2019). Paper PDF fetched via web.archive mirror (eprint firewalls
  direct PDF). Algorithm specs transcribed from paper sections 1.3, 3.1-3.3, 6.3-6.5. Saved: ~/raptor-spike/paper_eprint.txt
- Falcon-512 primitive: vendored from PQClean crypto_sign/falcon-512/clean (Copyright 2017-2019 Falcon Project,
  MIT-style permissive "Permission is hereby granted, free of charge ... without restriction"). PQClean repo is CC0.
  Falcon = NIST FN-DSA / FIPS 206, royalty-free. MIT-compatible. NO GPL.

## The construction (Linkable Raptor, paper §6.5) — what we implement
Falcon over Rq = Zq[x]/(x^n+1), n=512, q=12289. h = public CH+ polynomial (paramch), fixed system param.
Per-signer: TWO Falcon keypairs derived deterministically from seed:
  - main:  (a, f,g,F,G)   [a = g/f]
  - ots:   (aots, fots,...)   [the linking-tag keypair]
  Public key a0 := a + H1(aots) mod q   (H1: bytes -> Rq, random oracle = SHAKE256-derived poly).
  Secret key = both trapdoors + aots.
  NULLIFIER / linking tag = aots (the ots public key). Same signer => same aots (a0 fixed, a fixed => H1(aots) fixed
  => aots fixed). Two sigs w/ equal aots are LINKED. Soundness REQUIRES aots deterministically bound to seed at keygen.
Sign(skπ, µ, ring={a0_1..a0_ℓ}):
  1. ai = a0_i - H1(aots) for all i  (so a_π == signer's real main a).
  2. for i≠π: bi <-$ {0,1}^256 ; (ri0,ri1) <- D_{R,η}^2 (discrete Gaussian) ; ci = ri0 + ai*ri1 + h*bi.
  3. for i=π: cπ <-$ Rq.
  4. bπ s.t. b1 (+) ... (+) bℓ = H(µ, c1..cℓ).  [paper note: use add/sub over Rq, not XOR — bi live in Rq-ish space]
  5. uπ = cπ - h*bπ.
  6. (rπ0,rπ1) = Falcon.sign(aπ, skπ; uπ)  s.t. rπ0 + rπ1*aπ = uπ.   <-- the trapdoor preimage step
  7. sig = Falcon.sign(aots, ots-sk; ({ri0,ri1,bi}, {a0_i}, aots)).   <-- one-time sig binds the tag
  σ = ({ri0,ri1,bi}_{i=1..ℓ}, aots, sig).
Verify(µ,σ,ring):
  1. ai = a0_i - H1(aots).
  2. norms ‖ri0‖,‖ri1‖ ≤ B1 and bi ∈ Db.
  3. ci = ri0 + ai*ri1 + h*bi ; check Σ⊕ bi == H(µ,c1..cℓ).
  4. verify sig over ({ri0,ri1,bi},{a0_i},aots) under aots.
Link(σ,σ'): aots == aots'.

### KEY MAPPING to Falcon's PQClean inner API (the preimage step, step 6)
Falcon.sign producing (r0,r1) with r0 + a*r1 = c is EXACTLY Falcon's sign_dyn + the (s1,s2) pair:
  - hash target c = hash_to_point(nonce, msg) — but here the "message" is the chosen target uπ, so we must sign a
    target polynomial directly, NOT hash_to_point(µ). => we drive the inner sampler with c set = coefficients of uπ.
  - PQCLEAN_FALCON512_CLEAN_sign_dyn(sig=s2, sc, f,g,F,G, hm=c, logn=9, tmp) gives short s2 with s1 = c - s2*h... 
    Actually Falcon: s1 + s2*h = c where h=pk. verify_recover recovers h from (c0,s1,s2). Map: our a==h, r1==s2, r0==s1.
  => Need to expose sign over an arbitrary target c (not hash_to_point of a message). PQClean's sign_dyn already takes
     hm (the target point) directly; the pqclean.c wrapper computes hm via hash_to_point. We bypass the wrapper and
     call the inner sign_dyn with our own hm = uπ coefficients. Likewise verify via recompute c = r0 + a*r1 and the
     norm bound, OR verify_recover. We will recompute c ourselves (simplest, matches paper Verify step 3).

## Falcon inner API confirmed (from PQClean inner.h)
- PQCLEAN_FALCON512_CLEAN_keygen(rng, f,g,F,G,h, logn, tmp)  — det if rng=SHAKE256(seed). FALCON_KEYGEN_TEMP_9=14336.
- PQCLEAN_FALCON512_CLEAN_sign_dyn(sig, rng, f,g,F,G, hm, logn, tmp)  — produces short s2 for target hm. (CONFIRM exact sig)
- PQCLEAN_FALCON512_CLEAN_compute_public(h, f,g, logn, tmp)  — h = g/f.
- PQCLEAN_FALCON512_CLEAN_verify_recover / verify_raw.
- PQCLEAN_FALCON512_CLEAN_hash_to_point_ct(sc, x, logn, tmp).
- comp_encode / comp_decode (codec.c) = Falcon's compressed sig encoding (~666B/sig). USE THIS for packing.
- modq_encode/decode (14 bits/coeff) for public key a (897B), trim_i8_encode for f,g.
- q = 12289, n = 512.

## Packing plan (headline deliverable, target ~10KB @ ring 6)
Per ring member i: bi (256-bit = 32B), ri0 + ri1 as a Falcon-style compressed pair.
  - ri0,ri1 are short Gaussian polys (n=512 coeffs each, small). Use Falcon comp_encode on each => ~330B each? 
    Actually a full Falcon sig (one poly s2, since s1 recovered) is ~666B compressed. Here we carry BOTH r0,r1 explicitly
    (paper sends both). Compress each with comp_encode. Estimate ~650-1300B per member for (r0,r1) + 32B b.
  - aots: one Falcon pubkey = 897B (modq, 14b/coeff). sig (ots): one compressed Falcon sig ~666B.
  - canonical varint ring framing, no padding.
  Rough: ring6 ≈ 6*(comp(r0)+comp(r1)+32) + 897 + 666. If comp(r)≈330B => 6*(692)+1563 ≈ 5.7KB. If ≈650B => ~9.3KB.
  Will REPORT ACTUAL measured size, not estimate.

## C ABI to expose (from pqc/include/pq_ring_sig.h) — plain C, runtime-queried sizes, panic-guarded:
ccx_pq_scheme_id, _pubkey_bytes, _seckey_bytes, _nullifier_bytes, _pubkey_is_canonical,
_keygen(seed), _nullifier(sk,pk), _sign(msg,ring,stride,sk,signer_index,sig_out), _verify(...,nf_out).
nullifier_bytes = size of aots encoding (897B) OR a 32B hash of it — decide: use 32B = H(aots) as the on-chain tag
(smaller spent-set entry), but aots itself travels in the sig. Linkability check = compare H(aots). DECIDE in impl.

## Toolchain (installed this session)
- Rust 1.96.0 + cargo (rustup, ~/.cargo/bin). gcc 13.3. pdftotext. 16c/46GB free.

## TODO
[x] Fetch paper, transcribe algorithms.  [x] Fetch + license-check PQClean Falcon-512.  [x] Install Rust.
[ ] Vendor Falcon-512 clean C files into ~/raptor-spike/vendor/falcon (list every file + license).
[ ] Decide how to drive sign_dyn over arbitrary target uπ (verify exact inner signature).
[ ] Rust crate: cc build of Falcon + bindings; poly arith mod q (n=512); H, H1 via SHAKE256.
[ ] Implement keygen(det)/sign/verify/nullifier + C ABI + panic guards + canonical encode.
[ ] Compact packing (comp_encode).  [ ] Test harness: roundtrip, det, soundness, linkability, canonicity, size/time table.
[ ] REPORT.md with measured numbers + provenance + phase-2 integration notes + honest caveats.


## COMPLETE
All deliverables done. REPORT.md written. 24/24 harness + 3/3 adversary + 6/6 C-ABI pass.
Ring-6 compact sig = 9715 bytes [under 10KB target]. Matches paper Table 1b ~1.28KB/user.
Key hazard flagged: Falcon FP Gaussian sampler => cross-platform keygen determinism = consensus risk [REPORT sec 4].
No GPL. Falcon-512 = MIT [PQClean], fips202/randombytes = CC0. Construction from eprint 2018/857 only.
