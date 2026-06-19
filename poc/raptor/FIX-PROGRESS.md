# Raptor spike — adversarial-review fix progress (COMPLETE)

Worked ONLY in `~/raptor-spike/` (isolated crate, WSL host). No conceal-core changes, no merge,
no push. Build/test: `cd ~/raptor-spike && source ~/.cargo/env && cargo run --release --bin <harness|adversary|stats|bench>`.

Baseline (before fixes): harness 24/24, adversary 3/3, C-ABI 6/6, ring-6 sig = 9,701 B.
FINAL (clean `cargo clean` rebuild): **harness 25/25, adversary 0 failures (10 probes), stats PASS,
C-ABI 6/6, ring-6 sig = 9,719 B.**

## CRITICAL-1 — non-signer sampling uses Falcon's genuine preimage distribution — DONE

`approx_gaussian` CLT path removed. Non-signer (r0,r1) now come from Falcon's own `sign_target`
(random target `u` under a throwaway key; key + `u` discarded). One throwaway key per signature,
shared across non-signers (each gets an independent fresh target + randomness => independent
genuine-Falcon preimages). `c_i = r0 + a_i*r1 + h*b` still computed, ring relation/verify unchanged.

Evidence (`src/bin/stats.rs`, 400 sigs over ring-6):
  signer     : stddev 165.96, exkurt +0.001, max|c| 866, sqnorm_mean 28,202,863
  non-signer : stddev 165.62, exkurt -0.004, max|c| 803, sqnorm_mean 28,087,670
  => Δstddev 0.20%, Δexkurt 0.005, Δsqnorm 0.41% — coincide within sampling noise (old CLT diverged
     on kurtosis + the ±2047/±6σ tail clamp). Indistinguishability shown empirically, NOT proven.
Re-measured size/timing:
  ring | bytes | sign ms | verify ms
     2 |  4661 |  23.4   |  2.17
     4 |  7187 |  32.6   |  4.18
     6 |  9719 |  40.8   |  5.57
     8 | 12251 |  49.5   |  7.27
    16 | 22344 |  84.1   | 14.08
  Sign time up (genuine sampling: 1 throwaway keygen + L-1 real preimages per sig); verify unchanged.

## SECONDARY — all DONE

- HIGH-1 (keygen KAT tripwire): `raptor.rs` pins SHAKE256_32(modq(a0)||modq(aots)) for a fixed seed;
  harness check #0 = `keygen_kat_ok()`; `assert_keygen_kat()` for deployments. DETECTS cross-platform
  Falcon FP-keygen drift; does NOT fix it (integer-FP build = phase-2 consensus blocker). Sensitivity
  positive-controlled (drifted key -> different digest). NOTE: replaced an earlier weaker draft KAT
  (a0[0]/aots[0] coeff pins) with the full-vector digest; the digest version is authoritative.
- CRITICAL-2 (b_i in Db): `verify` calls `b_is_canonical` per member (coeffs in {0,1}, support < 256,
  exact byte round-trip), rejecting non-canonical b instead of relying on [u8;32] typing.
- MEDIUM-2 (FFI robustness): C shim null-checks all args (sign_dyn is void => no rc); Rust
  `sign_target` asserts r0 + r1*a == u_target (mod q) on EVERY preimage (signer + non-signers).
- HIGH-2 (adversary): 10 probes w/ positive controls — forged-OTS, cross-ring replay, ring-1
  (zero-anonymity doc), null-ring, nullifier-collision sanity, plus the original 3.
- MEDIUM-1 (ots transcript): `ots_target` length-prefixes member count + each r0/r1/b/a0/aots region.

## Final suite status (clean rebuild)
- harness: 25 passed, 0 failed (KAT #0 + round-trip + soundness + linkability + canonicity + sizes)
- adversary: 0 failures across 10 probes (each rejection has a passing positive control)
- stats: PASS (signer/non-signer distribution match within sampling noise)
- C-ABI (csrc/abi_test.c against libraptor_spike.so): 6/6 PASS

## Remaining open (audit / phase-2)
- Real integer/emulated-FP Falcon keygen (the only true cross-platform determinism fix; KAT only detects).
- Formal anonymity proof / statistical-distance bound (stats shows match, not a proof).
- paramch `h` derivation ceremony (currently a fixed domain string).
- Constant-time / side-channel review (schoolbook poly-mul + sampler are not constant-time).
- Norm-bound B1 re-derivation and the b-algebra (XOR vs R_q add/sub) vs the reference.
- Unaudited PoC. "It verifies" != "it's sound." Do not guard funds with this.

## Process note (concurrency hazard caught)
During the session a stale/foreign `harness.rs` (a prior draft's coeff-pin KAT) was on disk and an
early rsync of raptor.rs/harness.rs did not land (md5 mismatch). Caught via md5 + mtime audit;
re-pushed with post-push md5 verification, then re-validated from a full `cargo clean` rebuild so
the final numbers above are against the verified source, not a cached/foreign binary.
