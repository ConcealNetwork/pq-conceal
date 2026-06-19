# Raptor Linkable Ring Signature — Clean-Room Spike Report

**Status:** COMPLETE + POST-REVIEW HARDENING APPLIED. Standalone Rust PoC in `~/raptor-spike/`
on the WSL build host. Compiles, validates (**25/25 functional incl. keygen-KAT + 10/10
adversarial probes + statistical anonymity sanity + 6/6 C-ABI**), and produces real measured
signature sizes. **NOT consensus-wired. Unaudited research crypto for a testnet PoC.**

All claims below are framed accordingly — a spike to de-risk the construction and measure sizes,
not production-ready cryptography. **Section 0 records the fixes applied after two independent
adversarial reviews; sections 1-6 are the original spike report, with stale counts/caveats
updated in place.**

---

## 0. Post-adversarial-review hardening

Two independent reviews validated the APPROACH (license-clean, construction faithful, linkability
crux enforced, ~9.7 KB @ ring-6) and flagged the items below. All were addressed in `~/raptor-spike/`
(no conceal-core changes, no merge, no push). Final suite: **harness 25/25, adversary 0 failures
(10 probes), stats PASS, C-ABI 6/6**, all from a `cargo clean` rebuild.

### CRITICAL-1 — non-signer sampling now uses Falcon's genuine preimage distribution (FIXED)

**Problem.** `approx_gaussian` drew each non-signer `(r0,r1)` from a per-coordinate CLT Gaussian
(sum of 12 uniforms, clamp at ±2047, tails truncated at ±6σ). That marginal has the wrong tail
shape and no inter-coordinate lattice covariance, so it is *statistically distinguishable* from
the signer's genuine Falcon trapdoor preimage. An adversary holding many on-chain signatures could
score "which member looks like a real Falcon preimage" and partition the ring to unmask the signer
— defeating sender anonymity.

**Fix (`src/raptor.rs`).** Deleted the CLT path. Non-signer `(r0,r1)` are now produced by running
Falcon's own trapdoor preimage sampler (`sign_target`) on a uniformly random target `u` under a
**throwaway Falcon key**, keeping the short `(r0,r1)` and discarding `u` and the key. `c_i` is still
*computed* as `r0 + a_i·r1 + h·b` (it is defined, not solved), so the ring relation and verify are
unchanged. One throwaway key is created per *signature* and shared across all non-signers of that
ring — each non-signer draws an independent fresh target + fresh Falcon randomness, so the outputs
are independent genuine-Falcon preimages; the key is never published and never referenced again
(reusing it avoids `L-1` expensive keygens per signature with no effect on the observable
distribution, which is a property of the sampler/parameters, not of the trapdoor instance).

**Verification (anonymity restored).**
- (a) Functional: harness 25/25 PASS; the ring relation `c_i = r0_i + a_i·r1_i + h·b_i` still holds
  for non-signers and `verify()` still accepts honest sigs (adversary controls confirm).
- (b) New `src/bin/stats.rs`: signs 400× over a ring-6, separates the SIGNER member's vector from
  the NON-SIGNER vectors, and compares the moments an attacker keys on. Measured:

  | sample      | vecs | coeff stddev | excess kurtosis | max\|coeff\| | joint sqnorm mean | sqnorm stddev |
  |-------------|------|--------------|-----------------|--------------|-------------------|---------------|
  | signer      |  400 | 165.96       | +0.001          | 866          | 28,202,863        | 1,198,054     |
  | non-signer  | 2000 | 165.62       | −0.004          | 803          | 28,087,670        | 1,246,737     |

  Δstddev = 0.20 %, Δexcess-kurtosis = 0.005 (both ≈ 0, Gaussian-shaped), Δjoint-sqnorm-mean = 0.41 %.
  Signer and non-signer now coincide within sampling noise; the OLD CLT diverged on kurtosis and on
  the hard ±2047 / ±6σ tail clamp. **HONEST:** this shows the sampler now *matches* Falcon's output;
  it does NOT *prove* indistinguishability — a formal statistical-distance bound remains an audit item.
- (c) Sizes essentially unchanged (real Falcon vectors comp-encode the same): **ring-6 = 9,719 B**
  (was 9,701). Re-measured table:

  | ring | sig bytes | sign ms | verify ms |
  |------|-----------|---------|-----------|
  | 2    | 4,661     | 23.4    | 2.17      |
  | 4    | 7,187     | 32.6    | 4.18      |
  | 6    | 9,719     | 40.8    | 5.57      |
  | 8    | 12,251    | 49.5    | 7.27      |
  | 16   | 22,344    | 84.1    | 14.08     |

  **Sign time rose** (ring-6: ~10.6 ms → ~40.8 ms): the honest cost of genuine sampling is one
  throwaway keygen + `L-1` real Falcon preimages per signature (vs. cheap CLT draws). Verify time
  is unchanged. These are real numbers from the post-fix build.

### HIGH-1 — keygen-determinism KAT tripwire (DETECTS, does not fix)

`src/raptor.rs` pins `KAT_KEYGEN_DIGEST = SHAKE256_32( modq(a0) ‖ modq(aots) )` for a fixed seed,
computed on this reference build, and exposes `keygen_kat_ok()` / `assert_keygen_kat()`. The harness
runs it as check #0. It DETECTS any cross-platform Falcon keygen divergence (different
`a0`/nullifier ⇒ chain split / unspendable restore) by firing loudly on drift; the positive control
(`kat_neg` probe) confirms a perturbed key yields a different digest, so the gate is not vacuous.
**Update (FPEMU pass):** the underlying FP hazard is now addressed at build level — the vendored
PQClean "clean" Falcon is integer-only FP (no native `double`), so the tripwire is now expected to
PASS on every platform rather than DETECT drift; it remains as the cheap CI/boot safety net. A
cross-config KAT sweep (-O0/-O3, ±fast-math, ±ffp-contract, -march=x86-64) yields one identical
digest `8f24…745e`. See `FPEMU-PROGRESS.md`; true ARM/MSVC confirmation is a phase-2 item.
(Note: an earlier draft harness pinned only `a0[0]`/`aots[0]`; this version pins a digest of the
full `(a0, aots)` vectors, which is strictly stronger, and is now the authoritative KAT.)

### CRITICAL-2 — explicit `b_i ∈ {0,1}^256` (Db) check in verify (FIXED)

`verify()` now calls `b_is_canonical(&m.b)` for every deserialized member and rejects anything
outside Db, instead of relying on the `[u8;32]`-typing + byte-XOR-vs-transcript coincidence. The
check confirms the `b_i` polynomial has coefficients in `{0,1}`, support confined to the low 256
positions, and round-trips back to the exact `b_i` bytes. Closes the latent soundness gap if the
wire format ever widens `b_i` or changes its packing.

### MEDIUM-2 — FFI robustness on the preimage boundary (FIXED)

- `csrc/raptor_falcon.c`: `rfalcon_sign_target` now null-checks all pointer args. (PQClean's
  `sign_dyn` returns `void` and loops internally until it finds a short signature, so there is no
  return code to check — documented in the shim.)
- `src/falcon_ffi.rs`: `FalconKey::sign_target` now asserts the preimage relation
  `r0 + r1·a == u_target (mod q)` on **every** call (signer and non-signers). This catches a silent
  PQClean-internal-layout break (e.g. `s1`/`s2` written to different offsets) that would otherwise
  return garbage `(r0,r1)` that still packs. Exercised on every sign in the suite; passes.

### HIGH-2 — extended adversary coverage (DONE)

`src/bin/adversary.rs` now runs 10 probes, each rejection paired with a positive control so it
cannot pass vacuously:
- attack1-3 (original): swapped-aots, mismatched-aots/a0, member-reorder — all REJECTED.
- attack4 forged-OTS: a random short `(s0,s1)` inside the norm bound but not a transcript preimage
  is REJECTED by the OTS relation check (control: honest OTS verifies; the forged pair is asserted
  in-bound so rejection is due to the relation, not the norm gate).
- attack5 replay-across-ring: B's valid sig presented against a different ring (B at a different
  index) is REJECTED (control: a fresh honest sig on ring2 verifies AND yields the SAME nullifier —
  linkability holds across rings).
- attack6 ring-size-1: signs+verifies but documented as **zero anonymity** (anonymity set = 1);
  callers must enforce L ≥ 2.
- attack7 null-ring (size 0): REJECTED at both sign and verify (Err, not panic).
- attack8 nullifier-collision sanity: distinct signers ⇒ distinct nullifiers; same signer across
  different rings/messages ⇒ identical nullifier.
- attack9a/9b b_i tamper: flipping a bit of a non-signer's `b_i` (9a) or the signer's `b_pi` (9b)
  is REJECTED — both the `b_is_canonical`/XOR ring-hash relation contribute (control: untampered
  sig verifies). (These two probes were contributed in parallel by a co-agent on the shared tree.)

### MEDIUM-1 — boundary-safe ots transcript (FIXED)

`ots_target` now length-prefixes the member count and each `r0_i`/`r1_i`/`b_i` / `a0_i` / `aots`
region (`put_blob` with a u32 length). Today r0/r1 are fixed `[i16; N]` so a bare concatenation was
already injective; this keeps the Falcon-signed transcript collision-free if `N` or the member
layout ever changes. Sign and verify share the one `ots_target` function, so the encoding stays
self-consistent.

### Remaining open findings (audit / phase-2)

- **Real integer/emulated-FP Falcon keygen** — the only true fix for cross-platform keygen
  determinism. Phase-2 consensus blocker; the KAT only *detects* drift, same-platform.
- **Formal anonymity proof** — the stats harness shows the non-signer sampler now matches Falcon's
  distribution, but indistinguishability is not proven (needs a statistical-distance bound / reduction).
- **`paramch` h derivation ceremony** — `h` is derived from a fixed domain string; a real deployment
  needs a transparent nothing-up-my-sleeve / multiparty derivation.
- **Constant-time / side-channel review** — none performed; the schoolbook poly-mul and the sampler
  are not constant-time.
- **Norm bound `B1` re-derivation** and the **`b` algebra** vs the reference (XOR vs R_q add/sub) —
  still the two construction details worth a second opinion against the paper before consensus use.
- "It verifies" ≠ "it's sound." This stays an **unaudited PoC**.

---

## 1. Measured results (the headline)

Build host: WSL Ubuntu 24.04 x86_64, 16c/54 GB. Rust 1.96.0, gcc 13.3, release build.
Compact packing = Falcon's native `comp_encode` (Golomb-style) per short polynomial +
canonical varint framing, no padding.

### Size & timing vs ring size (compact encoding)

| ring | sig bytes | sign ms | verify ms |
|-----:|----------:|--------:|----------:|
|    2 |     4,654 |    7.6  |    2.3    |
|    4 |     7,179 |    9.4  |    3.9    |
|  **6** | **9,715** | **11.3** | **5.7** |
|    8 |    12,263 |   13.0  |    7.4    |
|   16 |    22,372 |   20.5  |   14.5    |

- **Ring size 6 = 9,715 bytes (9.5 KB) — under the ~10 KB target.**
- keygen: **23.3 ms/key** (two Falcon-512 keygens per Raptor key).
- Sizes grow linearly at ~1.26 KB/ring-member (construction is inherently linear-size).

### Byte breakdown at ring 6 (9,720 B for one instance)

| component | bytes | note |
|---|---:|---|
| members: 6 x (comp(r0)+comp(r1)) | 7,375 | ~614 B per short poly, Falcon-compressed |
| b nonces: 6 x 32 | 192 | 256-bit per-member nonces |
| aots (linking-tag pubkey, modq) | 896 | 512 coeffs x 14 bits |
| ots signature (comp(s0)+comp(s1)) | 1,228 | one-time sig binding the tag |
| varint framing | 29 | canonical LEB128 lengths, no padding |
| **total** | **9,720** | |

### Cross-check against the paper (eprint 2018/857, Table 1(b), Linkable Raptor-512)

The paper reports Linkable Raptor-512 sizes of **7.8 KB at 5 users** and **14.2 KB at 10 users**
(~1.28 KB/user), PK 0.9 KB, SK 9.1 KB, KeyGen 57 ms, verify 5.2 ms (5 users).

My measurements line up closely: ring-6 = 9.5 KB sits on the paper's ~1.28 KB/user line
(5->7.8 KB, 6->~9.0 KB, 10->14.2 KB). My per-member cost is marginally higher because I serialize
both r0 and r1 explicitly per member (the paper does likewise: "a lattice vector and a random
nonce of 2*lambda bits per user"). PK matches exactly (0.9 KB). This agreement is a strong signal
the clean-room construction is faithful to the paper.

> The paper's Table 2 lists much larger figures (80.6 KB @ 2 users) — those are for a different,
> higher-security (lambda=100, larger ring / standard-lattice) parameter set, NOT the practical
> Falcon-512 instantiation. Table 1(b) is the directly comparable one, and that is what I matched.

---

## 2. Validation: pass/fail for each required check

Run by `cargo run --release --bin harness` (+ `adversary`, + the C `abi_test`).

### Functional harness — 25/25 PASS (post-review; was 24/24)

(Check #0 is the keygen-determinism KAT tripwire added for HIGH-1 — see section 0.)

1. Round-trip: keygen -> sign -> verify accepts. Deterministic keygen: same seed => identical
   `a0`, `aots`, Falcon `f`. Pack -> unpack -> verify still accepts.
2. Soundness: tampered message rejected; tampered signature bytes rejected; tampered ring
   rejected; a non-member cannot sign as a ring member; a signer cannot claim another member's
   index; honest sign at correct index in a larger ring verifies.
3. Linkability: same signer across two DIFFERENT rings/messages => IDENTICAL nullifier;
   `link()` reports linked; two distinct signers => DISTINCT nullifiers; `link()` reports not-linked.
4. Canonicity: a real key is accepted; an out-of-range-coefficient (non-canonical) key is
   rejected; a wrong-length key is rejected.
5. Measurement: full size/timing table above.

### Adversarial probes — 0 failures across attack1-9 (post-review; was 3/3)

The original three crux probes still pass; HIGH-1 review added five more probe families with
positive controls. See section 0 (HIGH-2) for the full list. Summary:
- attack1 — swap a DIFFERENT `aots` into a valid signature: REJECTED (ring-hash and ots-signature
  relations both break). The nullifier is not freely substitutable.
- attack2 — a signer tries to mint a DIFFERENT nullifier for the SAME public key `a0` (different
  ots key, same a0): REJECTED at verify — `a0 = a + H1(aots)` binds the tag; using a different
  `aots` makes `a_i = a0 - H1(aots')` != the signer's real `a`, so the trapdoor no longer matches
  that ring index. This is the double-spend-linkability guarantee.
- attack3 — reorder members in a valid signature: REJECTED (transcript hash mismatch).
- attack4 — forged short OTS (in-bound, wrong relation): REJECTED. attack5 — cross-ring replay:
  REJECTED, with control confirming same-signer nullifier is stable across rings. attack6 —
  ring-size-1: works, documented as zero anonymity. attack7 — null ring: REJECTED (Err, not panic).
  attack8 — nullifier collision/linkability sanity: holds.

### C-ABI integration test — 6/6 PASS
A plain-C program (`csrc/abi_test.c`) links the compiled `libraptor_spike.so` and drives the
`ccx_pq_*` ABI with C types only: keygen+canonical, sign, verify, `nullifier(sk)==nullifier(verify)`,
cross-ring linkability, tamper rejection. All pass. Confirms the ABI is consumable from C++11.

---

## 3. Clean-room provenance statement

**Implemented from the paper only.** The Raptor construction — the CH+ chameleon-hash framework,
the ring-signature framework (sec 3.2), the linkable framework with the one-time-key tag (sec 3.3),
and the concrete Linkable Raptor over Falcon-512 (sec 6.5) — was implemented from the published
paper only: *Raptor: A Practical Lattice-Based (Linkable) Ring Signature*, Lu/Au/Zhang, ACNS 2019,
eprint **2018/857**. (eprint firewalls direct PDF fetch; PDF obtained via the web.archive mirror of
the same eprint URL; algorithms transcribed from sections 1.3, 3.1-3.3, 6.3-6.5. Extracted text at
`~/raptor-spike/paper_eprint.txt`.)

**No GPL Raptor code copied.** The upstream `zhenfeizhang/raptor` reference is GPLv3 +
patent-asserted. I did NOT read or reuse any source line from it. I used only its README prose
(high-level description). The paper's own Table 1(b) gave the reference numbers, so no black-box
oracle run was needed.

**Permissive Falcon vendored** into `~/raptor-spike/vendor/falcon/` from PQClean
(`crypto_sign/falcon-512/clean` + `common/`):

| file(s) | origin | license |
|---|---|---|
| codec.c, common.c, fft.c, fpr.c, fpr.h, keygen.c, rng.c, sign.c, vrfy.c, inner.h, api.h, pqclean.c | PQClean Falcon-512 "clean" | **MIT** — Copyright (c) 2017-2019 Falcon Project (Thomas Pornin); LICENSE.falcon: "This code is provided under the MIT license ... Permission is hereby granted, free of charge, ... without restriction" |
| fips202.c, fips202.h (SHAKE256) | PQClean common/ | **public domain / CC0** |
| randombytes.c, randombytes.h | PQClean common/ | **public domain / CC0** (linked, unused on deterministic paths) |

Falcon = NIST FN-DSA / FIPS 206, standardized royalty-free. LICENSE.falcon notes patent
US7308097B2 may touch parts of Falcon, with the designers' NIST pledge of a worldwide
non-exclusive royalty-free license upon standardization (now occurred). All vendored code is
MIT/CC0 => **MIT-compatible. No GPL anywhere in the spike.**

**Original clean-room code** (all MIT, written for this spike):
- `csrc/raptor_falcon.c` — C shim: deterministic keygen wrapper; **target-driven** Falcon preimage
  signing (drives Falcon's inner `sign_dyn` over an arbitrary target u_pi — the Raptor preimage
  step — instead of `hash_to_point(message)`); integer poly arithmetic mod q (schoolbook
  negacyclic multiply); `H1: bytes->R_q`; thin codec wrappers.
- `src/raptor.rs` — the Linkable Raptor construction.
- `src/abi.rs` — the `ccx_pq_*` C ABI + compact packing.
- `src/falcon_ffi.rs`, `src/bin/*` — FFI bindings + harnesses.

### Which Falcon operation Raptor invokes
Raptor's "Falcon.sign producing (r0,r1) with r0 + a*r1 = c" maps PRECISELY onto Falcon's inner
`PQCLEAN_FALCON512_CLEAN_sign_dyn(sig=s2, rng, f,g,F,G, hm=c, logn, tmp)`: it samples a short `s2`
for the chosen target `hm` and writes the matching `s1` to the start of `tmp`. So `r0 = s1`,
`r1 = s2`, `a = h = g/f`, and `s1 + s2*h = hm` is exactly the preimage relation. Verified
empirically that `r0 + r1*a == u` holds for the passed target. This is the Falcon trapdoor
preimage sampling the brief asked to confirm — exposed by calling the inner `sign_dyn` directly and
bypassing the public wrapper's `hash_to_point`.

---

## 4. Phase-2 integration notes (eventual consensus swap — NOT now)

### Slots behind the existing `ccx_pq_*` ABI
The crate exports the full swappable ABI from `pqc/include/pq_ring_sig.h` as a cdylib/staticlib
(`libraptor_spike.so`, all 9 `ccx_pq_*` symbols present, verified via `nm` + the C test). Sizes are
queried at runtime (`pubkey=896, seckey=48, nullifier=32`). The C++11 layer links it exactly like
the existing `ccx-pqc` crate. `scheme_id = 0x52415054` ("RAPT").
- pubkey = raw 896-byte modq encoding of `a0` (no PQClean 1-byte header; scheme-id frames).
- seckey export = the 48-byte deterministic seed (wallet/mnemonic-restorable) — keygen is fully
  deterministic from it, so the wallet stores only the seed, not the 9.1 KB expanded key.
- signature = compact packing (varints + comp-encoded short polys), parsed canonically
  (trailing-garbage rejected).

### Mapping the nullifier onto Conceal's spent-set / `m_spent_pq_nullifiers`
The linking tag is `aots` (the one-time public key); the on-chain **nullifier is a 32-byte SHAKE256
hash of `aots`** (domain-separated). Drop-in for the existing 32-byte `m_spent_pq_nullifiers`
model: on a spend, `verify` returns the nullifier; consensus inserts it and rejects re-use.
Same-signer-twice => identical 32-byte nullifier (proven by attack2 + the linkability harness), so
double-spends are caught exactly as in the current Tier-1 model. `aots` itself (896 B) rides inside
the signature; only its 32-byte hash needs to persist — spent-set entries stay the same size as today.

### Falcon FP-determinism — build-level CLOSED (was: consensus-determinism hazard)
**Update (FPEMU pass):** an earlier draft flagged this as the #1 consensus blocker on the premise
that "PQClean clean uses native `double` (FALCON_FPNATIVE)". That premise was **incorrect**. The
vendored **PQClean falcon-512 "clean"** variant ships ONLY the emulated, integer-only `fpr` layer
(`typedef uint64_t fpr;`; `fpr.c` is pure `uint64` arithmetic; `set_fpu_cw()` is a no-op stub; there
is no `FALCON_FPNATIVE`/`FALCON_FPEMU` conditional and no `double` in any compiled unit). Keygen AND
signing here are integer-only by construction. The old `build.rs` `.define("FALCON_FPNATIVE","1")`
was a dead no-op and has been removed. See `FPEMU-PROGRESS.md`.
- **Signing FP non-determinism is benign for verification anyway.** Verify is integer-only (recompute
  `c_i = r0 + a_i*r1 + h*b` mod q, check norms + hash + ots relation). Verify confirmed FP-free.
- **Keygen is now bit-exact across compiler/opt/arch on this ISA.** Evidence: a cross-config KAT
  sweep recomputed `SHAKE256_32(modq(a0) ‖ modq(aots))` under 7 configs that perturb *native* FP
  (-O0/-O3, ±-ffast-math, ±-ffp-contract=fast, -march=x86-64) — **all produced the identical digest**
  `8f24…745e` (= the value already pinned). fast-math/contraction not moving the digest one bit is
  direct evidence there is no native FP in the keygen path. `build.rs` additionally pins
  `-ffp-contract=off`/`-fno-fast-math` defensively.
- **Still phase-2 verification, not removed:** true ARM(aarch64)/MSVC builds were NOT run here — the
  integer-only argument is sound but an actual cross-arch KAT match is a phase-2 confirmation item
  (watch: 64x64 mul / 64-bit shifts use software helpers on *32-bit* targets; native on 64-bit
  ARM/x86). The `assert_keygen_kat()` boot/CI tripwire should still run on every platform (now
  expected to PASS everywhere). This engineering result does NOT replace the consensus-determinism
  review or the external audit.

### det-keygen status
Deterministic and reproducible (verified: same seed => identical key & tag). Cross-platform
bit-exactness is now supported AT BUILD LEVEL: the vendored Falcon is integer-only FP, and the
keygen KAT is identical across all opt/FP/ISA configs tested (see the FP-determinism section above
and `FPEMU-PROGRESS.md`). True ARM/MSVC KAT confirmation remains a phase-2 verification item. The signing seed in the
ABI is currently derived from `sk` (PoC convenience) so signatures reproduce; a real wallet would
derive per-spend signing randomness from the wallet seed + spend context.

### Soundness / parameter caveats (audit-needed)
- **Norm bound** uses Falcon-512's acceptance bound ||r0||^2+||r1||^2 <= 34,034,726. Right upper
  bound, but the paper's B1 = nu*eta*sqrt(n) should be re-derived against the anonymity parameter
  and double-checked — audit item.
- **Non-signer (r0,r1)** — UPDATED post-review (see section 0, CRITICAL-1). These are now drawn
  from Falcon's OWN preimage sampler (`sign_target` on a random target under a throwaway key), i.e.
  the genuine `D_{R,η}` Falcon produces — NOT the old CLT approximation, which has been removed.
  The `stats` harness shows signer and non-signer vectors coincide on width / tail shape / joint
  norm within sampling noise. Remaining caveats: still NOT constant-time, and indistinguishability
  is demonstrated empirically, NOT proven (a formal statistical-distance bound is an audit item).
- **b_i interpretation**: 256-bit b_i encoded as a binary polynomial (bit j -> coeff j, j<256),
  members combined via XOR (paper's {0,1}^256 / D_b), with H(transcript)->{0,1}^256. The sec 6.5
  note about "additions/subtractions over R_q instead of XOR" I read as applying to the
  a0 = a + H1(aots) mask, not the b combination (verify now checks b_i in D_b EXPLICITLY via
  `b_is_canonical` — see section 0, CRITICAL-2, no longer relying on the [u8;32]-typing coincidence).
  Defensible and consistent with the paper's verify, but the exact b algebra is the one place a
  second opinion against the reference would be worth getting before consensus use.
- PoC, not constant-time, not side-channel-hardened, unaudited.

---

## 5. Honest catches (what didn't work / shortcuts)

- **Public-key size was 896, not 897.** PQClean's 897-byte CRYPTO_PUBLICKEYBYTES includes a 1-byte
  format header the raw modq_encode omits (512*14 bits = 896 B). Caught when `pack` failed; fixed
  PUBKEY_BYTES = 896. The scheme-id frames in lieu of the header byte.
- **comp_encode rejects tail draws.** Falcon's compressor returns 0 for occasional large-norm
  preimages / oversized samples. Added reject-retry loops (non-signer pairs; re-roll signer's
  c_pi; re-roll ots signing randomness), capped at 64 attempts — mirrors Falcon's own internal
  rejection. Converges in 1-2 tries.
- **First non-signer sampler used sigma~80** (too small -> distinguishable from Falcon's ~+-680
  spread, an anonymity bug). Corrected to sigma~165. Still a CLT approximation (see caveat).
- **O(n^2) schoolbook poly-multiply** mod q instead of NTT — started an NTT, found the iterative
  twiddle indexing error-prone, chose the obviously-correct schoolbook path (n=512, a handful of
  mults/sig, ring<=16 -> microseconds). Production should use an NTT. The buggy NTT stub was removed.
- **Signing seed derived from sk** in the ABI for reproducible PoC tests — not how a production
  wallet should derive per-spend randomness.
- **No constant-time guarantees, no side-channel review, no formal proof check.** Construction
  matches the paper's algorithms and size/timing/linkability all validate, but "it verifies" is not
  "it's sound" — the discrete-Gaussian sampler, the b algebra, the norm bound, and cross-platform FP
  determinism are the four items an audit (and a read against the reference under a proper license,
  or a direct exchange with the authors) should close before this guards funds.

---

## 6. File map (`~/raptor-spike/`)
```
Cargo.toml, build.rs            crate + cc build of vendored Falcon
csrc/raptor_falcon.c            clean-room C shim (MIT)
csrc/abi_test.c                 plain-C integration test of the ccx_pq_* ABI
src/falcon_ffi.rs               FFI bindings + safe wrappers
src/raptor.rs                   Linkable Raptor construction
src/abi.rs                      ccx_pq_* C ABI + compact packing
src/bin/harness.rs              25-check functional + measurement harness (incl. keygen-KAT #0)
src/bin/adversary.rs            10 linkability/soundness probes (each with a positive control)
src/bin/stats.rs                CRITICAL-1 anonymity sanity (signer vs non-signer distribution)
src/bin/{probe,probe2,probe3,bench,breakdown}.rs   diagnostics
vendor/falcon/                  PQClean Falcon-512 (MIT) + fips202/randombytes (CC0) + LICENSE.falcon
paper_eprint.txt                extracted Raptor paper text (reference)
PROGRESS.md, REPORT.md          original spike report (section 0 added for post-review hardening)
FIX-PROGRESS.md                 post-review fix checkpoint log
```
Reproduce: `cd ~/raptor-spike && cargo run --release --bin harness` (then `adversary`, `stats`, `bench`).
C ABI: `cc -O2 csrc/abi_test.c -o /tmp/abi_test -Ltarget/release -lraptor_spike -lpthread -ldl -lm
&& LD_LIBRARY_PATH=target/release /tmp/abi_test`.
