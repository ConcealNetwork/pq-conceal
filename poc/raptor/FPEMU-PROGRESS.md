# FPEMU-PROGRESS.md — Falcon FP-determinism blocker (consensus blocker #1)

Goal: make Falcon keygen (and signing) bit-exact deterministic across platforms by ensuring the
vendored Falcon uses the **emulated integer-FP** `fpr` layer, then prove it with a cross-config KAT.

## Headline finding (the blocker was based on a misread)

The vendored Falcon is the **PQClean falcon-512 "clean"** variant. That variant ships **only** the
emulated, integer-only `fpr` implementation — there is **no native-`double` path in it at all**:

- `vendor/falcon/fpr.h`: `typedef uint64_t fpr;` (the integer-emulation type — NOT `typedef double fpr`).
- `vendor/falcon/fpr.c` (1622 lines): `fpr_add/sub/mul/div/sqrt/expm/rint/...` implemented in pure
  `uint64` bit arithmetic (`FPR_NORM64`, `fpr_ursh`, mantissa/exponent packing). No `double`/`float`
  variables in any compiled unit — the only "double"/"float" tokens in the 8 compiled `.c` files are
  three occurrences inside **comments** ("convert int to float", "double the mantissa").
- `vendor/falcon/inner.h`: unconditionally `#include "fpr.h"`; `set_fpu_cw()` is a **no-op stub**.
  There is **no `FALCON_FPNATIVE` / `FALCON_FPEMU` conditional** in the clean variant — that toggle
  and the native-double `fpr` live only in the `avx2` / `aarch64` variants, which we do NOT vendor.

Therefore the old `build.rs` line `.define("FALCON_FPNATIVE", "1")` was a **dead no-op**: nothing in
the clean sources reads it. The build was **already integer-FP**. The earlier review's premise — "PQClean
clean uses native `double` (FALCON_FPNATIVE)" — was factually incorrect about which backend the clean
variant compiles.

## What was done

1. Verified the FP backend is integer-only (source grep above).
2. Cross-config KAT determinism sweep (the real evidence): rebuilt the crate under 7 configs that
   would perturb *native* FP but must NOT change *integer* FP, recomputing the keygen KAT digest
   `SHAKE256_32( modq(a0) ‖ modq(aots) )` each time. **All 7 produced the identical digest:**

   ```
   8f245c82dc7390f3cb4d8955556a45d56af41c83a37fc0388b996b58f295745e
   ```

   | config                          | CFLAGS                                  | keygen KAT digest |
   |---------------------------------|-----------------------------------------|-------------------|
   | default (-O3)                   | <default>                               | 8f24…745e         |
   | -O0                             | -O0                                     | 8f24…745e         |
   | -O3 explicit                    | -O3                                     | 8f24…745e         |
   | fast-math                       | -O3 -ffast-math                         | 8f24…745e         |
   | ffp-contract=fast               | -O3 -ffp-contract=fast                  | 8f24…745e         |
   | O0 + fast-math + contract       | -O0 -ffast-math -ffp-contract=fast      | 8f24…745e         |
   | baseline ISA                    | -O2 -march=x86-64 -mtune=generic        | 8f24…745e         |

   `-ffast-math` + `-ffp-contract=fast` are precisely the flags that move *native*-FP results (FMA
   contraction, reassociation, denormal flushing). The digest not moving one bit is direct evidence
   the compiled keygen path contains **no native floating-point**. (Flag delivery confirmed: the `cc`
   crate logs `CFLAGS = Some(-O0 -ffast-math -ffp-contract=fast)` and appends them after its own `-O3`,
   so `-O0`/fast-math win.) The digest also equals the value `raptor.rs` already had pinned — so the
   prior pin was already the deterministic integer-FP value; **no re-pin was required.**

3. Hardened `build.rs`:
   - Removed the misleading `.define("FALCON_FPNATIVE", "1")`.
   - Added a header comment documenting the integer-FP guarantee + the KAT-sweep evidence.
   - Defensively pinned `-ffp-contract=off` / `-fno-fast-math` (`flag_if_supported`) so a stray
     ambient `$CFLAGS` can never reintroduce contraction/fast-math into any future code added to
     these units. For the current integer-only sources these flags are a belt-and-braces no-op.
   - Rebuilt clean: KAT digest unchanged (`8f24…745e`).

4. Re-ran all suites — all green (see below).

## Test status (post-hardening, release build, WSL x86_64 Ubuntu 24.04)

- harness:   25 passed / 0 failed (incl. KAT tripwire check #0)
- adversary: 12 attacks / 0 failures
- stats:     anonymity sanity PASS
- C-ABI:     6/6 PASS (libraptor_spike.so via plain-C abi_test)

## Timings — NO perf cost (because nothing actually changed in the FP backend)

Because the build was already integer-FP, switching the label carried **zero** performance cost.
Timings match the prior table within run-to-run noise:

| ring | sig_bytes | sign_ms | verify_ms |  (vs prior REPORT table)
|------|-----------|---------|-----------|
| 2    | 4,650     | 20.7    | 2.08      |  (prior 23.4 / 2.17)
| 4    | 7,171     | 29.1    | 3.73      |  (prior 32.6 / 4.18)
| 6    | 9,697     | 38.0    | 5.45      |  (prior 40.8 / 5.57)
| 8    | 12,217    | 46.1    | 7.06      |  (prior 49.5 / 7.27)
| 16   | 22,360    | 79.3    | 13.6      |  (prior 84.1 / 14.08)

keygen ~21.8 ms/key (prior ~23.3). Verify is integer-only (unchanged, as expected). There is **no
emulation slowdown to report** — the honest answer is the backend was emulated FP all along.

## Status of the blocker

**Build-level cross-platform FP determinism: CLOSED (engineering).** The compiled Falcon keygen and
signing are integer-only by construction (uint64 `fpr`), so the per-ULP rounding divergence that the
review feared cannot occur from compiler/opt/arch FP differences. Evidence: identical KAT across all
opt/FP/ISA configs + the structural fact that there is no `double` in the compiled units.

**Still NOT removed (phase-2 verification + human review):**
- True ARM (aarch64) and MSVC builds were not run on this host — the argument that integer ops are
  platform-independent is sound, but an actual cross-arch KAT match is a phase-2 confirmation item.
  (Caveat to watch: 64-bit-by-64-bit multiply and 64-bit shifts on a 32-bit target route through
  software helpers; on 64-bit ARM/x86 they are native and deterministic.)
- This does NOT substitute for the consensus-determinism review or the external cryptographic audit.
- The keygen KAT tripwire (`assert_keygen_kat`) should still run at boot on every platform as a CI/
  runtime gate — it is now expected to PASS everywhere rather than DETECT drift, but it remains the
  cheap safety net.

## Scope discipline

All work isolated in `~/raptor-spike`. No changes to the live conceal-core tree, no merge, no push.
Files touched: `build.rs`, `Cargo.toml` (+`[[bin]] katprint`), `src/bin/katprint.rs` (new sweep
helper), `REPORT.md`, `CODEX-ASSESS.md`, this file.
