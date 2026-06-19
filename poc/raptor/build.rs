// build.rs — compile the vendored PQClean Falcon-512 "clean" sources + our C shim into a
// static lib linked into the crate.  All vendored C is MIT (Falcon Project) / CC0 (PQClean
// fips202, randombytes).  See vendor/falcon/LICENSE.falcon and PROGRESS.md provenance.
//
// FLOATING-POINT DETERMINISM (consensus-critical):
// The PQClean "clean" variant of Falcon ships ONLY the emulated, integer-only fpr layer
// (`typedef uint64_t fpr;` in fpr.h; fpr.c implements add/mul/div/sqrt/expm in pure uint64
// arithmetic; set_fpu_cw() is a no-op stub).  There is NO native-`double` path in this
// variant and NO FALCON_FPNATIVE/FALCON_FPEMU conditional to select one — the native-double
// fpr lives only in the avx2/aarch64 variants, which we do NOT vendor.  Consequently Falcon
// keygen AND signing here are bit-exact across compilers, optimisation levels and -march:
// verified by a cross-config KAT sweep (-O0/-O3, ±-ffast-math, ±-ffp-contract=fast,
// -march=x86-64) all yielding an identical keygen KAT digest.  The defensive flags below pin
// strict FP semantics so a stray ambient $CFLAGS can never reintroduce contraction/fast-math
// into any future code added to these units; for the current integer-only sources they are a
// belt-and-braces no-op.

use std::path::PathBuf;

fn main() {
    let vendor = PathBuf::from("vendor/falcon");

    let falcon_srcs = [
        "codec.c", "common.c", "fft.c", "fpr.c", "keygen.c",
        "rng.c", "sign.c", "vrfy.c",
        // PQClean common deps Falcon's inner.h binds to:
        "fips202.c", "randombytes.c",
    ];

    let mut build = cc::Build::new();
    build
        .include(&vendor)
        .include("csrc")
        // Integer-only fpr (no native double) — see header comment.  Pin strict FP semantics
        // defensively so contraction/reassociation can never silently enter a compiled unit.
        .flag_if_supported("-ffp-contract=off")
        .flag_if_supported("-fno-fast-math")
        .opt_level(3)
        .warnings(false);

    for s in falcon_srcs {
        build.file(vendor.join(s));
    }
    // our clean-room shim
    build.file("csrc/raptor_falcon.c");

    build.compile("raptorfalcon");

    println!("cargo:rerun-if-changed=csrc/raptor_falcon.c");
    println!("cargo:rerun-if-changed=vendor/falcon");
}
