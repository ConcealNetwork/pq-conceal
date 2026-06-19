# Raptor PoC — clean-room lattice linkable ring signature

A **clean-room** proof-of-concept of the **Raptor** linkable ring signature
([eprint 2018/857](https://eprint.iacr.org/2018/857), Lu/Au/Zhang, ACNS 2019) implemented over
**PQClean Falcon-512**. This is the leading post-quantum ring-signature candidate for Conceal's
small-ring, plaintext-amount privacy path — it hides the sender among a ring of decoys while staying
quantum-resistant.

> ⚠️ **UNAUDITED RESEARCH PoC — NOT production-ready and NOT safe to guard funds.** It is built,
> adversarially reviewed, and hardened, but the human gates below are not met. See `REPORT.md`,
> `CODEX-ASSESS.md`, and `VET-SUMMARY.md`.

## What it is
- Sender anonymity via a ring signature (signer hidden among the ring) + a 32-byte **nullifier**
  (`SHAKE256(aots)`) for double-spend linkability — the CryptoNote/key-image model, post-quantum.
- Built on Falcon-512's trapdoor preimage sampler; the construction is reimplemented **from the paper
  only**. Compact (Golomb-compressed) signatures.

## Build & run (Linux x86_64)
```
cargo run --release --bin harness     # 25 functional checks (round-trip, det-keygen, soundness, linkability, canonicity)
cargo run --release --bin adversary   # 12 adversarial probes (forged-OTS, replay, ring-1, null-ring, b-tamper, …)
cargo run --release --bin stats       # anonymity evidence: signer vs non-signer vector distributions
cargo run --release --bin bench       # signature size + sign/verify timing per ring size
cargo run --release --bin katprint    # the keygen-determinism KAT digest
```

## Measured results
- Ring-6 compact signature **9.7 KB** (matches the paper's Table 1(b) ~1.28 KB/user within ~5%); verify ~5.4 ms.
- Harness 25/25 · adversary 12/12 · C-ABI 6/6 · anonymity stats PASS.
- A C-ABI (`ccx_pq_*`, see `csrc/raptor_falcon.c` + `src/abi.rs`) so it drops in behind a swappable
  ring-sig backend. Integrated into the Conceal daemon on a local testnet branch (build + 72 PQ unit
  tests + e2e consensus all green) — see the docs site.

## License & provenance — MIT, no GPL
- The Raptor **construction** + the C shim are **original clean-room** work from the published paper —
  the GPL upstream reference (`zhenfeizhang/raptor`) was **never read or copied**.
- **Falcon-512** is vendored from **PQClean** (MIT — `vendor/falcon/LICENSE.falcon`, © Falcon Project /
  Thomas Pornin); `fips202`/`randombytes` are public-domain/MIT. Falcon is NIST FIPS 206, royalty-free.
- **No GPL anywhere.** MIT throughout (see `LICENSE`).

## Not production-ready — the human-only gates
External cryptographic **audit**; formal **anonymity + unforgeability** proofs; **B1** parameter
calibration; the `paramch_h` nothing-up-my-sleeve **ceremony**; a production per-spend signing **KDF**;
**constant-time / side-channel** review; cross-arch (aarch64/MSVC) determinism KAT confirmation. "It
verifies + tests pass" ≠ "it is sound." Details in `REPORT.md` / `CODEX-ASSESS.md` / `VET-SUMMARY.md`.
