# Conceal-core daemon integration (reference snapshot)

This is the **consensus-wired** version of the Raptor ring signature — Raptor swapped into the live
conceal-core daemon behind the `ccx_pq_*` C ABI, replacing the demo lattice stand-in. (The *standalone*
PoC is in [`/poc/raptor`](../../poc/raptor); this is the daemon-integrated form.)

> ⚠️ **UNAUDITED testnet PoC — NOT mainnet-ready.** See `poc/raptor/VET-SUMMARY.md` + the audit gates.

## Full daemon branch
The complete core + wallet with **all** PQ changes lives on the fork:
**`ThrownLemon/conceal-core` branch `pqc/testnet-poc`** (commits `a1df5a1` → `f36c1d0` for the Raptor swap).
Builds the full set on Linux x86_64: `conceald`, `concealwallet`, `walletd`, `optimizer`.

## What's in this snapshot
- **`ccx-pqc/`** — the integrated crypto crate. `src/lib.rs` is the `ccx_pq_*` ABI dispatching to Raptor
  (+ the unchanged ML-KEM/ML-DSA/wallet entry points); `build.rs` carries the fips202 symbol-rename fix;
  `raptor.rs`/`falcon_ffi.rs`/`vendor/falcon` are shared with `poc/raptor`.
- **`CryptoNoteConfig.h`** — `PQ_RING_SCHEME_ID = 0x52415054` ("RAPT") and the PQ consensus constants.
- **`raptor-integration.patch`** — the authoritative diff (`a1df5a1^..f36c1d0`) of everything that
  changed in the daemon for the swap; applyable to a conceal-core checkout.

## How the swap works (no C++ consumer changes)
The C++ daemon already called the `ccx_pq_*` ABI with runtime-queried sizes, so swapping the Rust
backend to Raptor needed only the scheme-id bump on the C++ side. Sizes: pk 6144→896 B, sig fixed→
variable (Golomb-compressed, ~9.7 KB @ ring-6), nullifier 32 B (unchanged). Verified: build green,
72 PQ unit tests, e2e consensus (spend accepted / double-spend rejected / independent nullifier
accepted), wallet↔wallet PQ transfer.
