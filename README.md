# Conceal Network — Post-Quantum (CIP-0001) R&D

The knowledge base for making **Conceal (₡CCX)** quantum-safe: design docs, the team **decision dashboard**,
**measured** benchmarks, and the **scheme-landscape research**.

## 📖 Interactive site
**→ https://concealnetwork.github.io/pq-conceal/** — browsable, cross-linked, filterable. Landing page is the
**decision dashboard** (D1–D9). Same content as `/source/*.md`, rendered.

## What's here
- **`/poc/raptor`** — the **runnable** clean-room Raptor linkable-ring-signature PoC (Rust + vendored PQClean Falcon-512). Self-contained: `cd poc/raptor && cargo run --release --bin harness`. MIT, no GPL. See its `README.md`.
- **`/docs`** — the built interactive HTML site (served by GitHub Pages).
- **`/source`** — the Markdown sources + `build-site.py` (regenerate: `cd source && python3 build-site.py`, needs `pandoc`; output lands in `site/`).

## Status (read this)
- **Everything here is a *provisional default awaiting team consensus*, not a decision.** See the dashboard's
  framing note.
- **Unaudited research.** No PQ confidential-anonymous-payment scheme is audited or standardized anywhere; any
  choice here is audit-gated.
- **The standalone Raptor PoC IS here** (`/poc/raptor` — runnable, self-contained, MIT). The **consensus-wired**
  version (Raptor swapped into the conceal-core daemon behind the `ccx_pq_*` ABI) lives on the conceal-core fork
  (`pqc/testnet-poc`), kept local for human review — bringing the full daemon fork into this org repo is
  decision **D9** (see the dashboard).

## Highlights (measured this session)
- Deposit policy **Option 3** (PQ-only deposits after the fork) — implemented + e2e-verified.
- MatRiCT-Au library-ized; packed proof **~107 KB** (the "58 KB" needs unbuilt commitment-truncation = research).
- **Production direction:** Conceal keeps **plaintext amounts** (verify-funds needs visible amounts) → the PQ
  target is a small-ring **PQ linkable ring signature**. **Raptor** (clean-room over Falcon-512) leads —
  measured **9.7 KB @ ring-6**, built + adversarially vetted (4 reviewers, 1 CRITICAL + 3 HIGH fixed) +
  **integrated into the daemon** (build + 72 PQ unit tests + e2e consensus green). Runnable PoC in `/poc/raptor`.
  (ELRS demoted — flat size wasted at small rings; MatRiCT-Au demoted — hides amounts.)
