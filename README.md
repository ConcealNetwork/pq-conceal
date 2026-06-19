# Conceal Network — Post-Quantum (CIP-0001) R&D

The knowledge base for making **Conceal (₡CCX)** quantum-safe: design docs, the team **decision dashboard**,
**measured** benchmarks, and the **scheme-landscape research**.

## 📖 Interactive site
**→ https://concealnetwork.github.io/pq-conceal/** — browsable, cross-linked, filterable. Landing page is the
**decision dashboard** (D1–D9). Same content as `/source/*.md`, rendered.

## What's here
- **`/docs`** — the built interactive HTML site (served by GitHub Pages).
- **`/source`** — the Markdown sources + `build-site.py` (regenerate: `cd source && python3 build-site.py`, needs `pandoc`; output lands in `site/`).

## Status (read this)
- **Everything here is a *provisional default awaiting team consensus*, not a decision.** See the dashboard's
  framing note.
- **Unaudited research.** No PQ confidential-anonymous-payment scheme is audited or standardized anywhere; any
  choice here is audit-gated.
- **The PQ consensus/daemon code is NOT in this repo.** It's inline changes to the conceal-core daemon and lives
  on the conceal-core fork (`pqc/testnet-poc`), kept local for human review. Whether to bring the full fork
  into this org repo is decision **D9** (see the dashboard).

## Highlights (measured this session)
- Deposit policy **Option 3** (PQ-only deposits after the fork) — implemented + e2e-verified.
- MatRiCT-Au library-ized; packed proof **~107 KB** (the "58 KB" needs unbuilt commitment-truncation = research).
- **Direction update:** Conceal keeps **plaintext amounts** (verify-funds needs visible amounts) → the PQ target
  is a **PQ ring signature**, not confidential RingCT. **ELRS** (measured flat ~25–29 KB) leads the plaintext
  path; MatRiCT-Au demoted.
