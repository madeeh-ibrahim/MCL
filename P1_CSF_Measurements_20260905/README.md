# Paper 1 — cross-system Safe-Zone, logistic cycle structure and XOR-healing controls (2026-09-05/06)

Reproduction artifacts for §6.2–§6.3 and Fig. 1 of Paper 1
("Finite-Precision Safe-Zone Extraction and Lyapunov Scaling in Coupled Chaotic
Oscillators for Pseudorandom Number Generation"), and for Supplementary S6
(Tables S2–S6).

**Full record, tool by tool and log by log:** `RECORD_P1_CSF_MEASUREMENTS_20260905.md`
(Doc IDs, protocols, seeds, per-file hashes).

**Doc IDs**
- `MCL-ATTRACTOR-DUMP-2026-0905-001` — attractor, invariant density, coupling-phase marginal (Fig. 1)
- `MCL-THIRDMAP-SAFEZONE-2026-0905-001` — byte-level Safe-Zone scan of the reference maps (Table S2)
- `MCL-LOGISTIC-CYCLE-2026-0905-001` — Brent cycle detection for the binary64 logistic map (Tables S3, S3b)
- `MCL-XOR-CONTROL-2026-0905-001` — XOR-healing control across systems (Table S4)
- `MCL-CYCLE-SEARCH-2026-0906-001` — Brent cycle search on the full binary64 state (Table S5)

**Engine of record:** `mcl_core.hpp` v6.0.0, MD5 `241db79ecf8a42897eb9a8399cf37929` (copy included).
**Build:** `c++ -O3 -std=c++17 -ffp-contract=off` (Apple clang, arm64). The `nofma_*` and
`audit_*` logs are the fused-multiply-add control campaign: with the compiler's default
contraction the seed-to-x0 line compiles to a fused operation and the initial condition
differs by one ulp for three of the eight seeds, which in a chaotic map changes the
transient length and can change the cycle reached. Exact x0 values are listed in
hexadecimal binary64 in the record.

Compiled binaries are not shipped; rebuild from the `.cpp` sources with the line above.
`SHA256SUMS` covers every file in this directory.
