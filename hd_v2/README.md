# hd_v2 — Hierarchical channel-identity derivation, version 2 (additive sidecar)

**Doc ID:** MCL-HD-V2-2026-0905-001 · **Engine of record:** `../mcl_core.hpp` 8.1.3 (unmodified) · **Sidecar:** `mcl_hd_v2.hpp` v1.0.0

## Why
`derive_child` (v1, in `mcl_core.hpp`) mixes the derivation index into the parent's 32 raw bytes R with a **public, invertible XOR mask** (`raw[0:8] ^= fmix64(i)`, `raw[8:16] ^= fmix64(i)·0x9E3779B97F4A7C15`). Measured on 2026-09-05 (`../P5_ReviewMeasurements_20260905/`):
- **Sibling recovery:** from the p-values of three observed children, `R_lo` is recovered by enumerating 2⁶⁴/(M−2) candidates — 23.8 s single-thread at M = 10⁹ — and every other sibling is then computable without the seed or the parent pair (`sibling_recovery.cpp`).
- **Parity lock:** the odd multiplier keeps bit 0 and the even modulus M−2 keeps parity, so `parity(p) ⊕ parity(q)` is constant per parent (`p5_parity_lock.cpp`; q odd in 91.8 % of children of (3,5); 59.47 % of raw pairs non-coprime).
The Tech Guide (rev. 1.2, line 304) had recorded the fix as "SHAKE-256 over (parent‖index) recommended, not yet implemented".

## What v2 does
`derive_child_v2` = v1 with Step 2 replaced by a one-way mixing `d = SHA-256("MCL-HD-v2" ‖ R[0:32] ‖ LE64(i))`, `c₁ = LE64(d[0:8])`, `c₂ = LE64(d[8:16])`; the range map, `p ≠ q` bump, coprimality loop and the Step-4 resonance screen (`derive_child_safe_v2`) are the v1 code lifted verbatim. Uses the engine's own `mcl_sha256` (portable).

## Files
| file | purpose |
|---|---|
| `mcl_hd_v2.hpp` | the sidecar (include after `mcl_core.hpp`) |
| `mcl_hd_verify_v2.cpp` | `MCL_Public_Code/mcl_hd_verify.cpp` with every `derive_child*` call redirected to `*_v2`; Doc ID MCL-HD-VERIFY-V2-2026-0905-001 |
| `hd_verify_v2_FULL_v8.1.3_20260905.log` | full-range campaign (Test 4 over [2,100]², 9,702 candidates) — Paper 5 §IV / Table 1. **Result 2026-09-05: VERDICT PASS, 135 pairs / 0 Bonferroni rejections (threshold 7.41 × 10⁻⁶, smallest p = 0.0199), depth-3 max\|r\| = 0.002327, 9,702 candidates → 0 spurious collisions, resonance screen 20/20 chaotic at K = 1.0, Logistic/Tent families independent.** |
| `mcl_hd_throughput_v2.cpp` | v1 throughput program with the calls redirected to v2 (Doc ID MCL-HD-THROUGHPUT-V2-2026-0905-001); logs in `../P5_ReviewMeasurements_20260905/hd_throughput_v{1,2}_quiet_20260905.log` |

Build: `clang++ -O3 -std=c++17 -I.. mcl_hd_verify_v2.cpp -o mcl_hd_verify_v2 && ./mcl_hd_verify_v2 --full` (≈ 31 min on Apple M1 Pro).
