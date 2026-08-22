> **Publication note (2026-08-22, MCL v0.2.0):** the GATE paragraph below is **discharged** — the fourth application was filed on 21 August 2026 as PCT/IB2026/058860. The archived v6.0.0 engine copy (MD5 `241db79ecf8a…`) is **not duplicated** in this folder: it is byte-identical to `mcl_core.hpp` at git tag `v0.1.0` / Zenodo `MCL-v0.1.0.zip`, which is the engine these logs were measured on (every KAT is unchanged through v8.1.3). Compiled binaries are not shipped. The files added 2026-07 to 2026-08 (`mcl_safezone_holdout.cpp`, `mcl_perbit_msb_flank.cpp`, `mcl_tau_int.cpp`, `mcl_table10_multiseed.cpp`, `mcl_hd_throughput.cpp`, `mcl_nist_stream.cpp`, `mcl_fig1_arnold_sweep.cpp`, `mcl_bifurcation_sweep.cpp`) and their logs are the provenance of Paper 1 Tables 9–10 / Appendix A and Paper 3 Fig. 1.

# M1/M2 Apple-libm Verification — Paper 1 §III.B.3

**Date:** 2026-07-03 · **Platform:** Apple M-series (Darwin 23.5.0, Apple clang 16.0.0) · **Engine:** `mcl_core.hpp` **v6.0.0 (archived)**, MD5 `241db79ecf8a42897eb9a8399cf37929` — the exact copy pinned by Paper 1 ref [1].

> ⚠ **GATE:** `mcl_detj_verify.cpp` verifies Eq. (3e) / the q>p order relation — **Patent-4 adjacent material**. Do **not** publish, upload, or ship to Zenodo before Patent 4 is filed (see `05_Scientific_Papers/Reviews/Paper1_Fixes_NODY_Addendum_20260703.md`). `mcl_psi_equidist.cpp` (M1) is not gated by content, but ships together in the same archive version — hold both.

## Contents

| File | Doc ID | Purpose |
|---|---|---|
| `mcl_core.hpp` | — | archived v6.0.0 engine (MD5-verified copy) |
| `mcl_psi_equidist.cpp` | MCL-PSI-EQUIDIST-2026-0703-001 | M1: ψ-marginal TV/χ²/⟨ln\|cos ψ\|⟩ (3 seeds × 10⁷) |
| `mcl_detj_verify.cpp` | MCL-DETJ-VERIFY-2026-0703-001 | M2: (3c)–(3f) — exactness, Oseledets, topology sweep, K-asymptotics |
| `psi_equidist_apple_20260703.log` | — | run output, VERDICT: **PASS** |
| `detj_verify_apple_20260703.log` | — | run output, VERDICT: **PASS** |

Build: `c++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o <name> <name>.cpp -lm`

## Headline results (Apple libm) vs Paper 1 claims

| Claim (Paper 1 §III.B.3) | Paper value | Apple-measured | Status |
|---|---|---|---|
| ⟨ln\|cos ψ₁\|⟩ within 0.1% of −ln 2 | −0.693 ± 0.001 | −0.69300…−0.69335 (≤ 0.03%) | ✅ |
| TV(ψ marginal) | ≈ 0.005 | 0.0047–0.0050 | ✅ |
| ⟨ln\|cos ψ₂\|⟩ | ≈ −0.698 (−0.7%) | −0.6977…−0.6982 (−0.66…−0.73%) | ✅ |
| (3c)/(3f) closed forms = engine Jacobian | exact | ≤ 9.4×10⁻¹⁵ (factor-scale relative) | ✅ |
| Oseledets: ⟨ln\|det J\|⟩ = λ₁+λ₂ | 4 decimals | 6.7970 = 6.7970 (diff < 10⁻⁵) | ✅ |
| ⟨ln\|tr J\|⟩ vs λ₁ | ≈ −0.05% | 5.7761 vs 5.7787 (−0.046%) | ✅ |
| (3d) worst error, 8 coprime @ K=12 | ≤ 0.08% | 0.08% | ✅ |
| (3e) worst error | 0.62% at (2,3) | 0.62% at (2,3) | ✅ |
| (3e) six largest topologies | < 0.1% | 0.01–0.08% | ✅ |
| Reversed (5,3): λ₂ vs 2 ln(3/5) | −1.0225 / 0.08% | −1.0225 / 0.08% | ✅ |
| K-asymptotics (3,5) | −1.07/−0.33/−0.09/−0.01 % @ K=6/12/20/50 | same, from below | ✅ |

Paper 1 md (§III.B.3) was updated 2026-07-03 to quote the Apple-measured values; the earlier glibc values agree to the 4th decimal (cross-platform consistency per §III.B).

## Note on the (3c) exactness metric

det J from the closed form and from the engine's analytical Jacobian are **algebraically identical**; in floating point the two evaluation orders differ by rounding, which is *amplified* when (1 − qKcᵢ) nearly cancels. The correct exactness metric is therefore the difference relative to the **factor scale** (1+|qKc₁|)(1+|qKc₂|) — measured ≤ 9.4×10⁻¹⁵ — not relative to the cancelled product itself (which shows ~10⁻¹⁰ and is a property of cancellation, not of the identity).

## Pending

1. Ship both programs + logs to the software archive as a **new Zenodo version** — **after Patent-4 filing** (concept DOI unchanged).
2. Optional cross-check against engine v6.1.0 (map unchanged; expected identical).

## 2026-08-17 — Paper 1 pre-publication fixes (Table 10 multi-seed + Eq.(5) intra-pair premise)

**Tool:** `mcl_table10_multiseed.cpp` · **Log:** `table10_multiseed_apple_20260817.log` · **Doc IDs:** MCL-TABLE10-MULTISEED-2026-0817-001 (Table 10), MCL-GOLD-INTRAPAIR-2026-0817-001 (intra-pair block). Engine: frozen v6.0.0 (MD5 `241db79ecf8a42897eb9a8399cf37929`), Apple libm / M2 Max, clang -O3, N = 10⁸ samples/seed, D = 2, seeds {12345678901234, 31415926535897, 27182818284590}.

| Claim (paper, post-fix) | Measured | ✓ |
|---|---|---|
| Table 10 A (8-bit, 20⊕36) mean 270.1 (232.9–294.1) | 294.05 / 232.89 / 283.50 | ✅ |
| Table 10 B (8-bit, 6⊕31) mean 261.2 (255.8–267.6) | 255.76 / 260.22 / 267.60 | ✅ |
| Table 10 C (32-bit, 6⊕20, 4N pooled bytes) mean 273.6 (229.1–299.4) | 299.38 / 292.36 / 229.07 | ✅ |
| Eq.(5) intra-pairs (20+i, 36+i): 23/24 indep, \|c\| ≤ 3.5×10⁻⁵, χ²(1) ≤ 2.0 | as stated | ✅ |
| Single non-recurrent exception: pair (25,41), seed 1234…, χ² = 12.10, c = −8.7×10⁻⁵ | not in other 2 seeds | ✅ |

Superseded: prior single-campaign Table-10 values (A 221.94, B 225.63, C 233.92) — within null fluctuation, replaced by pinned multi-seed protocol. Removed from paper: 64-bit concat row D (protocol not recorded precisely enough for exact reproduction); Table 9 K∈[9.5,10.5] rows + "oscillator selection rule" (engine header STATUS: NOT REPRODUCED; 2026-08-17 remeasure at K=10: seed 1234… θ₁=25/θ₂=25, seed 7046… θ₁=26/θ₂=20 — direction reverses across seeds).

## 2026-08-17 — Paper 3 Figure 1 regeneration (Arnold tongue sweep)

**Tool:** `mcl_fig1_arnold_sweep.cpp` · **Data:** `fig1_arnold_sweep_apple_20260817.csv` (144 points) · **Plot script:** `make_paper3_fig1_20260817.py` · **Doc ID:** MCL-FIG1-ARNOLD-2026-0817-001. Engine: frozen v6.0.0, `-DMCL_UNSAFE_ALLOW_INVALID`, protocol = paper §III.A + `mcl_k_sweep_unified.cpp` (K 0.30→1.00 step 0.02, 500 KB/(K,seed), 3 seeds worst-case χ²).

| Claim (Table I) | Measured | ✓ |
|---|---|---|
| (2,3) 21/36 resonant, [0.36, 0.90] | 21/36, [0.36, 0.90] | ✅ |
| (3,5) 14/36, [0.30, 0.82] | 14/36, [0.30, 0.82] | ✅ |
| (5,7) 4/36, [0.30, 0.48] | 4/36, [0.30, 0.48] | ✅ |
| (7,11) 3/36, [0.38, 0.98] | 3/36, [0.38, 0.98] | ✅ |
| Public log overlap: (3,5) K=0.30 χ²=110491.37 / K=0.50 298.87 | identical | ✅ |

Old `paper3_fig1.png` (synthetic, contradicted Table I + public log, retracted "K=1.0 all chaotic" footer) preserved as evidence at `05_Scientific_Papers/Reviews/paper3_fig1_BACKUP_synthetic_20260817.png`; replaced by the real-data figure.
