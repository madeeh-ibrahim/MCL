# Paper 3 §III.A — K-window sweep over the validated range [6, 20] at step 0.005 — 2026-09-03

**Doc ID:** MCL-P3-WINSWEEP-2026-0903-001 · **Purpose:** pre-publication review measurement (P3_PrePublication_Review_20260903, item on the "step-0.005 over [6, 20]" sentence).
**Engine:** `02_Engine_Code/20260822_public/MCL/mcl_core.hpp` (public v0.2.1 header, MD5 `5d8b49ee11aa0bfb8b0bda3f47fa16e3`), `compute_lyapunov()` (Benettin QR), built with `c++ -O3 -std=c++17 -DMCL_UNSAFE_ALLOW_INVALID sweep.cpp -o sweep`.
**Protocol:** seed 12345678901234; K from 6.000 to 20.000 inclusive in steps of 0.005 (2,801 points per topology); 2×10⁵ QR iterations per point; a "window" is flagged when λ₁ ≤ 0.02 (the criterion of `VERIFY_cpp_range_sweep.cpp`, 2026-07-11). Single seed, single platform (Apple Silicon, Apple libm).
**Why:** before this run the record for K ∈ [6, 20] was step **0.01** for **(3,5) only** (`VERIFY_cpp_range_sweep.cpp`, 07-11) plus the step-0.25 coarse bifurcation sweep (`bifsweep_coarse_apple_20260719.csv`); the step-0.005 sweeps on record covered K ≤ 6 only (`bifsweep_fine_apple_20260719.csv`; `VERIFY_cpp_range_sweep` [1, 6]).

| (p,q) | points | windows (λ₁ ≤ 0.02) | min λ₁ | at K | log MD5 |
|---|---|---|---|---|---|
| (2,3) | 2,801 | **0** | 3.6041 | 6.000 | `bb2755543e50e857079435bd798b4263` |
| (3,5) | 2,801 | **0** | 4.4151 | 6.000 | `475515775ca25fcd9e8e0f2f31737f79` |
| (5,7) | 2,801 | **0** | 5.4210 | 6.000 | `e2ad5b7acf27e0045f2a7f3323b6ec2c` |
| (7,11) | 2,801 | **0** | 6.0886 | 6.000 | `db19d78a62a9242cf2a71ea649156c77` |

**Reading.** At step-0.005 resolution no point in [6, 20] has λ₁ ≤ 0.02 for any of the four Table I topologies; the minimum λ₁ in the range is at the lower edge K = 6 and is ≥ 3.6 for every topology. Windows narrower than 0.005 in K cannot be excluded by this grid (the paper already says so). The sentence in §III.A ("verified free of such windows for the tested topologies at step-0.005 resolution") is now supported for the four tested topologies by this record; cite it there.
