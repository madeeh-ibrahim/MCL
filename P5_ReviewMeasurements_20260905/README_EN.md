# P5 review measurements — 2026-09-05 (English summary; Arabic detail in README.md)

Engine of record `02_Engine_Code/mcl_core.hpp` v8.1.3 and keyed sidecar v1.0.6 are **unmodified**; where an experiment needed a
compile-time knob, a scratch copy was patched and the unified diff is archived beside the program.

| program | what it measures | key result |
|---|---|---|
| `mcl_txauth_v3_battery_q30` (v3.1.1, `p5_hardened_txauth/`) | Q30 protocol battery built for arm64 and x86_64 (Rosetta 2) | 19/19 on both; identical SHA-256 fingerprint over 5,000 tags (`cf465420…`) |
| `p5_burnin_curve.cpp` (v1 method, + `header_patch.diff`) | battery statistics vs burn-in B = 0…10,000 on Q30 | no first-order statistic separates B = 0 from 10,000; latency 0.007 → 0.326 ms |
| `p5_parity_lock.cpp` | derive_child v1 parity classes over 2×10⁵ indices | 100,005 / 99,995 / 0 mixed; q odd 91.8 % |
| `sibling_recovery.cpp` | v1 sibling recovery from three observed children, M = 10⁹ | R_lo recovered in 23.8 s; unseen child predicted |
| `redraw_rate.cpp` | weak-key re-draw rate of `mcl_t4_q30_params_from_key` on 2×10⁵ random keys | 395 raw symmetric (0.198 %) → 0 after re-draw |
| `p5_resonance_control.cpp` | positive control of the Step-4 χ² screen on the (3,5) window near K = 1.22 | χ² = 1.4–1.5 × 10⁶ at K = 1.218/1.220/1.221; 330.0 at 1.219 |
| `p5_weight_probe.cpp` (+ `weight_probe_sidecar_scratch_ctor.diff`) | wrong-credential flatness with perturbations applied to the twelve weights themselves | double: 10,800 probes, mean 128.065, 0 near-misses; Q30: 10,800, mean 128.120, 0 near-misses |
| `p5_G_entropy.cpp` (scratch burn-in knob) | birthday estimate of the collision entropy of the key→tag map G(U), 2²⁵ keys, 42-bit truncation, five burn-in lengths | ratios 0.945 / 1.016 / 0.953 / 1.070 / 1.133 at B = 0 / 2 / 8 / 64 / 10,000 (ideal 1.0 ± 0.088) |
| `p5_v2_coprime_parity.cpp` | derive_child_v2 census at parent (3,5), M = 10⁶, 2×10⁵ indices | 39.29 % raw non-coprime (39.21 % expected); no parity lock (3 classes 2:1:1) |
| `p5_ct_sine_cost.cpp` | cost of the opt-in constant-time sine (oblivious 65,536-entry scan) on the Eq. (3) tag | identical fingerprint; 4.03 s/tag vs 0.39 ms (≈ 10⁴×) — a full battery is infeasible |
| `mcl_hd_throughput.cpp`, `../hd_v2/mcl_hd_throughput_v2.cpp` | derivation latency, v1 and v2, two runs each, near-idle machine | v1 1.08 ms bare / 27.0 ms safe; v2 1.08 / 27.1–28.2 ms |
| `p5_burnin_curve_v2.cpp` | burn-in sweep with the v3.2 avalanche method (random bit of canon(TX)) | all statistics at null; latency 0.007 → 0.482 ms (loaded machine) |

Platform: Apple M1 Pro, macOS, Apple clang 16; single-thread unless stated. Build lines are in each program's header.
