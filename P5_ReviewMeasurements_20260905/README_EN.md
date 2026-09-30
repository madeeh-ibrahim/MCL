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
| `p5_ct_sine_cost.cpp` | cost of the opt-in constant-time sine (oblivious 65,536-entry scan) on the Eq. (3) tag | identical fingerprint; 4.03 s/tag vs 0.552 ms (3-tag means, ≈ 7,300×) — a full battery is infeasible |
| `mcl_hd_throughput.cpp`, `../hd_v2/mcl_hd_throughput_v2.cpp` | derivation latency, v1 and v2, two runs each, near-idle machine | quiet-host re-measurement (2026-09-06, `hd_throughput_v{1,2}_quiet_20260905.log`): v1 0.82 / 20.56–20.58 ms; v2 0.82–0.83 / 20.60–20.61 ms (the first-day loaded-host figures 1.08 / 27 ms are superseded) |
| `p5_burnin_curve_v2.cpp` | burn-in sweep with the v3.2 avalanche method (random bit of canon(TX)) | all statistics at null; latency 0.007 → 0.482 ms (loaded machine) |

Platform: Apple M1 Pro, macOS, Apple clang 16; single-thread unless stated. Build lines are in each program's header.

## 2026-09-30 — corrections
- `p5_adversarial.cpp`: the printed Bonferroni label said «~4.6 sigma»; the two-sided threshold for 92,160 tests at α = 0.001 is **5.72σ** (4.6σ ≈ family-wise α 0.39). Re-run 2026-09-30 with the same scratch engine (v8.1.3 + `header_patch.diff`) and keyed sidecar **v1.0.6** (`71a0dbaf84725ac7`): `adversarial_20260930.log` — every A1 row and both A2 maxima (0.03090 = 4.37σ at B = 10,000; 0.02981 = 4.22σ at B = 0) **byte-identical** to the 2026-09-05 record apart from the header and the label line. The 2026-09-05 log is kept unchanged.
- The «expected null maximum ≈ 4.92σ» quoted above is √(2 ln 2n), the leading-order asymptotic; the exact expectation of the maximum of 92,160 independent |Z| is **4.52σ** (median 4.48σ; P(max ≥ 4.37σ) = 0.68). Conclusions unchanged.
- `p5_system_eval.cpp`: one comment on the tag row — K is passed as both K and S_device; the timing is value-independent. No re-run (timing row unchanged).
- md5 rows above updated for the two sources; `SHA256SUMS` regenerated for them and extended by the new log.

## 2026-09-30
- `redraw_rate.cpp` **v2 (2026-09-30)**: SHA-256 now from the engine (`mcl_sha256`) instead of Apple CommonCrypto, so the program builds on macOS and Linux; the census is unchanged (395 raw symmetric sets of 200,000 → 0 after the re-draw; record `../P5_ReviewMeasurements_20260930/redraw_rate_v2_20260930.log`). The 2026-09-05 census had no archived output; `../P5_ReviewMeasurements_20260930/redraw_rate_20260930.log` (v1 build) and `parity_lock_20260930.log` are the records for §X.9 and §III.B of Paper 5.
