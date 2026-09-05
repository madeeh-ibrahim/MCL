# Changelog — MCL public repository

All notable changes to the **published** repository. Engine-level history is
kept verbatim in the `VERSION IDENTIFICATION` block of `mcl_core.hpp`; this file
summarises it at release granularity. Pin artefacts by **SHA-256**, never by
version string alone.

## v0.2.8 — 2026-09-06

Joint release of three sessions' staged work — **Paper 3** records, **Paper 4** round 6 (VDF128-T4 v3), and **Paper 5** TOPS-readiness. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged. Additive only.

<!-- 2026-09-06: the P3 block (staged as v0.2.8) and the P4 round-6 block (staged as v0.2.9) were merged with the P5 block under this single v0.2.8 entry before the push, as the P4 note invited; Paper 5 cites release v0.2.8 for its §VI.E and §VII.B records. -->

### Paper 3 (records completed)

Paper 3 v3 records completed after the referee-eye and external review rounds of the evening (engine `mcl_core.hpp` 8.1.3 unchanged; keyed sidecar v1.0.6 unchanged).

### Added / Changed (`P3_DeskRejectMeasurements_20260905/`)

- `decorr_time/decorr_time.cpp` — `DECORR_BURNIN=<steps>` option (a common on-attractor burn-in before the two trajectories split); `res_{omega,K}_35_K12_gs_burnin1e4_{summary,steps}.csv` — the control cited in Paper 3 v3 §V.K (iv): growth rates 5.74–5.79 and identical t_sat / t_dec at every δ with and without the burn-in.
- `RECORD_P3_DESKREJECT_MEASUREMENTS_20260905.md` — addendum: the burn-in control and the note that for a K change the measured first-step separation is ≈ 9.6 ΔK (sequential substitution), which corrected §IV.D of the paper.
- `decorr_time/plot_decorr_steps.py`, `window_control/analyze_trace.py` and the two figure PNGs — regenerated at 320 dpi for the journal's ≥ 300 dpi requirement (data unchanged).
- `SHA256SUMS` regenerated (90 files).
- `results/MCL_Scale_v2.2.0_Test_Results_20260519.md` — the Stage-1 channel-scaling record (runs A–D, 20 → 10⁷ channels, two Apple Silicon machines, verbatim outputs) behind Paper 3 Table IV, previously outside the public bundle.
- `P3_DeskRejectMeasurements_20260905/tableVI_lyap/` — re-measurement of Paper 3 Table VI (λ₁, λ₂ vs K for (2,3); 3 seeds × 10⁷ QR iterations; record MCL-P3-TABLEVI-2026-0906-001) — the old table had no archived record.

### Paper 4 (round 6)

Paper 4 round 6 ("a superior paper for the journal"). Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar v1.0.6 unchanged.

### Added

- `VDF128_T4/mcl_vdf128_t4_v3.hpp` — **VDF128-T4 version 3** (Doc ID MCL-VDF128-T4-2026-0905-003): project-neutral domain strings (`VDF128-T4-v3-kdf`, `VDF128-T4-v3-out`, KAT input `VDF128-T4-KAT-01`) and a **full-rank parity-matrix re-draw rule** that excludes every translation symmetry of the map. Reason: the new single-bit differential probe found on the version-2 battery instance a probability-one differential — all six weights touching one state word were even, so the half-turn shift of that word commuted with every coupling argument; the exact criterion is a rank-deficient 12×4 parity matrix over GF(2), present on 6.96% of version-2 weight sets (5.63% single-word, 1.37% global) and on 0.0000% under the new rule. Map, initialization and table unchanged; version-2 files kept for the record. Vector 5 v3: y = `75d76880369509b4…`.
- `VDF128_T4/p4_vdf128v3_distinguisher.cpp` — differential (single- and two-bit), linear (two-bit masks), cube-sum profile (6 instances × r = 1…6 × d = 12/16/20) and translation-symmetry statistics. Findings reported in the paper: one-iteration non-propagation of a word's top bits through even weights (832/16,384 pairs at r = 1, none at r ≥ 2); one-iteration cube-sum imbalance (43–58/128 at d = 20), balanced from r = 2.
- `VDF128_T4/mcl_vdf128v3_{battery,cyclecheck,bench,xplat}.cpp`, `p4_vdf128v3_{kat,weaklane,weakpair}.cpp`, `p4_sha256_vs_t4v3_bench.cpp`, `vdf128_t4v3_standalone.cpp`, `run_v3_all.sh` + logs — every VDF128-T4 measurement re-run on v3: battery 21/22 (the cube-sum balance at one iteration is the recorded finding), no orbit closure within 2³³ × 3 inputs, weak-lane/weak-pair probes incl. a genuine both-lanes-<2¹⁶ input, 9-cell fingerprint (the Linux/GCC cell from GitHub Actions run 33981717768, branch `p4-linux-check`, because Docker Desktop was blocked), quiet-host timings T4 28.9 ns vs SHA-256 37.5 ns (SHA-2 instructions) / 135 ns (library), checkpoint Verify 6.59× at k = 8.
- `P4_ReviewMeasurements_20260905/` — round-6 sources and logs added (62 files, `SHA256SUMS` regenerated; README section "Round 6").

### Paper 5 (TOPS-readiness round)

The two evaluation campaigns the revised Paper 5 depends on, plus a licence header.

- `P5_ReviewMeasurements_20260905/p5_system_eval.cpp` + `system_eval_20260905.log` (Doc ID MCL-P5-SYSEVAL-2026-0905-001) — **the system evaluation behind Paper 5 §VII.B**: the three wallet roles (enrollment, authentication, generation) measured in one process against a hash-based stack (KDF1/SHA-256 + HMAC-SHA-256 + SHA-256 counter DRBG) on an idle host, MCL rows n = 400 and hash rows n = 400,000. Enrollment 0.862 ms vs 0.459 µs (≈ 1,880×; 20.62 ms with the Step-4 screen, ≈ 44,900×); tag 0.295 ms vs 2.02 µs (≈ 146×); 1 KiB 0.351 ms vs 13.87 µs (≈ 25×); mutable state 72 B vs ≈ 104 B; read-only table 262,144 B vs 0; stored secrets 1 vs 1; **primitives required 2 vs 1** — the MCL stack needs the engine *and* SHA-256 for its own KDF. **The result refutes the consolidation motivation, and Paper 5 retracts it rather than repeating it.**
- `P5_ReviewMeasurements_20260905/p5_adversarial.cpp` + `adversarial_20260905.log` (Doc ID MCL-P5-ADVERSARIAL-2026-0905-001) — **the two attempted attacks behind Paper 5 §VI.E**, both negative. A1 per-field context binding: one random bit flipped in each ctx field alone, 2,000 trials per field, all six fields within 1.6 standard errors of the 128/256 null, repeated at B = 0. A2 first-order weight leak (the §X.12 concern): 20,000 keys × 360 weight bits × 256 tag bits = 92,160 point-biserial correlations at B = 10,000 and B = 0; max |r| 0.0309 (4.37σ) and 0.0298 (4.22σ) against a noise floor 0.00707 and an expected null maximum ≈ 4.92σ — no first-order weight leak at either burn-in. Uses the scratch burn-in-override engine copy; the engine of record is untouched.
- Quiet-host re-measurement of the derivation throughput (`hd_throughput_v{1,2}_quiet_20260905.log`): v2 bare 0.820–0.833 ms, with the Step-4 screen 20.60–20.61 ms (96.0 % of the safe path); v1 0.819–0.822 / 20.56–20.58 ms. These supersede the loaded-host figures of the v0.2.7 records.
- `hd_v2/mcl_hd_v2.hpp` — added the standard SPDX copyright/licence header and the four-PCT patent notice, matching `mcl_core.hpp` and the keyed sidecar. **No code change**: the derivation is byte-identical and the v2 campaign record stands.
- `P5_ReviewMeasurements_20260905/README.md` and `SHA256SUMS` regenerated.

### Changed (release)

- `CITATION.cff`: `version: 0.2.8`, `date-released: 2026-09-06`. `MANIFEST.md` and `SHA256SUMS_MCL_v0.2.8.txt` regenerated.

## v0.2.7 — 2026-09-05

<!-- 2026-09-05: the P4 round-5, P5 round-3 and P3 post-desk-reject blocks were merged under this one v0.2.7 entry by the P5 session before the push. -->

Joint release — **Paper 4 referee-eye review round 5** (re-review after round 4), **Paper 5 referee round 3** (`Paper_5_HD_Keys_TxAuth`, ACM TOPS submission) and **Paper 3 post-desk-reject measurements**. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged; VDF128-T4 v2 unchanged. Everything below is additive.

### Paper 4 (round 5)

### Added

- `VDF128_T4/p4_vdf128v2_weaklane.cpp` + `P4_ReviewMeasurements_20260905/vdf128v2_weaklane_apple_20260905.log` — **weak-lane instances** of the per-input map: 40 M inputs ground through the v2 derivation (a lane below 2²⁰ in 1.17% of inputs, below 2¹⁶ in 0.07%); the structural probes (avalanche profile r = 1…8 with per-word split, single-bit linear correlations r = 1, 2, cube/degree sums) on the maps of ground inputs whose smallest lane is 506,386 / 31,590 / 6, against the battery input. A lane of 6 delays the diffusion of one state word by about one iteration (61.1/128 after one, 63.4 after two, ≈64 from the third); no linear pair above 4.5σ; every cube sum non-zero.
- `VDF128_T4/p4_vdf128v2_weakpair.cpp` + log — **weak-pair instances** (one pair with both lanes small; expected once per ≈2²⁵ inputs, hence adversary-selectable): constructed sets (both < 2¹⁶ — indistinguishable from control; (6, 31590); (6, 7) extreme) with the re-draw rules re-checked; `--grind` mode searches for a genuine input.
- `VDF128_T4/p4_sha256_vs_t4_bench.cpp` + `sha256_vs_t4_bench_apple_20260905.log` — same-host interleaved best-of-5 bench of the VDF128-T4 iterate against a SHA-256 chain through the ARMv8 SHA-2 instructions (cross-checked against CommonCrypto: identical after 1000 links) and through the system library. Two runs: at load 5.9 with two foreign jobs present (ratios only) and on an idle host (`…_idle_…log`): **T4 29.2 ns / SHA-2-instruction compression 38.0 ns / library call 136.1 ns** — one iteration = 0.77 hardware SHA-256 compressions; a library call = 4.7 iterations; the idle absolutes are the ones the paper quotes.
- `VDF128_T4/vdf128v2_weakpair_grind_apple_20260905.log` — a genuine input whose pair (1,2) has both lanes below 2¹⁶ (`weak-lane-180785906`, found after 140,785,907 candidates) probed identically: indistinguishable from the control.

### Changed (Paper 4)

- `P4_ReviewMeasurements_20260905/README.md`, `SHA256SUMS` regenerated.

### Paper 5 (round 3) — security note: `derive_child` (Paper 5 §III, "HD derivation") is not one-way as published

In `derive_child` (v1, unchanged in `mcl_core.hpp`) the 32 raw bytes of the parent run are the same for every index and the index enters as a **public, invertible XOR mask** (`fmix64(i)`, `fmix64(i)·0x9E3779B97F4A7C15`). Consequences, both measured (`P5_ReviewMeasurements_20260905/`): **(a) sibling recovery** — from the p-values of three observed children the parent block `R_lo` is recovered by enumerating 2⁶⁴/(M−2) candidates (23.8 s single-thread at M = 10⁹) and every other sibling is then computable without the seed or the parent pair (`sibling_recovery.cpp`); **(b) parity lock** — `parity(p) XOR parity(q)` is constant per parent (`p5_parity_lock.cpp`). Do not use v1 where sibling secrecy matters. The Tech Guide had recorded the fix as "recommended, not yet implemented" since rev. 1.2.

### Added (Paper 5)

- `hd_v2/mcl_hd_v2.hpp` (v1.0.0, Doc ID MCL-HD-V2-2026-0905-001) — `derive_child_v2` / `derive_child_safe_v2`: the index is mixed one-way, `d = SHA-256("MCL-HD-v2" ‖ R[0:32] ‖ LE64(i))`, `c₁ = LE64(d[0:8])`, `c₂ = LE64(d[8:16])`; range map, p ≠ q bump, coprimality loop and the Step-4 resonance screen are the v1 code verbatim. Include after `mcl_core.hpp`.
- `hd_v2/mcl_hd_verify_v2.cpp` + `hd_verify_v2_FULL_v8.1.3_20260905.log` — the Paper-5 §IV campaign (135 pairs, global Bonferroni, 9,702-candidate collision check, resonance screen at K = 1.0, three map families) re-run on v2: **0 rejections**. `hd_v2/mcl_hd_throughput_v2.cpp` + re-timing of v1 and v2.
- `p5_hardened_txauth/` **harness v3.2** (`mcl_txauth_v3_battery.cpp`, `mcl_txauth_v3_battery_q30.cpp`; Doc IDs MCL-P5-V32BATTERY-2026-0905-001 / -Q30-2026-0905-002): portable (engine SHA-256, no CommonCrypto — builds on Linux); avalanche test flips a uniformly random bit of `canon(TX)` (384 positions; v3.1 exercised 16); weak-set re-draw census; `-DMCL_TX_COMBINER` builds the **PRF-XOR combiner** `Tag = HMAC-SHA-256(K_mac, ctx) XOR G(KDF(S_device, ctx))`, `K_mac = KDF(K, "MCL-TxMAC-v1", "")` (Paper 5 §V.E). Records `results_v32_{double_native, double_combiner, q30_native_arm64, q30_native_x86_64, q30_combiner_arm64}_20260905.txt` — all PASS; Q30 fingerprint identical across arm64 / x86_64. The constant-time-sine build (an oblivious 65,536-entry scan per sine) is timed separately by `P5_ReviewMeasurements_20260905/p5_ct_sine_cost.cpp` (identical tags, ≈ 4.0 s per tag vs 0.39 ms). v3.1/v3.1.1 sources kept as `_v31_backup_*.txt`.
- `P5_ReviewMeasurements_20260905/` — the round-3 measurements with `README.md` (Arabic), `README_EN.md` and `SHA256SUMS`: `sibling_recovery.cpp/.log`, `p5_parity_lock.cpp`, `redraw_rate.cpp` (395/200,000 raw symmetric weight sets → 0 after the sidecar's deterministic re-draw), `p5_v2_coprime_parity.cpp/.log` (v2: 39.29 % raw non-coprime vs 39.21 % expected; no parity lock), `p5_burnin_curve_v2.cpp` + log (B = 0…10,000: every first-order statistic at its null value; MDE ≈ 0.45 bit), `p5_G_entropy.cpp` + log (**birthday estimate of the collision entropy of the key→tag map G(U)**, 2²⁵ keys, 42-bit truncation — the one engine-dependent term of Paper 5's Theorem 1), `p5_resonance_control.cpp` + log (positive control of the χ² screen on the (3,5) window at K ≈ 1.22), `p5_weight_probe.cpp` + log + diff (wrong-weight flatness measured on the weights themselves, both realizations), `header_patch.diff` (the real scratch-engine diff for the burn-in knob), `mcl_hd_throughput.cpp` + logs.
- `P5_HDVerify_FULL_20260904/` — the **version-1** FULL campaign record on engine 8.1.3 (`hd_verify_FULL_v8.1.3_20260904.log`, throughput logs, `coprime_frac.cpp` 59.47 %): the provenance of the earlier draft's §IV numbers and the baseline the v1 break was measured against (staged for v0.2.3 but not pushed then).
- `RETIRED_mcl_txn_verify.md` — `mcl_txn_verify.cpp` implements the superseded input-composition tag; kept only as the provenance of its 2026-06 record. Paper 5's protocol is the `p5_hardened_txauth` harness.

### Changed (Paper 5)

- Paper 5 (text, not in this repository): §V now carries **Theorem 1** — the engine is a public post-processing of a single-use KDF output, so tx-auth unforgeability reduces to KDF-PRF + CR(H) + q_V·2^(−H∞(G(U))) with **no assumption on the map**; the "assumption diversity" claim of earlier drafts is withdrawn for the engine-native tag and holds only for the combiner.

### Paper 3 (measurements after the PRE desk rejection)
Paper 3 v3 measurements after the Physical Review E desk rejection (04 Sep 2026): the paper is reframed as *parameter-induced decorrelation with a Lyapunov time scale and a boundary at the phase-locking windows* (target: Chaos, AIP). Engine `mcl_core.hpp` **8.1.3 unchanged** (MD5 `5d8b49ee11aa0bfb8b0bda3f47fa16e3`); keyed sidecar v1.0.6 unchanged. No header patch: every tool calls the engine's own iteration, Lyapunov and statistics routines and asserts bit-identity where it re-implements a step.

### Added (Paper 3)

- `P3_DeskRejectMeasurements_20260905/` — record MCL-P3-{DECORR,WINDOWCTRL,JACOBI,PAIRDIST}-2026-0905-001 with `SHA256SUMS`, `RECORD_P3_DESKREJECT_MEASUREMENTS_20260905.md` and the run log:
  - `decorr_time/` — **decorrelation time of two same-seed trajectories under a parameter perturbation** (δω₂ = 10⁻¹²…10⁻¹, δK, adjacent integer weights; 16,384 seeds; (3,5) at K = 6/12/20 with Gauss–Seidel and Jacobi; (2,3), (7,11), (17,23) at K = 12): separation growth rate / λ₁ = 0.9968–1.0013 in 14 configurations; t_dec linear in ln(1/δ₁) with slope 1/λ₁ (Paper 3 v3 Eq. 9, Fig. 5).
  - `window_control/` — **the decorrelation fails inside the phase-locking windows**: ΔK = 0.01 on the Fig. 1 grid ((2,3),(3,5), K = 0.30…1.00): 36/36 locked cells with a locked partner keep a deterministic relation (periodic: r ≈ 0.99, MI = log₂ period; quasi-periodic: ensemble correlation oscillates without decaying), 0/32 chaotic cells; `window_trace` r_ens(t) traces (Paper 3 v3 §III.C, Fig. 4); `cell_check` for the four edge cells.
  - `jacobi_orth/` — **§V.B protocol with the Jacobi update**: 0/3,800 Pearson, 0/3,800 Hamming, 0/3,800 raw-phase rejections (max |r| = 0.001339); same-tool Gauss–Seidel control reproduces the published campaign exactly (0.001138 / 0.000249 / 3.18e-4 / 49.9999 %); λ_J for the 20 topologies; **fresh-seed replicate** (`SEED_OFFSET=1000003`, full precision): 0/3,800, max |r| = 0.001255, |z| half-normal by KS (p = 0.69) and Anderson–Darling (0.62).
  - `pairs_dist/` — `mcl_orth_verify --full --evidence-file` re-run on 8.1.3 (VERDICT PASS, values identical to the June record) + `pairs_ks.py` (KS/AD/CvM/Shapiro–Wilk on the pair statistics; rounded-null calibration: a 6-dp evidence file inflates Anderson–Darling under the null — median A² 4.9 — so tail tests need full-precision output, which the v3 tools print).

### Changed (Paper 3)

- Nothing in the engine or in previously published records.

### Changed (release)

- `CITATION.cff`: `version: 0.2.7`, `date-released: 2026-09-05`. `MANIFEST.md` and `SHA256SUMS_MCL_v0.2.7.txt` regenerated.

## v0.2.6 — 2026-09-05

Paper 4 referee-eye review round 4: **VDF128-T4 version 2 (per-input coupling weights)**. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged; the v1 header `VDF128_T4/mcl_vdf128_t4.hpp` is kept unmodified for the record.

### Added

- `VDF128_T4/mcl_vdf128_t4_v2.hpp` — additive v2 header (Doc ID MCL-VDF128-T4-2026-0905-002): the twelve weights are derived from `SHA-256(x)` through the sidecar's audited `mcl_t4_q30_params_from_key`, so each input evaluates its own map; output tag `MCL-VDF128-T4-v2-out`. Reason: a fixed public 128-bit map admits a generic Hellman/distinguished-point precomputation with jump-ahead probability ≈ N·W₀/2¹²⁸ (≈ 2⁻⁸ at N = 2⁴⁰, W₀ = 2⁸⁰), far above the term the v1 conjecture stated; the toy reproduction is `P4_ReviewMeasurements_20260905/p4_tmto_toy.py` (measured 2.27e-2 vs the v1 term 7.3e-6 on a 32-bit map).
- `VDF128_T4/mcl_vdf128v2_battery.cpp`, `…v2_cyclecheck.cpp`, `…v2_bench.cpp`, `…v2_xplat.cpp`, `p4_vdf128v2_kat.cpp` + logs — every VDF128-T4 measurement re-run on v2: battery **22/22** (10 properties, 4 attacks, 3 new structural probes: single-bit linear correlations at r = 1/2/4 indistinguishable from an independent control, cube sums non-zero at dimension 20 after one iteration, avalanche profile 63.2 → 64.5/128 over r = 1…8); **no orbit closure within 2³³ steps × 3 inputs**; 34.2 M iter/s; checkpoint Verify 6.70× at k = 16 on 8 cores; **9-cell cross-platform fingerprint identical** (arm64, x86_64/Rosetta, Linux GCC).
- `P4_ReviewMeasurements_20260905/` — record MCL-P4-REVIEWMEAS-2026-0905-002 with `SHA256SUMS`: the above sources and logs, `vdf128_t4v2_standalone.cpp` (engine-free re-implementation of Algorithm 1 v2; reproduces Vector 5 v2 — y = `1d0f60cc602b12ed…` — on macOS and on x86_64 Linux/glibc 2.36, from the table file and from a `sin()`-regenerated table), the normative sine table, the TMTO toy script, and a SHA-256 hash-chain rate on the same host (7.3 M hashes/s vs 34 M iter/s) for the paper's comparison table.

## v0.2.5 — 2026-09-04

Paper 4 external-review round 2. Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar v1.0.6 unchanged.

### Added

- `P4_ReviewMeasurements_20260904/vdf128_t4_standalone.cpp` — an **engine-free re-implementation of Paper 4's Algorithm 1 (VDF128-T4)** with its own SHA-256, KDF, weight derivation, table loader, four-oscillator Gauss-Seidel iterate and finalization (shares no code with the engine). Reproduces Appendix Vector 5 exactly on macOS and on x86_64 Linux/glibc 2.36 (logs included).
- `P4_ReviewMeasurements_20260904/q30_lut_int32le.bin` — the **normative sine table as a byte sequence** (65,536 × int32 little-endian, 256 KB; SHA-256 `f78c9584e5686cb1f54f382b1bfcf87c3399ae19f987e7761f339bdb3bd7dd1d`, CRC-32 0xde1340cf) with `p4_lut_digest.cpp`. Regenerating the table with `sin()` on Apple-libm and on glibc 2.36 yields the same digest.

### Changed

- `CITATION.cff`: `version: 0.2.5`. `MANIFEST.md` regenerated.

## v0.2.4 — 2026-09-04

Paper 4 external-review records. Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar v1.0.6 unchanged.

### Added

- `P4_ReviewMeasurements_20260904/p4_vdf128_kat_avalanche.cpp` + logs (macOS and Linux/glibc, byte-identical): a **complete VDF128-T4 known-answer vector** with every intermediate — SHA-256(x), K_pub, the twelve public weights, ω₁..ω₄, K_phase, LUT CRC-32, initial state, C₀…C₄, the 80-byte SHA-256 preimage and y (x = "MCL-VDF128-KAT-1", B = 10⁴, N = 10³; y = `3059e862…`) — plus per-iteration avalanche on the T4 map (one-bit state flip → 63.27 / 63.88 / 64.19 / 64.02 of 128 bits after 1–4 iterations). This is Paper 4's Vector 5 and its Algorithm 1 reference.
- `P4_ReviewMeasurements_20260904/vector4_q30_linux_glibc_20260904.log`: the Appendix Vector-4 program re-run natively on Linux/glibc — bit-identical to macOS.

### Changed

- `CITATION.cff`: `version: 0.2.4`, `date-released: 2026-09-04`. `MANIFEST.md` regenerated.

## v0.2.3 — 2026-09-04

Paper 4 (IACR Communications in Cryptology) pre-publication records. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged.

### Added

- `P4_ReviewMeasurements_20260904/` (record MCL-P4-REVIEWMEAS-2026-0904-001) — five single-file harnesses with logs: Gauss-Seidel-vs-Jacobi Pearson |r| and Hamming distance on 10⁶ extracted bytes (replica extractor self-checked byte-for-byte against `MCL_T2::gen_byte`; |r| = 0.000456, Hamming 49.969 %); a 10⁷-iteration exact state-collision search (0 repeats); orbit-averaged log-determinants and the determinant-ratio estimator (6.797 / 6.352 / 0.4459 vs the closed form 0.4463); the Appendix test vectors regenerated on macOS Apple-libm **and** on x86_64 Linux glibc 2.36 / GCC 13.4 (Debian 12 container) with θ bit patterns and CRC-32s; and a 36-cell Q30 determinism matrix — {arm64, x86_64/Rosetta} × {-O0…-O3} × {none, UBSan, ASan} on macOS plus {-O0…-O3} × {none, UBSan, ASan} with GCC on Linux — all cells byte-identical (aggregate CRC `0xD9FE9B13`; raw state-word bytes: entropy 7.999801, χ² 275.35).
- Finding recorded in the same folder: the Float64 (`MCL_T2`) stream is libm-**build**-dependent, not merely OS-dependent — glibc 2.36 gives CRC-32 `0xD65C897C` for the reference seed, the May-2026 glibc build gave `0xF5E977E0`, Apple-libm gives `0x1A734C6F`. The Q30 integer path is identical on all of them.

### Changed

- `CITATION.cff`: `version: 0.2.3`, `date-released: 2026-09-04`. `MANIFEST.md` regenerated with per-file SHA-256.

## v0.2.2 — 2026-09-03

Paper 3 (Physical Review E) pre-publication records. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged.

### Added

- `P3_ReviewMeasurements_20260903/` — direct phase-locking diagnostics on the Paper 3 Fig. 1 grid (`phaselock/`: unwrapped winding ratio W, order parameter R_α of the coupling argument, exact period, λ₁, byte-level χ²; 144 cells; record MCL-P3-PHASELOCK-2026-0903-001) and raw-phase cross-dependence tests (`rawphase/`: Pearson on cos/sin θ, lagged cross-correlation, mutual information, joint-density χ², distance correlation on 8 channel pairs plus identical / next-state / noisy controls; record MCL-P3-RAWPHASE-2026-0903-001). The two C++ tools read the engine's phases through a one-line read-only patch to a scratch copy of the header (`header_patch.diff` in each folder); no engine arithmetic is touched.
- `P3_WindowSweep_6_20_20260903/` — K ∈ [6, 20] at step 0.005 for (2,3), (3,5), (5,7), (7,11), 2 × 10⁵ QR iterations per point, criterion λ₁ ≤ 0.02: zero periodic windows (record MCL-P3-WINSWEEP-2026-0903-001).
- `P3_Fig3_Regeneration_20260903/` — Paper 3 Fig. 3 regenerated from a real run (20 canonical coprime channels × 10⁷ bytes, seed 12345678901234, K = 12): pairwise-|r| CSV, generator, figure script and PNG (record MCL-P3-FIG3-2026-0903-001; max |r| = 0.000870, mean 0.000265).
- `P3_NonlinearDependence_20260603/` — the June-2026 nonlinear-dependence campaign cited in Paper 3 §V.I: five test programs (mutual information, distance correlation, lagged cross-correlation, block-joint χ², lag autocorrelation), 66 channel pairs, `results_v3/` records and campaign manifest. Engine copy of 6.0.0 omitted (git tag `v0.1.0`; KAT-identical T2 path to 8.1.3).
- `results/mcl_k_independence.txt` — first archived run of `Verification_Suite/mcl_k_independence.cpp` on engine 8.1.3 (1,137 pairs, 0 rejections; the 22 per-configuration maxima are bit-identical to the April and June 2026 records). Built with `-DMCL_UNSAFE_ALLOW_INVALID` because the wide-K sweep starts below the runtime sentinel.

### Changed

- `Verification_Suite/README.md`: build flag and result path for `mcl_k_independence.cpp`.
- `keyed_q30_PQ/`: full `dieharder -a` battery on engine 8.1.3 + sidecar 1.0.6 — **117 PASSED / 0 WEAK / 0 FAILED** (`MCL_KEYED_Q30_DIEHARDER_20260903.txt`, dieharder 3.31.1); `README.md` and `STATUS.md` updated (the 13-test June subset is retained unchanged as a historical record).
- SPDX short headers (the `add_spdx_headers.sh` form) added to the six new tool files.
- `CITATION.cff`: `version: 0.2.2`, `date-released: 2026-09-03`. `MANIFEST.md` regenerated with per-file SHA-256.

## v0.2.1 — 2026-09-02 (metadata only; no code change)

* `CITATION.cff` and the README DOI badge now cite the Zenodo **concept DOIs**
  (`10.5281/zenodo.20496568` for this repository; `…20496684`, `…20496909`,
  `…20496911`, `…20496913`, `…20496915` for the five companion papers). A concept
  DOI is stable across versions and always resolves to the latest one; the
  version DOIs cited before (`…20496569`, `…20496685`, …) point permanently at the
  2026-06-01 v0.1.0 / v1 records. `CITATION.cff` `version`/`date-released` bumped.
* Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c…`, MD5
  `5d8b49ee11aa0bfb8b0bda3f47fa16e3`); every KAT/keystream identical to v0.2.0.
  Paper 1 pins its measurements to the engine of record 6.0.0 (MD5
  `241db79ecf8a42897eb9a8399cf37929`, release v0.1.0) and cites this release as
  the current, byte-identical implementation.
* `MANIFEST.md`: SHA-256 rows of the three edited files refreshed.

## v0.2.0 — 2026-08-22

### Engine `mcl_core.hpp`: 6.0.0 → **8.1.3** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`)

Every KAT, CRC and keystream of every pre-existing valid path is byte-identical
to 6.0.0 (re-verified on this release: `results/self_test_v8.1.3_20260822.txt`
PASS 7/7; `results/kat_gen_macos_v8.1.3_20260822.txt` reproduces the June CRCs;
`results/q30_macos_validation_v8.1.3_20260822.txt` reproduces the normative Q30
vectors `0xC8AFD74A/0x0DB2BAC6`, `0x6F88C52E/0xE06C516C`, LUT `0xDE1340CF`).

| Version | Date | Kind | Summary |
|---|---|---|---|
| 6.1.0 | 2026-06-11 | additive | 256-bit keyed path: SHA-256 KDF → keyed `MCL_T2_Omega` / `MCL_T4` weight derivation (§3.1, keyed factories). |
| 7.0.0 | 2026-07-06 | additive + stricter validation | `vdf_verify_transcript()` (seed-anchored, tamper-evident checkpoint transcripts; closes the fabricated-start-state gap of the segment API), `vdf_compute_checkpointed` out-param, T4 2⁶²-bound parity, fail-closed `distance_correlation`/`spectral_test`, heap-free streaming SHA-256 + secure_zero of key material, Q30 hot path in fully-defined unsigned arithmetic (bit-identical), new self-test controls, documentation corrections (integer-Q30 battery status, keyspace accounting). |
| 7.0.1 | 2026-07-07 | hardening | Unconditional null guards in `mcl_kdf256`, `mcl_sha256`, `vdf_compute_checkpointed`; sec.16 cross-reference to the keyed sidecar. |
| 7.0.2 | 2026-07-11 | docs/advisory | Periodic/quasi-periodic K-windows persist above K=1.0 for some topologies ((3,5) at K≈1.22, 2.595; (2,3) band 1.28–2.08): `MCL_K_RECOMMENDED_FLOOR` 1.0→6.0, `MCL_T2_K_RECOMMENDED` 2.0→6.0 (advisory; hard K_min sentinel unchanged). |
| 7.0.3 / 7.0.4 | 2026-07-12 | security hardening | F1–F7 + QA-1..3: NaN-K rejection in `mcl_q30_K_phase`, fail-closed `vdf_verify`/`vdf_verify_q30`, bounded verifiers (`*_bounded`, caller-policy N_delay/checkpoint ceilings against resource-exhaustion), KDF label/info 1 MiB cap, `mcl_make_validated_t2()` Lyapunov-validated factory, `#warning` when `MCL_UNSAFE_ALLOW_INVALID` is compiled in. |
| 8.0.0 | 2026-07-12 | renumbering | Release renumbering for the deposit package; no code/numerical change over 7.0.4. Document ID → `MCL-CORE-2026-0712-001`. |
| 8.1.0 | 2026-07-17 | additive | sec.4b device-bound keyed derivation: `mcl_keff_from_key_device`, `mcl_t2_params_from_key_device`, `mcl_t4_params_from_key_device` (256-bit device secret enters the **weight derivation**, not the seed). |
| 8.1.1 | 2026-08-21 | docs | Banner patent list: fourth application filed as PCT/IB2026/058860. |
| 8.1.2 | 2026-08-22 | docs | SECURITY WARNING on `vdf_compute_q30()` (retired two-oscillator raw path): seed-reachable translation symmetry (order-16 group for (3,5)) — see `T4_CycleStructure/T4_CYCLE_RECORD_20260822.md` §5a. |
| **8.1.3** | 2026-08-22 | contract narrowing | `MCL_PQ_MAX` 2⁶² → **2⁵³** (exact-integer bound of IEEE-754 double; inputs in (2⁵³, 2⁶²] previously lost precision silently and are now rejected). Header sweep count 919 → 489 (corrected figure of the 2026-07-11 periodic-window record). |

> Note: the free-text `Version:` line at the top of `mcl_core.hpp` still reads
> "8.1.1 … August 21, 2026" (the 8.1.2/8.1.3 bumps were recorded in the version
> macros and changelog block only). The macros `MCL_VERSION_STRING "8.1.3"` /
> `MCL_VERSION_DATE "2026-08-22"` are authoritative; the file is shipped
> byte-identical to the pinned SHA-256 above and will be reconciled in the next
> docs-only bump rather than altered here.

### Added — sidecar and evidence folders (all new to the public repository)

- `keyed_q30_PQ/` — `mcl_keyed_q30.hpp` **v1.0.6** (SHA-256 `71a0dbaf84725ac77d0b3f1eab5a40ba90c088e88df7d41aab19aed39a6f6512`): FPU-free keyed four-oscillator integer engine `MCL_T4_Q30` (12 integer weights, 256-bit key → NIST PQ Category 5 accounting) and `mcl_cascade_q30`; v1.0.6 adds `mcl_t4_q30_has_reachable_symmetry` + deterministic re-draw in `mcl_t4_q30_params_from_key` (rejects the ≈2⁻⁹ weak-key class; KATs `0x58C99E3E` / `0xF7C81BC4` unchanged; 125/65 536 test keys change one lane). Test suite 9/9 PASS on this release. Includes the capacity-realization experiment v1.1.0 (15/15), Dieharder / Lyapunov (MPFR) / M0 code-generation records.
- `VDF128_T4/` — `mcl_vdf128_t4.hpp` 128-bit-state integer sequential function (SHA-256 input injection into the 4×32-bit state, public nothing-up-my-sleeve weights with trivial symmetry group): property + falsification battery 14/14, cross-arch/cross-opt fingerprint 8/8, 2026-08-21 benchmark record.
- `T4_CycleStructure/` — reduced-width cycle study (λ₁₂₈ ≈ 2^62.3 ± 0.2), exact translation-symmetry group computation, symmetry impact on the retired raw VDF, weak-key parity check, Float64-path symmetry check (combinatorial class exists but is numerically unstable and not seed-reachable), full record `T4_CYCLE_RECORD_20260822.md`.
- `ReturnMap_Attack/` — Rule-13/Rule-7 chaos-specific attack battery (2-D return-map occupancy, conditional entropy, EFA) on the keyed stream, commit words and raw state; record `RETURNMAP_RECORD_20260822.md`.
- `p2_hardened_auth/` — Paper 2 hardened authentication profile v2 (12/12), keyed 12-weight credential FAR campaigns (10⁶/10⁷, keyed v4 4 devices × 10⁶/10⁷), avalanche 10⁶, engine-sensitivity 17 strategies × 2.5 M (0/42 500 002), records and logs. (`mcl_simswap_v3.cpp` gated — see `TOOLKIT_ACCESS_POLICY.md` addendum; its record/logs are here.)
- `p5_hardened_txauth/` — Paper 5 hardened transaction-authentication v2 (16/16), v3 Claim-4 route (11/11) and v3 battery (18/18), `mcl_d1_collision.cpp` Brent search (1.63×10¹⁰ trials) producing a real colliding payload pair on the retired 64-bit-fold path, architectural-finding record.
- `M1_M2_apple_verification/` — Paper 1 §III.B.3 (ψ-equidistribution, det-J), Tables 9/10 (multi-seed), Appendix A NIST STS campaign (188/188, archive zip), per-bit MSB flank, safe-zone hold-out, τ_int; Paper 3 Fig. 1 Arnold-tongue sweep generator + CSV. Engine copy of v6.0.0 omitted (it is git tag `v0.1.0`).
- `P3_CrossPrediction/` — ridge-regression cross-prediction (R²) sweep over K showing deterministic predictability at K=0.70 and none at K≥6 (record `XPRED_RECORD_20260822.md`).
- `Verification_Suite/` (14 legacy programs + results), `Layer_Combiner/` (robust-combiner demo).
- `results/` — three fresh 8.1.3 records (`self_test`, `kat_gen_macos`, `q30_macos_validation`) next to the June outputs.
- `CHANGELOG.md` (this file); `MANIFEST.md` regenerated with per-file SHA-256.

### Changed

- `PATENTS.md`, `CITATION.cff`, `README.md`, banners of all 23 root `.cpp` files: fourth application **PCT/IB2026/058860** (filed 21 August 2026) added. No other byte of the 23 programs changed.
- `CITATION.cff`: `version: 0.2.0`, `date-released: 2026-08-22`.
- `TOOLKIT_ACCESS_POLICY.md`: 2026-08-22 addendum (7th gated file; scope statement for the June attack scripts / CPA / VDF probes).
- `.gitignore`: exception for the NIST STS evidence archive.

### Not included (deliberately)

- Gated adversarial toolkit (7 files), the June-2026 lattice / return-map attack scripts, `SideChannel_Screen/` CPA tooling, the nine `VDF_security/` probe programs — per `TOOLKIT_ACCESS_POLICY.md`. Their findings are disclosed in the papers and the public records.
- Compiled binaries, `.DS_Store`, backups.

## v0.1.0 — 2026-06-01

Initial public package: engine 6.0.0 (MD5 `241db79ecf8a42897eb9a8399cf37929`),
23 reproduction / KAT / self-analysis programs with recorded outputs, governance
and licensing instruments, Zenodo concept DOI 10.5281/zenodo.20496569.
