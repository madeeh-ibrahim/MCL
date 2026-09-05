# Paper 3 — measurements ordered after the PRE desk rejection — 2026-09-05

**Doc IDs:** MCL-P3-DECORR-2026-0905-001 (`decorr_time/`) · MCL-P3-WINDOWCTRL-2026-0905-001 (`window_control/`) · MCL-P3-JACOBI-2026-0905-001 (`jacobi_orth/`) · MCL-P3-PAIRDIST-2026-0905-001 (`pairs_dist/`)
**Order:** author, 2026-09-05 («نفّذ الكل — ابدأ بالقياسات — نفّذ الأكواد أولاً — التعديلات بعد مراجعة نجاح التجارب»), executing items 5أ/5ب/5ج/10 of `05_Scientific_Papers/Paper_3_PRE/Reviews/P3_PostDeskReject_Assessment_20260905.md`.
**Engine:** `02_Engine_Code/mcl_core.hpp` v8.1.3, MD5 `5d8b49ee11aa0bfb8b0bda3f47fa16e3` (identical to the public v0.2.x copy), compiled `c++ -O3 -std=c++17 -DMCL_UNSAFE_ALLOW_INVALID` (Apple clang 16.0.0, macOS, Apple `libm`). **No header patch.** The tools call the engine's own `mcl_iterate_raw`, `mcl_iterate_jacobi`, `compute_lyapunov`, `compute_lyapunov_jacobi`, `hash_seed`, `mod2pi`, `mcl_extract_zone1/2`, `pearson_r`, `hamming_pct`, `pvalue_from_r`, `noise_floor`; where a tool re-implements a step (custom ω in `decorr_time`), bit-identity with the engine function is asserted at start-up over 10⁵ steps, and `jacobi_orth` in `gs` mode asserts its byte stream equal to `MCL_T2::gen_bytes`.
**Run log:** `run_all_20260905_101801.log` (+ `window_control/window_trace_run.log`). Smoke outputs kept in `*/_smoke/`.

## A. Decorrelation time versus parameter perturbation (`decorr_time/`, item 5أ)

**Protocol.** Two trajectories start from the *same* initial phases (engine seed → `hash_seed` → `mod2pi(s·ω)`), 16,384 seeds per run, and evolve under parameters that differ by δ in ω₂ (δ = 10⁻¹² … 10⁻¹), in K (same list), or by an adjacent integer weight ((3,5)→(3,6) or (4,5)). Per step t: ⟨ln d(t)⟩ (torus distance, seeds with d>0), and the *ensemble* Pearson correlation r_ens(t) of cos θ₁ across seeds. Configurations: (3,5) at K = 6, 12, 20 with Gauss–Seidel and with Jacobi; (2,3), (7,11), (17,23) at K = 12 (GS). Controls: δ = 0 (r_ens ≡ 1.000000, d ≡ 0); adjacent integers (d(1) ≈ 2.2 rad, t_dec = 2).
**Definitions.** δ₁ = exp⟨ln d(1)⟩ (measured separation after one step). Growth slope = least-squares slope of ⟨ln d(t)⟩ over the exponential phase (⟨ln d⟩ ∈ (ln δ₁ + 1, −2)). t_sat = first t with ⟨ln d(t)⟩ > 0 (1 rad). t_dec = first t from which |r_ens(t)| < 4/√16384 = 0.031 for five consecutive steps (`analyze_decorr.py`; the tool's own 3σ/no-persistence column is kept as `t_dec_tool`).
**Result.** Growth slope / λ₁(engine) = **0.9968 – 1.0013 (mean 0.9991, 14 configurations)**: the separation of two parameter-distinct trajectories grows at the maximal Lyapunov exponent of the map, for GS and Jacobi alike. t_dec is linear in ln(1/δ₁) with slope 1/λ₁ (fitted-slope × λ₁ = 0.92 – 1.25, mean 1.07, integer-quantised t_dec, 5–6 δ values per line) and an intercept of 1–2 steps; r_ens collapses to the noise floor within one to two steps of the separation reaching 1 rad. For δ = 10⁻¹² at K = 12 the whole process takes 8 steps (GS) / 10 steps (Jacobi) — three orders of magnitude inside the 10,000-step burn-in.

| update | (p,q) | K | axis | λ₁ (engine) | growth slope / λ₁ | slope t_dec | 1/λ₁ | ratio |
|---|---|---|---|---|---|---|---|---|
| gs | (17,23) | 12 | omega | 9.250 | nan | 0.099 | 0.108 | 0.92 |
| gs | (2,3) | 12 | omega | 4.970 | 0.9986 | 0.248 | 0.201 | 1.23 |
| gs | (3,5) | 12 | K | 5.778 | 0.9968 | 0.174 | 0.173 | 1.00 |
| gs | (3,5) | 12 | omega | 5.778 | 1.0003 | 0.217 | 0.173 | 1.25 |
| gs | (3,5) | 20 | K | 6.801 | 0.9991 | 0.174 | 0.147 | 1.18 |
| gs | (3,5) | 20 | omega | 6.801 | 0.9990 | 0.161 | 0.147 | 1.10 |
| gs | (3,5) | 6 | K | 4.414 | 0.9996 | 0.217 | 0.227 | 0.96 |
| gs | (3,5) | 6 | omega | 4.414 | 1.0002 | 0.248 | 0.227 | 1.10 |
| gs | (7,11) | 12 | omega | 7.475 | 1.0013 | 0.155 | 0.134 | 1.16 |
| jacobi | (3,5) | 12 | K | 3.586 | 0.9998 | 0.273 | 0.279 | 0.98 |
| jacobi | (3,5) | 12 | omega | 3.586 | 0.9994 | 0.273 | 0.279 | 0.98 |
| jacobi | (3,5) | 20 | K | 4.100 | 0.9980 | 0.248 | 0.244 | 1.02 |
| jacobi | (3,5) | 20 | omega | 4.100 | 0.9977 | 0.267 | 0.244 | 1.09 |
| jacobi | (3,5) | 6 | K | 2.892 | 0.9995 | 0.385 | 0.346 | 1.11 |
| jacobi | (3,5) | 6 | omega | 2.892 | 0.9987 | 0.354 | 0.346 | 1.02 |


Files: `res_*_summary.csv`, `res_*_steps.csv`, `decorr_fit_table.csv`, `decorr_fit.png`, `decorr_steps_fig.png` (three-panel figure for the paper).

## B. Failure inside the phase-locking windows (`window_control/`, item 5ب)
**Protocol.** On the Fig. 1 grid of Paper 3 (topologies (2,3) and (3,5), K = 0.30 … 1.00 in steps of 0.02, 36 cells each), two same-seed trajectories with couplings K and K + ΔK, ΔK = 0.01 (half the grid step). Two diagnostics per cell: (i) *ensemble* — r_ens(t), the Pearson correlation of cos θ₁ across 2,048 seeds at the same t, recorded for t ∈ [10⁴, 10⁴ + 200] (`window_trace grid`; full 3,000-step traces for eight cells with 4,096 seeds, `window_trace trace`); (ii) *time series* — one seed after the 10⁴-step burn-in, 10⁵ steps: Pearson of cos θ₁ at lag 0 and its maximum over |lag| ≤ 64, Miller–Madow mutual information and joint χ² of (θ₁ᴬ, θ₁ᴮ) on 32 × 32 bins (`window_control`). Lock classification per cell as on 2026-09-03 (exact period ≤ 256, or R_α > 0.9, or λ₁ ≤ 0.02; engine `compute_lyapunov`, 10⁵ QR steps). Cross-topology rows (2,3)-vs-(3,5) at the same K included as a further control. "Fails to decorrelate" = max |r_ens| ≥ 0.3 over the 200-step window, **or** time-series max |r_lag| > 0.5, **or** MI > 0.5 bit.

**Result (`window_composite_table.md`, `trace_summary.txt`, `window_summary.txt`, `trace_fig.png`, `window_map.png`).**

| class | cells | fail to decorrelate | note |
|---|---|---|---|
| (2,3) direct-locked | 24 | **23** | exception K = 0.74 (period-60 island): partner K = 0.75 is chaotic (λ₁ = +0.18) |
| (3,5) direct-locked | 16 | **13** | exceptions K = 0.30, 0.54, 0.86: partners 0.31 / 0.55 / 0.87 chaotic (λ₁ = +0.06 / +0.50 / +1.02) — `cell_check_results.txt` |
| (2,3) chaotic | 12 | **0** | time-series max |r_lag| = 0.028, max MI = 0.001 bit; ensemble max |r_ens| = 0.097 (2,048 seeds; expected extreme of 6,400 null values ≈ 0.093) |
| (3,5) chaotic | 20 | **0** | time-series max |r_lag| = 0.037, max MI = 0.021 bit; ensemble max |r_ens| = 0.075 |

So: **in every locked cell whose ΔK-partner is also locked (36/36) the parameter change fails to decorrelate; in every chaotic cell (32/32) it decorrelates; the four apparent exceptions are cells whose partner crosses the window edge.** Two distinct failure modes: *periodic* locked orbits ((2,3) period 15 at K = 0.40, period 30 at K = 0.60; (3,5) period 16/24/32) — r_ens(t) ≈ 0.99 constant, MI = log₂(period) (3.907 bit for period 15), i.e. the two trajectories sit on the same structurally stable cycle; *quasi-periodic* locked states ((2,3) K = 0.30, 0.34, R_α = 0.93–0.95, λ₁ = 0) — time-series r and MI ≈ 0 (the ergodic product of two incommensurate rotations), but r_ens(t) oscillates between −0.96 and +0.99 without decaying (rigid phase drift cos(ΔΩ·t)): ergodic, not mixing. In the chaotic cells r_ens(t) sits at the noise floor from the first sampled step. Cross-topology (2,3)/(3,5) pairs: time-series max |r_lag| = 0.017 everywhere; MI up to 1.58 bit and |r_ens| up to 0.80 only where both are locked. The measured decorrelation boundary therefore coincides with the resonance-window boundary of Table I: parameter-induced decorrelation of the mixing type is a property of the chaotic regime and fails, by structural stability, inside the tongues.

## C. Jacobi update (`jacobi_orth/`, item 10)
**Protocol.** `jacobi_orth.cpp` repeats the Paper 3 §V.B protocol with `mcl_iterate_jacobi` in place of the engine's Gauss–Seidel iteration: the 20 coprime topologies and 20 seeds of `mcl_orth_verify` (RATIOS[], SEEDS[]), N = 10⁷ bytes per channel, engine seed→phase map, 10,000-step burn-in, decimation 2, byte = `mcl_extract_zone1 ^ mcl_extract_zone2`, engine `pearson_r` / `hamming_pct` / `pvalue_from_r` / `noise_floor`, Bonferroni α = 0.001/3,800 = 2.63 × 10⁻⁷, Hamming 5σ = 2.80 × 10⁻⁴; plus a raw-phase Pearson on cos θ₁ over the first 10⁶ iterations of every pair. In `gs` mode the tool's byte stream is asserted bit-identical to `MCL_T2::gen_bytes` (10⁵ bytes) and the same campaign is run as a same-tool control. λ_J per topology by the engine's `compute_lyapunov_jacobi` (10⁶ iterations).

**Result — Jacobi (`res_jacobi_full_summary.txt`, `res_jacobi_full_pairs.csv`, `res_jacobi_full_lyapunov.csv`).**
| test | max | mean | EVT scale | min p | rejections |
|---|---|---|---|---|---|
| Pearson, bytes (N = 10⁷) | \|r\| = 0.001339 | 0.000254 (null 0.000252) | 0.001284 | 2.28 × 10⁻⁵ (87× above threshold) | **0 / 3,800** |
| Hamming, bytes | dev = 2.03 × 10⁻⁴ | 50.0000 % | — | — | **0 / 3,800** |
| Pearson, raw cos θ₁ (10⁶ steps) | \|r\| = 0.003577 | — | 0.004060 | 3.48 × 10⁻⁴ | **0 / 3,800** |

Null check: mean |z| = 0.8037 (half-normal 0.7979, SE 0.0098); observed max |z| = 4.23 vs expected extreme ≈ 4.06 for 3,800 (P(max ≥ 4.23) ≈ 9%). λ_J at K = 12: 3.07 ((2,3)) … 6.20 ((67,73)); λ_J,2 = 2.1–4.7 (larger than the GS λ₂ because det J_Jacobi keeps the −p²K²c₁c₂ term). **Conclusion: the Gauss–Seidel update is not necessary for the decorrelation; §II.A's "essential to the phenomenon" (v2) was an untested necessity claim and is replaced in v3 by "sets the stretching rate; not necessary" (§II.A, §VII.C, §VII.D).**

**Result — Gauss–Seidel same-tool control (`res_gs_full_summary.txt`):** same tool, `mcl_iterate_raw`: max |r| = **0.001138**, mean |r| = **0.000249**, min p = **3.180 × 10⁻⁴**, Hamming mean **49.9999 %**, raw cos θ₁ max |r| = 0.003871 (EVT 0.004060), rejections 0/3,800 in all three tests — **numerically identical to the Paper 3 §V.B / Table V campaign values** (0.001138 / 0.000249 / 3.18 × 10⁻⁴ / 49.9999 %), i.e. the tool reproduces the published campaign bit for bit and the Jacobi comparison is like for like. mean |z| = 0.7884 (half-normal 0.7979), max |z| = 3.60.

## D. Distribution of the pair statistics (`pairs_dist/`, item 5ج)
**Protocol.** (i) The paper's own `mcl_orth_verify` (MCL-ORTH-2026-0526-001 v6.0.0 source, built against engine 8.1.3) run in `--full` mode with `--evidence-file`: 20 seeds × 20 topologies, N = 10⁷, 3,800 Pearson + 3,800 Hamming entries (`evidence_full_20260905.tsv`, `mcl_orth_verify_full_20260905.txt`, 1,084 s). (ii) `pairs_ks.py`: z = r√N of the 190 signed values of the Fig. 3 matrix (full precision) against N(0,1) — KS, Anderson–Darling (fully specified), Cramér–von Mises, Shapiro–Wilk, moments, extreme; |z| of the 3,800 evidence values against the half-normal — KS, AD, moments, extreme. (iii) Fresh-seed replicate: `jacobi_orth` in `gs` mode with `SEED_OFFSET=1000003` (20 new seeds), N = 10⁷, |r| printed at full precision (`res_gs_freshseeds_*`).

**Result (i) — reproduction.** VERDICT PASS; max |r| = 0.001138, min p = 3.180 × 10⁻⁴, mean Hamming 49.9999 %, 0/3,800 + 0/3,800 — **identical to the published §V.B / Table V values** (and to the same-tool GS control of §C).

**Result (ii) — distribution.**
| set | n | KS | AD A² | mean | var | max |
|---|---|---|---|---|---|---|
| Fig. 3 matrix, signed z, full precision | 190 | D = 0.081, p = 0.15 | 2.25 (5 % point 2.49); CvM p = 0.11; Shapiro–Wilk p = 0.51 | +0.139 (SE 0.073) | 1.08 (χ² p = 0.39) | 2.75 (expected ≈ 3.0) |
| FULL evidence, \|z\|, **6-dp file** | 3,800 | D = 0.020, p = 0.084 | 3.16 — **not interpretable against the tabulated points**: with |r| rounded to 6 dp the null A² has median 4.9 and 95 % point 15.0 (4,000-replicate simulation; P(A² ≥ 3.16) = 0.73). The same artefact gives A² = 12.5 for the 6-dp Jacobi file (KS p = 0.71). | 0.788 (theory 0.798, SE 0.010) | 0.371 (theory 0.363) | 3.60 (expected ≈ 3.65) |
| Fresh-seed replicate, \|z\|, full precision | 3,800 | D = 0.012, p = 0.69 | **0.62** (5 % point 2.49) | 0.808 (SE 0.010) | 0.380 | 3.97 (expected ≈ 3.65; P ≈ 0.27) |

Per-seed mean |z| of the FULL file: 0.71–0.88 (SE 0.044 each), per-seed A² 0.33–4.69 (6-dp artefact applies). **Result (iii) — fresh-seed replicate (`jacobi_orth gs`, `SEED_OFFSET=1000003`, full precision):** bytes 0/3,800 (max |r| = 0.001255, mean 0.000256, EVT 0.001284, min p = 7.24 × 10⁻⁵), Hamming 0/3,800 (mean 50.0001 %), raw cos θ₁ 0/3,800 (max |r| = 0.003430); per-seed mean |z| 0.73–0.89. Signed raw-phase z (N = 10⁶, n = 3,800) vs N(0,1): KS p = 0.64, AD 0.61, Shapiro–Wilk p = 0.48, mean +0.012, var 0.974. **Conclusion: at full precision the pair statistics follow the null distribution by every test; the AD excess of the 6-dp evidence file is a rounding artefact.**

**Lesson recorded:** an evidence file that prints |r| to six decimals cannot be used for tail-weighted goodness-of-fit at N = 10⁷ (z resolution 0.003); the v3 tools print full precision.
