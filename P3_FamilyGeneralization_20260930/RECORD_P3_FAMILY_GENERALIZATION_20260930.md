# Paper 3 — ت-309: the time scale and the boundary in the three additional coupled families — 2026-09-30

**Doc IDs:** MCL-P3-FAMDECORR-2026-0930-001 (`decorr/`, tool `family_decorr.cpp`) · MCL-P3-FAMWIN-2026-0930-001 (`window/`, tool `family_window.cpp`) · MCL-P3-FAMMIX-2026-0930-001 (`mixing/`, tool `family_mixing.cpp`).
**Order:** author, 2026-09-30 («نفّذ ت-309»), item 6 of `05_Scientific_Papers/Paper_3_Chaos/Reviews/P3_PostDeskReject_Chaos_20260930.md` after the Chaos (AIP) desk rejection of 2026-09-28: extend the decorrelation-time law (Eq. 9) and the decorrelation boundary from the phase-oscillator map to the coupled Hénon, logistic and tent families of Sec. VII of the paper.
**Engine:** `02_Engine_Code/mcl_core.hpp` v8.1.3, MD5 `5d8b49ee11aa0bfb8b0bda3f47fa16e3`, compiled `c++ -O3 -std=c++17 -DMCL_UNSAFE_ALLOW_INVALID` (Apple clang 16.0.0, macOS 14.5, Apple `libm`, 8 cores). **No header patch.** The three families are the engine's own classes `CoupledHenon`, `CoupledLogistic`, `CoupledTent` (the systems of Sec. VII: a = 1.4, b = 0.3, K = 0.01; r = 4.0, K = 0.05; slope-2 tent, K = 0.05; Gauss–Seidel substitution; fmod + clamp confinement to [10⁻¹⁰, 1 − 10⁻¹⁰]; engine seed map and BURNIN = 10⁴). Because the map parameters are compile-time constants in the engine, `family_maps.hpp` re-implements the three iterations with the parameter (a, r, tent slope μ) exposed, operation for operation; at the default parameters the byte stream produced through the engine's own extraction (`d2b`, `GOLD_S1/S2`, `DECIMATION`) is **asserted bit-identical to the engine class over 10⁵ bytes (2 × 10⁵ iterations) at the start of every run** (`identity_check()`, `[ok]` lines in every log). The tent slope is written 0.5·μ·(1 − |2u − 1|) so that μ = 2 multiplies by exactly 1.0. λ₁ is measured by Benettin renormalisation of a shadow trajectory (d₀ = 10⁻⁹ along x₁; 10⁶ steps for the decorrelation runs, 10⁵ for the sweeps, after the engine burn-in) — the engine has no Lyapunov routine for these classes; cross-check: coupled tent at μ = 2 gives 0.642 (ln 2 = 0.693 for the uncoupled map), coupled logistic at r = 4 gives 0.553, coupled Hénon at a = 1.4 gives 0.429 (uncoupled 0.419).
**Run logs:** `window/run_windows_*.log` (+ `window/*_slice*.err`), `decorr/run_decorr_*.log`, `mixing/run_mixing_*.log` (the mixing grids of record were produced by the same commands run interactively; `mixing/*.err`), `analysis_run.txt`. Smoke outputs in `_smoke/`. Reproduction: `./run_all.sh` (~25 min).

## A. Decorrelation time versus parameter perturbation (`decorr/`, MCL-P3-FAMDECORR-2026-0930-001)

**Protocol** (as MCL-P3-DECORR-2026-0905-001, with the family step). 16,384 initial conditions from the engine seed map (seeds 10⁶ + 7919·i), a common burn-in of B = 10⁴ steps under parameter set A on the attractor (the engine's own burn-in; control with B = 0 below), then two copies evolved under A and under B, where B differs by δ in the **map parameter** (a − δ, r − δ, μ − δ: applied downward so that the perturbed map stays inside its domain), in the **coupling** (K + δ), or by an **adjacent integer weight** ((3,5) → (3,6) or (4,5)). Per iteration t: ⟨ln d(t)⟩ over the ensemble (Euclidean distance in the full state, (x₁, x₂) or (x₁, y₁, x₂, y₂)) and the ensemble Pearson correlation r_ens(t) of x₁ (and of x₂). δ₁ = exp⟨ln d(1)⟩; growth slope = least-squares slope of ⟨ln d(t)⟩ over the exponential phase (⟨ln d⟩ ∈ (ln δ₁ + 1, ln d_∞ − 2), d_∞ = saturated separation, mean over the last 50 of T = 400 steps); t_sat = first t with ⟨ln d(t)⟩ > ln d_∞ − 1; t_dec = first t from which |r_ens(t)| < 4/√16,384 = 0.031 for five consecutive iterations (`analyze_family.py`, recomputed from the per-step files). Base points: Hénon a = 1.4, 1.3, 1.28; logistic r = 4.0, 3.9, 3.7 (K = 0.05); tent μ = 2.0, 1.6, 1.3 (K = 0.05); δ = 10⁻¹², 10⁻¹⁰, 10⁻⁸, 10⁻⁶, 10⁻⁴, 10⁻³, 10⁻² (K axis of the Hénon map up to 10⁻³). Controls: δ = 0 (d ≡ 0, r_ens ≡ 1.000000); adjacent weights; B = 0 (split at the seed state); topology (2,3). Each base point was also classified by the mixing diagnostic of part C (`mixing/basepoints_*.csv`).

**Result.** At the seven **mixing** base points (far autocorrelation tail < 0.1: Hénon 1.28/1.3/1.4, logistic 3.9/4.0, tent 1.6/2.0) the separation grows at the maximal Lyapunov exponent — growth slope / λ₁ = **0.950–1.062 for δ₁ ≤ 10⁻⁴ (80 fits) and 0.950–1.171 over all δ (104 fits; the values above 1.06 come from the 3–4-point fits at δ ≥ 10⁻³)** — and t_dec is linear in ln(1/δ₁) with slope 1/λ₁ (fitted slope × λ₁ = 0.97–1.24 over the 14 mixing configurations; integer-valued t_dec). **The intercept t₀ is not universal: it tracks the correlation-decay time τ_c of the attractor** (τ_c = first lag from which |ρ(τ)| < 0.05 for eight consecutive lags, single trajectory, part C): Hénon a = 1.4/1.3/1.28 → τ_c = 14/29/78 and t_dec − t_sat = 11.6/19.5/50.6; logistic r = 4.0/3.9 → τ_c = 3 and t_dec − t_sat = 5.7–8.6; tent μ = 2.0/1.6 → τ_c = 3/6 and t_dec − t_sat = 2.9–6.4. For the phase-oscillator map (09-05) τ_c is one to two iterations and so is t₀. At the two **non-mixing** base points (logistic r = 3.7 and tent μ = 1.3, both in the banded-chaos regime, far tail 0.73 and 0.86) the separation still grows at λ₁ (growth/λ₁ = 0.88–0.99) **but r_ens never collapses within 400 iterations** (t_dec undefined at every δ): exponential divergence without decorrelation. The B = 0 control reproduces the B = 10⁴ law at every δ (t_dec 58 50 40 32 22 17 13 vs 57 49 40 31 22 17 12); topology (2,3) at r = 4 gives slope × λ₁ = 1.10, t₀ = 4.1; adjacent-weight controls decorrelate in 19–22 (Hénon), 8–9 (logistic), 7–8 (tent) iterations from δ₁ ≈ 0.005–0.03.

```
family    (p,q)       K   param axis        λ1    growth/λ1 min–max (n)  slope·λ1    t0 tdec−tsat far-tail  τ_c                   t_dec list
henon     (3,5)   0.01    1.28 K       0.2802    0.9513–1.0582 (6)     1.242 54.61     48.33    0.011   78        159 149 120 104 81 70
henon     (3,5)   0.01    1.28 param   0.2802    0.9497–1.1057 (7)     1.028 58.00     52.86    0.011   78     162 142 124 108 86 80 83
henon     (3,5)   0.01     1.3 K       0.3380    0.9995–1.0858 (6)     1.159 18.52     18.67    0.010   29           104 91 76 59 42 34
henon     (3,5)   0.01     1.3 param   0.3380    0.9971–1.0657 (7)     1.088 20.42     20.43    0.010   29        107 91 76 64 46 38 34
henon     (3,5)   0.01     1.4 K       0.4294    1.0023–1.0350 (6)     1.125 11.32     11.67    0.009   14            79 66 57 43 30 25
henon     (3,5)   0.01     1.4 param   0.4294    1.0015–1.0329 (7)     1.077 10.64     11.57    0.009   14         78 66 55 44 33 25 20
logistic  (3,5)   0.05     3.7 K       0.2871    0.8843–0.9901 (6)       nan   nan       nan    0.728   -1         -1 -1 -1 -1 -1 -1 -1   <- NON-MIXING base point (banded): separation grows at λ₁ but r_ens never collapses
logistic  (3,5)   0.05     3.7 param   0.2871    0.9148–0.9941 (6)       nan   nan       nan    0.728   -1         -1 -1 -1 -1 -1 -1 -1   <- NON-MIXING base point (banded): separation grows at λ₁ but r_ens never collapses
logistic  (3,5)   0.05     3.9 K       0.4461    0.9996–1.0086 (6)     1.069  5.98      8.57    0.009    3         70 59 48 37 26 20 15
logistic  (3,5)   0.05     3.9 param   0.4461    1.0015–1.0380 (7)     1.097  4.81      8.14    0.009    3         72 62 51 39 27 22 16
logistic  (3,5)   0.05       4 K       0.5529    1.0044–1.0678 (6)     1.084  3.39      5.71    0.007    3          55 46 38 29 20 15 9
logistic  (2,3)   0.05       4 param   0.6199    1.0043–1.1712 (7)     1.103  4.10      6.00    0.008    5         53 45 37 30 21 17 11
logistic  (3,5)   0.05       4 param   0.5529    1.0032–1.1461 (7)     1.080  3.56      6.00    0.007    3         57 49 40 31 22 17 12
logistic  (3,5)   0.05       4 param   0.5529    1.0048–1.1549 (7)     1.093  3.59      6.14    0.007    3         58 50 40 32 22 17 13
tent      (3,5)   0.05     1.3 K       0.2723    0.8854–0.9781 (5)       nan   nan       nan    0.859   -1         -1 -1 -1 -1 -1 -1 -1   <- NON-MIXING base point (banded): separation grows at λ₁ but r_ens never collapses
tent      (3,5)   0.05     1.3 param   0.2723    0.8819–0.9841 (6)       nan   nan       nan    0.859   -1         -1 -1 -1 -1 -1 -1 -1   <- NON-MIXING base point (banded): separation grows at λ₁ but r_ens never collapses
tent      (3,5)   0.05     1.6 K       0.4444    0.9793–1.0001 (6)     1.008  3.19      6.43    0.015    6         65 55 45 34 24 18 13
tent      (3,5)   0.05     1.6 param   0.4444    0.9906–1.0010 (6)     0.972  2.49      6.14    0.015    6         66 55 44 35 24 21 15
tent      (3,5)   0.05       2 K       0.6422    1.0005–1.0043 (6)     0.998  1.66      2.86    0.010    3         45 38 30 23 16 12 10
tent      (3,5)   0.05       2 param   0.6422    0.9882–1.0049 (7)     1.015  2.93      4.29    0.010    3         48 40 33 26 19 15 11
control henon pq delta=1.000e+00: <ln d>(1)=-5.2156 t_dec=22 r(T)=0.005237
control henon pq delta=2.000e+00: <ln d>(1)=-5.2034 t_dec=19 r(T)=-0.003449
control henon zero delta=0.000e+00: <ln d>(1)=-inf t_dec=-1 r(T)=1.000000
control logistic pq delta=1.000e+00: <ln d>(1)=-3.6129 t_dec=8 r(T)=-0.006491
control logistic pq delta=2.000e+00: <ln d>(1)=-3.5163 t_dec=9 r(T)=-0.006167
control logistic zero delta=0.000e+00: <ln d>(1)=-inf t_dec=-1 r(T)=1.000000
control tent pq delta=1.000e+00: <ln d>(1)=-3.7592 t_dec=7 r(T)=-0.006308
control tent pq delta=2.000e+00: <ln d>(1)=-3.7451 t_dec=8 r(T)=-0.006479
control tent zero delta=0.000e+00: <ln d>(1)=-inf t_dec=-1 r(T)=1.000000
```
Files: `decorr/res_*_summary.csv`, `decorr/res_*_steps.csv`, `decorr/decorr_fit_table.csv`, `decorr/decorr_summary.txt`.

## B. The boundary: parameter sweeps of the three families (`window/`, MCL-P3-FAMWIN-2026-0930-001)

**Protocol** (as MCL-P3-WINDOWCTRL-2026-0905-001, with the map parameter in place of K). Same-seed pairs (c) versus (c + δ) on a fine grid of the map parameter — Hénon a ∈ [1.000, 1.399] step 0.001 (K = 0.01), logistic r ∈ [3.500, 3.999] step 0.001 at K = 0.05 (the paper's coupling) and at K = 0.005 (weak coupling, at which the period-3 window of the uncoupled map survives), tent μ ∈ [1.200, 1.999] step 0.001 (K = 0.05) — with δ = 0.0005 (half the grid step), topology (3,5). Per cell: (i) *ensemble* r_ens(t), the Pearson correlation of x₁ across 2,048 seeds at the same t, for t ∈ [10⁴, 10⁴ + 200]; (ii) *time series* after the 10⁴-step split, 10⁵ steps: Pearson of x₁ at lag 0 and its maximum over |lag| ≤ 64, Miller–Madow mutual information and joint χ² of (x₁ᴬ, x₁ᴮ) on 32 × 32 bins; (iii) λ₁ (Benettin, 10⁵ steps) and exact period (≤ 256) of the cell and of its partner. "Fails to decorrelate" = max |r_ens| ≥ 0.3 over the 200-step window, or time-series max |r_lag| > 0.5, or MI > 0.5 bit — the 09-05 criteria unchanged. Cells are classified by the **intrinsic** mixing diagnostic of part C (a cell is *non-mixing* if it is locked — λ₁ ≤ 0.02 or periodic — or if its persistent autocorrelation, max |ρ(τ)| over τ ∈ [4001, 4096], is ≥ 0.1; the partner's class is taken from the two neighbouring grid cells). 2,200 cells, no escapes.

**Result.**

| sweep | cells | non-mixing cells (runs) | of which locked (λ₁ ≤ 0.02 or periodic) / banded chaos (λ₁ > 0.02) | both non-mixing: n / fail | both mixing: n / fail | mixed pair: n / fail | mixing-cell maxima \|r_lag\| / MI (bit) / \|r_ens\| | expected null extreme \|r_ens\| |
|---|---:|---|---|---|---|---|---|---|
| henon K=0.01 (a ∈ [1.000, 1.399]) | 400 | 189 (3) | 104 / 85 | 189 / 185 | 209 / 0 | 2 / 0 | 0.123 / 0.020 / 0.089 | 0.102 |
| logistic K=0.005 (r ∈ [3.500, 3.999]) | 500 | 229 (7) | 109 / 120 | 229 / 224 | 265 / 0 | 6 / 0 | 0.040 / 0.003 / 0.093 | 0.103 |
| logistic K=0.05 (r ∈ [3.500, 3.999]) | 500 | 223 (5) | 121 / 102 | 223 / 218 | 272 / 0 | 5 / 0 | 0.055 / 0.002 / 0.095 | 0.103 |
| tent K=0.05 (μ ∈ [1.200, 1.999]) | 800 | 153 (2) | 0 / 153 | 153 / 147 | 646 / 0 | 1 / 0 | 0.219 / 0.048 / 0.100 | 0.107 |

Totals over the four sweeps: **both members mixing: 0 failures in 1392 pairs; both non-mixing: 774 failures in 794 pairs; mixed pairs 0/14.** Failure rate of the pairs by the smaller persistent autocorrelation of the two members: min far tail in [0,0.05): 0/1394; min far tail in [0.05,0.1): 0/12; min far tail in [0.1,0.3): 0/7; min far tail in [0.3,0.6): 2/5; min far tail in [0.6,0.9): 298/302; min far tail in [0.9,1.01): 474/480. The 20 pairs of non-mixing cells that decorrelate all sit at the edges of the non-mixing runs: in 8 the partner cell is outside the run (its λ₁ exceeds the cell's by 0.19–0.65: r = 3.709, 3.753, 3.757, 3.763, 3.778, 3.803, 3.826, 3.981 — the same edge effect as the four cells of Sec. III.C), in 12 the persistent correlation of the pair is the smallest in the non-mixing class (0.10–0.65: Hénon a = 1.136–1.139, logistic r = 3.682 and 3.713, tent μ = 1.347–1.354), i.e. at the band-merging point where the band component starts to decay. The non-mixing cells are of two kinds: **locked** (periodic orbit: Hénon 104 cells, periods 4, 7, 8, 14, 24, 28, 32, 42, 98; logistic 121/109 cells, periods 3–36; tent none) and **banded chaos** (λ₁ > 0.02 but a persistent periodic component — chaotic within 2ⁿ bands with a rigid band cycle, the reverse-bifurcation regime between the period-doubling accumulation point and the last band merging): Hénon 85 cells (a ≤ 1.139 and a ≈ 1.26), logistic 102/120 cells (r ≤ 3.713/3.682 and the band structure inside the windows), **tent 153 cells (μ ≤ 1.351, band-cycle lags 4 and 6) with no periodic orbit anywhere on the grid** (λ₁ ≥ 0.19 in all 800 cells). In the banded cells the two trajectories decorrelate within the bands but share the band phase: time-series MI ≈ log₂(number of bands) (1.0, 2.0, 2.7 bit), max |r_lag| ≈ 0.9–1.0. The uncoupled tent map has one band for μ > √2 = 1.4142 and two bands below; at K = 0.05 the measured merging point is μ ≈ 1.352 (persistent tail falls below 0.1 at μ = 1.352–1.355), below √2, and between 1.352 and √2 the band correlation is present at short lags (near tail [65, 512] ≥ 0.1 up to μ ≈ 1.43) but decays (far tail < 0.1) — these cells are mixing with a long correlation time and decorrelate (0 failures).

Summary per sweep with the exceptions: `window/window_summary.txt`; per-cell data `window/<sweep>.csv` (merged from the eight slices `window/<sweep>_slice*.csv`).

## C. Intrinsic mixing diagnostic (`mixing/`, MCL-P3-FAMMIX-2026-0930-001)

`family_mixing.cpp`: single trajectory from the engine seed, engine burn-in, N = 10⁵ samples of x₁; autocorrelation ρ(τ) for τ = 1..512 and τ = 4001..4096; reported per cell: λ₁, exact period, max |ρ| and its lag over [1, 64], the positive-peak lag (band-cycle period), the **near tail** max |ρ| over [65, 512], the **far tail** max |ρ| over [4001, 4096] (a periodic component that has not decayed after 4,000 iterations; sampling floor 3/√N = 0.0095), and the decay lag τ_c (first τ with |ρ| < 0.05 for eight consecutive lags). The far tail is bimodal on every grid (Hénon: 208 cells < 0.05, 187 cells ≥ 0.3, 5 cells in between; logistic K = 0.005: 271 / 229 / 0; K = 0.05: 276 / 222 / 2; tent: 639 / 149 / 12), which is what makes the classification of part B insensitive to the threshold between 0.05 and 0.3. Grids: `mixing/<sweep>_mixing.csv`; base points: `mixing/basepoints_*.csv`; first version with the near tail only (N = 2 × 10⁴) kept in `mixing/_v1/`.

## D. Figure

`paper3_fig6.png` (300 dpi; `analyze_family.py`): top row, t_dec against ln(1/δ₁) at the mixing base points with the fixed-slope lines t₀ + ln(1/δ₁)/λ₁; bottom row, λ₁ and the persistent autocorrelation against the map parameter, locked cells shaded grey, banded-chaotic cells shaded red, and the pairs that fail to decorrelate marked below the axis.

## E. Files and integrity

`SHA256SUMS` lists every file of this folder except the compiled binaries and the smoke outputs. `stage_public_bundle.sh` copies the folder into the public bundle (`20260822_public/MCL/P3_FamilyGeneralization_20260930/`); the push is the author's decision, and the paper must not cite this record publicly before it is pushed (rule ق-12).

## F. Paper-form tables and derived roundings (provenance of every number printed in Sec. VII.F)

The two tables below are the ones printed in the paper (Tables XII and XIII), generated from `decorr/decorr_fit_table.csv`, `decorr/res_*_summary.csv`, `mixing/basepoints_*.csv` and `window/window_table.md` by the paper-edit script of 2026-09-30 (rounding: λ₁ and the persistent tail to 3 decimals, growth ratios to 3 decimals, slope × λ₁ to 2, t₀ and t_dec − t_sat to 1). Prose roundings used in the paper: growth / λ₁ "0.95–1.06" = 0.9497–1.0617 (δ₁ ≤ 10⁻⁴, mixing base points); "0.88–0.99" = 0.8819–0.9941 (banded base points, all δ); "0.97–1.24" = the slope × λ₁ column; τ_c and t_dec − t_sat as in Table XIII (Hénon 11.6/11.7 → 12, 20.4/18.7 → 20, 52.9/48.3 → 51); mixing-cell maxima "0.22 / 0.05 bit / 0.100" = 0.2191 / 0.0481 / 0.1002 (tent sweep); expected null extreme "0.10–0.11" = 0.102–0.107; totals: locked 104 + 121 + 109 + 0 = 334, banded 85 + 102 + 120 + 153 = 460, both-non-mixing pairs 189 + 223 + 229 + 153 = 794 with 185 + 218 + 224 + 147 = 774 failures, both-mixing pairs 209 + 272 + 265 + 646 = 1,392 with 0 failures, mixed 2 + 5 + 6 + 1 = 14 with 0; failure rate by the smaller persistent tail of the pair: ≥ 0.6 → (46 + 76 + 77 + 99) + (138 + 148 + 140 + 48) = 298 + 474 = 772 of 302 + 480 = 782; < 0.3 → 0 of 1,394 + 12 + 7 = 1,413 (see `window/window_summary.txt`, lines "failure rate of pairs by min(far tail…)"); exceptions 20 = 8 partner-outside + 12 weak-persistence (`analysis_run.txt` categorisation of 2026-09-30).

**Table XII: The Decorrelation Time Scale in the Three Additional Families (topology (3,5); 16,384 seeds; seven perturbation sizes per axis; Hénon K = 0.01, logistic and tent K = 0.05)**

| Family | base point | perturbed | λ₁ | attractor (persistent \|ρ\|) | τ_c | growth / λ₁ (δ₁ ≤ 10⁻⁴) | slope × λ₁ | t₀ / (t_dec − t_sat) |
|---|---|---|---|---|---|---|---|---|
| Hénon | a = 1.4 | a | 0.429 | mixing (0.009) | 14 | 1.002–1.025 | 1.08 | 10.6 / 11.6 |
| Hénon | a = 1.4 | K | 0.429 | mixing (0.009) | 14 | 1.002–1.024 | 1.13 | 11.3 / 11.7 |
| Hénon | a = 1.3 | a | 0.338 | mixing (0.010) | 29 | 0.997–1.044 | 1.09 | 20.4 / 20.4 |
| Hénon | a = 1.3 | K | 0.338 | mixing (0.010) | 29 | 0.999–1.062 | 1.16 | 18.5 / 18.7 |
| Hénon | a = 1.28 | a | 0.280 | mixing (0.011) | 78 | 0.950–0.995 | 1.03 | 58.0 / 52.9 |
| Hénon | a = 1.28 | K | 0.280 | mixing (0.011) | 78 | 0.951–0.995 | 1.24 | 54.6 / 48.3 |
| logistic | r = 4 | r | 0.553 | mixing (0.007) | 3 | 1.005–1.043 | 1.09 | 3.6 / 6.1 |
| logistic | r = 4 | K | 0.553 | mixing (0.007) | 3 | 1.004–1.041 | 1.08 | 3.4 / 5.7 |
| logistic | r = 3.9 | r | 0.446 | mixing (0.009) | 3 | 1.001–1.017 | 1.10 | 4.8 / 8.1 |
| logistic | r = 3.9 | K | 0.446 | mixing (0.009) | 3 | 1.000–1.009 | 1.07 | 6.0 / 8.6 |
| tent | μ = 2 | μ | 0.642 | mixing (0.010) | 3 | 1.001–1.003 | 1.01 | 2.9 / 4.3 |
| tent | μ = 2 | K | 0.642 | mixing (0.010) | 3 | 1.000–1.002 | 1.00 | 1.7 / 2.9 |
| tent | μ = 1.6 | μ | 0.444 | mixing (0.015) | 6 | 0.997–1.001 | 0.97 | 2.5 / 6.1 |
| tent | μ = 1.6 | K | 0.444 | mixing (0.015) | 6 | 0.991–1.000 | 1.01 | 3.2 / 6.4 |
| logistic | r = 3.7 | r | 0.287 | banded (non-mixing) (0.728) | > 512 | 0.953–0.994 | — | — |
| logistic | r = 3.7 | K | 0.287 | banded (non-mixing) (0.728) | > 512 | 0.932–0.990 | — | — |
| tent | μ = 1.3 | μ | 0.272 | banded (non-mixing) (0.859) | > 512 | 0.923–0.984 | — | — |
| tent | μ = 1.3 | K | 0.272 | banded (non-mixing) (0.859) | > 512 | 0.885–0.978 | — | — |

**Table XIII: The Decorrelation Boundary in the Three Additional Families (topology (3,5); grid step 0.001, partner c + 0.0005; 2,048 seeds per cell)**

| Family, coupling | parameter range (cells) | non-mixing cells: locked / banded | both non-mixing: pairs / fail | both mixing: pairs / fail | mixed pairs / fail | mixing-cell maxima: \|r_lag\| / MI (bit) / \|r_ens\| |
|---|---|---|---|---|---|---|
| Hénon, K = 0.01 | a ∈ [1.000, 1.399] (400) | 104 / 85 | 189 / 185 | 209 / 0 | 2 / 0 | 0.123 / 0.020 / 0.089 |
| logistic, K = 0.05 | r ∈ [3.500, 3.999] (500) | 121 / 102 | 223 / 218 | 272 / 0 | 5 / 0 | 0.055 / 0.002 / 0.095 |
| logistic, K = 0.005 | r ∈ [3.500, 3.999] (500) | 109 / 120 | 229 / 224 | 265 / 0 | 6 / 0 | 0.040 / 0.003 / 0.093 |
| tent, K = 0.05 | μ ∈ [1.200, 1.999] (800) | 0 / 153 | 153 / 147 | 646 / 0 | 1 / 0 | 0.219 / 0.048 / 0.100 |
| **all four sweeps** | **2,200** | **334 / 460** | **794 / 774** | **1,392 / 0** | **14 / 0** | expected null extreme of \|r_ens\|: 0.10–0.11 |

