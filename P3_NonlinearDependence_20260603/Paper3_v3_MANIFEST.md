# Paper 3 v3 — Nonlinear Dependence Test Suite: MANIFEST

All deliverables for the PRE-submission nonlinear-dependence campaign.
Engine: mcl_core.hpp (frozen, MD5 241db79ecf8a42897eb9a8399cf37929).
Build (all): g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion
             -Wsign-conversion -Werror -DMCL_UNSAFE_ALLOW_INVALID -I<core> <file>.cpp -o <bin>
License: PolyForm Noncommercial 1.0.0.

## The five test binaries (all compile -Werror clean; all apparatus-validated)

| # | File | Tests for | Positive control (verified) | Real channels |
|---|------|-----------|------------------------------|---------------|
| 3 | mcl_lag_autocorrelation_test.cpp | temporal (within-channel) | sine: rho(1)=cos(2pi/p) exact | PASS (rho1<0.01) |
| 1 | mcl_mutual_information_test.cpp   | nonlinear (MI, Miller-Madow) | identical=8bit; quadratic=6.7bit | PASS (MI~0) |
| 2 | mcl_distance_correlation_test.cpp | nonlinear (dCor) | identical/quadratic perm-p=0.00050 → FAIL | PASS (perm-p>alpha/66) |
| 4 | mcl_lagged_crosscorr_test.cpp     | delayed linear | shift:5 -> \|r\|=1 at lag 5 | PASS (Bonferroni) |
| 5 | mcl_block_joint_test.cpp          | joint-distribution (chi2) | identical/quadratic z~2e5+ → FAIL | PASS (one-sided z<3.5) |

## Paper section
- Paper3_v3_section_V_H.md : ready-to-paste §V.H + Table VI (slots [FULL-RUN] for
  your 53-pair Apple Silicon campaign), apparatus-validation paragraph, Methods.

## Review status (two adversarial passes, verified against independent references)
- dCor permutation math: exact (matches recenter-from-scratch). VERIFIED.
- Fixed-denom shortcut (dVar_y permutation-invariant): VERIFIED (0.00 diff).
- Miller-Madow sign/magnitude: matches Python reference (0.00235). VERIFIED.
- chi2 formula: matches scipy.chi2_contingency exactly. VERIFIED.
- lag indexing: matches Python reference (lag-7 control). VERIFIED.
- Bonferroni thresholds (SUPERSEDED — see "Methodological correction" below): originally
  dCor |z|<3.5, MI p>alpha/53, chi2 |z|<3.5. CORRECTED to: dCor one-sided perm-p>alpha/66;
  MI p>alpha/66 (magnitude gate primary); chi2 one-sided z<3.5; lag-xcorr family=66.
- FIX applied: Test 4 threshold was fixed 3.5; corrected to nlags-dependent
  Bonferroni (z_crit=3.664 for 201 lags) via Acklam inverse-normal. VERIFIED.

## SHARED property (second-pass finding) — affects all five
All use MCL_T2 float64 (std::sin), which is NOT bit-identical across platforms.
- Deterministic within a platform (repeat = identical).
- Independence CONCLUSIONS are platform-invariant (property of the dynamics).
- Exact per-channel numbers are libm-dependent => report STATISTICAL (not
  bit-exact) reproducibility. Q30 engine available if bit-exact is required.

## Full campaign (run on your Apple Silicon)
Family = 66 pairs = C(12,2) of the 12 Table-II channels. MEASURED wall-clock on Apple Silicon
(8 cores / 6 performance): ~4.5h single-thread, ~45–60 min on 6 cores (NOT the "5-7 days" of an
earlier estimate). Per channel / per pair:
  ./mcl_lag_autocorrelation_test  --p <P> --q <Q> --K 12 --N 10000000                              # 12 channels
  ./mcl_mutual_information_test    --p1 <..> --q1 <..> --p2 <..> --q2 <..> --K 12 --N 10000000 --nperm 2000   # nperm>=1320 for the p-gate
  ./mcl_distance_correlation_test  --p1 <..> --q1 <..> --p2 <..> --q2 <..> --K 12 --n 5000 --nperm 2000 --family 66
  ./mcl_lagged_crosscorr_test      --p1 <..> --q1 <..> --p2 <..> --q2 <..> --K 12 --N 10000000 --maxlag 100 --family 66
  ./mcl_block_joint_test           --p1 <..> --q1 <..> --p2 <..> --q2 <..> --K 12 --N 10000000
Then fill §V.H / Table slots from results_v3/AGGREGATE_v3.md and submit to PRE.

## Methodological correction (post-review campaign, 2026-06-03)

The review above ("two adversarial passes ... VERIFIED") confirmed the ESTIMATOR math
(dCor/chi2/MI/lag), which is correct. A subsequent full 66-pair campaign (family = C(12,2) of
Paper-3 Table II) surfaced a DECISION-LOGIC flaw that the estimator review did not cover:

- dCor flagged (3,2)vs(4,6) with z = +4.07 ("FAIL"). Investigation: the signal VANISHED at three
  other seeds (z = -0.39, -0.42, -0.25), SHRANK with sample size (z = 4.07 at n=5000 -> 2.67 at
  n=12000), and the same pair was clean under MI (-2e-5 bits), block-chi2 (z=-0.96), and lag-xcorr
  (max|r|=9.1e-4) at N=1e7. => a seed-specific finite-sample FALSE POSITIVE — not real dependence,
  and not a code bug.
- ROOT CAUSE: a Gaussian z-score was applied to the dCor permutation null, which is NON-NEGATIVE and
  right-skewed (null mean ~0.022), so a normal-theory z OVERSTATES upper-tail significance. The chi2
  test likewise used a two-sided |z| on a one-sided (upper-tail) statistic, and lag-xcorr corrected
  only over its 201 lags, not the 66-pair family.

FIXES APPLIED (all still compile -Werror clean against the frozen engine mcl_core.hpp 241db79e):
- dCor: decision now uses a ONE-SIDED permutation p-value with Bonferroni alpha/family (--family);
  z retained for context. Requires nperm >= family/0.05 (>=1320 for family=66) to resolve the
  threshold — campaign re-run at nperm=2000.
- chi2: ONE-SIDED z < 3.5 (a large negative z = benign under-dispersion, not dependence).
- lag-xcorr: --family folds cross-pair multiplicity into the Bonferroni z_crit.
- MI: alpha/53 -> alpha/66 (magnitude gate MI<0.01 remains operative for nperm<1320).

APPARATUS RE-VALIDATION after fixes: identical and quadratic controls BOTH correctly FAIL
(perm-p = 0.00050), confirming the suite still detects real linear AND nonlinear dependence.

RESULT after fixes (results_v3/, dCor nperm=2000): 66/66 pairs PASS all five tests; smallest dCor
perm-p = 0.00200 ((3,2)vs(4,6), > alpha/66 = 7.6e-4). See AGGREGATE_v3.md.

NOTE on "53": in the corpus, 53 refers to the 53 Lyapunov scaling-law CONFIGURATIONS (Paper 1/3
initial fit, K in [1,50], R^2=0.9912), NOT an enumerated set of 53 independence pairs. The
independence family is defined here explicitly as the 66 = C(12,2) Table-II channel pairs.
