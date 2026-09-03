# Paper 3 — Supplementary Results: Nonlinear Dependence Test Suite

**Manuscript:** *Parameter-Induced Statistical Independence in Coupled Chaotic Oscillators: An Anti-Synchronization Paradigm* (Zenodo DOI 10.5281/zenodo.20496912).
**Author:** Madeeh Ibrahim — Independent Researcher, Cairo, Egypt — ORCID 0009-0002-8562-8325.
**Engine:** `mcl_core.hpp` v6.0.0, MD5 `241db79ecf8a42897eb9a8399cf37929` (frozen). **License:** PolyForm Noncommercial 1.0.0.

---

## 1. Purpose
The decorrelation evidence in §V.A–§V.G of the manuscript rests on second-order statistics (Pearson, Hamming) and marginal uniformity (chi-square), which by construction cannot detect **nonlinear**, **temporal**, or **joint-distribution** dependence. This supplement applies five additional tests to a pre-specified, enumerable family of channel pairs to close that gap.

## 2. Family (pre-specified, reproducible)
**66 pairs = C(12,2)** of the twelve Table-II channels:
`(2,3) (3,5) (5,7) (7,11) (8,13) (11,17) (3,2)ᵀ (5,3)ᵀ (4,6) (6,9) (13,19) (17,23)`
The set deliberately includes the **transposed** (p>q) and **non-coprime / same-ratio** controls — the configurations where any residual dependence would most plausibly appear. (Note: the number 53 elsewhere in the corpus refers to 53 Lyapunov scaling-law *configurations*, not pairs; the independence family is the 66 above.)

## 3. The five tests
| # | Test | Detects | Decision statistic |
|---|---|---|---|
| 1 | Lag autocorrelation | temporal (within-channel) | rho(1), tau_dec, N_eff/N |
| 2 | Mutual information (Miller-Madow) | nonlinear | MI magnitude + permutation p (alpha/66) |
| 3 | Distance correlation (Szekely-Rizzo) | linear AND nonlinear | one-sided permutation p (alpha/66) |
| 4 | Lagged cross-correlation | delayed linear | max\|r\| vs family-Bonferroni floor |
| 5 | Block-joint chi-square | joint distribution | one-sided z |

Settings: MI `N=1e7, nperm=1000`; dCor `n=5000, nperm=2000, family=66`; lag-xcorr `N=1e7, maxlag=100, family=66`; block-chi2 `N=1e7`; autocorr `N=1e7, maxlag=100`. Seed `12345678901234`.

## 4. Apparatus validation (controls)
The suite was validated on known-dependence controls; both correctly FAIL, confirming it detects real linear and nonlinear dependence:
- `identical` (Y = X): dCor perm-p = **0.00050 → FAIL**.
- `quadratic` (Y = ((X−128)²), Pearson ≈ 0): dCor perm-p = **0.00050 → FAIL** (nonlinear dependence Pearson misses).

## 5. Per-channel temporal independence (lag autocorrelation, 12 channels)

| channel | rho(1) | tau_dec | N_eff/N | verdict |
|---|---|---|---|---|
| (2,3) | -1.351315e-05 | 1 | 1.000027 | PASS |
| (3,5) | -7.465196e-04 | 2 | 1.001871 | PASS |
| (5,7) | 7.542659e-05 | 1 | 0.999849 | PASS |
| (7,11) | 1.397385e-04 | 1 | 0.999721 | PASS |
| (8,13) | -3.670885e-04 | 2 | 1.001260 | PASS |
| (11,17) | 9.476515e-05 | 1 | 0.999811 | PASS |
| (3,2) | -9.439592e-05 | 1 | 1.000189 | PASS |
| (5,3) | -5.583001e-05 | 1 | 1.000112 | PASS |
| (4,6) | 1.913330e-04 | 1 | 0.999617 | PASS |
| (6,9) | 7.550163e-05 | 1 | 0.999849 | PASS |
| (13,19) | 1.356784e-04 | 1 | 0.999729 | PASS |
| (17,23) | -2.387751e-04 | 1 | 1.000478 | PASS |

## 6. Cross-channel nonlinear dependence (66 pairs)

| pair | MI_MM (bits) | dCor perm-p (z) | lag-xcorr max\|r\| | block chi2 z | all-pass |
|---|---|---|---|---|---|
| (2,3)vs(3,5) | -8.268812e-06 | 0.67716 (z=-0.5572) | 1.161672e-03 (lag 36) | -0.5233 | YES |
| (2,3)vs(5,7) | 1.988605e-06 | 0.63918 (z=-0.5083) | 8.836321e-04 (lag -47) | -0.0851 | YES |
| (2,3)vs(7,11) | 3.490871e-05 | 0.33433 (z=0.2175) | 8.941269e-04 (lag 84) | 1.1809 | YES |
| (2,3)vs(8,13) | 1.522165e-05 | 0.35132 (z=0.1620) | 8.715852e-04 (lag -46) | 0.4488 | YES |
| (2,3)vs(11,17) | -6.807083e-05 | 0.22289 (z=0.5783) | 8.409809e-04 (lag -76) | -2.8036 | YES |
| (2,3)vs(3,2) | 6.557605e-05 | 0.06847 (z=1.6539) | 9.971220e-04 (lag -90) | 2.2660 | YES |
| (2,3)vs(5,3) | -7.897936e-05 | 0.54723 (z=-0.3054) | 8.282402e-04 (lag -88) | -3.1649 | YES |
| (2,3)vs(4,6) | -2.047025e-05 | 0.66717 (z=-0.5598) | 9.625191e-04 (lag 59) | -0.9803 | YES |
| (2,3)vs(6,9) | 2.724258e-05 | 0.50825 (z=-0.2298) | 8.983779e-04 (lag 24) | 0.8551 | YES |
| (2,3)vs(13,19) | -5.577852e-06 | 0.66167 (z=-0.5369) | 1.135421e-03 (lag -70) | -0.4357 | YES |
| (2,3)vs(17,23) | -3.096820e-06 | 0.37881 (z=0.0667) | 1.008943e-03 (lag -76) | -0.3034 | YES |
| (3,5)vs(5,7) | 3.335217e-05 | 0.62519 (z=-0.4505) | 8.221066e-04 (lag 37) | 1.1009 | YES |
| (3,5)vs(7,11) | 1.577458e-05 | 0.15642 (z=0.9753) | 9.408169e-04 (lag -80) | 0.4211 | YES |
| (3,5)vs(8,13) | 3.316138e-05 | 0.10595 (z=1.3160) | 1.167776e-03 (lag -77) | 1.1406 | YES |
| (3,5)vs(11,17) | 1.809159e-05 | 0.75012 (z=-0.7096) | 9.264365e-04 (lag 41) | 0.5237 | YES |
| (3,5)vs(3,2) | 5.050269e-05 | 0.47526 (z=-0.1490) | 8.719424e-04 (lag 42) | 1.7513 | YES |
| (3,5)vs(5,3) | -9.613509e-06 | 0.19190 (z=0.7924) | 8.467331e-04 (lag -46) | -0.6136 | YES |
| (3,5)vs(4,6) | 4.791143e-06 | 0.55772 (z=-0.3330) | 7.767063e-04 (lag 66) | -0.0349 | YES |
| (3,5)vs(6,9) | 1.245727e-05 | 0.20240 (z=0.7196) | 1.009501e-03 (lag 94) | 0.2813 | YES |
| (3,5)vs(13,19) | 2.399805e-05 | 0.50725 (z=-0.1992) | 1.122774e-03 (lag -96) | 0.6797 | YES |
| (3,5)vs(17,23) | 2.316476e-05 | 0.35882 (z=0.1222) | 8.253941e-04 (lag -18) | 0.7183 | YES |
| (5,7)vs(7,11) | 2.373081e-05 | 0.09495 (z=1.3458) | 1.036032e-03 (lag -87) | 0.7285 | YES |
| (5,7)vs(8,13) | -9.505179e-06 | 0.12194 (z=1.1904) | 8.417700e-04 (lag 68) | -0.5586 | YES |
| (5,7)vs(11,17) | 2.355343e-05 | 0.85057 (z=-0.9032) | 8.326339e-04 (lag -84) | 0.5762 | YES |
| (5,7)vs(3,2) | -3.527311e-06 | 0.06547 (z=1.8051) | 1.083400e-03 (lag -37) | -0.3858 | YES |
| (5,7)vs(5,3) | 3.609971e-05 | 0.26787 (z=0.3899) | 9.057856e-04 (lag -55) | 1.1669 | YES |
| (5,7)vs(4,6) | 3.030935e-05 | 0.71914 (z=-0.6344) | 9.878384e-04 (lag 45) | 0.9087 | YES |
| (5,7)vs(6,9) | 3.370406e-05 | 0.09895 (z=1.3484) | 1.096465e-03 (lag -93) | 1.0712 | YES |
| (5,7)vs(13,19) | 2.647265e-05 | 0.41329 (z=-0.0159) | 9.303232e-04 (lag -95) | 0.7844 | YES |
| (5,7)vs(17,23) | -1.357750e-05 | 0.70115 (z=-0.6006) | 1.166916e-03 (lag 87) | -0.7928 | YES |
| (7,11)vs(8,13) | 1.736809e-05 | 0.27736 (z=0.3336) | 9.453829e-04 (lag 47) | 0.4728 | YES |
| (7,11)vs(11,17) | -6.639200e-07 | 0.83708 (z=-0.8892) | 8.387979e-04 (lag -39) | -0.2264 | YES |
| (7,11)vs(3,2) | 8.185684e-06 | 0.76012 (z=-0.7391) | 1.068434e-03 (lag 0) | 0.1159 | YES |
| (7,11)vs(5,3) | -2.383365e-05 | 0.28936 (z=0.3753) | 8.357805e-04 (lag -14) | -1.2234 | YES |
| (7,11)vs(4,6) | -3.691148e-05 | 0.31284 (z=0.2457) | 7.890613e-04 (lag -29) | -1.6191 | YES |
| (7,11)vs(6,9) | 2.361030e-05 | 0.45327 (z=-0.1161) | 9.159355e-04 (lag 99) | 0.6642 | YES |
| (7,11)vs(13,19) | 8.884802e-06 | 0.64668 (z=-0.5080) | 1.116617e-03 (lag -58) | 0.0891 | YES |
| (7,11)vs(17,23) | 1.200949e-05 | 0.20640 (z=0.7294) | 1.081144e-03 (lag 62) | 0.2809 | YES |
| (8,13)vs(11,17) | 7.431020e-06 | 0.18691 (z=0.7380) | 8.946817e-04 (lag -7) | 0.1013 | YES |
| (8,13)vs(3,2) | 2.003619e-05 | 0.20840 (z=0.6944) | 1.027898e-03 (lag 43) | 0.5769 | YES |
| (8,13)vs(5,3) | 3.042779e-05 | 0.88406 (z=-0.9796) | 7.602213e-04 (lag -84) | 0.9221 | YES |
| (8,13)vs(4,6) | 3.521187e-05 | 0.34033 (z=0.1826) | 9.420047e-04 (lag 20) | 1.1983 | YES |
| (8,13)vs(6,9) | 3.461402e-05 | 0.32184 (z=0.2240) | 1.114307e-03 (lag 90) | 1.1777 | YES |
| (8,13)vs(13,19) | 9.492288e-06 | 0.12844 (z=1.1021) | 1.149139e-03 (lag 53) | 0.0488 | YES |
| (8,13)vs(17,23) | 3.732715e-05 | 0.23938 (z=0.4700) | 8.537349e-04 (lag 76) | 1.2448 | YES |
| (11,17)vs(3,2) | -3.347377e-05 | 0.41879 (z=-0.0135) | 1.067119e-03 (lag 3) | -1.4037 | YES |
| (11,17)vs(5,3) | 3.919228e-05 | 0.52624 (z=-0.2541) | 9.551875e-04 (lag -97) | 1.2671 | YES |
| (11,17)vs(4,6) | 3.625103e-05 | 0.45277 (z=-0.1004) | 1.074110e-03 (lag -81) | 1.1766 | YES |
| (11,17)vs(6,9) | -1.853876e-05 | 0.27386 (z=0.3779) | 8.650193e-04 (lag -68) | -0.8886 | YES |
| (11,17)vs(13,19) | 3.815170e-06 | 0.40080 (z=0.0337) | 9.116147e-04 (lag -2) | -0.0040 | YES |
| (11,17)vs(17,23) | 3.813839e-05 | 0.11894 (z=1.1864) | 7.890716e-04 (lag -33) | 1.3154 | YES |
| (3,2)vs(5,3) | 1.445198e-06 | 0.61319 (z=-0.4498) | 9.201414e-04 (lag -83) | -0.1528 | YES |
| (3,2)vs(4,6) | -1.979727e-05 | 0.00200 (z=4.0656) | 9.080560e-04 (lag 64) | -0.9623 | YES |
| (3,2)vs(6,9) | 1.155630e-05 | 0.89405 (z=-1.0692) | 7.669528e-04 (lag 94) | 0.2417 | YES |
| (3,2)vs(13,19) | -3.902353e-05 | 0.74263 (z=-0.7038) | 7.987104e-04 (lag -49) | -1.5996 | YES |
| (3,2)vs(17,23) | 1.076147e-05 | 0.37681 (z=0.1270) | 8.106526e-04 (lag -61) | 0.2928 | YES |
| (5,3)vs(4,6) | 2.715918e-05 | 0.69865 (z=-0.6062) | 8.618114e-04 (lag 60) | 0.8136 | YES |
| (5,3)vs(6,9) | 1.153748e-05 | 0.54223 (z=-0.3012) | 8.062106e-04 (lag -60) | 0.1569 | YES |
| (5,3)vs(13,19) | 1.930120e-05 | 0.01849 (z=2.8463) | 9.392203e-04 (lag 79) | 0.5573 | YES |
| (5,3)vs(17,23) | -8.064547e-06 | 0.87856 (z=-1.0118) | 8.933635e-04 (lag 70) | -0.3842 | YES |
| (4,6)vs(6,9) | -3.809779e-05 | 0.47476 (z=-0.1287) | 9.085533e-04 (lag 29) | -1.6053 | YES |
| (4,6)vs(13,19) | 1.429887e-05 | 0.12844 (z=1.1247) | 9.351286e-04 (lag -72) | 0.3081 | YES |
| (4,6)vs(17,23) | 3.081972e-06 | 0.48526 (z=-0.1948) | 1.046519e-03 (lag 61) | -0.0734 | YES |
| (6,9)vs(13,19) | 1.405405e-05 | 0.58271 (z=-0.3826) | 8.358359e-04 (lag 60) | 0.3333 | YES |
| (6,9)vs(17,23) | 3.045871e-05 | 0.89105 (z=-1.0091) | 1.001215e-03 (lag 40) | 1.0431 | YES |
| (13,19)vs(17,23) | -2.189559e-05 | 0.57171 (z=-0.3609) | 9.173343e-04 (lag -28) | -1.0292 | YES |


## 7. Summary


| test | FAILs / 66 | note |
|---|---|---|
| Mutual Information | 0 | mean MI ~9e-6 bits, max ~8e-5 (magnitude gate) |
| Distance correlation | 0 | one-sided perm-p, alpha/66; min perm-p = 0.00200 |
| Lagged cross-corr | 0 | family=66 Bonferroni (was 3 artifactual FAILs before fix) |
| Block joint chi2 | 0 | one-sided z<3.5 |
| Lag autocorrelation | 0 | 12/12 channels, rho(1)<=7.5e-4 |

Controls (apparatus validation): identical -> FAIL (p=0.00050); quadratic -> FAIL (p=0.00050).

## 8. Methodological correction (transparency)
An initial build used a Gaussian z-score for the distance-correlation significance. Because the dCor null is non-negative and right-skewed, a normal-theory z overstates upper-tail significance; this produced a single seed-specific FALSE POSITIVE on `(3,2)vs(4,6)` (z=+4.07). Investigation showed the signal **vanished at three other seeds** (z = −0.39, −0.42, −0.25), **shrank with sample size** (z = 4.07 at n=5000 → 2.67 at n=12000), and the pair was clean under MI, block-chi2, and lag-xcorr at N=1e7 — i.e. a finite-sample artifact, not real dependence and not a code bug. The decision statistic was corrected to a **one-sided permutation p-value** (with the apparatus re-validated as in §4). Full record: `Paper3_v3_MANIFEST.md`, "Methodological correction".

## 9. Reproduction
- Code (5 binaries, PolyForm-NC, SPDX-tagged): `mcl_lag_autocorrelation_test.cpp`, `mcl_mutual_information_test.cpp`, `mcl_distance_correlation_test.cpp`, `mcl_lagged_crosscorr_test.cpp`, `mcl_block_joint_test.cpp`.
- Build: `g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Werror -DMCL_UNSAFE_ALLOW_INVALID -I<core> <file>.cpp -o <bin>`
- Raw per-test outputs: `results_mutual_information.txt`, `results_distance_correlation.txt`, `results_lagged_crosscorr.txt`, `results_block_joint.txt`, `results_lag_autocorrelation.txt`, and the machine table `AGGREGATE_v3.md`.
- Cross-platform note: channels use float64 `std::sin` (not bit-identical across libm); the **independence conclusions are platform-invariant** but exact per-pair numbers are libm-dependent (statistical, not bit-exact, reproducibility). A Q30 integer engine is available for bit-exact reproduction.

## 10. Conclusion
Across all five tests — covering linear, nonlinear, temporal, and joint-distribution dependence — **66/66 channel pairs are consistent with statistical independence** at N=1e7, with the apparatus validated to detect real dependence. This complements the second-order evidence of §V and is consistent with empirical statistical independence within the resolution of the present design; it does not, by itself, constitute a measure-theoretic proof.
