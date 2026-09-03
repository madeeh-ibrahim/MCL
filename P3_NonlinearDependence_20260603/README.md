# P3_NonlinearDependence_20260603 — Paper 3 nonlinear-dependence campaign (June 2026)

Five test programs and their recorded outputs (`results_v3/`) for the 66 = C(12, 2) pairs of the twelve
Table II channels of Paper 3 (Physical Review E), N = 10⁷ bytes per channel, seed 12345678901234, K = 12:
mutual information (Miller–Madow, permutation null), distance correlation (Szekely–Rizzo, permutation p),
lagged cross-correlation (|lag| ≤ 100), block-joint χ², and within-channel lag autocorrelation.
Aggregate: `results_v3/AGGREGATE_v3.md` (0 failures / 66 pairs per test; identical and quadratic controls fail).
Cited in Paper 3 §V.I. Campaign manifest: `Paper3_v3_MANIFEST.md`.

**Engine.** The campaign ran on `mcl_core.hpp` **6.0.0** (MD5 `241db79ecf8a42897eb9a8399cf37929`) — git tag `v0.1.0`
of this repository; its copy is omitted here, as for `M1_M2_apple_verification/`. The T2 float path of the
current engine 8.1.3 is KAT-identical to 6.0.0, so the programs build against the repository root header:

```bash
c++ -O3 -std=c++17 -Wall -Wextra -DMCL_UNSAFE_ALLOW_INVALID -I.. mcl_mutual_information_test.cpp -o mi_test
```

License: PolyForm Noncommercial 1.0.0 + Security Research & Evaluation Grant (see repository root).
