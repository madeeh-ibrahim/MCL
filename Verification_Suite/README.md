# Verification_Suite — legacy science/verification tests

The older working verification programs (engine `mcl_core.hpp` v6.0.0→v6.1.0, Q30/Float64 paths). Brought into Stage 2 on 2026-06-16 — they were in the old working folder but had not been migrated and are **not** part of the public toolkit. Build any with `c++ -std=c++17 -O2 -I ../  <file>.cpp` (needs `mcl_core.hpp` from `02_Engine_Code/`). Saved outputs in `results/`.

| File | Verifies | Tech-Guide-cited |
|---|---|---|
| `mcl_burnin_sweep.cpp` | burn-in iteration sweep → justifies the 10⁴ burn-in constant | 📌 §1 |
| `mcl_decimation_sweep.cpp` | decimation sweep → justifies D = 2 | 📌 §1 |
| `mcl_k_independence.cpp` | coupling-strength independence → justifies K = 12 | 📌 §1 |
| `mcl_hex7_proto.cpp` | 7-oscillator prototype → N-oscillator generalization beyond N=4 (§4 / [0018a]) | 📌 §1 |
| `mcl_gs_jacobi_independence.cpp` | Gauss-Seidel vs Jacobi → the sequential-advantage / VDF basis | |
| `mcl_lyap_ratio.cpp` | GS/Jacobi Lyapunov ratio (> 1.5) | |
| `mcl_auth_verify.cpp` | hardware authentication (FAR/FRR) | |
| `mcl_topology_generalization.cpp` | cross-system / channel generality (the 135-test campaign) | |
| `mcl_hop_unified.cpp` | parameter hopping / forward secrecy | |
| `mcl_t3_t4_unified.cpp` | T3 / T4 variant tests | |
| `mcl_safe_zone_per_osc.cpp` | per-oscillator safe-zone extraction analysis | |
| `mcl_numerical_verify.cpp` | numerical / closed-form law verification | |
| `mcl_paper1_extras.cpp` | Paper 1 supplementary measurements | |
| `bench_diagnose.cpp` | benchmark diagnostics | |

*Note:* these complement — not replace — the suites already in Stage 2: `MCL_Public_Code/` (toolkit), `VDF_security/` (VDF cryptanalysis), `keyed_q30_PQ/` (keyed T4-Q30), and `Verfications codes June 2026/` (the parameter-recovery break, scripts 06–11).
