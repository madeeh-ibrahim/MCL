# Engine-equivalence check for the M1_M2 tools — v6.0.0 (engine of record) vs v8.1.3 (repository root) — 2026-09-16

**Question.** Paper 1 §3.3 states that v8.1.3 reproduces the v6.0.0 results (keystream byte-identical over the five seeds of Table 11). Do the thirteen M1_M2 tools — which also exercise the Lyapunov/Jacobian, holdout, per-bit, bifurcation and derivation paths — give identical output under both engines?

**Method.** Sources taken from the Zenodo v0.2.10 archive (10.5281/zenodo.22782254, `M1_M2_apple_verification/`), each built twice with `c++ -O3 -std=c++17 -I<dir> <tool>.cpp -lm` where `<dir>` holds either the frozen v6.0.0 `mcl_core.hpp` (MD5 241db79ecf8a42897eb9a8399cf37929) or the archive-root v8.1.3 `mcl_core.hpp` (MD5 5d8b49ee11aa0bfb8b0bda3f47fa16e3); run with the README arguments; stdout compared (MD5 of the full output). Apple Silicon, Apple clang. `mcl_nist_stream` (bulk stream generator, argument-driven) not run.

| Tool | args | v6.0.0 output MD5 | v8.1.3 output MD5 | identical | run time (s) |
|---|---|---|---|---|---|
| `mcl_detj_verify` | [] | `dda3d86889` | `dda3d86889` | ✅ | 38.7 / 38.6 |
| `mcl_psi_equidist` | [] | `227b09fb6e` | `227b09fb6e` | ✅ | 3.5 / 3.3 |
| `mcl_single_osc_zone` | [] | `e609f3f78f` | `e609f3f78f` | ✅ | 17.8 / 17.8 |
| `mcl_bytezone_scan` | [] | `310ae89c54` | `310ae89c54` | ✅ | 15.2 / 15.2 |
| `mcl_paper2_L2_verify` | [] | `e8a53e5f13` | `5d81404168` | ⚠ see below | 42.8 / 43.0 |
| `mcl_table10_multiseed` | [] | `0b7f5500bd` | `0b7f5500bd` | ✅ | 49.8 / 50.0 |
| `mcl_tau_int` | [] | `969bcc91ce` | `969bcc91ce` | ✅ | 1.2 / 1.0 |
| `mcl_perbit_msb_flank` | ['2'] | `4e5734d944` | `4e5734d944` | ✅ | 17.8 / 17.5 |
| `mcl_safezone_holdout` | ['12345678901234'] | `9ba094bdfd` | `9ba094bdfd` | ✅ | 18.3 / 18.4 |
| `mcl_bifurcation_sweep` | ['coarse'] | `4b2f43c4b1` | `4b2f43c4b1` | ✅ | 1.0 / 1.0 |
| `mcl_fig1_arnold_sweep` | [] | `32a7baee5a` | `32a7baee5a` | ✅ | 0.2 / 0.2 |
| `mcl_hd_throughput` | [] | `450932f4fa` | `4c6bd5be77` | ⚠ see below | 1.4 / 1.4 |

**The two non-identical outputs, line by line** (`*_v6.out` / `*_v8.out` in this directory):
- `mcl_paper2_L2_verify`: **2 lines differ — the banner only** (`engine v6.0.0` vs `engine v8.1.3`); every numerical line identical.
- `mcl_hd_throughput`: **6 lines differ — wall-clock timings only** (µs/derivation, derivations/s); no numerical result involved.

**Conclusion.** 12/12 tools numerically identical under both engines. The M1_M2 tools can be built against the repository-root engine (`-I..`); no frozen v6.0.0 copy needs to ship in this directory. Consistent with the engine's own VERSION IDENTIFICATION block (8.x: "no existing function modified — all KATs unchanged").
