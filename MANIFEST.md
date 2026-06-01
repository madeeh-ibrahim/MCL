# MCL — Public Code Archive · MANIFEST

**Engine:** `mcl_core.hpp` — Version 6.0.0 — MD5 `241db79ecf8a42897eb9a8399cf37929`
**Author:** Madeeh Ibrahim · ORCID 0009-0002-8562-8325 · madeeh.chaotic.lock@gmail.com
**License:** PolyForm-Noncommercial-1.0.0 · Patent Pending PCT/IB2026/052737, 053253, 053673

Open reference engine + verification binaries reproducing every numerical claim in
Papers 1-5, plus published self-cryptanalysis evidence. Active dual-use attack tooling
is NOT here (access-controlled per TOOLKIT_ACCESS_POLICY.md).

## Cross-platform reproducibility anchors
- Float64 CRC-32 (T2 default (3,5) 10KB): Linux `0xF5E977E0` · macOS `0x1A734C6F` (libm-dependent, non-normative).
- Q30 fixed-point (bit-exact NORMATIVE): init `0xC8AFD74A`/`0x0DB2BAC6`, 10k-iter `0x6F88C52E`/`0xE06C516C`, LUT CRC `0xDE1340CF`.

## A. Engine
| File | Purpose |
|------|---------|
| `mcl_core.hpp` | MCL coupled-oscillator core engine (v6.0.0) |

## B. Reproduction binaries (cited in papers)
| File | Cited | Purpose |
|------|-------|---------|
| `mcl_benchmark.cpp` | P1,P2,P4,P5 | Measure actual throughput (MiB/s) and memory (bytes) of MCL. |
| `mcl_dynamical_signatures.cpp` | P1 | Compute the standard battery of dynamical-signatures used in the |
| `mcl_generality.cpp` | P3 | Verify that the MCL coupling principle generalizes beyond |
| `mcl_hd_verify.cpp` | P5 | Experimental verification of Hierarchical Key Derivation |
| `mcl_k_sweep_unified.cpp` | P3 | * Sweep coupling strength K from 0.1 to 500 across MCL_T2, MCL_T3, MCL_T4 |
| `mcl_lyapunov.cpp` | P1,P3 | Compute Lyapunov exponents of the MCL T² system using the |
| `mcl_lyapunov_lambda2_verify.cpp` | P1 | Verify the semi-analytical closed form for the SECOND Lyapunov |
| `mcl_omega_independence.cpp` | P2,P3 | Verify that different angular frequencies (ω₁,ω₂), with FIXED |
| `mcl_orth_verify.cpp` | P2,P3 | Verify that MCL channels indexed by different (p,q) pairs are |
| `mcl_paper4_verify.cpp` | P4 | Reproduce all numerical claims in Paper 4 (VDF Sequential Function) |
| `mcl_postquantum.cpp` | P2,P4 | Verify MCL's resistance to quantum computing attacks. |
| `mcl_practrand.cpp` | P1 | Stream cryptographic-quality bytes from the MCL_T2 engine to |
| `mcl_reference.cpp` | P3,P4 | Canonical reference implementation of the MCL coupled chaotic |
| `mcl_safe_zone_verify.cpp` | P1 | Empirically characterizes the Safe Zone bit-extraction regions of |
| `mcl_scale.cpp` | P2,P3 | Verify MCL scales from 20 to 1M+ simultaneous orthogonal |
| `mcl_txn_verify.cpp` | P2,P5 | Experimental verification of non-replayable transaction |
| `mcl_vdf_verify.cpp` | P4 | Experimental verification of the MCL Verifiable Delay Function |
| `q30_macos_validation.cpp` | P2,P4 | Validate MCL Q30 (fixed-point engine) cross-platform bit-exactness |

## C. KAT / self-test support
| File | Purpose |
|------|---------|
| `kat_gen_macos.cpp` | Generate Known Answer Test (KAT) CRC-32 vectors for MCL_T2 engine |
| `self_test.cpp` | Run the MCL engine built-in self-test verifying all Known Answer |

## D. Self-cryptanalysis evidence (analytical; attacks MCL only; carry ACCEPTABLE USE notice)
| File | Purpose |
|------|---------|
| `mcl_vdf_falsification.cpp` | Four-attack falsifiability battery for MCL-VDF open problems OP1 (sequentiality), |
| `beff_deep_audit.cpp` | Audit the b_eff backward-inversion claim underpinning Paper 5 X one-wayness. |
| `mcl_beff_compounding.cpp` | Test whether the per-step keystream-constrained backward branching |

**Total code files: 24** (1 engine + 18 reproduction + 2 KAT-support + 3 self-cryptanalysis). Results in `results/`.

## Build
```
g++ -O3 -std=c++17 -march=native -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
    -DMCL_UNSAFE_ALLOW_INVALID -o <name> <name>.cpp -lm   # +(-lpthread where noted)
```

## NOT in this archive — access-controlled toolkit (TOOLKIT_ACCESS_POLICY.md)
`mcl_attack_suite`, `mcl_steganalysis`, `mcl_adv_attack`, `mcl_simswap_verify`,
`mcl_extraction_security`, `mcl_neural_distinguish.py` (dual-use; released to vetted researchers).
