# P4_Dev_20260925 — measurements behind review #16 (adjudication + development)

**Doc ID:** MCL-P4-DEV-2026-0925-001 · **Record:** `../P4_ReadOnly_Adjudication_20260925g.md`
**Paper source examined:** `Paper_4_VDF_Sequential.md` sha256:16 `bcbf890d45739bad` (not modified).
**Status:** promoted to a records folder of [4] on 2026-09-25 (ت-140, order ت-134(أ)); the original copy stays under `05_Scientific_Papers/Paper_4_IACR_CiC/Reviews/P4_Dev_20260925/`. These are the toy random-mapping measurements behind Proposition 3(a) as restated, Attack 8 (§VII.E) and the clocked-map comparison in Paper 4 version 4.
**Host:** `host_20260925.txt` (Apple M1 Pro, Apple clang 16, 1-min load 2.5–4.7 during the runs — timings indicative only).

| File | What it establishes | Build / run |
|---|---|---|
| `parity_enum.py` → `parity_enum_20260925.log` | exhaustive census of the 4,096 weight-parity patterns of Algorithm 1: 3,808 full rank, 288 deficient (7.0312%); single-word 235, global 64, both 23, neither 12 | `python3 parity_enum.py` |
| `census_oldrule.cpp` → `census_oldrule_20260925.log` | exact replication of record (E) of `p4_vdf128v3_distinguisher.cpp` (same 2^18 inputs): 6.958 / 5.630 / 1.369% reproduced; **overlap 0.374% (paper: 0.04%)**, deficient through neither special case 0.333% | `clang++ -std=c++17 -O3 -DNDEBUG -I<records 0905> -I<02_Engine_Code> census_oldrule.cpp` |
| `walkdp_sim.c` → `walkdp_toy_s32_20260925.log`, `walkdp_toy_s37_MggN_20260925.log` | Proposition 3(a)'s attack on random 32-/37-bit mappings, every success verified against s_N: measured success 366–1,286× Prop 3(a)'s value at equal memory, ≈N² scaling; with memory ≈ 6.5·N the SCIA-128-analog bound is exceeded 8.3× (Wilson lower 6.3×); merge-aware expectation matches | `cc -O3 -o walkdp_sim walkdp_sim.c -lm`; `./walkdp_sim s log2N eps P d trials seed` |
| `walkclock_sim.c` → `walkclock_toy_20260925.log` | same attacker, unclocked vs clocked map (iteration index in every step): 8.56% → 0.015% (s = 28), 17.5% → 0.195% (s = 24); clocked success tracks P·T/2^s | `cc -O3 -o walkclock_sim walkclock_sim.c -lm`; `./walkclock_sim clocked s log2N eps P d trials seed` |
| `realscale.py` → `realscale_20260925.log` | continuous form of the merge-aware expectation at P = M = 2^60, s = 128 vs SCIA-128's N(M+N)/2^127; clocked ideal-model ceiling | `python3 realscale.py` |
| `argstate_rt.cpp` → `argstate_rt_20260925.log` | argument-state reformulation of the round (twelve coupling arguments as state, per-input premultiplied tables, no multiplication on the dependency chain): Vector 5 (N = 10^3, 10^5) and 200/200 further inputs bit-identical to the reference | `c++ -std=c++17 -O3 -o argstate_rt argstate_rt.cpp && ./argstate_rt q30_lut_int32le.bin` |
| `shiftdiff.c` → `shiftdiff_20260925.log` | no shift c1 ∈ [1, 65535] makes INC[i+c1] − INC[i] constant (core step of the converse "commuting offset ⇒ invariant arguments", odd-weight case); table exactly odd: LUT[i+2^15] = −LUT[i] | `cc -O2 -o shiftdiff shiftdiff.c && ./shiftdiff q30_lut_int32le.bin` |
| `stats_20260925.log` | the reviewer's numbers recomputed: 1.4967e-3; 2^-43.75; 4.42e13; 2^-27.14; toy aggregate CI | — |

**Model caveat.** The walk simulations use a keyed 64-bit mixer truncated to s bits as the random-mapping proxy, and a fresh key per trial (per-input map). They test the paper's generic propositions in the paper's own model; they are not measurements on VDF128-T4.
