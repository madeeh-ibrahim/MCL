# P4_Dev_20260927 — (1) exhaustive translation-symmetry enumeration on reduced-width replicas of the unclocked map (ت-218; visit order corrected and all runs repeated under ت-222); (2) the small-memory walk-collision count under light and heavy merging (ت-232)

**Doc ID:** MCL-P4-DEV-2026-0927-001 · **Order:** ت-218 (adjudication `../P4_ReadOnly_Adjudication_20260927.md` §ج/§د.4; question raised as D-5 on 2026-09-25) · **Paper sentence:** §VII.D, last paragraph.
**Question:** §VII.D proves that a state translation δ commutes with the unclocked map G_x whenever it preserves every coupling argument (p_ij δ_j ≡ q_ij δ_i and p_ij δ_i ≡ q_ij δ_j mod 2^w for all pairs), and that such δ ≠ 0 exist iff the 12×4 parity matrix is rank-deficient. The **converse** — that every commuting translation preserves the arguments — is not proved for 32-bit words. This record tests it exhaustively at reduced widths.
**Host:** `host_20260927.txt` (Apple M1 Pro, Apple clang 16; single-threaded; the three configurations ran concurrently). **Record version:** v2 (2026-09-27) — see *Coverage note* below.

## Method
`symenum.c` replicates the structure of Algorithm 1's unclocked map with n words of w bits: Gauss–Seidel order, coupling argument a = p·t_j − q·t_i mod 2^w, sine table of 2^(w/2) entries indexed by the top w/2 bits (LUT[i] = trunc(sin(2πi/2^(w/2))·2^(w−2))), increment low_w((K_phase·s) >> (w−2)) with K_phase = ⌊12·2^w/2π⌋, ω_k = ⌊Ω_k/2π·2^w⌋, weights uniform in [2, 2^(w−2)) with the pair rule and **without** the parity rule (rank-deficient sets are wanted). For every non-zero δ ∈ (ℤ/2^w)^n it tests (S) F(t+δ) = F(t)+δ for **all** t and (P) F(t+δ) = F(t) for all t (early exit on the first failing t; every t is visited exactly once, in the order t = (v·0x9E3779B1) mod 2^(n·w) for v = 0 … 2^(n·w) − 1 — an odd multiplier, hence a permutation of the state space, verified to visit 2^16/2^16 and 2^24/2^24 distinct states), and compares the set of commuting δ with the argument-preserving set. Reported per weight set: parity rank, |found S|, |predicted|, |found∖predicted| (a commuting translation outside the mechanism — the converse would fail), |predicted∖found| (would contradict the proved direction), |found P|.

## Results
| configuration | states / translations | weight sets | rank-deficient sets | commuting δ found | argument-preserving δ | found∖pred | pred∖found | periods | log |
|---|---|---|---|---|---|---|---|---|---|
| n = 4, w = 6 (table 8, weights [2,16)) | 2²⁴ | 300 | 10 (all 10 carry symmetries; 0 of 290 full-rank sets do) | 16 | 16 | **0** | **0** | **0** | `symenum_n4w6_20260927.log` (478.0 s) |
| n = 3, w = 8 (table 16, weights [2,64)) | 2²⁴ | 100 | 21 (all 21; 0 of 79) | 75 | 75 | **0** | **0** | **0** | `symenum_n3w8_20260927.log` (209.2 s) |
| n = 2, w = 8 | 2¹⁶ | 3,000 | 1,431 | 46,217 | 46,217 | **0** | **0** | **0** | `symenum_n2w8_20260927.log` (113.6 s) |

**Coverage note (why a v2 exists):** the first run of this record (2026-09-27 morning, superseded and not shipped) visited the states in the order (v·c) >> (64 − n·w), which is not a permutation: it covered 58,482 of 65,536 states at 2¹⁶ and 14,447,500 of 16,777,216 at 2²⁴, so its README's phrase "all t" was not accurate. Incomplete coverage cannot hide a symmetry — a translation that commutes at every state is found whatever subset is visited — and can only fail to exclude a non-commuting one, i.e. it can produce entries in found∖predicted (false positives) but never in predicted∖found; the first run reported found∖predicted = 0 in every configuration, so its conclusion already stood. The table above is from complete re-runs with the corrected order (same seeds); every count is identical to the first run. A fourth configuration (n = 4, w = 8, 2³² states) had been started in the first run and stopped after one set for time; it is not part of this record.

**Reading:** at every tested width the commuting translations are exactly the argument-preserving ones, symmetries occur only on rank-deficient sets, and no translation is a period of the map. This is evidence at those widths only; it does not prove the converse for 32-bit words (the table, the weight range and the 2-adic structure scale with w, and a counter-example could need a width not tested).

## Reproduce
`cc -O3 -std=c11 -o symenum symenum.c -lm && ./symenum 4 6 300 11 && ./symenum 3 8 100 13 && ./symenum 2 8 3000 12` (seeds as in the logs; deterministic). Exit code 0 iff found∖pred = pred∖found = 0 over all sets. The compiled binary is not shipped.

## Part 2 — the small-memory count of §IV under light and heavy merging (ت-232)

**Paper sentence:** §IV, the paragraph after Proposition 3 ("Below the range of (a), with M ≪ P points stored in expectation …"). **Question:** the count of recognized coincidences for a memory far below the number of walks, E ≈ M·N²/(72·2^s) at ε = ¼, is derived for walks that merge lightly (P′·N² ≤ 2^(s−4) for P′ walks). Does the measured success rate match it there, and what happens when the walks merge heavily?

**Program:** `walkdp_sim.c`, byte-identical to the file of the 2026-09-25 development record (the simulator of Proposition 3(a): P walks on a fresh random mapping per trial, an F-independent distinguishing test of rate 2^−d, first writer wins, every declared success verified against s_N). Nothing in it was changed for these runs.

| run | s | N | walks | P·N²/2^s | d | stored records (mean) | trials | successes | measured rate (Wilson 95%) | the count (`E_det` → `1-exp(-E)`) | log |
|---|---|---|---|---|---|---|---|---|---|---|---|
| light merging | 30 | 2^10 | 64 | 1/16 | 13 | 6.0 | 600,000 | 54 | 9.0 × 10^−5 (6.9 × 10^−5 – 1.17 × 10^−4) | 8.13 × 10^−5 | `walkdp_smallM_light_20260927.log` (57 s) |
| heavy merging | 28 | 2^10 | 65,536 | 256 | 16 | 88.3–88.9 | 4 × 750 = 3,000 (seeds 301–304) | 1 + 2 + 0 + 4 = 7 | 0.23% (0.11% – 0.48%) | 4.13% | `walkdp_smallM_heavy_20260927.log` (4 × 73 s, run concurrently) |

**Reading:** inside the light-merging hypothesis the measured rate agrees with the count. With heavily merging walks the count overstates by a factor of about 18: the walks visit far fewer distinct states than they compute points (88 stored records against the 768 that 65,536 × 768 distinct points would give at rate 2^−16), and the attack can succeed only if the honest walk meets a marked state among the at most (1 − ε)N = 768 points it looks up, a chance of at most 768 · 2^−16 = 1.17%. Both runs satisfy N² ≤ 2^(s−8).

**Column note:** the column "Prop 3(a) with that M" and the ratio at the end of each log line are the version-3 floor that the simulator prints for the comparisons of 2026-09-25 (the undercounted form); they are not used here. The count of this record is `E_det`.

**Reproduce:** `cc -O3 -o walkdp_sim walkdp_sim.c -lm && ./walkdp_sim 30 10 0.25 64 13 600000 101 && for sd in 301 302 303 304; do ./walkdp_sim 28 10 0.25 65536 16 750 $sd; done` (arguments: s, log2 N, ε, walks, d, trials, seed; deterministic).
