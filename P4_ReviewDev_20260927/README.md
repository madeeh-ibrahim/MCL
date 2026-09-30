# P4_Dev_20260927 — (1) exhaustive translation-symmetry enumeration on reduced-width replicas of the unclocked map (ت-218; visit order corrected and all runs repeated under ت-222); (2) the small-memory walk-collision count under light and heavy merging (ت-232); (3) clock separation of the version-4 map at structured clock offsets (ت-256); (4) the x86_64 Linux/glibc cell of version 4 (ت-267)

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

## Part 3 — clock separation at structured clock offsets (ت-256; forty inputs since ت-285, 2026-09-30)

**Paper sentence:** §VI.C, paragraph "Clock separation"; Table 1, row "Structure of the round"; OP4. **Question:** the first probe (2026-09-25) evolved the same state at two clocks i and j with j − i uniform in [1, 1000] on 256 states. The clock enters the state as τ(i), and τ(i + k) − τ(i) = k·(1, α, β, γ) + η·(0, 1, α, β) (mod 2^32 in each word) with η = ⌊(i + k)/2^32⌋ − ⌊i/2^32⌋, the advance of hi: for k below 2^32, η is 0 without a wrap of lo and 1 with one; at k = 2^32 and k = 2^33 lo does not change and η is 1 and 2 on every clock. An offset k of high 2-adic valuation injects a difference whose low bits are zero. Does the same state at two clocks still separate at such offsets?

**Programs:** `clocksep_structured.cpp` (the probe) and `clocksep_word1.cpp` (the first-updated word at the four offsets that carry structure), on the version-4 header of `../P4_ReviewMeasurements_20260925/` (nothing in the header or the engine was changed). Per cell: 2^18 random states z; clock i = hi·2^32 + lo with hi uniform below 2^8; z advanced r = 1, 2, 3 iterations from clock i and from clock i + k; the two results compared bit by bit. Reported per cell: the mean Hamming distance with its z-score against 64 (standard error 0.011); the number of output bits whose flip frequency leaves 1/2 by more than the 4.5σ floor (0.00439); the number of bits that never or always flip ("det"); the largest deviation and, at r = 1, the bit that carries it with its flip frequency. "No wrap": lo + k stays below 2^32; "wrap": lo + k passes 2^32. **Inputs:** forty — the battery input, the known-answer input and the numbered inputs `VDF128-T4-clock-probe-0` … `-37`. (The run of 2026-09-28 used nine inputs — the first eight of these and `-probe-7`; a referee-style rerun on other inputs found the one-iteration bias at further offsets, so the record was rerun on forty. Its logs are in the archive of the paper.) Controls: (P) the detector fires on the case found in the review (k = 2^31, no wrap, r = 1); (N) two independent states at one clock show nothing. Both pass; the program exits 0 only then.

**Result** (`clocksep_structured_20260930.log`, about 4 minutes; 1,560 cells of 2^18 states):

| offset k | r = 1: inputs of 40 with a bit above the floor | bits above the floor | largest deviation | most determined bits in one cell | mean distance, r = 1 | r = 2 and r = 3 |
|---|---|---|---|---|---|---|
| uniform in [1, 1000] | 0 | 0 | 0.0038 | 0 | 63.978 – 64.018 | nothing above the floor |
| 1 | 2 | 2 | 0.0052 | 0 | 63.963 – 64.021 | nothing |
| 2^16 | 4 | 4 | 0.0113 | 0 | 63.972 – 64.024 | nothing |
| 2^24 | 7 | 7 | 0.0377 | 0 | 63.967 – 64.017 | nothing |
| 2^28 | 10 | 19 | 0.0770 | 0 | 63.922 – 64.022 | nothing |
| 2^29, no wrap | 10 | 16 | 0.4999 | 0 | 63.486 – 64.078 | nothing |
| 2^30, no wrap | 13 | 123 | 0.5000 | 31 | 49.516 – 64.522 | nothing |
| 3·2^30, no wrap | 13 | 126 | 0.5000 | 31 | 49.525 – 64.509 | nothing |
| **2^31, no wrap** | **40** | 489 | 0.5000 | **32** | 48.478 – 64.509 | nothing |
| 2^31, wrap | 1 | 1 | 0.0069 | 0 | 63.983 – 64.013 | nothing |
| 2^31, all clocks | 40 | 398 | 0.2531 | 0 | 56.214 – 64.265 | nothing |
| 2^32 (hi + 1, lo unchanged) | 7 | 9 | 0.0348 | 0 | 63.975 – 64.034 | nothing |
| 2^33 | 4 | 4 | 0.0098 | 0 | 63.973 – 64.027 | nothing |

Totals: at r = 1, 151 of 520 cells carry at least one bit above the floor (1,198 bits). At r = 2 and r = 3, 1,040 cells and 133,120 bit tests: **0 bits above the floor** (0.91 expected by chance), largest deviation 0.0043, means 63.967 – 64.034, largest |z| of a mean 3.10.

**The case k = 2^31 without a wrap.** The injected difference is 2^31 in each of the four words, because α, β and γ are odd. A coupling argument p·t_j − q·t_i moves by 2^31·(p − q): it does not move when p ≡ q (mod 2), and it moves by half a turn, which reverses the sign of the table value, when p − q is odd. The bit of largest deviation is the lowest bit of the first-updated word on all forty inputs; it flips with frequency within 2 × 10^−4 of 1 on the inputs with an odd number of odd pairs among (1,2), (1,3), (1,4) and within 2 × 10^−4 of 0 on the others — the rule holds on 40 of 40. On the eight inputs whose three pairs all have p ≡ q (inputs 2, 6, 9, 17, 22, 30, 35, 36) the first-updated word differs by exactly 2^31 — 32 bits determined, mean distance 48.48 – 49.49 — and further bits of the other words are biased. The second program, `clocksep_word1.cpp`, measures that word directly (`clocksep_word1_20260930.log`): on these eight inputs its arithmetic difference is 0x80000000 on 262,144 of 262,144 states; on inputs 2 and 9 it is 0x40000000 at k = 2^30 and 0xc0000000 at k = 3·2^30, again on every state. Over the forty inputs and the four offsets of that program (160 cells of 2^18 states) no pair of outputs is equal. When lo wraps (half of all clocks at this offset) the half-turn is not injected, which is why the cell "all clocks" shows frequencies near 1/4 and 3/4.

**The other offsets.** At k = 2^30 and 3·2^30 without a wrap thirteen inputs carry structure, two of them (inputs 2 and 9) with 31 bits determined; at k = 2^29 ten inputs (eight with the top bit of the first-updated word, two with its lowest bit). At k = 2^16, 2^24, 2^28, 2^32, 2^33, across a wrap at 2^31 and even at k = 1, the trace is a bias of the top bit of the first-updated word on some inputs: 4, 7, 10, 7, 4, 1 and 2 inputs of forty, with largest deviations 0.011, 0.038, 0.077, 0.035, 0.010, 0.007 and 0.005 (the last just above the floor). The nine-input run of 2026-09-28 had seen this bias on one or two inputs per offset and none across the wrap; the larger sample shows it on more inputs and, at 2^28, up to 0.077.

**Reading:** the clocked map has a related-clock differential of one iteration at clock offsets of high 2-adic valuation — of probability one on part of the state at k = 2^31, 2^30, 3·2^30 and 2^29 while lo does not wrap, and a bias of the top bit of the first-updated word, between 0.005 and 0.077 in flip frequency, on a minority of inputs at the other offsets tested. It is the one-round property of the modular arithmetic that the paper reports for state differences (§VI.B), reached through the clock. After two and after three iterations the bit tests detect nothing at any offset tested; this is an absence of detection by these tests, not a proof that no relation between the two walks remains (ت-270). No cell shows equal outputs (the smallest mean distance is 48.48 of 128), so no period of the unclocked map was met. The probe samples offsets and states; it is not a proof of absence at other offsets or over more iterations of other relations.

**Reproduce:** `clang++ -std=c++17 -O3 -DNDEBUG -I../P4_ReviewMeasurements_20260925 -I.. -o clocksep_structured clocksep_structured.cpp && ./clocksep_structured` (deterministic; exit 0 iff both controls pass; about 4 minutes); the same line with `clocksep_word1` for the second program (about 40 s). The compiled binaries are not shipped.

## Part 4 — the x86_64 Linux/glibc cell of version 4 (ت-267)

**Paper sentences:** §III.B (the re-implementation and the fingerprint), §VI.C (cross-platform cells), Supplementary Material A (Vector 5). **Question:** the version-4 programs had been run on macOS only (arm64, and x86_64 under Rosetta 2). Do they return the same values on x86_64 Linux with GCC and glibc?

**Run:** `run_linux_v4.sh` builds and runs, in a `gcc:13` container without network and with the sources mounted read-only, the three version-4 programs of `../P4_ReviewMeasurements_20260925/`. Environment in `linux_env_20260928v4.txt`: Debian 12, GCC 13.4.0, glibc 2.36, x86_64 (the container runs under the x86_64 emulation of Docker Desktop on an Apple M1 Pro host; compiler, C library and instruction set are those of x86_64 Linux). No source file was changed.

| program | log | result |
|---|---|---|
| `p4_vdf128v4_kat.cpp` (−O3) | `vdf128v4_kat_linux_glibc_20260928.log` | Vector 5 of version 4: final state `f335a4ec 9ec6ba3e 960e885a ba6f363d`, y = `b6ca50df…4ed0b5ae`; **byte-identical** to `vdf128v4_kat_apple_20260925.log` |
| `vdf128_t4v4_standalone.cpp` (−O2) | `vdf128_t4v4_standalone_linux_glibc_20260928.log` | `REPRODUCED` twice — from the normative table file and from a table regenerated with glibc's sin() (digest `f78c9584…`, equal to the normative one); **byte-identical** to `vdf128_t4v4_standalone_apple_20260925v4.log` |
| `mcl_vdf128v4_xplat.cpp` (−O0, −O1, −O2, −O3) | `vdf128v4_xplat_linux_glibc_20260928.log` | four cells, one fingerprint `31f68f295d631139` — the fingerprint of the four x86_64 cells of macOS; against the arm64 cells only the printed architecture label differs |

With these the fingerprint of the realization stands at twelve cells: arm64 and x86_64 on macOS with Apple Clang 16, x86_64 on Linux with GCC 13.4, each at four optimization levels.

**Header chain:** the version-4 header includes `../keyed_q30_PQ/mcl_keyed_q30.hpp`. The run of record used the header in force today (1.0.7, `05c01cf8a15626c0`); the macOS logs of 2026-09-25 were produced with 1.0.6 (`71a0dbaf84725ac7`). The three programs were also run in the same container with 1.0.6: every output file is byte-identical to the run of record. The digests printed in `linux_env_20260928v4.txt` are those of the files as run.

**Reproduce:** `./run_linux_v4.sh` from this folder (needs Docker and the `gcc:13` image), or on any x86_64 Linux host, from `../P4_ReviewMeasurements_20260925/`: `g++ -std=c++17 -O3 -DNDEBUG -I.. p4_vdf128v4_kat.cpp -o kat && ./kat`; `g++ -O2 -std=c++17 -o sa4 vdf128_t4v4_standalone.cpp && ./sa4 q30_lut_int32le.bin && ./sa4`; `g++ -std=c++17 -O2 -I.. mcl_vdf128v4_xplat.cpp -o xp && ./xp`.

## Part 5 — the data behind Figure 2 of the paper (ت-279, 2026-09-30)

**Paper location:** Supplementary Material B.1, Figure 2 and the sentence on the 2.0888-radian separation. **Question:** what does the distance between the Gauss-Seidel and the Jacobi trajectory of the two-oscillator floating-point model look like as a function of the iteration count, when both start from the same state?

**Program:** `fig2_gs_jacobi_divergence.cpp` on the reference engine header (`../mcl_core.hpp`, version 8.1.3, unchanged): 200 seeds; for each, the engine's Gauss-Seidel trajectory and a Jacobi trajectory started from the same post-burn-in state, 10^4 iterations; the distance is the raw |a − b| per phase averaged over the two phases, the metric of Part 4 of the post-quantum test program. Output `fig2_gs_jacobi_divergence_20260930.csv` (t, one seed's instantaneous distance, the mean over the 200 seeds, one seed's running mean) and `fig2_gs_jacobi_divergence_20260930.log`.

**Result:** the mean over the 200 seeds is 0.995 at t = 1, 2.015 at t = 2, 2.150 at t = 3 and 2.0942 averaged over t = 101 … 10,000 (2π/3 = 2.0944); the Part-4 measurement of the post-quantum test program, which burns each trajectory in with its own update rule, reproduces its 2.0888 for seed 12345678901234. The separation is complete within two iterations. The figure of the paper is drawn from this CSV by `05_Scientific_Papers/_figures/figures_final/make_paper4_fig2.py` (identified release). The figure it replaces (2026-09-02) showed a rise over thousands of iterations that matched no measurement; it is kept in the archive of the paper.

**Reproduce:** `clang++ -std=c++17 -O2 -I.. -o fig2_gs_jacobi_divergence fig2_gs_jacobi_divergence.cpp && ./fig2_gs_jacobi_divergence > fig2_gs_jacobi_divergence_20260930.csv 2> fig2_gs_jacobi_divergence_20260930.log` (deterministic, about 10 s).
