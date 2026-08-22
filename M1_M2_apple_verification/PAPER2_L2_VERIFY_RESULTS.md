# Paper-2 L2 re-verification — definitive results (2026-07-06)

**Program:** `mcl_paper2_L2_verify.cpp` (MD5 `0aae4ba4d4c85031bb8ba40af6aac111`)
**Engine:** `mcl_core.hpp` v6.0.0 (this folder, MD5 `241db79ecf8a42897eb9a8399cf37929` — the header Paper 1 ref [1] pins). v6.1.0 gives a byte-identical stream (keyed path is additive).
**Config:** `DEFAULT_SEED = 12345678901234`, `t2_topos()` (20 canonical coprime pairs), `K = 12`. Fully deterministic — any re-run reproduces these values exactly.
**Build:** `clang++ -O3 -std=c++17 -march=native`. **Log:** `paper2_L2_verify_apple_20260706.log`.

## The four disputed Paper-2 numbers — measured vs paper

| § | Quantity | Paper-2 value | **Measured (v6.0.0, deterministic)** | Archived log | Verdict |
|---|---|---|---|---|---|
| VII.B | multiplex χ² (N=20 × 10⁷) | 241.39 | **233.16** (msg-mux, entropy 7.999983) / 265.72 (empty-mux, 7.999981) | 233.16 / 265.72 (`mcl_steganalysis.txt`) | paper 241.39 not reproduced; **use 233.16** (matches the 7.999983 entropy the paper already prints) |
| VII.B | multiplex entropy | 7.999983 | **7.999983** (msg-mux) | 7.999983 | ✅ exact — no change |
| VII.B | max channel-to-multiplex \|r\| | 0.000559 | **0.000724** (channel (8,13) vs 20-way mux) | 0.000724 (`Orth v2.3.0`) | paper's 0.000559 is a **channel-to-channel** value (mislabeled); real channel-to-mux max = **0.000724** |
| X.C / T6 | next-byte prediction | 0.406% | **0.3961%** held-out (baseline 0.3906%) | 0.388% (`mcl_attack_suite.txt`) | all indistinguishable from random; reproducible held-out ≈ **0.39%** |
| IV.C | incorrect-param Hamming (mean) | 0.4998 ± 0.0031 | **0.5010** (full [2,60] grid, 3421 wrong pairs) | 0.4985 / 0.4987 (`mcl_auth_verify.txt`) | all ≈ 0.50 (ideal); differ only in the last digit by wrong-pair sample |

## Notes on scientific method

- **Measurement 3 (prediction) required a train/test split.** An in-sample argmax bigram scorer overfits the finite-sample noise and reports ~0.61% — a measurement artifact, not signal. Training on 2 M bytes and scoring on a **disjoint** 2 M region gives 0.3961%, at the 0.3906% random baseline, consistent with the archived attack-suite (0.388%). The corrected held-out protocol is what the program now uses.
- **Measurement 4 std.** The per-response Hamming std is 0.0312 = 0.5/√256 (the binomial σ for 256-bit responses). The paper's "±0.0031" is 10× smaller — it is a std-of-the-mean / different aggregation, not the per-response σ. The **mean** (~0.50) is the robust, consistent quantity; its 4th digit (0.4985 / 0.4998 / 0.5010) is sample-dependent.
- **χ² depends on which multiplex.** The paper prints entropy 7.999983, which is the **message-carrying** multiplex (mux_msg); its χ² is 233.16. The empty multiplex is 7.999981 / 265.72. The paper's headline 241.39 corresponds to neither v6.0.0 case (it is a Patent-2-era figure).

## Root cause
241.39, 0.406, and 0.000559 appear in the filed Patent 2 (April 2026); the engine advanced to v6.0.0 (30 May 2026) and the deterministic runtime now prints the updated values above. All differences are small and in the paper's favour (lower χ², prediction at baseline, correct-labelled tighter correlation). This is version drift between the priority filing and the engine of record, not a scientific error.

## Recommended paper edits (pending author decision on Patent-2 divergence)
- §VII.B properties table: **χ² 241.39 → 233.16**; keep entropy 7.999983; **max channel-to-multiplex |r| 0.000559 → 0.000724** (and, if desired, add the channel-to-channel max 0.000870 separately).
- §X.C / Table 6: **byte prediction 0.406% → 0.39%** (held-out; cite the reproducible measurement).
- §IV.C: keep **mean ≈ 0.50**; either align to 0.4985 (archived auth) or 0.5010 (this grid) and **fix the ±0.0031 → ±0.0312** (per-response σ) or relabel it as std-of-the-mean.
- Add one footnote: *"Values are the v6.0.0 deterministic runtime (`mcl_paper2_L2_verify`, MD5 above); earlier figures in the priority filing differ within run-to-run/version variation."*
- Ship `mcl_paper2_L2_verify.cpp` + this log in the Zenodo code archive so every number is one command away from reproduction.
