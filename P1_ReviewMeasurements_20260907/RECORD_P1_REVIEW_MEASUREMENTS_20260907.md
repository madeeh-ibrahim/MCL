# Paper 1 — review measurements, 2026-09-07

Two targeted measurements ordered by the read-only adjudication of 2026-09-07
(`05_Scientific_Papers/Paper_1_CSF/Reviews/P1_ReadOnly_Adjudication_20260907.md`, item ق3),
plus one source inspection recorded here for completeness.

**Engine of record:** `mcl_core.hpp` v6.0.0, MD5 `241db79ecf8a42897eb9a8399cf37929`
(frozen copy, byte-identical to `02_Engine_Code/M1_M2_apple_verification/mcl_core.hpp`).
**Platform:** Apple Silicon, macOS, Apple clang, `-O3 -std=c++17 -ffp-contract=off`
(no fused multiply-add: same convention as the 2026-09-05/06 P1 campaigns).

---

## 1. `mcl_p1_table3_lambda` — Doc ID `MCL-P1-TABLE3-LAMBDA-2026-0907-001`

**Question.** Paper 1 Table 3 carries the measured value λ₁ = 4.4165 at (p, q, K) = (3, 5, 6),
which no log in any code tree or public archive accounts for; that row also sets the
"maximum error 0.50%" figure quoted in §3.2.3, §4.3, the Conclusion and the Highlights.

**Protocol.** Analytical-Jacobian sequential QR (`compute_lyapunov` of the engine of record),
10⁷ iterations after the engine's 10,000-iteration burn-in, three independent seeds
(12345678901234, 98765432109876, 31415926535897 — the seeds of the seed-averaged rows of
Table 2), reported as per-seed values and their mean. **All 14 rows of Table 3** were measured,
not only the row in question, so the whole column acquires a record.

**Result — the published value is confirmed.**

| | (3, 5, 6) | max |Δ| vs published | max err (3a) | max err (3b) |
|---|---|---|---|---|
| published | 4.4165 | — | 12.73% | 0.50% |
| re-measured (3-seed mean) | **4.4165** | 0.0023 | **12.73%** | **0.50%** |

Eleven of the fourteen rows agree to ≤ 0.0006; the three largest deviations are
(13, 19, 12) +0.0023, (7, 11, 18) +0.0015 and (3, 5, 16) +0.0012 — agreement to three
significant figures, the precision Supplementary S1 establishes as platform-independent.
Both headline error figures are unchanged, computed either way.

> **Correction (2026-09-09, external review #2, item ت-33).** The sentence above — "Eleven of the fourteen rows
> agree to ≤ 0.0006 … agreement to three significant figures" — misdescribes the log in this directory:
> **four** rows exceed 0.0006, the fourth being (89, 97, 12) at **−0.0012** (12.5616 → 12.5604), so **ten** rows
> agree to ≤ 0.0006; and "three significant figures" fails for (13, 19, 12), which rounds to 8.71 against 8.72.
> The correct statement is agreement to within 0.03% relative throughout (maximum 0.0023 at 8.7129).
> The log, the tool and both headline figures (0.50%, 12.73%) are unaffected; only this prose was wrong.

Files: `mcl_p1_table3_lambda.cpp` · `table3_lambda_apple_20260907.log`

---

## 2. `mcl_p1_goldilocks_outbit` — Doc ID `MCL-P1-GOLDBIT-2026-0907-001`

**Question.** Supplementary S5 reported one nominal exception to the intra-mantissa
independence premise of Eq. (5) — pair (bit 25, bit 41), χ²(df=1) = 12.096, c = −8.695e−05 —
and dismissed it as "below the single-bit detection margin". It is not: p = 5.05e−04 survives
Bonferroni over the 24 combinations (0.012), and 2|c| = 1.74e−04 is 3.5 SE of a single-bit
frequency at N = 1e8. The decisive question is whether the residual reaches the **emitted** bit.

**Protocol.** Eq. (5) emits output bit k = mantissa(20+k) XOR mantissa(36+k), so (25, 41) is
output bit 5 of the Goldilocks byte. N = 1e8 output samples per seed at decimation D = 2,
**six** seeds, all eight output bits measured (48 statistics), each with its 0/1 frequency,
χ²(df=1), and the source-pair covariance for cross-reference.

**Result — the residual is real, reaches the output, and does not recur.**

- Seed 12345678901234: emitted bit 5 has P(1) − ½ = **+1.739e−04**, χ² = **12.096** — numerically
  the −2c term of Eq. (6) to four significant figures. Largest of the 48 statistics, and above
  the Bonferroni threshold for 48 tests (10.752).
- Same bit in the other five seeds: 1.240, 0.003, 0.061, 0.125, 1.545.
- Largest statistic anywhere outside the flagged seed: 4.389 (nominal only; ≈ 2.4 nominal
  exceedances are expected by chance over 48 tests).
- Byte level unaffected: configuration A passes in every seed (232.9–294.1 vs 310.46).

**Consequence for the paper.** `gen_byte` — the production extractor behind the batteries of
§4 — **is** this dual-window extractor, and 12345678901234 is the seed of BigCrush Run 1 and of
the NIST campaign of Appendix A. The residual was therefore present in the streams that
returned 160/160 and 188/188. That bounds the defect (it is below the detection power of both
batteries at those volumes) rather than removing it, and it is disclosed in those terms in
§3.5 and Supplementary S5.

Files: `mcl_p1_goldilocks_outbit.cpp` · `goldilocks_outbit_apple_20260907.log`

---

## 3. BigCrush follow-up: where the stream starts (source inspection, no new run)

`mcl_bigcrush_test102.c` (single-test re-run harness for BigCrush test #102, `sstring_Run`,
r = 27) constructs `MCL_T2 engine(seed, 3, 5)` afresh and calls
`sstring_Run(gen, res, 1, 1000000000L, 27, 3)` — i.e. it consumes the stream **from the start**.
Inside the full battery, test #102 consumes a segment reached only after the preceding tests.

The follow-up is therefore an independent re-run of the same statistic on a **different, fresh
segment** of the same stream — evidence of non-recurrence, not a re-analysis of the original
sample. Paper 1 §4.2 said "a fresh pass over the test's sample"; corrected 2026-09-07.

---

*Record written 2026-09-07. All three items feed `P1_Revision_Execution_20260907.md` §1.*
