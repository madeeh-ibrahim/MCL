# P1_ReviewMeasurements_20260909 — Paper 1, external review #2 (item ت-37)

**Doc ID:** MCL-P1-GOLDBIT-SEG-2026-0909-001 · **Engine of record:** `mcl_core.hpp` v6.0.0 (MD5 `241db79ecf8a42897eb9a8399cf37929`, byte-identical frozen copy included) · **Platform:** Apple Silicon, macOS, Apple clang.

**Build line:** `c++ -O3 -std=c++17 -ffp-contract=off -o mcl_p1_goldbit_segments mcl_p1_goldbit_segments.cpp -lm` (no fused multiply-add; same convention as the 2026-09-05/07 Paper-1 campaigns). Compiled binaries are not shipped.

**Question.** MCL-P1-GOLDBIT-2026-0907-001 found that emitted output bit 5 of the Goldilocks byte (Eq. 5 of Paper 1: mantissa bit 25 XOR mantissa bit 41) carries P(1) − ½ = +1.739 × 10⁻⁴ (χ²(df = 1) = 12.096) in seed 12345678901234 over the first N = 10⁸ output samples, and not in five other seeds. That measurement re-used the stream start; it could not say whether the residual is a transient or a persistent property of the orbit.

**Protocol.** Ten pre-specified, consecutive, non-overlapping segments of N = 10⁸ output samples of the same stream (10⁹ samples, 2 × 10⁹ engine iterations at decimation D = 2, burn-in 10,000 once at construction), all eight emitted bits per segment and cumulatively, plus the 256-bin byte-level χ² per segment; and the byte-level χ² at N = 10⁸ for the six seeds of the 2026-09-07 run (which that run did not record).

**Result (log `goldbit_segments_apple_20260909.log`).** The residual is confined to the first segment: segment 1 reproduces +1.739 × 10⁻⁴ / 12.096 exactly; segments 2–10 give |P(1) − ½| ≤ 9.5 × 10⁻⁵ and χ² ≤ 3.585 for bit 5 (largest statistic of any bit in any later segment 7.354, nominal only); the cumulative deviation over 10⁹ samples is +1.03 × 10⁻⁵ (χ² = 0.426). The byte-level χ² passes in every segment (247.3–294.1) and in all six seeds (232.9–294.1 vs 310.46).

Files: `mcl_p1_goldbit_segments.cpp` · `goldbit_segments_apple_20260909.log` · `mcl_core.hpp` · `SHA256SUMS`.
