# Paper 1 — review measurements, 2026-09-07

Two targeted measurements ordered by the 2026-09-07 read-only adjudication of Paper 1,
closing review items Y4 (a table value with no runtime record) and R5 (an intra-mantissa
independence exception dismissed without measuring its effect on the emitted bit).

**Full record:** `RECORD_P1_REVIEW_MEASUREMENTS_20260907.md`.

- `MCL-P1-TABLE3-LAMBDA-2026-0907-001` — `mcl_p1_table3_lambda.cpp` /
  `table3_lambda_apple_20260907.log`: all 14 configurations of Paper 1 Table 3 re-measured
  by analytical-Jacobian sequential QR, 1e7 iterations, three seeds. The value 4.4165 at
  (3, 5, K = 6) — which sets the paper's "maximum error 0.50%" figure — reproduces to four
  decimals; both headline error figures (12.73% for the empirical fit, 0.50% for the
  semi-analytical form) are unchanged.
- `MCL-P1-GOLDBIT-2026-0907-001` — `mcl_p1_goldilocks_outbit.cpp` /
  `goldilocks_outbit_apple_20260907.log`: 0/1 frequency of every emitted bit of the
  Goldilocks byte (Eq. 5), N = 1e8 output samples per seed at decimation D = 2, six seeds
  (48 statistics). Output bit 5 — the (mantissa 25, mantissa 41) pair — carries a
  frequency deviation of +1.739e-04 (chi2 = 12.096) in seed 12345678901234, above the
  Bonferroni threshold for those 48 tests, and does not recur in the other five seeds.

**Engine of record:** `mcl_core.hpp` v6.0.0, MD5 `241db79ecf8a42897eb9a8399cf37929` (copy included).
**Build:** `c++ -O3 -std=c++17 -ffp-contract=off [-DMCL_UNSAFE_ALLOW_INVALID for the lambda tool]`.
Compiled binaries are not shipped. `SHA256SUMS` covers every file in this directory.
