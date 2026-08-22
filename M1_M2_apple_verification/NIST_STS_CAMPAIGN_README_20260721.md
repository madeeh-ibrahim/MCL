# NIST SP 800-22 Full Campaign — Doc ID MCL-NIST-STS-2026-0721-001
- Suite: official NIST sts-2.1.2 (csrc.nist.gov), built with system gcc, run 2026-07-21 on Apple M2 Max.
- Data: 1000 sequences x 10^6 bits (125,000,000 bytes), single-channel production stream:
  MCL_T2::gen_byte() (Goldilocks dual-zone, D=2, burn-in 10,000), engine of record
  mcl_core.hpp v6.0.0 (frozen copy in this folder, MD5 241db79ecf8a42897eb9a8399cf37929),
  seed 12345678901234. Generator: mcl_nist_stream.cpp (this folder).
- Stream SHA-256: b697a62b129786b4a3c3d44c3a839c0d527deaca88bb63cc9d1b4aabb3a1e79f  (deterministic - regenerate with the generator to verify)
- assess invocation: ./assess 1000000 ; input file mode, all 15 tests, default parameters, 1000 bitstreams, binary.
- RESULT: 188/188 statistics pass BOTH criteria.
  Proportions: min 981/1000 (BlockFrequency; threshold 980/1000). Random Excursions family:
  613 qualifying sequences, min 604/613 (threshold 599/613).
  Uniformity: all P_T >= 0.0001; min P_T = 0.003481 (RandomExcursionsVariant).
- Artifacts: nist_sts_finalAnalysisReport_apple_20260721.txt (188-row report),
  nist_sts_experiments_apple_20260721.zip (full per-test stats tree),
  nist_sts_assess_run_20260721.log (console log).
