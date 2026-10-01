# P5_ReviewMeasurements_20261001 — Paper 5, records of 1 October 2026

Doc IDs MCL-P5-PREUPLOAD-2026-1001-002 … -005. Engine `mcl_core.hpp` 8.1.3 (SHA-256 `416ad145e79c095b…`), keyed sidecar v1.0.7 (`05c01cf8a15626c0…`), Apple clang 16, arm64 (Apple M1 Pro), single thread. The host was shared and heavily loaded during these runs (load averages are printed in each log header): every statistic is deterministic and load-independent; wall-clock times are upper bounds, and the timing record reports the minimum over batches.

| Program | Record | Paper 5 | What it shows |
|---|---|---|---|
| `p5_burnin_avalanche_large.cpp` | `burnin_avalanche_large_20261001.log` | §VI.C, Table 4 | The avalanche test of Table 4 at nine burn-in lengths, (a) on the original 5,000 inputs — reproduces the avalanche column of Table 4 exactly — and (b) on one fresh set of 100,000 inputs shared by all rows: z = +0.61, +0.08, +0.96, +1.10, +1.13, +1.53 (B = 0 … 16), +0.60 (64), −2.13 (1,000), −0.34 (10,000). The +2.1…+2.7 SE offset of Table 4 at B = 0, 2, 4, 8 and 16 (B = 1 sits at −0.35) is not reproduced on fresh inputs (fresh rows at B ≤ 16 ≤ +0.04 bit). Rows share their inputs within each set, so they are not independent of each other. |
| `sibling_recovery_full.cpp` | `sibling_recovery_full_20261001.log` | §III.B | Full sibling recovery for the archived derivation (version 1): from the p- and q-components of three observed children, R_lo and R_hi are both recovered exactly (the q side through a replica of the coprimality loop), and every unseen child 3…40 is predicted in full, 38 of 38. Extends `../P5_ReviewMeasurements_20260905/sibling_recovery.cpp` (p side only). |
| `p5_crosssystem_v2.cpp` | `crosssystem_v2_20261001.log` | §IV.G, Table 1, Fig. 2 | The cross-system check with the version-2 derivation: logistic child (7, 867), \|r\| = 0.000351, p = 0.73; tent child (204, 581), \|r\| = 0.000941, p = 0.35; both coprime, no rejection at α/135. Part (a) reproduces the two rows of Test 9 of `../hd_v2/mcl_hd_verify_v2.cpp`, whose local helper applies the version-1 mask and no coprimality step — (970, 423) and (442, 13), the latter not coprime. |
| `p5_bip32_cost.cpp` | `bip32_cost_20261001.log` | §IV.H, §IX, Table 7 | One BIP-32 child derivation (HMAC-SHA512 + addition modulo the secp256k1 order), checked against BIP-32 test vector 1: 0.811 µs minimum over 200 batches of 10,000 (median 1.053 µs on the loaded host), ≈ 1,000× below the 0.82 ms of `derive_child_v2`. Uses Apple CommonCrypto (macOS only). |

## Build

```sh
# burn-in program: a scratch copy of the engine whose BURNIN constant is overridable (the engine of record is untouched)
mkdir -p _scratch && cp ../mcl_core.hpp ../keyed_q30_PQ/mcl_keyed_q30.hpp _scratch/
(cd _scratch && patch -p0 mcl_core.hpp < ../../P5_ReviewMeasurements_20260905/header_patch.diff)
for B in 0 1 2 4 8 16 64 1000 10000; do clang++ -std=c++17 -O3 -DNDEBUG -DMCL_BURNIN_OVERRIDE=$B -I_scratch p5_burnin_avalanche_large.cpp -o av_$B && ./av_$B; done
clang++ -std=c++17 -O3 -DNDEBUG -I.. sibling_recovery_full.cpp -o sibling_recovery_full && ./sibling_recovery_full
clang++ -std=c++17 -O3 -DNDEBUG -I.. -I../hd_v2 p5_crosssystem_v2.cpp -o p5_crosssystem_v2 && ./p5_crosssystem_v2
clang++ -std=c++17 -O3 -DNDEBUG p5_bip32_cost.cpp -o p5_bip32_cost && ./p5_bip32_cost
```

`SHA256SUMS` covers every file of this folder except itself.
