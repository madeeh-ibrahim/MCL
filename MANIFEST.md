# MCL — Public Code Archive · MANIFEST (v0.2.16, 2026-09-30)

**Engine:** `mcl_core.hpp` — Version **8.1.3** (2026-08-22) — SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80` — MD5 `5d8b49ee11aa0bfb8b0bda3f47fa16e3`  
**Keyed integer sidecar:** `keyed_q30_PQ/mcl_keyed_q30.hpp` — **v1.0.7** (2026-09-28) — SHA-256 `05c01cf8a15626c0e6f892103868afc11f36b07bad3a27472b9a8d608f396a29`  
**VDF128-T4 header:** `VDF128_T4/mcl_vdf128_t4.hpp` — SHA-256 `e08f702e2da92221588285a6a61ee2e48edfb63afbde8220fc3632fd2180ed0d`  
**Author:** Madeeh Ibrahim · ORCID 0009-0002-8562-8325 · madeeh.chaotic.lock@gmail.com  
**License:** PolyForm-Noncommercial-1.0.0 + Security Research & Evaluation Grant · Patent Pending PCT/IB2026/052737, 053253, 053673, **058860**

Open reference engine + every verification / reproduction program and evidence record cited by Papers 1–5, plus published self-cryptanalysis (including negative findings). Active dual-use attack tooling is NOT here (gated per `TOOLKIT_ACCESS_POLICY.md`, 7 files). Previous release: v0.1.0 (2026-06-01, engine 6.0.0 MD5 `241db79ecf8a42897eb9a8399cf37929`); see `CHANGELOG.md`.

## Cross-platform reproducibility anchors (re-verified on 8.1.3, 2026-08-22)
- Float64 CRC-32 (T2 default (3,5) 10KB): Linux `0xF5E977E0` · macOS `0x1A734C6F` (libm-dependent, non-normative) — `results/kat_gen_macos_v8.1.3_20260822.txt`.
- Q30 fixed-point (bit-exact NORMATIVE): init `0xC8AFD74A`/`0x0DB2BAC6`, 10k-iter `0x6F88C52E`/`0xE06C516C`, LUT CRC `0xDE1340CF` — `results/q30_macos_validation_v8.1.3_20260822.txt`.
- Keyed T4-Q30 (sidecar v1.0.7, 2026-09-28): commit CRC `0x58C99E3E`, cascade(m=7) `0xF7C81BC4` — suite 9/9 PASS — `results/keyed_q30_test_v1.0.7_20260928.txt` (the v1.0.6 run of 2026-08-22 is kept beside it; the two differ in timing lines only). Six known-answer values in `mcl_keyed_q30_self_test()`; record `keyed_q30_PQ/CASCADE_GUARD_V107_RECORD_20260928.md`.
- Engine self-test: 7/7 KATs PASS — `results/self_test_v8.1.3_20260822.txt`.

## Build
```
g++ -O3 -std=c++17 -march=native -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
    -DMCL_UNSAFE_ALLOW_INVALID -o <name> <name>.cpp -lm   # root programs (+ -lpthread where noted)
clang++ -std=c++17 -O3 -I. -I keyed_q30_PQ -I VDF128_T4 <folder>/<name>.cpp -o <name>   # sub-folder programs
```
Build notes (syntax-checked 2026-08-22, Apple clang 16, all 87 `.cpp` files): `keyed_q30_PQ/mcl_keyed_q30_lyap_sweep.cpp` and `mcl_keyed_q30_mpfr_lyap.cpp` need GNU MPFR/GMP (`-I/opt/homebrew/include -L/opt/homebrew/lib -lmpfr -lgmp` on macOS); `keyed_q30_PQ/mcl_keyed_q30_dump_weights.cpp` needs `-DHDR='"mcl_keyed_q30.hpp"'`; all programs in `p2_hardened_auth/` and `P3_CrossPrediction/mcl_gen_series.cpp` use Apple CommonCrypto (macOS only — the engine itself is portable; the `p5_hardened_txauth/` v3.2 harnesses and `P5_ReviewMeasurements_20260905/redraw_rate.cpp` v2 use the engine's own SHA-256). Python helpers need numpy (and scikit-learn for `xpred.py`). The `results/*.txt` of the 23 root programs are the June-2026 records (engine 6.0.0, KAT-identical to 8.1.3); only the 8.1.3 / v1.0.6 / v1.0.7 re-runs named above were regenerated; `mcl_postquantum` and `Verification_Suite/mcl_hop_unified` are version 6.1.0 with their June outputs kept beside the new ones (`QUANTUM_SCOPE_NOTE.md`). Every program that includes the keyed sidecar (42 files) was syntax-checked against v1.0.7 on 2026-09-28; `P5_ReviewMeasurements_20260905/p5_weight_probe.cpp` needs the scratch-constructor patch shipped in its folder, which applies to v1.0.6 and to v1.0.7.

## NOT in this archive
- Gated adversarial toolkit (7 files; `TOOLKIT_ACCESS_POLICY.md`): `mcl_attack_suite`, `mcl_steganalysis`, `mcl_adv_attack`, `mcl_simswap_verify`, `mcl_extraction_security`, `mcl_neural_distinguish.py`, `mcl_simswap_v3` (record + logs of the last one ARE public in `p2_hardened_auth/`).
- Out of scope (as in v0.1.0): June-2026 lattice/return-map attack scripts, `SideChannel_Screen/` CPA tooling, the nine `VDF_security/` probe programs. Compiled binaries and the duplicate v6.0.0 engine copy of `M1_M2_apple_verification/` are not shipped.

## File inventory — 985 files (+ this MANIFEST), SHA-256 of every file

Files that the repository's `.gitignore` excludes are not part of the repository and are not listed.

### (root)  (47 files)

| File | SHA-256 | Note |
|---|---|---|
| `.gitignore` | `01d1a768f05574888f32c708956076a85d1daf4112e0452c1823f4976f115464` |  |
| `APPLY_GUIDE.md` | `754cbc1d15713c292648e686d643e919882653dfe2cd88fc791c641baa96b957` |  |
| `CHANGELOG.md` | `0ba892dfa73b5800e11091d20e28a48cdbe1e02439057dd68088d14e733d266c` |  |
| `CITATION.cff` | `f1fd946fc5d6c33a86c63bce062f69d69b785fcc87c58427e1cd86fd9d6bb439` |  |
| `CLA.md` | `975fe9c31ca4bb96cdcb427f2c62ed2fb46a3df443bff8a80f294aa619d06129` |  |
| `CODE_OF_CONDUCT.md` | `da98355a1277938de1cfededa9beaaa2a56e63dba34f97f65e5a05a2d3102c43` |  |
| `COMMERCIAL.md` | `d3233e9f03ea2e82acb8144414b83ad760beb396dd6e6e2407065157e7bae0ab` |  |
| `CONTRIBUTING.md` | `238434c313a101b7ada8073ddfbf5fd4eec0b2248f4d3932641249dba1e705b9` |  |
| `GOVERNANCE.md` | `4e1cf312a4805452d4f41c9bc402add0b0e8547cc24b1cb64a7eea9c0704c1e6` |  |
| `HALL_OF_FAME.md` | `fb4eaf6b0b33659a57d9f553efb09e5c9c3e98fd19702275433d5fd30d911117` |  |
| `LICENSE` | `839932d57880e179074222334b1a3d1ae7117feaea0f36020580dc73f6a9f76f` |  |
| `NOTICE` | `4d42df4771c2f8c7b6f983eb29b28b81b7fec01917d30ea063c2e0dcb512af2e` |  |
| `PATENTS.md` | `c8034b61bd795351ae67d04395940de782c5e82f9cf2856a3f7d03cf2a101bb3` |  |
| `QUANTUM_SCOPE_NOTE.md` | `981d4f9518b13d2c47960d5b73d20b31f1fd51d9cc03bca14f5125039231ffdb` |  |
| `README.md` | `f7e54e3ead323b21d681375650ca5248f5648dba6165974f2addc60e62daa471` |  |
| `RETIRED_mcl_txn_verify.md` | `589742fcc12b80332c2478e21e51658bd243e6de9308e08ac22d90d1bffbddd0` |  |
| `REUSE.toml` | `805bea6173d163f417b8097f162d2978deae445f1c21e3ea62cd284c2b40768b` |  |
| `SECURITY-RESEARCH-GRANT.md` | `24a8609549aec66bbb18126a015e3513332bc665b7dd1154501707e70ac816e3` |  |
| `SECURITY.md` | `fb923ca3236106a55b6c62e9ba404a46b1054b9f6338884425af82af0048dd37` |  |
| `TOOLKIT_ACCESS_AGREEMENT.md` | `3cf1b9ac0ecf0b2b3aeebb98728dbedaabb1e9342106662fd661215b16d7c08e` |  |
| `TOOLKIT_ACCESS_POLICY.md` | `83a93bc5db57c8a49c18df96a36772c725fab173984fca543dac525d618e1433` |  |
| `TOOLKIT_ACCESS_REQUEST_TEMPLATE.md` | `2da1c63b20eadbb243d187550b0f7372ebaccebb16a56abccb57eb1ee4ef9225` |  |
| `add_spdx_headers.sh` | `3a985c3332a513fdd925100e5cfed287964f9f48321e6f9042744d99d53173db` |  |
| `beff_deep_audit.cpp` | `16b3c502be19b71c918898d5e0ae6f3d51a7af3835eb752cf13df41c6f8b73c6` | Audit the b_eff backward-inversion claim underpinning Paper 5 X one-wayness. |
| `kat_gen_macos.cpp` | `c6b6da6c0f3589d6d0d953e4e33f53a3185976db3a8a951ab9837b2b02e6f971` | Generate Known Answer Test (KAT) CRC-32 vectors for MCL_T2 engine |
| `mcl_beff_compounding.cpp` | `24329fea6fe2fbb92caf2d63968c341ad3a4b9d0353daeda7efb7d0a3325a76e` | Test whether the per-step keystream-constrained backward branching |
| `mcl_benchmark.cpp` | `1995b9fb0f919547856285db1e55810d17f3041cd464c7fbdd91f7c71526868f` | Measure actual throughput (MiB/s) and memory (bytes) of MCL. |
| `mcl_core.hpp` | `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80` |  |
| `mcl_dynamical_signatures.cpp` | `3cf84f5fc712634cb889979a71180534e83c92ca27f51b6f16f12a408fca2e64` | Compute the standard battery of dynamical-signatures used in the |
| `mcl_generality.cpp` | `8761f6027d4878204b97376309aadf2c0b2bccead8ce61a1c3ef75bcaecfecc7` | Verify that the MCL coupling principle generalizes beyond |
| `mcl_hd_verify.cpp` | `bc09dec7b13ed89cec962d1dcc94713a37086a2be9de0c403fa04dcc7c995601` | Experimental verification of Hierarchical Key Derivation |
| `mcl_k_sweep_unified.cpp` | `bd5f66e5514ba3a52b71e63f8e2099a18498f4f9015c2015d2e6641e71162914` | *   Sweep coupling strength K from 0.1 to 500 across MCL_T2, MCL_T3, MCL_T4 |
| `mcl_lyapunov.cpp` | `a44d28267007ff1406ab05d40a1d1f8e3c8433c15951bd407f5dc4f65e3a18db` | Compute Lyapunov exponents of the MCL T² system using the |
| `mcl_lyapunov_lambda2_verify.cpp` | `c72b788c8e99633b5574bea4dd69462b2dfaddc1046150451e63cc42f6d46d15` | Verify the semi-analytical closed form for the SECOND Lyapunov |
| `mcl_omega_independence.cpp` | `463133cef854b5728e614419ecf63a80c9bd41f5ce8563eab7dc7002da04b911` | Verify that different angular frequencies (ω₁,ω₂), with FIXED |
| `mcl_orth_verify.cpp` | `b777600f785167aa2dc0dc3b68bb2724990af090efabb5e807297edabd2c3e40` | Verify that MCL channels indexed by different (p,q) pairs are |
| `mcl_paper4_verify.cpp` | `4770a8af84c3083f29c2e4ebd69d3fdc68aac7e5311eda5c52504ae8902d8c87` | Reproduce all numerical claims in Paper 4 (VDF Sequential Function) |
| `mcl_postquantum.cpp` | `ac238023479de0fed5e68cc09dece4184bcb62f39384a88a07a9b17965ba7a66` | Classical diagnostics of the two-oscillator engine; NOT a quantum-security test. |
| `mcl_practrand.cpp` | `0371f203f1993ece26347395a192ee8f71a2992c0a44111ac9ccfa621ecefb57` | Stream cryptographic-quality bytes from the MCL_T2 engine to |
| `mcl_reference.cpp` | `140ee9a39a3224e8faf9c0323fc0ba66f5eaadaf23fce6c33e6bcf28dea9167d` | Canonical reference implementation of the MCL coupled chaotic |
| `mcl_safe_zone_verify.cpp` | `13e2893008f1591bf9bf88943a99de6ea0e80b5b3d43c930ee2a1377f5569214` | Empirically characterizes the Safe Zone bit-extraction regions of |
| `mcl_scale.cpp` | `740a207f27e301b8650c74ffc4f0502eff3a73083c389c32dc41a7c08c988526` | Verify MCL scales from 20 to 1M+ simultaneous orthogonal |
| `mcl_txn_verify.cpp` | `4d5e7dbe29a1596da37033cd9268e9d4e41e60338719d689de88be81ce8d500c` | Experimental verification of non-replayable transaction |
| `mcl_vdf_falsification.cpp` | `25f24508227e4e41481291976d350e370d7291d1c1c3bdf6e1000df2aa9fa40c` | Four-attack falsifiability battery for MCL-VDF open problems OP1 (sequentiality), |
| `mcl_vdf_verify.cpp` | `c7e517e33647d802f8f485e5e2104d838b70de059fb32a1e29c24e339008e1ac` | Experimental verification of the MCL Verifiable Delay Function |
| `q30_macos_validation.cpp` | `d58b0c11796a4036e6b3a216b1a4d4784d7840385358b10c9a30c93fd32354f3` | Validate MCL Q30 (fixed-point engine) cross-platform bit-exactness |
| `self_test.cpp` | `9971324ad99bde6dea410b2f969443b85db07b77600ca797dd6d2eb2c9ca53bd` | Run the MCL engine built-in self-test verifying all Known Answer |

### results  (31 files)

| File | SHA-256 | Note |
|---|---|---|
| `results/MCL_Scale_v2.2.0_Test_Results_20260519.md` | `e47c80e57a08ff886aa6aed9e74d3c568161925505af288387269c0b6206fcd3` | Consolidated documentation of FOUR independent runs of mcl_scale |
| `results/beff_deep_audit.txt` | `0fa5baf9f152d39af5b23f3bd3d2602d326ea141198a144ad272f9d436ecd11e` |  |
| `results/kat_gen_macos.txt` | `959fa8bde760d0957c18e5617c251025b012d21665f1d9e56fd89f9cbfe01733` |  |
| `results/kat_gen_macos_v8.1.3_20260822.txt` | `00732e5077696d503de2f01b31f3facf51c44bdf8f7230d98f3409a3a4a07f34` |  |
| `results/keyed_q30_test_v1.0.6_20260822.txt` | `bdd7b17d4b5c3ed7431da2cd37336ac4a4110f0dd48bc9bb6f07b020e944c17f` |  |
| `results/keyed_q30_test_v1.0.7_20260928.txt` | `ade24653817ce5fed9f9882a7c5d04f286bce8af408f10bacb9a150571d2f75d` |  |
| `results/mcl_beff_compounding.txt` | `2e4d0c2e8cbe02895e15de7404670062f39b989ca1441acc2ac5875d6c5a086c` |  |
| `results/mcl_benchmark.txt` | `2b4b54303dd163df0df7b4abc98ae033007c53ab078baa8c51a1503f55b5d2b4` |  |
| `results/mcl_dynamical_signatures.txt` | `4ae1450f5a1c8308d63685a1ac54eb4b2de6973911f28087beb5f4697978747d` |  |
| `results/mcl_generality.txt` | `70fafa524cd44e84cf35eee5e764d007860b1ae7e660b133ebd21a84161d04b9` |  |
| `results/mcl_hd_verify.txt` | `a59a830313f1303117b1df372cd7b0ad39db86d6531a08b27b5caf6d2756aa1d` |  |
| `results/mcl_k_independence.txt` | `5a039cfac35684ad7cadecadbd375c51f527d9cb3172df2c4a795d9fa5aad58c` |  |
| `results/mcl_k_sweep_unified.txt` | `eb681d8ca165bb6f3ed6cbe034b769bdc35c0133cb9b3ceb28d9d442e0b06051` |  |
| `results/mcl_lyapunov.txt` | `7f826b5cd87b6844aeb85c6c1acc8598a2b8a4b4fb553bcd3f7a2f9c52e7fd71` |  |
| `results/mcl_lyapunov_lambda2_verify.txt` | `594f59955435eb632bb3072619b5974c693bdc883a1d0f6a1d348862fff26087` |  |
| `results/mcl_omega_independence.txt` | `02f854ab16ad9603dd4acb54492433fd8bf1f70eee226af41215fa2e38a24fb7` |  |
| `results/mcl_orth_verify.txt` | `b6a49a6037175db04a8844c2ef5bb9cf3db86f0bb23e03c20c15ffaff3659e0e` |  |
| `results/mcl_paper4_verify.txt` | `a27bbfb46c0f025ac8bb4c61eedb95437cafab30f10064ce27439bc947cbcaad` |  |
| `results/mcl_postquantum.txt` | `29fd400279e13b1c822a290d4e4620b83f8220b7a01c82d23fc42f9cc74ea865` |  |
| `results/mcl_postquantum_v6.0.0_20260526.txt` | `365f1bd4693015bd736f678b8063006dd7a53cee2d404d9602f4fdacbe795f4a` |  |
| `results/mcl_practrand.txt` | `ccc393fa030c3d8879c5d1a7c5532a8d0df42fabc7d4ee7375479c79651fd300` |  |
| `results/mcl_reference.txt` | `4845bdf6a8d7af38632d07d77e5292f993458bf2fc98a32a2c69779210356a9b` |  |
| `results/mcl_safe_zone_verify.txt` | `3affbed2a99f31106a393b98a8f563fcbc88f262f8ecd9e76bff393153366648` |  |
| `results/mcl_scale.txt` | `9f54b60162c9d83bcebee6080e7507d2f6656b8f11b053e91800b36099fbb967` |  |
| `results/mcl_txn_verify.txt` | `c42b7124a797d72b219667cdd9e7937944c1e2927e62c902f0f36d15b6bd8b6d` |  |
| `results/mcl_vdf_falsification.txt` | `44a84f01018cac03d200b19f194981c34e60c685a3337bf30c3e36043ce026c3` |  |
| `results/mcl_vdf_verify.txt` | `87c5789ab177e03d6528699d3e2571f1f51e72126c6af3891317dbb8b16fb46c` |  |
| `results/q30_macos_validation.txt` | `2dbdc84ab5940ef948d6d8000f332a453d7a04446b67d02afdfef36acbae2d15` |  |
| `results/q30_macos_validation_v8.1.3_20260822.txt` | `c368a19970620a583f37638f57059653bf24c8afd06db8ef87a7580d47f83267` |  |
| `results/self_test.txt` | `f77482b4c178ed4ec759e09e1d68ef183f24387117b98dbf043bc0c2f95630c6` |  |
| `results/self_test_v8.1.3_20260822.txt` | `ec20df38c1630e6a60109c99908137cc3d8d0d23108796ccbf5b8bac57eaf92a` |  |

### keyed_q30_PQ  (40 files)

| File | SHA-256 | Note |
|---|---|---|
| `keyed_q30_PQ/CASCADE_GUARD_V107_RECORD_20260928.md` | `3e4727b475f2f176a83cbe777d78ea603a2aee6e360e4af9ddc7277e202bf500` | Sidecar v1.0.7 — cascade symmetry check and opt-in seed rule — record |
| `keyed_q30_PQ/CT_SINE_CODE_EVIDENCE_20260919.txt` | `e00d26b1906cd68fa36eeec10a6f265a054f6ea977b052c47b1d8cdc0b457cfa` |  |
| `keyed_q30_PQ/M0_CODEGEN_CLAIM13_20260612.txt` | `94091cd667e5dce60ede9e292741d19c112cc4a68b53c190feb01100cd3e67ac` |  |
| `keyed_q30_PQ/MCL_CAPACITY_REALIZATION_20260812.txt` | `1e40229ab6b8c2e65d8a4e13e38ab1cdead5f5e707dbf6e965507ad4c22206c9` |  |
| `keyed_q30_PQ/MCL_CAPACITY_REALIZATION_20260812_v1.1.0.txt` | `672535dc365e7046bf88065efa44a56146ce949b5579c8d3fa4ddc68ca636726` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_BEFF_RECHECK_20260611.txt` | `212fecde6d6bc6d10c4bca9a1624f50bc3ed1baf0130425774f8438030e9a38c` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_DIEHARDER_20260611.txt` | `2a2e214691216e44dc438ba975e301fe2d5045682c345f226e25ad6022e13d53` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_DIEHARDER_20260903.txt` | `27fb8771136328072ed13454236beeeb897bfd685ac1c7262f39d37b344c7708` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_LYAP_SWEEP_20260616.txt` | `b8b6f9afe37f87ac344714fceac94a8b712143f86469b93b1f8300a4c0643998` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_MEASURE_20260612.txt` | `771226a6ace705e00513eaa4ac6298ec7a28fcf9fb402c4a05a51b5b65cf33c3` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_MPFR_LYAP_20260611.txt` | `a540c45c7e97e716b53a7ea3dee41d4d700e69640065f5a114f672e2059bf4d7` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_RESULTS_20260611.txt` | `a9177690e18bfed15ef04e97491467f1db9ba37d065978c41af3c2035523570a` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_SCIENCE2_20260611.txt` | `1606151b0d449f346857b7f0f3d5b9b625788b8dbd7ecec55c474f7d73d439e2` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_SCIENCE3_20260611.txt` | `861b4247ca3f2983beacc7c1593c03ca6b1cd9414218758a16cc5ea3d577dec6` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_SCIENCE_20260611.txt` | `e7d1b57a3cdcd5c272048efc298a0335882df04dd27b2d6b2bc0739da1dcb36e` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_V107_COMPARE_20260928.txt` | `1f2111c5154a29fdde6d7ccfeb6e0751eeb8224b272fb2c127aec409aba106ff` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_V107_VERIFY_20260928.txt` | `709a441a6803b340100bcca42b175c206ab580faf1b56e8b0d19aef62e7570c3` |  |
| `keyed_q30_PQ/NOSYM_V106_RECORD_20260822.md` | `bc56e7eb28a32ccf61947d87a1417ae87eba7c57e80cfe34a85ea6df9ce1abdb` | sidecar v1.0.6 — رفض التناظر القابل للوصول من البذرة في `mcl_t4_q30_params_from_key` — 2026-08-22 |
| `keyed_q30_PQ/README.md` | `188e812689a4afc6b16e2928638bb15b4a38737d6869454c9d2c65ee0a13c146` | MCL Keyed Q30 — FPU-free, key-bound, post-quantum extension |
| `keyed_q30_PQ/STATUS.md` | `efa158570a83c0376ca2552ae2b3805f02b4a0f58c088959536bb5d414d6e8de` | MCL Post-Quantum / Keyed-Q30 — STATUS truth table |
| `keyed_q30_PQ/dump_keyN.cpp` | `ef0a8649cd46f413b631188b12b8457457b51464d0aca832a587010675d11672` |  |
| `keyed_q30_PQ/lyap_2osc_signcheck.py` | `c34b8e36fcbc2c773ad444e7f7b676a01789c32704873a0b66aa328d3922291d` |  |
| `keyed_q30_PQ/lyap_independent_check.py` | `77199d6bf3d0a46250daede2a1019eb5af03d5b17508a5cb1ce0730aebc5d8fc` |  |
| `keyed_q30_PQ/m0_codegen_probe.c` | `14281a7140a24bd711edc215725041ef664d943d3d92c2877de97fa63786e0d2` |  |
| `keyed_q30_PQ/m0_probe.s` | `68dd9d08e9ec22bed614d9971d3b0d72163d26f8cb7dd711e0c9eca2ab04df50` |  |
| `keyed_q30_PQ/mcl_capacity_realization.cpp` | `8853337a453eb4c3f33b9587a56664a79ac31c1eed1e50ba25945a1303464972` |  |
| `keyed_q30_PQ/mcl_keyed_q30.hpp` | `05c01cf8a15626c0e6f892103868afc11f36b07bad3a27472b9a8d608f396a29` |  |
| `keyed_q30_PQ/mcl_keyed_q30_ct_test.cpp` | `6a56233a56c3ce1574cdc23f0d04e688bda2b73ab7441df75b97847137999db3` |  |
| `keyed_q30_PQ/mcl_keyed_q30_dump_weights.cpp` | `f09a2460cdf8e8e26d2f200363e16125949da1cd777db1337521148b0fd07f79` |  |
| `keyed_q30_PQ/mcl_keyed_q30_lyap_sweep.cpp` | `b156f89cb99cf3e1daf425c12b77728531e139eab4bdd585298bc43a93904258` |  |
| `keyed_q30_PQ/mcl_keyed_q30_measure.cpp` | `8c4e76c8d06d6a1d7c9bcda7cb8055e7184dc9cb55565e0b1e5bc99c36c379ee` |  |
| `keyed_q30_PQ/mcl_keyed_q30_mpfr_lyap.cpp` | `20c29a2a9b3e913cd7b6490febf0f0c7263ed197272fbaa7387e5b3f79d4343b` |  |
| `keyed_q30_PQ/mcl_keyed_q30_nosym_verify.cpp` | `95551bcc1a48c8921184375e64e85fa64f12b4e915aa1edf83e4622458536ee2` |  |
| `keyed_q30_PQ/mcl_keyed_q30_science.cpp` | `5a33ab998204419c5eb608e9671f5dd9b55e59024c6651b83f90434fe1b0c6ac` |  |
| `keyed_q30_PQ/mcl_keyed_q30_science2.cpp` | `87e4b9ef6e2580b1642b5deba531d02f7c66310314b0ef2aad254493a43342dd` |  |
| `keyed_q30_PQ/mcl_keyed_q30_science3.cpp` | `9ca5703dc844fec31302e0f35b417afb502f3c3062646ab6b6881815e7d232d3` |  |
| `keyed_q30_PQ/mcl_keyed_q30_test.cpp` | `48545db0b55bd3fe27e69b13f704a7d247923b18cbb4121da10563ad7b2d7ebe` |  |
| `keyed_q30_PQ/mcl_keyed_q30_v107_compare.py` | `95dd482b4d9d1415752a7e724903637fbec88f4ae78fc726c1af2862ac7e17a4` |  |
| `keyed_q30_PQ/mcl_keyed_q30_v107_dump.cpp` | `a250ee787139d8296739a671166eb5b3ac9bcabc4d3eaee02dc687e6af4469f6` |  |
| `keyed_q30_PQ/mcl_keyed_q30_v107_verify.cpp` | `198e8f131f456b968d4cbfd923cb640a9e0a3f9bbce083d95f038c60ef53d15e` |  |

### VDF128_T4  (61 files)

| File | SHA-256 | Note |
|---|---|---|
| `VDF128_T4/BENCH_RECORD_20260821.md` | `1d48424b0bfd9a3555a4c3a21a8c3ed32db29d3f201c98cbc6e093ea486cf3c6` | VDF128-T4 — قياس Eval/Verify على المعالج — 2026-08-21 |
| `VDF128_T4/README.md` | `429f723c00cbc6d8b97ba17f7a54093ab3677ec9194150d1e74dbda56a65ae6f` | VDF128_T4 — 128-bit-state integer VDF path (Paper 4 path-A rebuild, 2026-08-17) |
| `VDF128_T4/kat345.cpp` | `0e3b99af92ad721645775bd40cfc8d0639c39f33dce80a0235b42d203c8fff63` |  |
| `VDF128_T4/linux_env_gha_20260905v3.txt` | `5b249afb3b6d63d3d3205f24a9ea6421211976e5de064d9b548441e3031a38bb` |  |
| `VDF128_T4/linux_provenance_20260905v3.txt` | `2c893eb49813088c136fdbf087dc93d623e8a7c5610fabca06bfd0c3b7cceade` |  |
| `VDF128_T4/mcl_vdf128_battery.cpp` | `e69aea857f34a1eb3e894ee2b1afeaf2b4ee66a7cdd2f5445554d57c514bd7d9` |  |
| `VDF128_T4/mcl_vdf128_bench.cpp` | `2a43c33da96b8979d64ff7e727a602ab5d899fbe601d88741808cbe700a8390b` |  |
| `VDF128_T4/mcl_vdf128_cyclecheck.cpp` | `fb5dc4a9e06d59e88c79808444817461c43d334355f755886819bd7d21456496` |  |
| `VDF128_T4/mcl_vdf128_t4.hpp` | `e08f702e2da92221588285a6a61ee2e48edfb63afbde8220fc3632fd2180ed0d` |  |
| `VDF128_T4/mcl_vdf128_t4_v2.hpp` | `41171250455fa33e311c1484f4d5d4fb67699e2f6275551224f1d06c1f63716f` |  |
| `VDF128_T4/mcl_vdf128_t4_v3.hpp` | `b46f1a1329ccbc4dc4eac02b930be7b71f74847800ed7c01358163d80f615439` |  |
| `VDF128_T4/mcl_vdf128_xplat.cpp` | `36a9c5878030ddf40dd2808ab58259d50b993f2f53a2e07b5411593259e51ebc` |  |
| `VDF128_T4/mcl_vdf128v2_battery.cpp` | `08c532c3a510bf7a9c1912dbabc4306d405e7230356af1274b0c3c8dc3a8685b` |  |
| `VDF128_T4/mcl_vdf128v2_bench.cpp` | `c109f8e008a4bff73459391b4a44262d344a49e738d24642ab33a26935121d9f` |  |
| `VDF128_T4/mcl_vdf128v2_cyclecheck.cpp` | `7515bba87b0bf3218c9199308774adcff24e0474a6407dd57bcf0c193555de85` |  |
| `VDF128_T4/mcl_vdf128v2_xplat.cpp` | `f465117c06ec2f8b27d0f455ca55f260eaf286dd4ac396aa36d55c8fa6a0b014` |  |
| `VDF128_T4/mcl_vdf128v3_battery.cpp` | `2425b901f6e2db208edced7740fe454bd5775b183fc50443fd300a1c00e2b0ed` |  |
| `VDF128_T4/mcl_vdf128v3_bench.cpp` | `0f580565e502915fee694b8a2586c22e9f74f6e1d94ed008314b3b23262cfdb3` |  |
| `VDF128_T4/mcl_vdf128v3_cyclecheck.cpp` | `eefeed0bcf670a5db76f536ca7bff4e30bff2176949f5b443b512e55ad959159` |  |
| `VDF128_T4/mcl_vdf128v3_xplat.cpp` | `57feeb1680d4af37b748077d710947459ade0c76639c57f2eed01189540ac95f` |  |
| `VDF128_T4/p4_sha256_vs_t4_bench.cpp` | `d38320478d230291bebc3e5b1b2d289cb6f972c894b0745dcc8a6429af04e98a` |  |
| `VDF128_T4/p4_sha256_vs_t4v3_bench.cpp` | `df4dd3b6e8de13685e19ac3ec438d217e3355e9a067611855f3c4de0f9de488d` |  |
| `VDF128_T4/p4_vdf128v2_kat.cpp` | `28f38551f00005d27634d4547552fd8eb4d616018186dee9a68ac12709fdba58` |  |
| `VDF128_T4/p4_vdf128v2_weaklane.cpp` | `3a71f26cea40ec43f3f09a9a9a16a16cd9b9be04d6324e60b6f24a6ef381e3d5` |  |
| `VDF128_T4/p4_vdf128v2_weakpair.cpp` | `a3e9fdf9acbca7370c479a630e0e7fe402ea5f8923d2f2eba32798c23756c76a` |  |
| `VDF128_T4/p4_vdf128v3_distinguisher.cpp` | `c0cb7bb956681a99df2cd5edc64e1db020f77377b4eb50f96e89206ca18c819a` |  |
| `VDF128_T4/p4_vdf128v3_kat.cpp` | `c263f9c44d5cc656cd208d64d83fb466dd6d71ebf0e21bef3cea801e867941ae` |  |
| `VDF128_T4/p4_vdf128v3_weaklane.cpp` | `7ad87bcc590444a09fe2a5b98c7b84297ebca866a74d895242119537dcad92e7` |  |
| `VDF128_T4/p4_vdf128v3_weakpair.cpp` | `4f374c2b8e6a154a4932781e910f771af4053f6fcf8969d1b6ba535640f2f167` |  |
| `VDF128_T4/run_v3_all.sh` | `fed8b5fe4477d931d59b70d016350f64406ad01bae1b67c9fbd5041a69156ca0` |  |
| `VDF128_T4/sha256_vs_t4_bench_apple_20260905.log` | `a0331d60e0d388e0bc26f7d5b7156f2e1de36aa6f4c6f9cff9b7093478be3c6a` |  |
| `VDF128_T4/sha256_vs_t4_bench_idle_apple_20260905.log` | `14f35a587d371a5729d79c344645da549778c519337fa859d31d3563bbb883e9` |  |
| `VDF128_T4/sha256_vs_t4v3_bench_apple_20260905v3.log` | `23234fdec89fbadbad8b074f8a100f6a9082fd2e1263c14901aa1c977061ebd2` |  |
| `VDF128_T4/vdf128_battery_apple_20260817.log` | `35fd9d87066e1fa6c82fde0a9861f7e7e29a2835920915a3b4a1aa2e15f75c09` |  |
| `VDF128_T4/vdf128_bench_apple_20260821.log` | `40a9e3f4b7622358309b858a798c2ff3a1857ed9d6c6552ba8dead36414adacd` |  |
| `VDF128_T4/vdf128_cycleprobe_apple_20260817.log` | `6d3c1301b1a2c746b485c604aa7c1b7e6e2091d6fe893c18e3c003b5cc33be7e` |  |
| `VDF128_T4/vdf128_t4v3_standalone.cpp` | `34906621a6aeabf8284a341d993f73e144d5898a1c3cc22b3078b93726034ae5` |  |
| `VDF128_T4/vdf128_t4v3_standalone_apple_20260905v3.log` | `8e049b6474e7afa4019f8de2ae33dd556bdc7dceb1ba8aa26644a87669516941` |  |
| `VDF128_T4/vdf128_t4v3_standalone_linux_glibc_20260905v3.log` | `8e049b6474e7afa4019f8de2ae33dd556bdc7dceb1ba8aa26644a87669516941` |  |
| `VDF128_T4/vdf128_xplat_apple_20260817.log` | `46f75037747dfabfcac9170de2fb7070e5e89ee68b6f6f388ffb5af2b147567d` |  |
| `VDF128_T4/vdf128v2_battery_apple_20260905.log` | `c11dbe50318ddc6d34a9f10fd86aabb47e14799f5aab9e9eca3446a75a4500d0` |  |
| `VDF128_T4/vdf128v2_bench_apple_20260905.log` | `ba35222678ef737eb7f2f2238ecfedc94970d662157600c8f7ae1765d8c47e9f` |  |
| `VDF128_T4/vdf128v2_cycleprobe_apple_20260905.log` | `5150cbd452b67ca05c03c6bcb5f40bc23615215751612a40307585f485b4e358` |  |
| `VDF128_T4/vdf128v2_kat_apple_20260905.log` | `ad25753aa01278a6679b89b8ab887a6e7da2632ab6ce37f17e5a11af58d58be0` |  |
| `VDF128_T4/vdf128v2_kat_linux_glibc_20260905.log` | `ad25753aa01278a6679b89b8ab887a6e7da2632ab6ce37f17e5a11af58d58be0` |  |
| `VDF128_T4/vdf128v2_weaklane_apple_20260905.log` | `9573e8b90e34c709c5344f6a834291fc4acf8198890a47bb0a82858b9931a1e6` |  |
| `VDF128_T4/vdf128v2_weakpair_apple_20260905.log` | `d237035e216be8acb54e0ce41f32301062b8b54c2d60d6311e223773fa3027e7` |  |
| `VDF128_T4/vdf128v2_weakpair_grind_apple_20260905.log` | `1ef86035ef568b4704c2784221c739a93545ab222f5fc1563695e25e5c99fe4d` |  |
| `VDF128_T4/vdf128v2_xplat_apple_20260905.log` | `3e934b09990f744f849e8d7533006dc1b5d6c88d5f7f02f235e54202133ee795` |  |
| `VDF128_T4/vdf128v2_xplat_linux_glibc_20260905.log` | `9016a4fa2ed1b1594457fdf3ae17fed38f20cf996b141ee4eb4441d6ec8d3a18` |  |
| `VDF128_T4/vdf128v3_battery_apple_20260905v3.log` | `e852542032c6a58137f312eded0f2f0f7423502031e5c7ffe221d62ca3745b15` |  |
| `VDF128_T4/vdf128v3_bench_apple_20260905v3.log` | `23800077453eba4342768b78fe440c9b3e01164671296b8ead8a97f9aea64af1` |  |
| `VDF128_T4/vdf128v3_cycleprobe_apple_20260905v3.log` | `c5cae69affd019ff0126c90d968955632f55878235e57f20866416c7f5b85dcf` |  |
| `VDF128_T4/vdf128v3_distinguisher_apple_20260905v3.log` | `8308128c267c43e6376bc5d17594f13e4a2e2d9231291e7e955d18879954cf98` |  |
| `VDF128_T4/vdf128v3_kat_apple_20260905v3.log` | `7c2905397cb81f03019708fe72ec5f0e04fb0304d7b378ce52d2502d81b65b0e` |  |
| `VDF128_T4/vdf128v3_kat_linux_glibc_20260905v3.log` | `7c2905397cb81f03019708fe72ec5f0e04fb0304d7b378ce52d2502d81b65b0e` |  |
| `VDF128_T4/vdf128v3_weaklane_apple_20260905v3.log` | `6c5caccf76603d18f1b9c6db3fafa02a1735834ae8d0a9137b41d0cd06cda828` |  |
| `VDF128_T4/vdf128v3_weakpair_apple_20260905v3.log` | `e22fc09dff3244245cacec62924b00d390c5f4473a3a43f33c3027f5b4e3b5ee` |  |
| `VDF128_T4/vdf128v3_weakpair_grind_apple_20260905v3.log` | `f66687c58741f1a2aa3390eda14fe44cf94d44658ad15d6efb73561fd61354a2` |  |
| `VDF128_T4/vdf128v3_xplat_apple_20260905v3.log` | `01468d7882a04fe10c64dda48e4c0dc1c5b4bc4236c4dafbbf8e4e84195a01c4` |  |
| `VDF128_T4/vdf128v3_xplat_linux_glibc_20260905v3.log` | `d308f061a3b5e1d21c069bdd5193416bba5ee8c88db771ce9223de2f369b57f8` |  |

### T4_CycleStructure  (24 files)

| File | SHA-256 | Note |
|---|---|---|
| `T4_CycleStructure/README.md` | `38f541cd1f31ff4646ba7030e901279ed133c964e9954727c6599b37d81604ce` | T4_CycleStructure — دراسة دورات محرك T4-Q30 بعرض حالة مُصغَّر |
| `T4_CycleStructure/T4_CYCLE_RECORD_20260822.md` | `165b1fc554afbd1fd3387d191c9bef560963f8806547f8182648d7199116d420` | سجل دراسة دورات محرك T4-Q30 بعرض مُصغَّر + اكتشاف التناظر الانتقالي — 2026-08-22 |
| `T4_CycleStructure/cycle_translates_apple_20260822.log` | `9eaa8796227727dac5713c693afa8854194a9fadd20e79169ed5aea52344e8f5` |  |
| `T4_CycleStructure/cycle_translates_v1_SUPERSEDED_apple_20260822.log` | `53ee2f02606103b3446deca9d5384fb73611658f814225ed2b7714b28e75e17c` |  |
| `T4_CycleStructure/fit7_summary.txt` | `a4e00813bd4d198914193bb0589e43c86f4d04779d0d75cf1f1401184963a771` |  |
| `T4_CycleStructure/float_symmetry_apple_20260822.log` | `673caddecc138ef8fbd0a4af142e774163d90362bda6cbd4d066df2b0f3016be` |  |
| `T4_CycleStructure/mcl_cycle_translates_check.cpp` | `0d3d2a65fe820d27bf8477d18571c8e85bfcab21767fe36148621ee03a886a6b` |  |
| `T4_CycleStructure/mcl_float_symmetry_check.cpp` | `797918cdd5a62690ee30853dbcb61def1e4721d9c8c1bf58a7833787184ce1cb` |  |
| `T4_CycleStructure/mcl_symmetry_check.cpp` | `5429594d837b7bbb6be340ab54339d1ac31d08041b71b2606039ad8d10344bcc` |  |
| `T4_CycleStructure/mcl_symmetry_group_exact.cpp` | `da5eb14b05d7a6e7ca82243bca33917899555e569966bb0ae515439621bc651b` |  |
| `T4_CycleStructure/mcl_symmetry_impact.cpp` | `de0eb8093111011ac721bd0366d952ff7682e7a9e8177d5a4bb8deb85edb6800` |  |
| `T4_CycleStructure/mcl_t4_cycle_reducedwidth.cpp` | `d34a0df96a611f4a563e6cf58a43f62dff25d530b3c29db20a2cb180c274eca4` |  |
| `T4_CycleStructure/mcl_vdf128_symmetry_check.cpp` | `1ccb3234c73947ee77db07d21f6930abfce55a8fa3b2cf8a0ae9da631b3df6fb` |  |
| `T4_CycleStructure/mcl_weakkey_parity_check.cpp` | `12257cacab48e165969e862393de1063192c7e0f3246b04ed5f4c369b7a219b5` |  |
| `T4_CycleStructure/symmetry_check_apple_20260822.log` | `8961d3c2b61469993f8ecce3ffce1328dd36e8a2ade873598d47845e8b44112d` |  |
| `T4_CycleStructure/symmetry_group_exact_apple_20260822.log` | `50c160e1bf0c95f0f70e84bd0f7ad3f566ceb9c5de0acb8d9d45e1bfed0964cf` |  |
| `T4_CycleStructure/symmetry_impact_apple_20260822.log` | `8ac01a37e1e295a9f6b480a77422d644a75ed0ca763fae4ea8d49decdf933eb9` |  |
| `T4_CycleStructure/symmetry_impact_v1_SUPERSEDED_apple_20260822.log` | `0d8bd4ea0f2d4f6014a9d9901b19dba3b8b5e083bb3a6e2a9c57378b03e2f5bf` |  |
| `T4_CycleStructure/t4_cycle_brent_w13-14_k4_apple_20260822.log` | `b3f5804847c43d112183f64b0eaf936d6c9a384bf3c7d65daff17e76f1e79a33` |  |
| `T4_CycleStructure/t4_cycle_brent_w8-12_k16_apple_20260822.log` | `24d6849f1eca9006c6805020e9c383e8d0c5e9e5f79a3788d12fdd5a8007d328` |  |
| `T4_CycleStructure/t4_cycle_calib_apple_20260822.log` | `917c60adf8fc7364618346e26773ebe324051720ca31b5ae42cc30608387f3e2` |  |
| `T4_CycleStructure/t4_cycle_exhaustive_apple_20260822.log` | `9ad1b3aef840063543ef2eed0de865618062923c4ac4a543cedae4953ed6f4cf` |  |
| `T4_CycleStructure/vdf128_symmetry_apple_20260822.log` | `a42a36df05297ed8d061bbff1f9d53a2d30f828e4ac707bb2fe4de1cba783966` |  |
| `T4_CycleStructure/weakkey_parity_apple_20260822.log` | `ca4ca878aca3190946cbaf9e1f92b5f94c1ac92bb72e7ee4a12126394946d05b` |  |

### ReturnMap_Attack  (4 files)

| File | SHA-256 | Note |
|---|---|---|
| `ReturnMap_Attack/README.md` | `6c4fcea85df50052acf7f5eff96d52861c62f0161426fe1ed0daf2b181a00215` | ReturnMap_Attack — محاولات الهجمات الخاصة بالفوضى (Rule 13 / Rule 7) |
| `ReturnMap_Attack/RETURNMAP_RECORD_20260822.md` | `4c28ef4d1a8ab286b118173e90b9890a8fae86e10b71e04924b718ab8523c829` | سجل محاولات الهجمات الخاصة بالفوضى (Rule 13 / Rule 7) — 2026-08-22 |
| `ReturnMap_Attack/mcl_returnmap_attack.cpp` | `9abf251f10cc6d9919bbc195045d60b6846614f92031c4e72b54aca517f7a5f6` |  |
| `ReturnMap_Attack/returnmap_apple_20260822.log` | `87832b71220f7e0eac39cc806f356379fd390a7863d0a250936a1c47a6b7da0b` |  |

### p2_hardened_auth  (19 files)

| File | SHA-256 | Note |
|---|---|---|
| `p2_hardened_auth/ENGINE_SENSITIVITY_RECORD_20260821.md` | `31327eba86a9308a562bbe62e3c8a935b2cccae810f92b3afd1e6a334c1674a4` | الورقة 2 — حملة حساسية المحرك (مستوى المحرك) — اكتملت 2026-08-22 |
| `p2_hardened_auth/FAR_CAMPAIGN_RECORD_20260821.md` | `c1142f22f3840f1141afb17067bceb5d7550b90d0b73c71ef2c41c28d15978fe` | الورقة 2 — حملة FAR على الملف المصلَّد v2 — 2026-08-21 |
| `p2_hardened_auth/FAR_V4_KEYED_RECORD_20260822.md` | `692caa453a5e8491d23572b8404d011c1c76f7834d420d3b7a8d71053cbfb06e` | الورقة 2 — حملة FAR على المسار المفتاحي (بيانات الاعتماد = مفتاح جهاز 256-بت → 12 وزناً) — 2026-08-21/22 |
| `p2_hardened_auth/README.md` | `f7c82e38464e5a2c716bede4da7e17253e5ba6b4727244b23d6183e58d54f90b` | p2_hardened_auth — الملف المصلَّد لمصادقة الورقة 2 (v2) + بطاريته العدائية |
| `p2_hardened_auth/SIMSWAP_V3_RECORD_20260821.md` | `ef4e28be49ef868617bed62f09d766f855feb4e66801d69e7b15659fa5942b36` | حملة SIM-swap على مسار الاشتقاق — الورقة 2 §V.B — 2026-08-21 |
| `p2_hardened_auth/avalanche_1e6_20260821.log` | `b44bbeeeefaa25c250169be7869f6fa9eabf6da687218bb26716455168e970bd` |  |
| `p2_hardened_auth/engine_sensitivity_20260821.log` | `d1eedca6b3954f0e4a75e3f61f5d5326b13656539ee038a8f49daa2eb4ba9d83` |  |
| `p2_hardened_auth/far_campaign_1e6_20260821.log` | `b82f60d81c5b52b38cbd251128dd2deb5e1bcb3300fa9213b96fc608cb8c8de5` |  |
| `p2_hardened_auth/far_campaign_1e7_20260821.log` | `6c7227dba85808d8b68f3edb5a3ab9d34c789481a62604c6c815914dc6f5ea2d` |  |
| `p2_hardened_auth/far_campaign_1e8_20260821.log` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |  |
| `p2_hardened_auth/far_v3_1e6_20260821.log` | `503a11a5040dfc2ec9de737b1db30b6073a79a86dde774c030f9d35566cae25c` |  |
| `p2_hardened_auth/far_v4_keyed_1e7_20260822.log` | `b361bba63f193cc2f18d9c615093edd18ba54718a5b868fc675e925a1a12aaab` |  |
| `p2_hardened_auth/far_v4_keyed_20260821.log` | `cbde581d367c934aca0622bc8ab7ed573ea74fa9dbc89fe2c6e57acf3d347426` |  |
| `p2_hardened_auth/mcl_auth_avalanche.cpp` | `ee252092357b01650faf373a33a54a2cc216127c4b6c5873bc542cfd54e8367d` |  |
| `p2_hardened_auth/mcl_auth_far_campaign.cpp` | `84bf48c3bf248952d2a44f0aa4beaf80c7037db63f2362155d8dca132fc28326` |  |
| `p2_hardened_auth/mcl_auth_far_v4_keyed.cpp` | `f2c373b592fc8157b830c74dea2e0d5c8be06e5976180aa6de876fd5549fbe44` |  |
| `p2_hardened_auth/mcl_auth_hardened.cpp` | `8823800937297dafcbdd0cdfb04f00db46668e66859e936046f48d8d6da0a1cc` |  |
| `p2_hardened_auth/mcl_engine_sensitivity.cpp` | `5f89de5413a606bde798194fa20a7f67f2e956b5292e4b45e46b524f13385564` |  |
| `p2_hardened_auth/results_20260821.txt` | `bf65fa9fc185d4f9e9e22d5f47374bb0e04908f6978944b208d5604b079fc905` |  |

### p5_hardened_txauth  (23 files)

| File | SHA-256 | Note |
|---|---|---|
| `p5_hardened_txauth/README.md` | `8a1de8753500660eff988ef833b4ca8ee6406cb0bab853f61ecf2ff4d0a2428b` | p5_hardened_txauth — مسار الورقة 5 المصلَّد (v2) + بطاريته الكاملة |
| `p5_hardened_txauth/_v311_backup_mcl_txauth_v3_battery_q30.cpp.txt` | `e825f1daaa6f7053a751fe0242a13d805f88b1ef40e87d22185266fab0006a29` |  |
| `p5_hardened_txauth/_v31_backup_mcl_txauth_v3_battery.cpp.txt` | `f9ac7d3e2e8e12a83ff1e1aa61cccdc1fb0dd00f56c1d8a1c564ea7b75a40e30` |  |
| `p5_hardened_txauth/d1_collision_20260821.log` | `4c59d1fe0824525316554bce3cd6d7aa72aca0700bca51235ce545dfcf47d087` |  |
| `p5_hardened_txauth/mcl_d1_collision.cpp` | `6eedb6294d75d9020401f1f026e5806af56267e5d267a05fb0467e0673ae3b88` |  |
| `p5_hardened_txauth/mcl_txauth_hardened.cpp` | `1c8d66d063e18fb1b2673a55073de00da149301ffbf03e5be8354cb2d538af04` |  |
| `p5_hardened_txauth/mcl_txauth_v3_battery.cpp` | `343fd97fa05aea9a445ceadb7d5123072e2b8e593274b44f88ecf8a1313875f0` |  |
| `p5_hardened_txauth/mcl_txauth_v3_battery_q30.cpp` | `9cd21e45c0be89cc9971bddba9afc2df4ff5ace3c8e936801a10b76c6b08fe78` |  |
| `p5_hardened_txauth/mcl_txauth_v3_claim4.cpp` | `32f117afaf93314f7d92edf8b274b2eb4571974b3a5286b23b7b6a3cdace4c97` |  |
| `p5_hardened_txauth/quiet_rerun_conditions_20260905.txt` | `a69fada04a9ae7f8780736449d226deadcd09cb89aa245a07af4fa7a53fccf4d` |  |
| `p5_hardened_txauth/quiet_rerun_double_conditions_20260905.txt` | `07d01208233a6b903c05ff4822c067f639cdd2a8bd0c233fd71e2d63e432cd1a` |  |
| `p5_hardened_txauth/results_20260821.txt` | `c127d31be9ac8758c02dbd7e729e662d7f8f65ff7b533f4782d8b934824f2ed8` |  |
| `p5_hardened_txauth/results_v32_double_combiner_20260905.txt` | `e6107d815281ed89edc3d3e57be67b9ab05b79ca45e353e95948b44eca567b84` |  |
| `p5_hardened_txauth/results_v32_double_native_20260905.txt` | `7d6d2b754f9aa5ca9416228ccdd02b22be928281343a8c09d265bcad1dfe0b26` |  |
| `p5_hardened_txauth/results_v32_q30_combiner_arm64_20260905.txt` | `4c077575cbd8a9b312eac4b8faf42e2c0017d20eec74c5c3bd6c9f8130626563` |  |
| `p5_hardened_txauth/results_v32_q30_native_arm64_20260905.txt` | `388d9044a2d19bd62ea5462aec759595477ee767c513fc53972297b6b9e7360e` |  |
| `p5_hardened_txauth/results_v32_q30_native_x86_64_20260905.txt` | `a6f78d47b288987da20650b1354a856ad5fcad33226d1ce42fa5e7366375246d` |  |
| `p5_hardened_txauth/results_v3_20260821.txt` | `0329d38aa78a2552f24bda89cfa8b1a9c2a4e7d9f25da1885177416518cb4cb7` |  |
| `p5_hardened_txauth/results_v3_battery_20260821.txt` | `3facb57c4d38217a7e50c2052d8b413e32e42b767780131101c58f241c18c614` |  |
| `p5_hardened_txauth/results_v3_battery_q30_v8.1.3_20260904.txt` | `fc19e07e64273c6bd431480710575b21d7f7c0170ea0f797908fda0586344ef1` |  |
| `p5_hardened_txauth/results_v3_battery_q30_v8.1.3_20260905_arm64.txt` | `e063f867f69b6fe135d0bcdd9249763b867d85f01ffa28c857920016b22c5add` |  |
| `p5_hardened_txauth/results_v3_battery_q30_v8.1.3_20260905_x86_64.txt` | `0b7b9ebbe7a1890d1f7df10fe0116f18e6b815abecd693a4136e6c075075c9bb` |  |
| `p5_hardened_txauth/results_v3_battery_v8.1.3_20260904.txt` | `abe5f6a26a232ded5e58209bec2ac027cbd9578545d9ee2ec20a8fb510a6b08c` |  |

### M1_M2_apple_verification  (40 files)

| File | SHA-256 | Note |
|---|---|---|
| `M1_M2_apple_verification/NIST_STS_CAMPAIGN_README_20260721.md` | `610ed641ec7022923913a8f3c75a069f1c86335d61d3733740574c091b189d1b` | NIST SP 800-22 Full Campaign — Doc ID MCL-NIST-STS-2026-0721-001 |
| `M1_M2_apple_verification/PAPER2_L2_VERIFY_RESULTS.md` | `ea19992131a69107115f9cc96f940ab4e6067f9c0e82270cbd3ff556016e390c` | Paper-2 L2 re-verification — definitive results (2026-07-06) |
| `M1_M2_apple_verification/README.md` | `52bc35cd7e7b69acbbb01cc4eb9904b285e469ac0c41510b5d643be0335df985` | M1/M2 Apple-libm Verification — Paper 1 §III.B.3 |
| `M1_M2_apple_verification/SHA256SUMS` | `e2f70228448bb423a985672e31d6e68154720e3a193cfc03128d11e48a6e6507` |  |
| `M1_M2_apple_verification/_engine_equivalence_20260916/ENGINE_EQUIVALENCE_20260916.md` | `c632d479dc808a877c67246200ab42ae8284a67b846a188ed697a4cf721a46a3` | Engine-equivalence check for the M1_M2 tools — v6.0.0 (engine of record) vs v8.1.3 (repository root) — 2026-09 |
| `M1_M2_apple_verification/bifsweep_coarse_apple_20260719.csv` | `a96837f02b60f6fe9669cb65d8156ab4ca9ef0d56934532d6908226efa2d3fcb` |  |
| `M1_M2_apple_verification/bifsweep_fine_apple_20260719.csv` | `ebd7d1a3fbc58dc7952eda3e1148df94fb011de69eeb9a69e2737be3d6e73376` |  |
| `M1_M2_apple_verification/bytezone_scan_apple_20260704.log` | `39eebdc634d11186de5331e7759cce4f9e1b3f7b725b92b8a7aa3f79cf7094fb` |  |
| `M1_M2_apple_verification/detj_verify_apple_20260703.log` | `6e498469a9c65a0f51b782f7a3792f4003c82097d07b1d14b9e649858aa30ee2` |  |
| `M1_M2_apple_verification/fig1_arnold_sweep_apple_20260817.csv` | `c3e5c1a81eb4fe7d6d4680d221b9ec76008fe621ec560d68191f438761de57e4` |  |
| `M1_M2_apple_verification/hd_throughput_apple_20260817.log` | `79e302bc35e2da6b6d02cfbaf7adf97b501672c2e46d488e1e35e434f30b7a44` |  |
| `M1_M2_apple_verification/make_paper3_fig1_20260817.py` | `ae6215ca8a5738ebea5c86335d8848ae3d62587fc2a7e25396092b15a2939283` |  |
| `M1_M2_apple_verification/mcl_bifurcation_sweep.cpp` | `aac797454872144d50443765b845b19a538791a3fa9d715f0832abcf4a2de449` |  |
| `M1_M2_apple_verification/mcl_bytezone_scan.cpp` | `0447cdc839b82331dbb1a5ef720a506b6e38d74eefa855d2a1940fd011ba3ef9` |  |
| `M1_M2_apple_verification/mcl_detj_verify.cpp` | `1530b2b6f582286cf83f695cbf84002cf83f416b31575ecb2945a918cb109d0a` |  |
| `M1_M2_apple_verification/mcl_fig1_arnold_sweep.cpp` | `e409460053085fb392c45ee033070f0905b60e46c1ca0f2a4691fc2a732cc7da` |  |
| `M1_M2_apple_verification/mcl_hd_throughput.cpp` | `7d922b50ea6b6d041f8a8a5a978f4dce48757d0352b6b2fff9f7c22320caebd4` |  |
| `M1_M2_apple_verification/mcl_nist_stream.cpp` | `c1cecae06e30786b0f66b4e669d580125858366aafdb52a8ac569708c5f7c155` |  |
| `M1_M2_apple_verification/mcl_paper2_L2_verify.cpp` | `f3bc80c356965a9e88c230e7d3583200a8e8cb1dc796ede8b0b4fe05318dcc73` |  |
| `M1_M2_apple_verification/mcl_perbit_msb_flank.cpp` | `d79aea882d981d3116c3fbdfae377432d6f0ccc84df025418d635964436ae6da` |  |
| `M1_M2_apple_verification/mcl_psi_equidist.cpp` | `8cd8f894b28e5fbf0346801c740fb7e74bf660c92dd7f39306d7289241471e0b` |  |
| `M1_M2_apple_verification/mcl_safezone_holdout.cpp` | `9e534cc4fc8793742fb09db10ec51a79fb0757f2adef01013ac68e9706b533da` |  |
| `M1_M2_apple_verification/mcl_single_osc_zone.cpp` | `4144e9a237dd4c39904d38e9f7ced13c5b7787826b781208fc4a4aa1732c63d1` |  |
| `M1_M2_apple_verification/mcl_table10_multiseed.cpp` | `2f79e7775463d748fafff77920a8f19f00ae49cb9ca0e1265a562b62d6191a74` |  |
| `M1_M2_apple_verification/mcl_tau_int.cpp` | `ed61e35a96b5b262aa66d8be1a94fb2e0efbe69964445e91d3c3b85b131225fd` |  |
| `M1_M2_apple_verification/nist_sts_assess_run_20260721.log` | `343b4876d4509d6a66369ee94d2c2947965471a35ff79fd0ffbbe74a9947d36f` |  |
| `M1_M2_apple_verification/nist_sts_experiments_apple_20260721.zip` | `44ecfc6ff97ad9a66b269ca4da2ebfc3fddf669afab86d68d89a8670bfd32ced` |  |
| `M1_M2_apple_verification/nist_sts_finalAnalysisReport_apple_20260721.txt` | `3a27f50d866d544b487423996089a2989a02cd980b70e062d9a12ffbd467cf8d` |  |
| `M1_M2_apple_verification/paper2_L2_verify_apple_20260706.log` | `1133ba55c11544c04f64b4db1631a0da3833caca63a5264569f8305aaf4df09c` |  |
| `M1_M2_apple_verification/perbit_msbflank_apple_20260719.log` | `56e025e3d3564ab50984397467ea151a3738c2ffb26fe82e46faf9ad3cf9be4f` |  |
| `M1_M2_apple_verification/perbit_msbflank_stride2_apple_20260719.log` | `57ebb0ccd9ae2a2f5e3c16b52810796a6fc7ec126054c5027eaa7453fd939fb2` |  |
| `M1_M2_apple_verification/psi_equidist_apple_20260703.log` | `2662f48f1950b9a3114e712595012ed6344cfffa90cab5d2e67cef008c2a689c` |  |
| `M1_M2_apple_verification/safezone_holdout_canonical_apple_20260719.log` | `e70f1cacbd1cdd3bc36e03bde8e6c688144455aa53e53c974d1406479c543144` |  |
| `M1_M2_apple_verification/safezone_holdout_seed55129803364771_apple_20260719.log` | `109dd17d9c53ead8a598f965bede96ce514d0b07ba1cc68f19243dc082d0a1f8` |  |
| `M1_M2_apple_verification/safezone_holdout_seed70466644885213_apple_20260719.log` | `814af15ce1f2a00712d87448e57bf7655e0c3d7831ee16e0a8a1c0b35c63a93c` |  |
| `M1_M2_apple_verification/safezone_holdout_seed89623471905588_apple_20260719.log` | `8ca73dca5e8d5d1e5f38a932757b7072723bdd4f978a4ae16b43eccf9d6e04b6` |  |
| `M1_M2_apple_verification/safezone_scan_canonical_apple_20260719.csv` | `f345c12206de72adbe7daba0ab0b552bc01be49c39b0942db8e5370aca42c7ce` |  |
| `M1_M2_apple_verification/single_osc_zone_apple_20260703.log` | `9f4698e4048fdebe13ec10037d31cf36d3ce71ecba2d2936b743b163762926f7` |  |
| `M1_M2_apple_verification/table10_multiseed_apple_20260817.log` | `1c8407d6f86951b02e056d34b89e6132e6736c2425c02721348a648a524ac8e1` |  |
| `M1_M2_apple_verification/tau_int_qr_apple_20260719.log` | `cb65b972ec8663c3e47b43a69601cc145e63162126c49c00c597eea5510bac18` |  |

### P3_CrossPrediction  (4 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_CrossPrediction/XPRED_RECORD_20260822.md` | `d51afa3919a1479787de8552b96f33676591e6f6dbe2cf1a9267f91082d525d3` | تجربة التنبؤ المتقاطع (R²) — الورقة 3 §IV — 2026-08-22 |
| `P3_CrossPrediction/mcl_gen_series.cpp` | `02e15ef638b9da0180b57a40daf27edb61b432e6bfccee7af6fe1240c1316df8` |  |
| `P3_CrossPrediction/xpred.py` | `c1654e6aee3d69b62296be0476de104bc5f9c0aa99aacf0f6a4efb293de0401a` |  |
| `P3_CrossPrediction/xpred_sweep_20260822.log` | `26b870062dfa5657a1be20ba6f18d1f46265db80772b811c392ff58ae474ffc7` |  |

### Verification_Suite  (30 files)

| File | SHA-256 | Note |
|---|---|---|
| `Verification_Suite/README.md` | `562c8a6fbd78661d363e9c5461deedd7b6973c9c71d4df8475e01987455f0db0` | Verification_Suite — legacy science/verification tests |
| `Verification_Suite/bench_diagnose.cpp` | `5852bf88575ff5011cd098b40a00ad14de278713bb50cafa31a6ecc0c726b330` |  |
| `Verification_Suite/mcl_auth_verify.cpp` | `c4b229a99b5808fc2ce84aba99c6e0b400afa15d80156f309eb9b76b14b6980b` |  |
| `Verification_Suite/mcl_burnin_sweep.cpp` | `24982c1da2f41cc85d6e1f69e303b0f1c7fd934a832b3cc8d887cc2562ab1207` |  |
| `Verification_Suite/mcl_decimation_sweep.cpp` | `758875ed7676185f9bc3340982ccc8a0e3f4e94d5850cd6b2ac481f175223df6` |  |
| `Verification_Suite/mcl_gs_jacobi_independence.cpp` | `58a61680ce293f34a455367644fee005adb1fcabada260fd05b08164a34451ae` |  |
| `Verification_Suite/mcl_hex7_proto.cpp` | `2cc74f70b92b6074140c8e350ed72f4e45eb1f808d480c7aac2024a2fe83e5a8` |  |
| `Verification_Suite/mcl_hop_unified.cpp` | `5831e5ffd3367f46ecb10baa687c97b96f45ffbca71a2adb4b4c2499aef5f9ee` |  |
| `Verification_Suite/mcl_k_independence.cpp` | `51bc223d5c403654fe029d8e329098420bbe2bbd4897aefd1834b03bfa6c3dad` |  |
| `Verification_Suite/mcl_lyap_ratio.cpp` | `31fb90c2ff7f9aaa291172a5b85bfaa59a8a73d3bfbed2a6d4c7d42deba9dde6` |  |
| `Verification_Suite/mcl_numerical_verify.cpp` | `3e4e456f55eb096b142ab79b06102dd61648d4418272fc8b5e7ae73708762b73` |  |
| `Verification_Suite/mcl_paper1_extras.cpp` | `49b357bbfedded5dabace02091b6ef0621c4c42aedbcf64a22ef05e808f7c9bb` |  |
| `Verification_Suite/mcl_safe_zone_per_osc.cpp` | `6a21501462b6791516c74d29827655c6e106fb9a30184bec4642a80b880bdac1` |  |
| `Verification_Suite/mcl_t3_t4_unified.cpp` | `74506b0b308bc7ac3b2ea98a5e1dabda7cd72c5f829bae80f0f8bf90def7758f` |  |
| `Verification_Suite/mcl_topology_generalization.cpp` | `bd6f0366f865dca0a18f7af2d1689b702567a56e30b5f4e5b9a5cc28193fac60` |  |
| `Verification_Suite/results/bench_diagnose.txt` | `f43a5e820d7120f0863306d3a33886335ae4587c9c215d7f5d1f9d913a21f567` |  |
| `Verification_Suite/results/mcl_auth_verify.txt` | `9c292cf8f158ff1774699328ce9bed7744380108e85029f370ae2568efad57d6` |  |
| `Verification_Suite/results/mcl_burnin_sweep.txt` | `8976b0ac77497ab4fff887c12b3d2d5bac22a11bc1e6652c6633cf23898fdb52` |  |
| `Verification_Suite/results/mcl_decimation_sweep.txt` | `d383c3c3943dc5ef5a8ee56a383c9d3be208ef022160227beefcdba118e451c0` |  |
| `Verification_Suite/results/mcl_gs_jacobi_independence.txt` | `df40a4b16052e5f5a2d733cfdab0001defd16ce1c4f0f1ff8e744c694ed49010` |  |
| `Verification_Suite/results/mcl_hex7_proto.txt` | `114ad8215f165572d0345861c5682e38324e882323db03b4ae6c3c6f43afc7f0` |  |
| `Verification_Suite/results/mcl_hop_unified.txt` | `378bff18554102a7a1a3761586049f06e07acfbc220af4d6264e76080837f5f1` |  |
| `Verification_Suite/results/mcl_hop_unified_v6.0.0_20260526.txt` | `93126ee31ddee46bc0fefb8ea1660eaa3875809462f8fdd70b56612a248c76e2` |  |
| `Verification_Suite/results/mcl_k_independence.txt` | `163ef48b7d19a6607e3a738c7f67e657f3d505c3d69f5bb9d34ef853a9fcecca` |  |
| `Verification_Suite/results/mcl_lyap_ratio.txt` | `f6864c077fa4a7d0d944930833b9616d3c0cd2de491d6a7ef18b0c36384791d9` |  |
| `Verification_Suite/results/mcl_numerical_verify.txt` | `4d0be606100e3debd45f0823ae1f6c4dc7d0c00b3c495539e635005b099ec33f` |  |
| `Verification_Suite/results/mcl_paper1_extras.txt` | `b9e7d618819929eca6c195650eb3701581fdff637198900b2f5bbafe4e5667a2` |  |
| `Verification_Suite/results/mcl_safe_zone_per_osc.txt` | `9a8dce33fd436bd9bc132216c10e4197bf04bdee24ad6589a1df4df79fe51ce7` |  |
| `Verification_Suite/results/mcl_t3_t4_unified.txt` | `79b24c7da52b702242ef1f9ea236aaf9707ba9cd311d4355fa9a7c5bf1940efb` |  |
| `Verification_Suite/results/mcl_topology_generalization.txt` | `b76875b733f343273b22cc4f017a93d5867f1641c5a9fb953c8ef0dcd9cc3256` |  |

### Layer_Combiner  (4 files)

| File | SHA-256 | Note |
|---|---|---|
| `Layer_Combiner/README.md` | `e8729b9797c821d337ab6f6d587294f2c71ffa48803ff9ab9c17665581543de4` | Layer_Combiner — robust-combiner (non-degradation) demonstration |
| `Layer_Combiner/RESULTS.txt` | `b876d83d935c0cfa5cc4b398ff8bd3343082de459947f085a9f16e4f7d09cd64` |  |
| `Layer_Combiner/combiner_analysis.py` | `d468a1f6938d4e28a23026683677de7aef5552f17b0db596290a90a233f1946c` |  |
| `Layer_Combiner/gen_mcl_ks.cpp` | `1d49fef7bd51c4aaf01596a236eed5190ccb02da12c52aa11731b1260f4498b4` |  |

### .github  (6 files)

| File | SHA-256 | Note |
|---|---|---|
| `.github/CODEOWNERS` | `6133bc4953b614d8e27bd1f80ff70ce6ee950b42ca7b69575c87055f074e1f3a` |  |
| `.github/FUNDING.yml` | `cc4f169ae7db0badb280b2fb4df7a8eda1a13230ad71361631d0212aee8603de` |  |
| `.github/ISSUE_TEMPLATE/bug_report.md` | `31b8e41bf00e19f1e56a208f52cc69ac5fc7b95abc761cdd772460374bfefb1c` |  |
| `.github/ISSUE_TEMPLATE/config.yml` | `d340846d2b30223ccc240d67884257f063a3d37a7ad717dbfc09a761e7e8686a` |  |
| `.github/ISSUE_TEMPLATE/feature_request.md` | `414a473637508e5ed942a45dea1e6525b893dcaa6c1fa1537e4955631b037e89` |  |
| `.github/PULL_REQUEST_TEMPLATE.md` | `f321df6f7cb136eef4bd43c28b652a1af8e86173785ffebf13f9a71622145043` | Description |

### .well-known  (1 files)

| File | SHA-256 | Note |
|---|---|---|
| `.well-known/security.txt` | `858f51b1a2acda09092f5f2762815e90cfc23bd9ad86748a2e9b655ca6715bce` |  |

### LICENSES  (2 files)

| File | SHA-256 | Note |
|---|---|---|
| `LICENSES/LicenseRef-MCL-Security-Research-Grant.txt` | `24a8609549aec66bbb18126a015e3513332bc665b7dd1154501707e70ac816e3` |  |
| `LICENSES/PolyForm-Noncommercial-1.0.0.txt` | `ffcca38841adb694b6f380647e15f17c446a4d1656fed51a1e2041d064c94cc8` |  |

### P1_CSF_Measurements_20260905  (110 files)

| File | SHA-256 | Note |
|---|---|---|
| `P1_CSF_Measurements_20260905/README.md` | `9eb2082e8e90e48ac7fecd4e04ea71b06be7f0a21f200162a8a65a183368be67` | Paper 1 — cross-system Safe-Zone, logistic cycle structure and XOR-healing controls (2026-09-05/06) |
| `P1_CSF_Measurements_20260905/RECORD_P1_CSF_MEASUREMENTS_20260905.md` | `2646438f8571bb5e3a6775f3a1b4ae4bd341f02c5530b754d130d7b394c9bb72` | RECORD — P1 CS&F revision measurements · 2026-09-05 / audited and re-run canonically 2026-09-06 |
| `P1_CSF_Measurements_20260905/SHA256SUMS` | `d2bc3992d1dd7b564dd2b203b12a9e8a4ba755f3f5939c388a75d4c97bcbb5d2` |  |
| `P1_CSF_Measurements_20260905/attractor_dump_seed12345678901234_M1Pro_20260905.log` | `bd7274ef87c8f0c9101af6a7bb584d0a1190ca7b58e1456ca771d85a537cf226` |  |
| `P1_CSF_Measurements_20260905/attractor_points_12345678901234.csv` | `c67515ab5f7763be605543fb7a71a10213c724c8b7198bb02f9475f2bea42d15` |  |
| `P1_CSF_Measurements_20260905/attractor_points_98765432109876.csv` | `d5240f825853f3526fdc86858a3d762f403125aff94ff082644ec30d647740f4` |  |
| `P1_CSF_Measurements_20260905/audit_cycle_MCL_seed12345678901234.log` | `050b9bb7eb32563529d1fe612d7f3cf5b64caf31c6e4e1e874425f7b9dc417a3` |  |
| `P1_CSF_Measurements_20260905/audit_cycle_std_seed12345678901234.log` | `222b5681018b0680a6b8242d81c4d7fec0b4bc5837c1afece64671b9afda3950` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.1.log` | `2162e29b59dfd47812bcc882bbd646a3c00376f9b0ebb09d55ce6f46bdd18fdd` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.123456789.log` | `d4da2280d19aa03c3f1b3279426509990520a28c278cba69ddcfea35af1a83e3` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.2.log` | `c3f5b5d199f1ee934636d83c0dc152c0796936f304a4dbb72eb5a4a6efced0ff` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.3.log` | `77a6ce3371a8cb0317cbe190e8582c7ad61453a69c8995b4d7a24a5abc81d0a3` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.314159265.log` | `110582e9a84cc7391b16a8873e7b0cac041c4ed8eeea49e25ff90c8e05da853d` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.4.log` | `9d3e9d686736575d39952ef1f59fcc04b634771d162e2b32d34bb04008e0e041` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.6.log` | `08132837629a826fd2375cdd955969b985ffcc187bf21a2fa80003c43f70add7` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.7.log` | `9f0e5a801674262df94454d6e59312dace22b112a6683d2e6f12f0a4d434878a` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.8.log` | `5eefeb3eb663dd3fc24f2603fabc7db40ee99d87407ce2908041110029916c3d` |  |
| `P1_CSF_Measurements_20260905/audit_logistic_x0_0.9.log` | `593a7df6454473514315343533a48fc39f37d5f316d719344071cdf5a999c754` |  |
| `P1_CSF_Measurements_20260905/audit_map4_MCL_seed12345678901234.log` | `f796b4dc30ddd58f46039ec768d84bf44aa171d1f774e0a0d08eab588b305759` |  |
| `P1_CSF_Measurements_20260905/audit_nofma_map0_seed12345678901234.log` | `88858641bb96c3a72da393ea790f952ae107cbbe41291ac99cc27d916050a3a9` |  |
| `P1_CSF_Measurements_20260905/audit_nofma_map1_seed12345678901234.log` | `d5fdf7f90aa6461c28ceb9b2a0ba5364bd00e303874a0a0cdb0233f33c4950cf` |  |
| `P1_CSF_Measurements_20260905/audit_nofma_map2_seed12345678901234.log` | `a37a62de5c806bed28e0a07c60f213c8a99c0dd75d17e5414a10531b108a72e4` |  |
| `P1_CSF_Measurements_20260905/audit_nofma_xor0_seed12345678901234.log` | `97e7d6c950a019d6ef5c833fcdf96375625427c24b77772350172edf2323b47d` |  |
| `P1_CSF_Measurements_20260905/audit_nofma_xor1_seed12345678901234.log` | `21e457c2c91a8d35c2783da7dcdac7932e6af951d83c182cfd75db1b915cb3f5` |  |
| `P1_CSF_Measurements_20260905/audit_nofma_xor4_seed12345678901234.log` | `d79a1aa70939414e1a54eb3808fd556f406287176ceb3076f8e71441014eaf87` |  |
| `P1_CSF_Measurements_20260905/audit_python_brent.log` | `f7c5699b2a11d21f8a87380b12d5970781ff80992e19bb2d1002e0a5a62558f5` |  |
| `P1_CSF_Measurements_20260905/brent_logistic_check.py` | `d55d0f6755cbb1356f7e36e4d6bf708ae68d5228a721c29d4d0654ace99875c1` |  |
| `P1_CSF_Measurements_20260905/density128_12345678901234.csv` | `36c18ed663e74629f9bed99d3648df2096dd33bb47a6b57240acafd39cc8225c` |  |
| `P1_CSF_Measurements_20260905/density32_12345678901234.csv` | `b1e55b8b0de1c5f70a73d09363cf0c3ac5ce29b21e1e301bcc582eb4433eace1` |  |
| `P1_CSF_Measurements_20260905/density64_12345678901234.csv` | `438a6e0c8878740bbd5a70a2f983e810d54fc7978f3f627ae62f9bba8f20d034` |  |
| `P1_CSF_Measurements_20260905/density64_98765432109876.csv` | `bf9fbf10503d43401f60d1851777cf711bd83fd75af966d19dc6c2c44b5930b1` |  |
| `P1_CSF_Measurements_20260905/logistic_cycles_M1Pro_20260905.log` | `128dce25a790c26331ea68f1780c728b7aa810c1969e0d2cb03c880feb8e468c` |  |
| `P1_CSF_Measurements_20260905/mcl_attractor_dump.cpp` | `5e7a97277091226d2f0450d190481346d3d070692669c29b1010fc674ce3bfd3` |  |
| `P1_CSF_Measurements_20260905/mcl_core.hpp` | `32aa22f032d6495a5d8baa602a4662cf46477ad48cf3fc7e864049138db966d3` |  |
| `P1_CSF_Measurements_20260905/mcl_cycle_search.cpp` | `073a2757ce0f995eee9acfd604c4d0975b7b4b68d2c261e3b88d81d847cf1f0e` |  |
| `P1_CSF_Measurements_20260905/mcl_logistic_cycle.cpp` | `e29cad0cdba4044d313b3cf64e16ffba9b3d30fba7ac16abb5ae45af3ad8fe8f` |  |
| `P1_CSF_Measurements_20260905/mcl_thirdmap_safezone.cpp` | `c802eae29364586e8b1dac9c8d4d9d664acf9285f904c55fd7e210941ddc5548` |  |
| `P1_CSF_Measurements_20260905/mcl_xor_control.cpp` | `b0108f0f18c8affb98d89ce0daefff96e8f0b161aa318945b8d87b2590fe0bfd` |  |
| `P1_CSF_Measurements_20260905/nofma_logistic_cycles.log` | `a5a773feb2035635109796f15a4d281b9d7a7e3dfa3ef637216496956316aab7` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_cyclefree_seed27182818284590_N8.4e7.log` | `b8185151a2c65883b06a638cbd69d1a0d7a96cbeabd2939d65bdfc90be34159a` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_cyclefree_seed70466644885213_N8.7e7.log` | `57993500a5d17050282aa4c225ac43dcf512c7c32cccb52413abd29100e6f483` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_seed12345678901234.log` | `88858641bb96c3a72da393ea790f952ae107cbbe41291ac99cc27d916050a3a9` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_seed17320508075688.log` | `40cb0ed4fb54f171259fd7dc81915e8fed6c63c0e03ce25eac93be98886c9319` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_seed27182818284590.log` | `420d99bea9422809db076fd777ec398ede621a6083521875ea7e4a3425e6afa6` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_seed31415926535897.log` | `980476c5a3db658f2926093be2995327ec0b7ea6fe39400b015a9be4264fc6ee` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_seed55129803364771.log` | `720228a680be5134256c8e24c5ffaba8d9cc9df65a61c22d813adb9b27d04502` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_seed70466644885213.log` | `8aac1bb1278cb82b724c128f8f71e13234db8a4bc5db9fc8dd587ef551ee5168` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_seed89623471905588.log` | `768e6fdef967c2ada3da2f031ea2ddd4cefb73091063f539eedf365e190f5b78` |  |
| `P1_CSF_Measurements_20260905/nofma_map0_seed98765432109876.log` | `313aa07e64e295c3d4d978880a1f81710f1fcb02c3c6875fd98b097bf40ba809` |  |
| `P1_CSF_Measurements_20260905/nofma_map1_seed12345678901234.log` | `d5fdf7f90aa6461c28ceb9b2a0ba5364bd00e303874a0a0cdb0233f33c4950cf` |  |
| `P1_CSF_Measurements_20260905/nofma_map1_seed55129803364771.log` | `b6302ff387c286ece9f4b6b0e91b9ee5e2ef4ad0f51fa2d0c70f103ef814a23b` |  |
| `P1_CSF_Measurements_20260905/nofma_map1_seed70466644885213.log` | `53824bf6ba2d56c81733d950e81f03c18cb83225a54628259aec03ea7355b9ac` |  |
| `P1_CSF_Measurements_20260905/nofma_map1_seed89623471905588.log` | `ecddcff723a3778d2f26b63caf381fcb3fc11d5a35c03e743a6a3f8aa00c96b6` |  |
| `P1_CSF_Measurements_20260905/nofma_map2_seed12345678901234.log` | `a37a62de5c806bed28e0a07c60f213c8a99c0dd75d17e5414a10531b108a72e4` |  |
| `P1_CSF_Measurements_20260905/nofma_map2_seed55129803364771.log` | `1e98de9648c7e1cc86ee04099243be8e3b4a2bb880b7d053c00d6284403cfa2d` |  |
| `P1_CSF_Measurements_20260905/nofma_map2_seed70466644885213.log` | `7b13809e836f1253a53bbcd0a570fcdf775eb54cf3b9bbf83bcc42f2478121af` |  |
| `P1_CSF_Measurements_20260905/nofma_map2_seed89623471905588.log` | `b0ef79d1c1d7fe7528a391ac1e3e6d7a31b3895d37d492af16b4c7f445ea4e30` |  |
| `P1_CSF_Measurements_20260905/nofma_map3_seed12345678901234.log` | `29bf457b565001ecf64906d28fe7e6ba70924755b11f4ffc19f5c5cdf04b21a3` |  |
| `P1_CSF_Measurements_20260905/nofma_map3_seed55129803364771.log` | `91c9f75a16aa0799b1376838b2c44400da426b29e8f1f1529cfe548e12c65aae` |  |
| `P1_CSF_Measurements_20260905/nofma_map3_seed70466644885213.log` | `916d2b01081f39eb6b6a7272ba69ac03c5b6eaeaa8a29bd8e9a785f75aa3310f` |  |
| `P1_CSF_Measurements_20260905/nofma_map3_seed89623471905588.log` | `cd5b89984ca9e8d05ab88758ae5fcd4dfa8f57be40e9c18534c69e771536e7a6` |  |
| `P1_CSF_Measurements_20260905/nofma_xor0_seed12345678901234.log` | `97e7d6c950a019d6ef5c833fcdf96375625427c24b77772350172edf2323b47d` |  |
| `P1_CSF_Measurements_20260905/nofma_xor0_seed70466644885213.log` | `805995313ba903daeb7b6a50ffa9467a3a176f335fc4be32fa78cf026333d3b8` |  |
| `P1_CSF_Measurements_20260905/nofma_xor1_seed12345678901234.log` | `21e457c2c91a8d35c2783da7dcdac7932e6af951d83c182cfd75db1b915cb3f5` |  |
| `P1_CSF_Measurements_20260905/nofma_xor1_seed70466644885213.log` | `f76b541785bec408aee63305f2b542cfad3ccb89ace2d93290515ca261d89f25` |  |
| `P1_CSF_Measurements_20260905/nofma_xor2_seed12345678901234.log` | `002cd1e89a69fc3b27aca9253b3090f02f8c30551acd3ec9402a4fe14e24ccfd` |  |
| `P1_CSF_Measurements_20260905/nofma_xor2_seed70466644885213.log` | `d289852b326ec861452b78288f5be7b84c1db8fd89f8b0ba48612b1952432085` |  |
| `P1_CSF_Measurements_20260905/nofma_xor3_seed12345678901234.log` | `ec706dce3bc9020403140c146284ae976b859bfb236673bc3b306d3c17107299` |  |
| `P1_CSF_Measurements_20260905/nofma_xor3_seed70466644885213.log` | `7225ba06d0624207824978723440c951bfcbac489681ee5075a329f9dfa7e64f` |  |
| `P1_CSF_Measurements_20260905/nofma_xor4_seed12345678901234.log` | `d79a1aa70939414e1a54eb3808fd556f406287176ceb3076f8e71441014eaf87` |  |
| `P1_CSF_Measurements_20260905/nofma_xor4_seed70466644885213.log` | `ffd07b95705cad8fc339a810681b9fc517f221c62bc68cb8a1cf255781012bd5` |  |
| `P1_CSF_Measurements_20260905/psi1_hist_12345678901234.csv` | `a2f6ba410ee62ffd2100e0c4ecc62b23c0209460097596828bf3d5349df03509` |  |
| `P1_CSF_Measurements_20260905/psi1_hist_98765432109876.csv` | `d361a6feba6e7461e94c20ae21986b915405f1b09025a169caacd86da67a4df1` |  |
| `P1_CSF_Measurements_20260905/run_audit1.sh` | `5249a1dfc9992f9e7ed9d928562a14755ec1919e87f94f5fb5480019f0bb53d6` |  |
| `P1_CSF_Measurements_20260905/run_nofma_campaign.sh` | `a77a544f9398966187244564a04ff2d52dc770b2583745cc2c9f5ba7fa3ed59f` |  |
| `P1_CSF_Measurements_20260905/run_round2.sh` | `3c20221867c7d7a48e1fac3cad86dfd74cfcd79c57e3ac7575bac8b9f95b603f` |  |
| `P1_CSF_Measurements_20260905/run_round3.sh` | `966e7f86d32b2e7aee1a5b2c11c6580cdf0d3738eae7806173dc83eff9e7c7ba` |  |
| `P1_CSF_Measurements_20260905/run_thirdmap_all.sh` | `77db05600d5a05da4427a2c9700befcb3b47c8ac0959fd65299b02225b767ffd` |  |
| `P1_CSF_Measurements_20260905/run_xor.sh` | `c2ae1d0dfee1d8b6ba482fd4a811d220760f11f193ddab679a28450806d223c2` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map0_seed12345678901234_M1Pro_20260905.log` | `3561bd3dd464bfc9b321abe3f44844715f08adbef4963524e12de22889fa8325` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map0_seed17320508075688_M1Pro_20260905.log` | `efd082a0f712b4ac0529c6a2f4d3f451aa333a284a400aa8dcd4dcef126b5a2b` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map0_seed27182818284590_M1Pro_20260905.log` | `c7af278114c0e1d92cf3d1e378739def1f8528c7b81de6cada56f0abbbb28b97` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map0_seed31415926535897_M1Pro_20260905.log` | `bb2e3fab9a9e2963d537425a86623a5368d49a1a311539582fcad3516da4af57` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map0_seed55129803364771_M1Pro_20260905.log` | `5acdac9b9b7f2eb131d0145f429d292de0e586bd952dd38cc23d7c85b96a722b` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map0_seed70466644885213_M1Pro_20260905.log` | `21b40039c409bfec7677c71bc1fccf89fad5e1b2aafd2f808bb84f058b5865bb` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map0_seed89623471905588_M1Pro_20260905.log` | `7a17c27b6b8faac1166fcf7f67b2985e84cfff212ec324e0170a425e54d55926` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map0_seed98765432109876_M1Pro_20260905.log` | `cbb07b873bcfc44ddea56e7524aec98361913657c56fc4b22c75b3f6cb181442` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map1_seed12345678901234_M1Pro_20260905.log` | `73e358985acb3d038d41ad2582e45601ed2306eece7c45d0b45682b81fd7d185` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map1_seed55129803364771_M1Pro_20260905.log` | `25a0779c4849750f870bf559303ab46c062a6184a9e145f14615d7e0d052b060` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map1_seed70466644885213_M1Pro_20260905.log` | `5e340389445930a9888898ebcee42917097346e477cf838b04f73aba536a1bbf` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map1_seed89623471905588_M1Pro_20260905.log` | `af856460c29918c60c5fe8240139e2b268fb3d944634e4bd642783a163e5a656` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map2_seed12345678901234_M1Pro_20260905.log` | `581bee47d70856f40e647a13bc3cc9ddec7fff2d997d369f9030692253dacb2e` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map2_seed55129803364771_M1Pro_20260905.log` | `112de528c11ed299489a10e466566b77b88421e3c2561bb5ea5c77e26416b13f` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map2_seed70466644885213_M1Pro_20260905.log` | `8bd70247017ec81365ad273088b6a74589b2ed91249897a1d0b68dcc600ac81e` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map2_seed89623471905588_M1Pro_20260905.log` | `b922033c74236fa360e2b34fdeef74f4550bca56f298ecfa7511967e76b8382e` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map3_seed12345678901234_M1Pro_20260905.log` | `2a37c54c1ba89c1d74fee5c659fa408845e39581197d148a430f9444406c4c53` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map3_seed55129803364771_M1Pro_20260905.log` | `3211eb3f39927de9955cf47d838da6097e1ba04cee977bd20fa981a89a9b1bc0` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map3_seed70466644885213_M1Pro_20260905.log` | `a9d49434390a6d1cbfc2baa8301e115cc42deb6fe08de7a2e3126fd022a6c311` |  |
| `P1_CSF_Measurements_20260905/thirdmap_map3_seed89623471905588_M1Pro_20260905.log` | `25d82d35a7a0a8b485af2f34c0bbdb420540a3a62619597cffed117b30d19a9e` |  |
| `P1_CSF_Measurements_20260905/x0_hex.cpp` | `8935685f648607d1efe4bb691ab2d0cf5071d89025a6a9b9cd579bd2a4c48df1` |  |
| `P1_CSF_Measurements_20260905/xorctl_case0_seed12345678901234_M1Pro_20260905.log` | `97e7d6c950a019d6ef5c833fcdf96375625427c24b77772350172edf2323b47d` |  |
| `P1_CSF_Measurements_20260905/xorctl_case0_seed70466644885213_M1Pro_20260905.log` | `805995313ba903daeb7b6a50ffa9467a3a176f335fc4be32fa78cf026333d3b8` |  |
| `P1_CSF_Measurements_20260905/xorctl_case1_seed12345678901234_M1Pro_20260905.log` | `21e457c2c91a8d35c2783da7dcdac7932e6af951d83c182cfd75db1b915cb3f5` |  |
| `P1_CSF_Measurements_20260905/xorctl_case1_seed70466644885213_M1Pro_20260905.log` | `f76b541785bec408aee63305f2b542cfad3ccb89ace2d93290515ca261d89f25` |  |
| `P1_CSF_Measurements_20260905/xorctl_case2_seed12345678901234_M1Pro_20260905.log` | `002cd1e89a69fc3b27aca9253b3090f02f8c30551acd3ec9402a4fe14e24ccfd` |  |
| `P1_CSF_Measurements_20260905/xorctl_case2_seed70466644885213_M1Pro_20260905.log` | `d289852b326ec861452b78288f5be7b84c1db8fd89f8b0ba48612b1952432085` |  |
| `P1_CSF_Measurements_20260905/xorctl_case3_seed12345678901234_M1Pro_20260905.log` | `ec706dce3bc9020403140c146284ae976b859bfb236673bc3b306d3c17107299` |  |
| `P1_CSF_Measurements_20260905/xorctl_case3_seed70466644885213_M1Pro_20260905.log` | `7225ba06d0624207824978723440c951bfcbac489681ee5075a329f9dfa7e64f` |  |
| `P1_CSF_Measurements_20260905/xorctl_case4_seed12345678901234_M1Pro_20260905.log` | `d79a1aa70939414e1a54eb3808fd556f406287176ceb3076f8e71441014eaf87` |  |
| `P1_CSF_Measurements_20260905/xorctl_case4_seed70466644885213_M1Pro_20260905.log` | `ffd07b95705cad8fc339a810681b9fc517f221c62bc68cb8a1cf255781012bd5` |  |

### P1_ReviewMeasurements_20260907  (8 files)

| File | SHA-256 | Note |
|---|---|---|
| `P1_ReviewMeasurements_20260907/README.md` | `5f5037000a9842052f91827cfc968dbda215390641edb1af9bcecdac79b62c39` | Paper 1 — review measurements, 2026-09-07 |
| `P1_ReviewMeasurements_20260907/RECORD_P1_REVIEW_MEASUREMENTS_20260907.md` | `298a1938c0bdb6870e6e2b105834ffe2592cd32437f5779fd461d10a60de3b42` | Paper 1 — review measurements, 2026-09-07 |
| `P1_ReviewMeasurements_20260907/SHA256SUMS` | `3f1fa6853b7ad5c8d47d825baa7ef4a365a5e7a2ed243d29e578e16cfeaa842f` |  |
| `P1_ReviewMeasurements_20260907/goldilocks_outbit_apple_20260907.log` | `801543bb98798fa599da612749e67757c625c27ce315c2ffc465ffb02f960f24` |  |
| `P1_ReviewMeasurements_20260907/mcl_core.hpp` | `32aa22f032d6495a5d8baa602a4662cf46477ad48cf3fc7e864049138db966d3` |  |
| `P1_ReviewMeasurements_20260907/mcl_p1_goldilocks_outbit.cpp` | `5ab5f01b26b612d3d2fccd6c1579e1e58379243cb30ea8e8d33bb81c180cc3da` |  |
| `P1_ReviewMeasurements_20260907/mcl_p1_table3_lambda.cpp` | `6450ab3c6397f1a312d0995d2314a008d9735f4aa67666a8f215cf7cc353dc3d` |  |
| `P1_ReviewMeasurements_20260907/table3_lambda_apple_20260907.log` | `8f35ba7153871d5262d173395c2f79f07d7570d1afd0342a627a0e3a78c23171` |  |

### P1_ReviewMeasurements_20260909  (5 files)

| File | SHA-256 | Note |
|---|---|---|
| `P1_ReviewMeasurements_20260909/README.md` | `2dc0c4723f14290c7c5b8a851e64a495af39870a527ef616719f8188727c1208` | P1_ReviewMeasurements_20260909 — Paper 1, external review #2 (item ت-37) |
| `P1_ReviewMeasurements_20260909/SHA256SUMS` | `4f9adefc2c70447c0f5de05ba5184bbeab4a1ca2ce9b1e28a86536b850e2ec95` |  |
| `P1_ReviewMeasurements_20260909/goldbit_segments_apple_20260909.log` | `be4da17ec24469f3f14d122996854c46a6b016df1262c39e9fd34fc5c50717ce` |  |
| `P1_ReviewMeasurements_20260909/mcl_core.hpp` | `32aa22f032d6495a5d8baa602a4662cf46477ad48cf3fc7e864049138db966d3` |  |
| `P1_ReviewMeasurements_20260909/mcl_p1_goldbit_segments.cpp` | `10b10e25cad5e7b05d6da5c5b83a767434428f4656a34522abc60c5b47516706` |  |

### P1_ReviewMeasurements_20260909b  (9 files)

| File | SHA-256 | Note |
|---|---|---|
| `P1_ReviewMeasurements_20260909b/README.md` | `08db61b17bdc5db69cb7ec401c8e683c11c410586eeda5cf452d0bed6c8ef4aa` | P1_ReviewMeasurements_20260909b — Paper 1, external review #5 (item ت-49) |
| `P1_ReviewMeasurements_20260909b/SHA256SUMS` | `227ae0c3080df448d23822ed753ed2e062281cbd9f6832ad21d6328c30e4100c` |  |
| `P1_ReviewMeasurements_20260909b/initconv_apple_20260909.log` | `ad0d48ca0dd711a41cee8792de73ca416e5863343d805c3ed7a63b998291bd59` |  |
| `P1_ReviewMeasurements_20260909b/lsb_paradox_apple_20260909.log` | `7a4b9689c9a77ba3b3e82022496c0770f6741205edddd0c900d71ce8455c7b2f` |  |
| `P1_ReviewMeasurements_20260909b/mcl_core.hpp` | `32aa22f032d6495a5d8baa602a4662cf46477ad48cf3fc7e864049138db966d3` |  |
| `P1_ReviewMeasurements_20260909b/mcl_p1_init_convention_scan.cpp` | `a45812e72fa82c3c86d677e5d3d6d01ed8fa3058d5a18a48f80bef106b58c5e4` |  |
| `P1_ReviewMeasurements_20260909b/mcl_p1_lsb_paradox_measure.cpp` | `fe4c6cf9c6dcd40a3aab2e5065a8739a4e4b271f19d013dc919d4877ac7da98e` |  |
| `P1_ReviewMeasurements_20260909b/mcl_p1_singlewindow_bytes.cpp` | `408f13fb5c9e9ceae076841a6b0044e8504740d95fe7e04f4f3b7c5a71568c36` |  |
| `P1_ReviewMeasurements_20260909b/singlewindow_apple_20260909.log` | `28c67568d1879e941228658951c4c17280422ea221f42f478974f1669f533f63` |  |

### P3_DeskRejectMeasurements_20260905  (92 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_DeskRejectMeasurements_20260905/RECORD_P3_DESKREJECT_MEASUREMENTS_20260905.md` | `3d3289756daa6b13e29055eb5d3d46ef984b3ac00d43a003863b12d9341a3496` | Paper 3 — measurements ordered after the PRE desk rejection — 2026-09-05 |
| `P3_DeskRejectMeasurements_20260905/SHA256SUMS` | `f0f9a3892785c714bfbb4aca5f9220a222da46ca2dfd79a086e9066b911dda8c` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/analyze_decorr.py` | `d5d109ff10eb97460ef856eb10128f01f4ea6ab018ed33c8fd22908a8ecee8e9` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/decorr_fit.png` | `3f8f8f434432074aebccfaa8d7b0bbb76509afad1ebd3144c85762cdc90f1a44` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/decorr_fit_table.csv` | `9570186c5e131b8dd04f8cbf58bbafb70cc0b3b4d2d709fc2a5f0fc7079b1661` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/decorr_steps_fig.png` | `28466919c88d76f3757bc3ffe304bd2c95743f1dd347c3a55e8fdf4d4c343c57` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/decorr_time.cpp` | `c3c2a87ea84acf11b67cc9b5eeaea92d6a89e304ec9210c1109fdb1e379c9089` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/plot_decorr_steps.py` | `d895b0ade005abc315d1d69f2e2be9d68cfa7d416aa49fa942b2d61605929ad2` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K12_gs_burnin1e4_steps.csv` | `59768456051cf891075dde222517c3d0d873c3c0c73e7762f6ad797863c81adf` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K12_gs_burnin1e4_summary.csv` | `feca581743a3a6639b4e17287367a27f3e8b491ede47a510716ef17a4df4e460` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K12_gs_steps.csv` | `37a3f6f2c0076ac79428a30222f5c24d5cf6f7a0b8fb51a2268b7d9e33a9da4c` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K12_gs_summary.csv` | `82075b850f1161bf438a88d006b8b7f76c29ff45f97d7cbe7b572e2e415d2abc` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K12_jacobi_steps.csv` | `b5666cd21b2269ee1174dae0ea0d1837c3e99e4f218d54269e026afe89bf9da1` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K12_jacobi_summary.csv` | `3b0df9459fd83d49f324c265c5722b9f61cb3b67173e47b63840f6c8945b3a2c` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K20_gs_steps.csv` | `9d2c1f722608a91c3c661477fd6360614e735f85272e0920f1e51dbb634734ef` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K20_gs_summary.csv` | `e023fe815a752a62f250fcb48c44b49f3a226a440b3f03c5e32ce1c42d0411e7` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K20_jacobi_steps.csv` | `171cf7649d4c58e12392eaf3c156408074360fd306ed230713f7e935516da6a8` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K20_jacobi_summary.csv` | `629e23de64fbb6f51598d202bcf63b6752425188b92a9f1959f9428631acfed4` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K6_gs_steps.csv` | `c85b5e81794ed82ccce15a8787f2a0726e2b725744165941f98c8f1822c49c1f` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K6_gs_summary.csv` | `ddab893663db9b0befca87422402a337989b26a2a126e556d1d039190b7cae02` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K6_jacobi_steps.csv` | `9f639a627e0b4a91a9e4c0ffbda6be73246e6327d80090808ebe211894a87f8d` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_K_35_K6_jacobi_summary.csv` | `2cfb99759441a89720f1a9f8723e0a98c7a50d3a81dcf648b87b08c0bc680292` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_1723_K12_gs_steps.csv` | `94295b73811a348d577d743a6c7a98dc9801ff32d848f3fb2571d029c67e6dc7` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_1723_K12_gs_summary.csv` | `fdab443bdcc240cf6009184122597761c877501f7a0d569c02a1a09bf9d3d21d` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_23_K12_gs_steps.csv` | `e8b7f343101ad9291041179f6adbcb9e7bfb342cb141cadc6beba5f81d44d747` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_23_K12_gs_summary.csv` | `6e9ff0cbf0e9a7fc3d959c189becad788c800d9b09a1de073897420637a9fcd4` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K12_gs_burnin1e4_steps.csv` | `12ccd505592e5d8d6815ab995aafad9e4767dd055ae0755448b26176b87a2ba9` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K12_gs_burnin1e4_summary.csv` | `aa77bb2412e5f0320aa72245ff1ee8612ba4282db5f35ba1c3cf5a751dd0a934` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K12_gs_steps.csv` | `958d3d8c34602555aea46bdb9410100394f0731eaf3090fe8850769594629e9f` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K12_gs_summary.csv` | `80764dca4ec1fc151d8a400f3d122c05f87a1888e641b693dc5d9326172399b8` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K12_jacobi_steps.csv` | `e1dc9082a600dd92a7f274d9216ec7e8ba4057473bf113c90ff683c8adbbcf38` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K12_jacobi_summary.csv` | `a06a887c531001102acdad8a375c59869a47196e38bbccbc3c4537dec46719fc` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K20_gs_steps.csv` | `cc3f2ae06c75d112b43ae4b838b160dea413a1b6ad45abfbef9c11bcd4c38145` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K20_gs_summary.csv` | `f88ef18b1bfd5a3632d446259cbf2b752cbc1492d0dff59eefb27e518ea1f1b5` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K20_jacobi_steps.csv` | `614f6a0a11e744a26e4b637b28b21a8cd1f7ff4722adbfe4c6b569cc566a6a7a` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K20_jacobi_summary.csv` | `7e1884b9b715c7fd98a830c7bdf768d6638dac9c7f3b5a896dafd3867d519325` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K6_gs_steps.csv` | `f30cb18f943622fc62c80a2e4d64db93db477f82e5d884c7c2c172988b028429` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K6_gs_summary.csv` | `63ceca204c18e96250f97a2d2eba1a380c8b3d2e505376108c9da952eb16297c` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K6_jacobi_steps.csv` | `9f0a4a8fb45d08290cb360d3ec028636e54b50c8e17df6a13699ef4a62fd2853` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_35_K6_jacobi_summary.csv` | `9d42a884aa5e18e355cc6dc96bef59207460a88569f5011a0e575a5642d6439c` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_711_K12_gs_steps.csv` | `b0ad57472ee6e4551862acd2c70880faf2ec7b4faaa1a25dc3521ea1a98b15fe` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_omega_711_K12_gs_summary.csv` | `17c8f8f1885ade78d10323bc2de3511062b204e2cb3ca82d9fb4727b271b5178` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K12_gs_steps.csv` | `2cba9a58f93e5b6de1808a70d6f454ba2a2e13beca51e41707e441942dc31ece` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K12_gs_summary.csv` | `2e1c3a324342d74908e62507a4a312b70524decc8c4d62c8389e528c09393ef3` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K12_jacobi_steps.csv` | `01ab798fcb36dd7cc7ef3fe2ab3e9f24e67116da2efd3a8c7f8202c1ac2bcf4e` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K12_jacobi_summary.csv` | `448b3d67f4cc33cc9ad96c21b3c7a25afb7f620eb8ba4634423fd10a7c062a7d` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K20_gs_steps.csv` | `ee09934fb02fabe93cd138c6eb7c62f9e1d6814475a59a808d365c96cb18daf5` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K20_gs_summary.csv` | `3257756948236b07d6bfd7d5e7c20f2ca8256544746b438f0bc02a82ed00adf3` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K20_jacobi_steps.csv` | `225be22d7e3fab4eadd4bf352c31333accbcac58f4acde011f01d0017229ca94` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K20_jacobi_summary.csv` | `3a70f98decf18255b7ed833a93451eeff658cf0e8de49260efb9f9a4bb518c59` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K6_gs_steps.csv` | `bdb7e1d5121bfac794d7c01aa6a634a5ad1d93b6339ba63cd9204ba1baaf07ee` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K6_gs_summary.csv` | `eccb02f34e587921f3d09c167530bc0c91c9acd7690c0b999c8c184a81d28146` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K6_jacobi_steps.csv` | `5914e8ac5495bde7fd423cc78039b6bab1090dedbeeae49e624420d30f977b67` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_pq_35_K6_jacobi_summary.csv` | `81e809d4b352c7bf10756a2599c89b20160401da4286204cfdf0ffc4d6e55d81` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_zero_35_K12_gs_steps.csv` | `a23c1adfca5c642bc5328607a413ed18d8d058c36b01ec4d4c4f37a74f29c871` |  |
| `P3_DeskRejectMeasurements_20260905/decorr_time/res_zero_35_K12_gs_summary.csv` | `60b3d66085a19c3a4b410807882b50ecae41dcf95a762e65ef3eb11fe7a73d00` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/jacobi_orth.cpp` | `b47e6a7f0f0d5aafb00b7a4efacc3a4de4c58e2a208537324f04225a9e66dc2e` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_gs_freshseeds_lyapunov.csv` | `ac07cc3f4453d006056476aaffee866a908cd048875213f6ae1948cabcfe44f9` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_gs_freshseeds_pairs.csv` | `748f26f35f548cddd34927e71f6758e4d29aec5785ed8048529e567770de5b65` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_gs_freshseeds_run.log` | `d1d712292dc383f1d4e1c78e1c889953f7e8754430bdbf1eae496d185de11065` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_gs_freshseeds_summary.txt` | `f9e32443ea541454e47f3ddf33d77029c2b5693049771a228a1173aaa4e5c0f4` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_gs_full_lyapunov.csv` | `ac07cc3f4453d006056476aaffee866a908cd048875213f6ae1948cabcfe44f9` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_gs_full_pairs.csv` | `1034ddffe1c4df66c2870d769687bdd22f74729a5c4945c54be6450af0fe4b04` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_gs_full_summary.txt` | `9ab0636fd6b23f82d387b33ee6ae3305d3b1bad9d4bc4d919733080104294439` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_jacobi_full_lyapunov.csv` | `54dd548e169e3fd7e3543ff89ef37bbcd04713fac4e4218114d661cd5adea49b` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_jacobi_full_pairs.csv` | `a8f0550c36605c2063444826b0ab3c6190aaa4d18a45e6014ac8bf1ba1149ed2` |  |
| `P3_DeskRejectMeasurements_20260905/jacobi_orth/res_jacobi_full_summary.txt` | `0d8138aae09182ae01d2f603d4d5250c75ca668ad04fb667a813e5074c8773e7` |  |
| `P3_DeskRejectMeasurements_20260905/pairs_dist/evidence_full_20260905.tsv` | `7746150d88a436ac0fc3ce4cf5968f4d8666fa80445e1a79b58c51181278a40f` |  |
| `P3_DeskRejectMeasurements_20260905/pairs_dist/mcl_orth_verify_full_20260905.txt` | `9748c35958b6a52c706974da159fe68f2afec48e70ae260bf1d2a349c4cdec3f` |  |
| `P3_DeskRejectMeasurements_20260905/pairs_dist/pairs_ks.py` | `afca5571950b4e3831056350b0d3e734b6dfeaaf128a733acf936272e48f7423` |  |
| `P3_DeskRejectMeasurements_20260905/pairs_dist/pairs_ks_results.txt` | `0426f84a5bc502e6f2c321944f55263b82a84d4cdc4bd0f04b258db6a24562cb` |  |
| `P3_DeskRejectMeasurements_20260905/pairs_dist/pairs_qq.png` | `d7c18dfcaeb5ae4441650e2123b89be8370e8d7eb9218076d179fb474e3d67d4` |  |
| `P3_DeskRejectMeasurements_20260905/run_all.sh` | `23aa243426a9c3de652f2a890db8d3e2e70577f95a1725001bb1cbb8f6848289` |  |
| `P3_DeskRejectMeasurements_20260905/run_all_20260905_101801.log` | `08febeb8ad3420e534191a9b55bd0f16e1d5dc3aad98fe92355d0e730369518e` |  |
| `P3_DeskRejectMeasurements_20260905/tableVI_lyap/tableVI_lyap.cpp` | `de567e34af1ae8d8e8f81f3f2860ae99750e1dc0eb41cd6d75514c56c72e3098` |  |
| `P3_DeskRejectMeasurements_20260905/tableVI_lyap/tableVI_lyap_1e7_20260906.csv` | `06e2d568b0535b8f1e1b8c5808c6762a79868522e768f94083ebc09efb1e2a55` |  |
| `P3_DeskRejectMeasurements_20260905/tableVI_lyap/tableVI_lyap_1e7_20260906.log` | `1bc6d782570b40e61ef8b862b06812e6ad2b64c0ed1bb78572a54ca57e77bdc6` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/analyze_trace.py` | `ca4eaa24c1cc6b113facba17a4bc6d3973fcb7827c0c813d2b18e20d1f0c47e9` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/analyze_window.py` | `e06da78d0a1bec376d445f1769f575c315b3c6a3e2cfa000c07f5bc2990929e4` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/cell_check.cpp` | `245149d040dda52c6c84600f86150aa2cc6219fe368f454c843a6b0a93f9d527` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/cell_check_results.txt` | `ff1f778813bbc581af615634df45a3f71ec8fe574ff690ddc70d6a09dad47a0f` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/res_trace_cells.csv` | `389e105ace3729f54571a4dfa4b82b8e31f6f49b422e3eff0d9a9dde2433d097` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/res_trace_grid.csv` | `cd2ce3607826364d9b58bbaad6734b24abbfea7e02c02b54d9381213a44f9fb2` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/res_window_grid.csv` | `eb179836eabf6d15faab99154115ce99aea87499cb7995a5b0b7059475fd98fe` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/trace_fig.png` | `1ef7842816086503565165e334a0ffcdb4c8df58f3b946636a1fe1fafbf5231f` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/trace_summary.txt` | `8e9e953956779bf96fc9bd7ae11c9ec9d5e905ebd81d1de54d1a547cfa8e413b` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/window_composite_table.md` | `d84bb1245c972bdca1aef39bf42ef8deb9d71bfa003eaf3aad65c82f60094736` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/window_control.cpp` | `fbda42ed64e3860b36f1fa58dc19c46d9f6ef030bbdc82ba00597d681c2a9df3` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/window_map.png` | `ff2639f0eac153f24c5f86e51b49e4145f26f34d30fc9dc2c34ebbeaef5d871f` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/window_summary.txt` | `b13abc1d0aacaae60f8241db26eb8f3368e826994e874b62701a8f8a990dcc10` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/window_trace.cpp` | `4cd1e031f9d9872b6cc531060722ef5e9a742f437ba03ce12051049401d881dc` |  |
| `P3_DeskRejectMeasurements_20260905/window_control/window_trace_run.log` | `fddb6c566627750507a3f3aabca34a090f1990def0544e11528d6a3835124ab5` |  |

### P3_FamilyGeneralization_20260930  (155 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_FamilyGeneralization_20260930/RECORD_P3_FAMILY_GENERALIZATION_20260930.md` | `a8f1eb2aa9a668cf37e3423964afab23bdae02f87b3fb0aa02ebba1ae5e112d2` | Paper 3 — ت-309: the time scale and the boundary in the three additional coupled families — 2026-09-30 |
| `P3_FamilyGeneralization_20260930/SHA256SUMS` | `7bf6353dbd61895b609cb635d736b7b02bd1bbdf9f5462b6955211566b9fe425` |  |
| `P3_FamilyGeneralization_20260930/analysis_run.txt` | `2a15eaac50bbeb8340b16cbd125cb9682548cac98c644a62f580220b8ea6d09b` |  |
| `P3_FamilyGeneralization_20260930/analyze_family.py` | `14d3416116fc809a72cf9b4a87f7180d05c8978842b9b5f0581fe40880cd9e20` |  |
| `P3_FamilyGeneralization_20260930/decorr/decorr_fit_table.csv` | `2e997be30d4a856c92703bfb3ac1a61c9e0d7375597bee64e502d4ac79e1395f` |  |
| `P3_FamilyGeneralization_20260930/decorr/decorr_summary.txt` | `42cdfa6068285f04a02ae362e55386c551fe47a490c31999cf774953320ea968` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.28_K_steps.csv` | `d2d51f3cf87c68f2620f36ffabe9e85137abf4d061b9f5db1b7082a60ef06d1f` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.28_K_summary.csv` | `51e9d46c1bfdeed368ddffef42b64d28d64d7e31ffa14ebfad968e77a6f5fc8b` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.28_param_steps.csv` | `564001d2296dca494765ba1bca20514af7271b85533060f129b9b36cce3c03e4` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.28_param_summary.csv` | `b56145a5e97d6343b4fca8a34f2de471c7bee94106aa45c98f89e70891661a4d` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.3_K_steps.csv` | `4363a4059bd3d859bcd0dbfc20c493418ab36fc3a6a227632f7828da6e9b9e5e` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.3_K_summary.csv` | `87361f8ba672c5619426f22463e5e603d9c327a97575a0b5f38c446c618d9d93` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.3_param_steps.csv` | `25503c11b7b89c33c26692fc24266fa6439d9a33fdda464554b1191a4dfbe6f5` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.3_param_summary.csv` | `cb30dd80805ec19fa26311d6c5fb1e665de13afeb5e9dbb7df4a5bbd3b3ff6a5` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.4_K_steps.csv` | `baa1c44c703bb516c3f911f26388abb328d5ca8bba1cc9d7980c2b6de01beec2` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.4_K_summary.csv` | `debfe02ce1b30d3155125f0212fd577273397c247d688e4aa7e5054ae2c86ec0` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.4_param_steps.csv` | `4c76ebd2ae0be7375018ce534dd250906ad0ce181ae834de4d11c2c03ef17cea` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.4_param_summary.csv` | `60309bef015e88674efb1c1cad2473c43c1116d05d4bb4326b906e388953bed7` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.4_pq_steps.csv` | `9b07254644b4f495fe055f508bd54a3dbceba566cceb02c298173a1bac227418` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.4_pq_summary.csv` | `f86389fea4c9eb8f0c1031d14f4744610882e31b625dcfa7e05c809956163a4d` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.4_zero_steps.csv` | `9bb892b349f56f530198bc676a6d04ded0893ece4523e6e3f57e817a478a3cb4` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_henon_a1.4_zero_summary.csv` | `0b70067564a4b58978d574d3373a884456dc4144cc4751fad6c4a444de5fe60f` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r3.7_K_steps.csv` | `abacab6c3f9637314c333d56154760705eae06d50d956a97bed91d72cda01051` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r3.7_K_summary.csv` | `fb5efcbfa12c2c5b77b51868d8eda28244a7125698f98be5a161fbaee762e79d` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r3.7_param_steps.csv` | `4b19245707674a2ea1d24628ec8f777546e3211c9725f82b2e6b48ba2fe75be0` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r3.7_param_summary.csv` | `0f00d6d069709f16731c5db11e3503f5c22f1b575cb00da5d118414898106c96` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r3.9_K_steps.csv` | `d976dc8a6d841a88ee7008dbf76e8e83758a7f0fe2d9f5981c5d4990a96df21d` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r3.9_K_summary.csv` | `88f2e5c69b3fd5f2889ea7a58344f567b93763e95a481662d94ea491a853c75c` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r3.9_param_steps.csv` | `6d785a3e819d97a3dddc800da9fa8404cbb7a1af190069987fe18a3c06579346` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r3.9_param_summary.csv` | `8d1493782bcbcf63db0dbfcfec217059989a727c757e6dcf6486c9afc3b8ed94` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_K_steps.csv` | `425ff93f3a3e3fb521630d1877a4401d5ce73df61bc3060d1742aeb7032b2236` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_K_summary.csv` | `2706cf9a66ec52130cbdaa3f793c6889bbee9e930e423bcffd16f779c0bd9b13` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_param_23_steps.csv` | `aba242cf2bc43e177563a605f7cb96f9a38f0ffe232fa1e38fba1eb10fd588ef` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_param_23_summary.csv` | `7a062ce89a0ba757131af6c455ae37cfc467459b690fe869130a586e0edcb90b` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_param_burnin0_steps.csv` | `87febb5fbc46428321bd83a1cfd4f986fe4eb1844e681d6d74053850737a3f06` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_param_burnin0_summary.csv` | `baf4a49546f915acc72f3eb3f5754a4f4888de3eaa24152af18a8c1232f00c1c` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_param_steps.csv` | `8f1880bac05b6ea646d3d3b6fd4f6680d173471e3803c901ec023e337c07495e` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_param_summary.csv` | `df9f4a05f9fdc980c659a1a93fa5a081a8c66d96b3dacb483bc7b7272878a9d9` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_pq_steps.csv` | `dc40f78b7201b5ebc393087fd67c7e8244dfa767049c5bd4147bc43810609900` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_pq_summary.csv` | `da9fb719eb29eca185f296311e1a33fb0c1ad1246f6562a13ad4a20e9dedafab` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_zero_steps.csv` | `5c8366a60720f1b5cec720711624d22ba911548b6c56b43a35cdd537cd50f516` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_logistic_r4.0_zero_summary.csv` | `c899cb285fab9350e1de03e46342a199bac44ffed9adc57fad9dba6504e66a7e` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu1.3_K_steps.csv` | `6f9fc388cd94062f0916916de8a78ae3ff04201655e9198659727055ee75c6df` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu1.3_K_summary.csv` | `4e3783e7307ad33b1ad23092d50d12d1fd6927842241e29758e54754c0b8e662` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu1.3_param_steps.csv` | `d57759970741af61112e526c0743458632ad785f4e7a4b9e99b88f9cd225f8cd` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu1.3_param_summary.csv` | `9c8ac8e96e66316f7e01d3d0e6ec59411819bec5b2202fcf3de59cf0df46f540` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu1.6_K_steps.csv` | `9af7c649a29746b688dc3ff583bf2fb0987e41ab15611483f470d7afb37bbc00` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu1.6_K_summary.csv` | `a55fdbb2c6f8fb31ffbbe32a82d8a3de6ae27872dcb41bebe2346ccec85e8865` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu1.6_param_steps.csv` | `581d55b049bd6a8524652c9407cf3fd16ce44085f23bd5db3b11d2051de7e744` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu1.6_param_summary.csv` | `d9085afc9448f99d72d4799fb41622c8b66c5095a9d19e048680a79099e9fe4c` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu2.0_K_steps.csv` | `87319568d9803ea8a8597e1af41ced577d67a8fce56fec60af1f425e7dd479d5` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu2.0_K_summary.csv` | `fcc9af26943999b4347723de3d8688de85a7aaa4c38cc4ab699b08fea8b21af9` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu2.0_param_steps.csv` | `733d34417e2b008600582cd9ac62cbea022331a6f7c1fc2332c6396a25f462e4` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu2.0_param_summary.csv` | `1ff825aec6257fc817613d4676007018d782f0499b2b01317c3c75634d6d1858` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu2.0_pq_steps.csv` | `b50079be8a248f5047be1dab95b10e023a340bd9bd6ccf7daa8a997797dd7934` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu2.0_pq_summary.csv` | `26b43fad18ef2f0068701dd7d2fa913bc951c383d85b3097b023e9aff67cde3b` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu2.0_zero_steps.csv` | `1799b129c26187932a6399cbc1665b94ef390e3974d4f02af6747da50fcd0d5d` |  |
| `P3_FamilyGeneralization_20260930/decorr/res_tent_mu2.0_zero_summary.csv` | `0dea292dbcf84173da2e64ab2351518f23de146e6c40bec924c8b715370caf8c` |  |
| `P3_FamilyGeneralization_20260930/decorr/run_decorr_20260930_175634.log` | `5a4a2ae429f16c7e10cc63716fe3a328404803f6f413e982637a8097986a7759` |  |
| `P3_FamilyGeneralization_20260930/family_decorr.cpp` | `64f37bc862701aa4213ee21d90d235316a305a68c09983cf08f742ef82f7e839` |  |
| `P3_FamilyGeneralization_20260930/family_maps.hpp` | `e89dbca61f6419147045cc99be07d834e8fdcd62773aa8065bd75d9cacbdb2ef` |  |
| `P3_FamilyGeneralization_20260930/family_mixing.cpp` | `9af29e7959e2bffb95788ba74a9251451b7da8e72a927f3e8132b646708589ea` |  |
| `P3_FamilyGeneralization_20260930/family_window.cpp` | `1f29752da8e9b51bc358b25b09753a25746c5609a69cc088b2d3b8f1fecf1564` |  |
| `P3_FamilyGeneralization_20260930/mixing/_v1/henon_a_K0.01_mixing.csv` | `dee2e23bb2b10cbb522c02a1f1c2ea7c14cc2681a656542b02ce4d3e6d29ebd1` |  |
| `P3_FamilyGeneralization_20260930/mixing/_v1/logistic_r_K0.005_mixing.csv` | `0120db091f1ddee8002c24284e0bc6eacbf7d97b8a8de1a031c0009d6d58f5f6` |  |
| `P3_FamilyGeneralization_20260930/mixing/_v1/logistic_r_K0.05_mixing.csv` | `26d51488b5b225f05b615fdc2bb15554ea6a06c8007a22c883e0033928779a7a` |  |
| `P3_FamilyGeneralization_20260930/mixing/_v1/tent_mu_K0.05_mixing.csv` | `ddc93b9442d3c028d01ee75d15731ac06d5144940027b2f70ab2ce1f8a4c5159` |  |
| `P3_FamilyGeneralization_20260930/mixing/basepoints_henon.csv` | `b9c37ac897d6b39baa6cd68671556bd5a679962481d7453d1ee1c73c5c27a3b5` |  |
| `P3_FamilyGeneralization_20260930/mixing/basepoints_logistic.csv` | `ed2e956c86b265d187634c57fd0c3c080f347170a385d8f7e0a01ed039734e94` |  |
| `P3_FamilyGeneralization_20260930/mixing/basepoints_logistic23.csv` | `abd6cb97066876c888e0e6fe9a7abab2c535b6ff7c12c19d0e7a9f41ff6791e8` |  |
| `P3_FamilyGeneralization_20260930/mixing/basepoints_tent.csv` | `91cb9a64bbe8da6ecb7e2b641e26709f0456236bb7e25284d1bed7ff915666cb` |  |
| `P3_FamilyGeneralization_20260930/mixing/henon.err` | `2f703d92ff5dcc38809df2d040dfc8f79f064a3881519ae32e3978bc7bb3b35c` |  |
| `P3_FamilyGeneralization_20260930/mixing/henon_a_K0.01_mixing.csv` | `cd2b25c3ec290909ff3737d8da4c8ac7255251692bf66028bc72310970ef89cf` |  |
| `P3_FamilyGeneralization_20260930/mixing/log005.err` | `e2e4e2f0638c42e3c52e18e7d2245b3098f1410261930ddf6107a97bf2ce76d1` |  |
| `P3_FamilyGeneralization_20260930/mixing/log05.err` | `217372464d1c8d274f45f05f4fc9b2dd69e86a097d5c655653427277d5e0e3a8` |  |
| `P3_FamilyGeneralization_20260930/mixing/logistic_r_K0.005_mixing.csv` | `dd87acfb2be2d4e7183b079cddd6260f5398e95c7bf706aeae7a68b5ce3fcbac` |  |
| `P3_FamilyGeneralization_20260930/mixing/logistic_r_K0.05_mixing.csv` | `652847931f81257ec78beff8dcd019e1dba0d048a710a4dfad6d487c0cb6067d` |  |
| `P3_FamilyGeneralization_20260930/mixing/tent.err` | `95d809f64be4faedb18381b1b8e8a270fea2f918d305437083e32bbbec7980e1` |  |
| `P3_FamilyGeneralization_20260930/mixing/tent_mu_K0.05_mixing.csv` | `b149c4b02409bf0ef25971f6df37255c9a35cbc713f3418740fad410236c88a8` |  |
| `P3_FamilyGeneralization_20260930/paper3_fig6.png` | `0d62bd6681e4e418e2e5d6501a0ef562d39e132808c012686237107948ab40ce` |  |
| `P3_FamilyGeneralization_20260930/run_all.sh` | `3c437e613bdac5e440b5896f70853a98b43b6e6f25fc146981b1dbf159e37c62` |  |
| `P3_FamilyGeneralization_20260930/run_decorr.sh` | `4136e7dcb92b536c784444e47a1d97c0601131d0674b3dd17dc63b9b7e67d35c` |  |
| `P3_FamilyGeneralization_20260930/run_mixing.sh` | `7a2eb7a59f635fe1fc5e9fcd795eda5a5512b07e4ae762ed9b60335e80b19dde` |  |
| `P3_FamilyGeneralization_20260930/run_windows.sh` | `5381acdeb137af61cca5806c8df1c73fb53eadd27f40eac6bb18792e987a8def` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01.csv` | `7d103483a6ade8f2fef358f3c1b71eb5c8597b440f0114baed9a6f47364ca3e4` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice0.csv` | `ddc25cb8ecb82036e4c95f2637d5872f4ebe3f1a40292ebf4a07a0eef24117c1` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice0.err` | `f7f538f74ecd1778edf6d95f7db41483bf332bbaf97697a2b5e60069ec5c2428` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice1.csv` | `2411ad77d4974660adc2ded19f977531a934699bb8e41781ec9f4d2a3baa166d` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice1.err` | `c3b57201b5df5874f8e70981e51e6abbf7fa9a61bfd8a32cdf219a977f79fd9f` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice2.csv` | `9d5fcad09c4dd39286c3ec06e676bb0cdfe507d4fd27838867ce812d3a2ae111` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice2.err` | `3b5ed966c5f251ffb00da0165b9dbd5537d0aeb6481f8ec2f5e8e0456937cc20` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice3.csv` | `6493ea18f9c1e26aebf721d1eacd8d41f279cbb61d64c2bac88289e29e1ef055` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice3.err` | `a4aecf46ca3a6a1c12bf79fbbe5604f9d03dddca4378af5b7f380eb328ff8945` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice4.csv` | `d2a21253f34bf3a5b0424e1872146a608e12fd704e73dfab7cca1d447912dfde` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice4.err` | `454f8ae8d9fe349d07e0c4a757b4f373408dbb4d98c6e7cb057ac7f3c97e67ed` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice5.csv` | `0d4572090eb42d4592fe45eb9f19d60030d200e42782883bbe70550b0a6a8e99` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice5.err` | `28837361564bdb1f0d3daf4b890369d83a33766488c38e3bcc27b6ecc556810b` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice6.csv` | `9ee38904f5286d0688ad7dda79c4972846d8e8296cebd40fda33a36d0dad3ad1` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice6.err` | `2dac30a672d14df3e0c32788e1ab40fb20e8628f3352e334cef7a1a3b2ced67d` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice7.csv` | `ff9aa3ff9887c8aec318fcc8ac7faec43763f84a20139a7e1aad7fefcd1b348e` |  |
| `P3_FamilyGeneralization_20260930/window/henon_a_K0.01_slice7.err` | `39d7cfbce2aa6451fbcd9d6e6532d941863714e8bf25e843c1414e9206126462` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005.csv` | `c75ba0171edfb33e4ab16159278c7efa1f9e2c76b315037a3f4c0b66a01c3f22` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice0.csv` | `f693c54c877219c1a89b242216e8edc1dcc7eb4ab3edc1e79c490ab1dac51fad` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice0.err` | `69b90c5619ec3f111d5f8bc28fb05d0f80c3548f81e8ac7640b6c816caccbfca` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice1.csv` | `f7906dc47d17fbfafa55284ed680e964bae87b9c32ff462f48cba1909738db0c` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice1.err` | `ac4e1f16c2908b089806fb05eeb9f8338b080a00d223724ecda49d4c3d66a1a4` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice2.csv` | `370fd66128c7c02d30fa7b4e549bee97fc2d1e6939a5b3e57a52a9a4c40b61fb` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice2.err` | `4a81433ea78540c22ba2aa895b7dc22b696ff3a29ff95dd2326c0199c9369a05` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice3.csv` | `31cccf56f1cc97be6f85e02d48459f5e79f16f1194521fb8cc8ab526cbca53e2` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice3.err` | `a989826645e47e348dda021c79678560e1d67a0213ade281b79289da482d45fa` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice4.csv` | `9484e15877df956d577d7315cbb502ba5010b73902c2e2ee35cd0cc37d53335a` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice4.err` | `8b51a0bccdaf425df700b8430cb3dfded470b59da2a671ded1e57b55ec9c0973` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice5.csv` | `a0f6dc98930c338d903e88dbc74d28ae97b8616a38f52e76f1a8b2dc11cf2666` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice5.err` | `10b0c9837ee5bd42e0831e9df00b3999f7cf4692bb0e96bfb1639588d1ce9a59` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice6.csv` | `a7c770e989c1fae6cdd45b3dbaa6815b918a14f53b27a97e086595dafbcba8ea` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice6.err` | `4b5bcc8215d5cef171f7a8cc5ba23a5b29d82ea80611ae018f660fcbff970f28` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice7.csv` | `d5c42c12a00c49e7fb855a4c23893878c3368434b945689102a4df6c0630a2bf` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.005_slice7.err` | `a0ce05cc157a3abc84d35ef2e1a7b4f3803292add4dfda72ccc67dacd30a1850` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05.csv` | `6e79d6454fb6f278eda60379fd42357a7b3b26e4a8671eb6b3fc0c3000495e36` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice0.csv` | `2c3ed120aebfd68add13dacec171c4a26ee783d8fbc6639ad6d5a5f24eedba22` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice0.err` | `230e2d55c26ffea0bfd5bc43f61fe803f5760e29f2068fff9631cfbd51449ca8` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice1.csv` | `59b1e98ea6da33e68170a10882d1886f05a459abe363283e0402ce526f712566` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice1.err` | `b0217a951812ca158ed7df54ffd4bfa0668fdd7aa4494d6c401f06fff23eea29` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice2.csv` | `e89ec776fb988a55da048e8e5b8144807b06a78653cea9547d9f9b219af9b4e3` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice2.err` | `91abc36eb1970c353f4fcdf87e10e61d2f4553bda54da73da4dad545ec04ed88` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice3.csv` | `0e8651af878215f134887550b9cc37574f37045a35ace5e00eb4996d25804438` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice3.err` | `7e37340aca44b4551e8864d6e1715c1e82ecf979941661395a0570e70c37c1dc` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice4.csv` | `6f5247d0c0038b7570673fbeab685e7e09ef6926a402f5b98afd28f40e079933` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice4.err` | `c626bef5317a55aa21c6a09290ab6c71320da2626dccead606b1016e1cca5e83` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice5.csv` | `b19e196225a2b399c236b6a79690f6bdf603230f172732b2ba6676b254c63166` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice5.err` | `f98ccf5345e96b1b9ce224cad1028148060208f1213a6a865a3d70f4eec567e9` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice6.csv` | `d51e21b8d049ebfa8b30f764955e4100f9f3eaa268d68eb809e78a6f6840584c` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice6.err` | `487beb3b04e8ff7aa31a0e0f65034a3345cb0d622bb41fabfbf055abbfcd20e2` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice7.csv` | `f2d038fddca3eaace71c7e00fde19add633a6ee05823fbcca6efa8a23065e5c3` |  |
| `P3_FamilyGeneralization_20260930/window/logistic_r_K0.05_slice7.err` | `680b7c87e174e949c7ec9bfd60c2a7bf4a250078f087727d6d1d1d894d7e56b6` |  |
| `P3_FamilyGeneralization_20260930/window/run_windows_20260930_175545.log` | `26f503a298565c0920e038665c501767e95691e697c04aaf854b7ea7b4eea60b` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05.csv` | `b48ea30b31e404f700060443e7c114c385edf2b2df32e605d48f4a6f97770063` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice0.csv` | `e408ad38a5daf00350fc423d9fb4439a167b3602caaeba219382ee8951d4bf0c` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice0.err` | `133422354046904d5ed06817752e99e17dc38238dd09451800a8cc069cb65b65` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice1.csv` | `3c44f88184523ff15fab8378767be99322bdce19f990d75b18f125753c85d59b` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice1.err` | `2b12c9a3da33b651cec079adec15e2b196e9db294aff5974d638277a1b215dd2` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice2.csv` | `70b0e73913653108f2993d9983faeeb813b2b77643c7c67ba27f015259a3783f` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice2.err` | `34be32068c3d517b2ae20d9e192c13e5a74f73123a81744b091042f0ee0ede28` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice3.csv` | `2616b3d3860f7939042a4a1db5186fd70304837ea8bfabf45f07ef006ca11d6c` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice3.err` | `266fb08df47d2485ab517c350feecda0777299f73cd8588d9621191b6c122c45` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice4.csv` | `46aa7777e73d95a74d3d599ff8a47765a820c9100be6b13caf291a53621cec80` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice4.err` | `ddd0fa6337878781a79cea6a14e4b705b2dcd7c5b2a5236dc81e03c65b7b3338` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice5.csv` | `f620106e30f20b138cebaa6ed5c45de5d6a7ad6293f4a0a02ee5e307f01b3ec9` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice5.err` | `37acf72910c4d743c3fe16bb9bc9b2efe4f388a1d3994bd1ba0d0d50614e5d89` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice6.csv` | `a3731d1637fec26d2510ec7032bb1be2f8d7ffbb8b4106c2d9a7197e53c14bd9` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice6.err` | `0874858569d6ca399808315195164a4660547378a220102e13dec18ed66c466f` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice7.csv` | `3855f091662571bf0089c3282dc00b07bc9e38b3ee668e3011f6eed25459c527` |  |
| `P3_FamilyGeneralization_20260930/window/tent_mu_K0.05_slice7.err` | `7d12e93a3f1c5f7d8d3a2c77196b21f2d7a92a215bf4773a54284176fdb72b91` |  |
| `P3_FamilyGeneralization_20260930/window/window_summary.txt` | `ace696f57bf3d3e31a0172fdec7bd079babc2d9fb4f69a559b5a4466affa371f` |  |
| `P3_FamilyGeneralization_20260930/window/window_table.md` | `9f44962529065d87ff67696e627c9871dcdb1fa620660309cd11d07bc5ec8a05` |  |

### P3_Fig3_Regeneration_20260903  (5 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_Fig3_Regeneration_20260903/RECORD_FIG3_20260903.md` | `08fa9679d5d004cf5842934cf371d4a33d40bd7138f43cc3b2ef059513d1e3a1` | Paper 3 — Figure 3 regeneration record — 2026-09-03 |
| `P3_Fig3_Regeneration_20260903/fig3_matrix.cpp` | `02ca769f39eaf06cb83149ef9a9c99af432ee5cbe81a7f4b22ea28235df3c181` |  |
| `P3_Fig3_Regeneration_20260903/fig3_matrix_seed12345678901234_20260903.csv` | `173db621c18f09fe1b4ac385cbb37ead93e996e1a48e065fafcf0b409d99c25d` |  |
| `P3_Fig3_Regeneration_20260903/make_paper3_fig3.py` | `3281ce36d30f47b1a8c6f6fd963f99ecd1397d39bdbcdf3a55d991deea827182` |  |
| `P3_Fig3_Regeneration_20260903/paper3_fig3.png` | `110cc7b0de4bfcea428acfdca99267cd7e505427422c5f86c33d7fbe21b8092a` |  |

### P3_NonlinearDependence_20260603  (14 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_NonlinearDependence_20260603/Paper3_v3_MANIFEST.md` | `562de9fd892e9cf95d71a157cbcdd3539de0cae53f002e9fbc0072d9e8a986e1` | Paper 3 v3 — Nonlinear Dependence Test Suite: MANIFEST |
| `P3_NonlinearDependence_20260603/README.md` | `184f9bc3bd263dff657ddc6d05a615126a9a098786f7fb71c08c5d281a02bc0c` | P3_NonlinearDependence_20260603 — Paper 3 nonlinear-dependence campaign (June 2026) |
| `P3_NonlinearDependence_20260603/mcl_block_joint_test.cpp` | `473c6247e02d7dd7237c2c02ef68007c01df600ef87fd7578b42a9cce6d497f7` |  |
| `P3_NonlinearDependence_20260603/mcl_distance_correlation_test.cpp` | `17e3f2a0c39755a1534de60fda07a6f731b781e72c3646020eb921e078f5c518` |  |
| `P3_NonlinearDependence_20260603/mcl_lag_autocorrelation_test.cpp` | `a45ad1f891bf0b97e1410fe2b694c606581e55299502862bcbe5d44620d93894` |  |
| `P3_NonlinearDependence_20260603/mcl_lagged_crosscorr_test.cpp` | `e6d47e0cd463935358cc74ae6ab225476ed593438fc31bbd0dd5327e254a74e4` |  |
| `P3_NonlinearDependence_20260603/mcl_mutual_information_test.cpp` | `3e1f0e942bb95e683bf813e0b7dfa32333810b50dbfe7505c56b3784dd7d81dc` |  |
| `P3_NonlinearDependence_20260603/results_v3/AGGREGATE_v3.md` | `fbc409d4f6b6dd3a9de0896d41fa9c3e1490bd789c3cf6160d2d2fa18daf316c` | MCL Paper-3 v3 — Nonlinear Dependence Campaign (AGGREGATE, REVISED) |
| `P3_NonlinearDependence_20260603/results_v3/Paper3_Nonlinear_Dependence_Results.md` | `0a6c20b50bff0f202c787b4f5e595b092789428e09f62fe4e93a4bb81802ff3b` | Paper 3 — Supplementary Results: Nonlinear Dependence Test Suite |
| `P3_NonlinearDependence_20260603/results_v3/results_block_joint.txt` | `574991de23a09cf4f7e6b67721fbe571bd408405168289026208204274bd68cd` |  |
| `P3_NonlinearDependence_20260603/results_v3/results_distance_correlation.txt` | `9f31713987a0ef3503cc74782a1d267d62adaefebf790cd77fefd7d3b24c165d` |  |
| `P3_NonlinearDependence_20260603/results_v3/results_lag_autocorrelation.txt` | `2aa8ff462aa7b7b82f117dcbd89840c0f56f392b86df4c640fb56395b20e7c05` |  |
| `P3_NonlinearDependence_20260603/results_v3/results_lagged_crosscorr.txt` | `3c3ae82e46ee535313098b9ef51f3f9fca6f1723847a055acca7f4700ecca311` |  |
| `P3_NonlinearDependence_20260603/results_v3/results_mutual_information.txt` | `40c124a4a07c53b9931e63e2696ffd197e9a9b99c86ca2682384e7220c381c85` |  |

### P3_ReviewMeasurements_20260903  (8 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_ReviewMeasurements_20260903/RECORD_REVIEW_MEASUREMENTS_20260903.md` | `c50079f8ba9900e094b0d99961ce0029f157aa9e9c63af83958e2882a88d0f1d` | Paper 3 — review measurements for the external-review adjudication — 2026-09-03 |
| `P3_ReviewMeasurements_20260903/phaselock/header_patch.diff` | `b88bdef989562c212091be4806c7919f9fc087475c6a1b63f33bb8a37b224169` |  |
| `P3_ReviewMeasurements_20260903/phaselock/reson.cpp` | `d08ec2d15d1c0b25aaada12edb36a6ea83be7014e733abef7c82d1dc9dd659b3` |  |
| `P3_ReviewMeasurements_20260903/phaselock/reson_fig1grid.csv` | `1126204833da2e412110e3892c52a186da093aa367cedf1389fa8871f10932c5` |  |
| `P3_ReviewMeasurements_20260903/rawphase/analyze.py` | `47e8b0bc84c0be4db54e5f9dcdd8fcc5987d589eb37078a4fc8d5214ed0b369a` |  |
| `P3_ReviewMeasurements_20260903/rawphase/header_patch.diff` | `b88bdef989562c212091be4806c7919f9fc087475c6a1b63f33bb8a37b224169` |  |
| `P3_ReviewMeasurements_20260903/rawphase/rawphase.cpp` | `2bc671f2e71361de6a918dfec5d208037b7636c8de55198313301f5e8ac5b0ad` |  |
| `P3_ReviewMeasurements_20260903/rawphase/rawphase_results_20260903.txt` | `6170155d567af3998fea1e7b5538dd36973cf24c99bc64d28aebb4cc99051b15` |  |

### P3_WindowSweep_6_20_20260903  (6 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_WindowSweep_6_20_20260903/RECORD_WINDOWSWEEP_20260903.md` | `f59b4dba3489304cb7604eb612dcc9b6bdd43a8f7dbf7e87a21eabf91e8c277b` | Paper 3 §III.A — K-window sweep over the validated range [6, 20] at step 0.005 — 2026-09-03 |
| `P3_WindowSweep_6_20_20260903/sweep.cpp` | `27939d092e8bfc48b27aedaf4c2f450e226700b82d28dfed8b47aeda5e29279f` |  |
| `P3_WindowSweep_6_20_20260903/sweep_2_3.log` | `61a762b1ad6c2421c312651a0ef7e426052eade47995dd7cb9dbb8dc539ca071` |  |
| `P3_WindowSweep_6_20_20260903/sweep_3_5.log` | `a8f29a48a673f6e90f709a4fde7a2b63548a78bf8505e55220d3374c8560e594` |  |
| `P3_WindowSweep_6_20_20260903/sweep_5_7.log` | `b12c6cf04d314e1a5e532322598f0527add80c3ce42305576158a3014ecdf05d` |  |
| `P3_WindowSweep_6_20_20260903/sweep_7_11.log` | `f2e23bd5bb599d8755e290244e3c199629dce36e05bf6e4aec172193b60744ee` |  |

### P4_ReviewDev_20260925  (20 files)

| File | SHA-256 | Note |
|---|---|---|
| `P4_ReviewDev_20260925/README.md` | `e807e49b8eda9f3788b15ef706ac9986696095d6d9745c72aa1eef671f9d1f23` | P4_Dev_20260925 — measurements behind review #16 (adjudication + development) |
| `P4_ReviewDev_20260925/SHA256SUMS_16.txt` | `bc9e1d8ffd7a0c6f7e4046a5741a1ab807489603789c9ce2a64d6b1ccf0cbb88` |  |
| `P4_ReviewDev_20260925/SHA256SUMS_20260925.txt` | `1866714667d195edfd054b7f0c88e21e989d94343aa951eddff8dce36f11d460` |  |
| `P4_ReviewDev_20260925/argstate_rt.cpp` | `01e2442974f8928a112d03b4415005948fc5c9f240b9f7d4eeb9a0d2135ed62b` |  |
| `P4_ReviewDev_20260925/argstate_rt_20260925.log` | `a1c486cad21793a0af9945f5382aa85984b68e65472a28f2c7b8080395214ede` |  |
| `P4_ReviewDev_20260925/census_oldrule.cpp` | `7de1ef93933c37423db896da46da3535cf5d1f1c4e7729373613d4f5e2b18850` |  |
| `P4_ReviewDev_20260925/census_oldrule_20260925.log` | `fda259226371acdddc35bf6d8a65e306774446866bea4d33c67cfbcb76e70ebb` |  |
| `P4_ReviewDev_20260925/host_20260925.txt` | `31ddf1475516b87d9d43949c7a26edcd3b81b3f4f39077e64aff0550fa92bd8d` |  |
| `P4_ReviewDev_20260925/parity_enum.py` | `7049d3a0bf1b2c99472cd9effa9a3e2a57532d89ba199ff49ec03eebc5cbdf2d` |  |
| `P4_ReviewDev_20260925/parity_enum_20260925.log` | `58b061aa2f28e2d1940e838c3b43f85b6d6a08795a8d08333a40f34cc940637e` |  |
| `P4_ReviewDev_20260925/realscale.py` | `f781f76b5b6d9ee8d359f8a7205b759e5261f49a99164043fed09e18e80f945f` |  |
| `P4_ReviewDev_20260925/realscale_20260925.log` | `b244defa340ac89f3d00889061406fe03bc3f948db928fdbd7c99eaa3d05f4f1` |  |
| `P4_ReviewDev_20260925/shiftdiff.c` | `a419828a6d2ea591d119e7e1a6e6922358b89f6e5ebc25e637a70441e4db27b6` |  |
| `P4_ReviewDev_20260925/shiftdiff_20260925.log` | `2dae87ab501d50f4bd7c0b0351e2f96c06be978643c00686f5656f2c8d0d682f` |  |
| `P4_ReviewDev_20260925/stats_20260925.log` | `c103c48b3afd8d470a36a69677759c7260fe72b66775674df7d92f15c87386fe` |  |
| `P4_ReviewDev_20260925/walkclock_sim.c` | `d7ade5f4b7b41da0b1d232b348436be0896ac07068702019ed8b71fb9462b788` |  |
| `P4_ReviewDev_20260925/walkclock_toy_20260925.log` | `bba28fcf52e356b44a82586a6706b7c50b85520f060e0d2e540223e02f3aa79d` |  |
| `P4_ReviewDev_20260925/walkdp_sim.c` | `4a2bed6acfcc056de5da13477d148ec1f41a1388191586906c6b7938a708ef77` |  |
| `P4_ReviewDev_20260925/walkdp_toy_s32_20260925.log` | `97a200bd07e9a21cb2631536aafcbac2bbf46ed7a2c5eb5bc4388649485f6f4a` |  |
| `P4_ReviewDev_20260925/walkdp_toy_s37_MggN_20260925.log` | `572076a85660d185a1ca27a7039e60f3b0d5f29c90a3ad930bd5d55fe8363137` |  |

### P4_ReviewDev_20260927  (24 files)

| File | SHA-256 | Note |
|---|---|---|
| `P4_ReviewDev_20260927/README.md` | `c2c5f4859ed1cd873ecff551c696b814f8b9b0ff966f59ef048d88f8385f7f10` | P4_Dev_20260927 — (1) exhaustive translation-symmetry enumeration on reduced-width replicas of the unclocked m |
| `P4_ReviewDev_20260927/SHA256SUMS_16.txt` | `11bda880a04006c7c3989b90d26596c7b60c10e1e2d0842b481769c7577f90d8` |  |
| `P4_ReviewDev_20260927/clocksep_structured.cpp` | `761737cfd0d09781bd7d8b17977d7b919360fd956675e4f12bb448b5c2582e3c` |  |
| `P4_ReviewDev_20260927/clocksep_structured_20260928.log` | `412e60ecc30d60157b835d67e02ee40e235dd0a43ca810cf888aec6db4f17d0f` |  |
| `P4_ReviewDev_20260927/clocksep_structured_20260930.log` | `3618274cc94e180bfc74ac6aa20ee9c322ab0cc274eb1385d5a55a42571e6365` |  |
| `P4_ReviewDev_20260927/clocksep_word1.cpp` | `d46bbf27f306530e04ea9ee58a9e23e39201abf71cc312aa1809ac96345b87a7` |  |
| `P4_ReviewDev_20260927/clocksep_word1_20260928.log` | `5bdffb275c59740f0c550fa8659cb9895ceb9df015f5d5952665307e9e8cf2fe` |  |
| `P4_ReviewDev_20260927/clocksep_word1_20260930.log` | `0f84b87d9939b63e6d9f19a22c20f84294dd472103f38c7c88db65a6e5796f85` |  |
| `P4_ReviewDev_20260927/fig2_gs_jacobi_divergence.cpp` | `6c08c6887eca00edc4e9d257ac72469f8568cbd44be7a52de98a375821a9e1c5` |  |
| `P4_ReviewDev_20260927/fig2_gs_jacobi_divergence_20260930.csv` | `b63007c27cf86568785af14028916154bc94257384f9475694f60d47f1d29c65` |  |
| `P4_ReviewDev_20260927/fig2_gs_jacobi_divergence_20260930.log` | `2ac4028c4ceffcc36447cc93474dea689073a7f501298de2e68bd44c5e6a6eb4` |  |
| `P4_ReviewDev_20260927/host_20260927.txt` | `66553457dd382e83d343a6eaf46e34368c8a71fd6793e45656a2d99d80618f45` |  |
| `P4_ReviewDev_20260927/linux_env_20260928v4.txt` | `0e1953bf1d23ed0b06bc362e88225055c5fd5457eb21be4663c9731a02584078` |  |
| `P4_ReviewDev_20260927/run_linux_v4.sh` | `04c5869e128fa95a388059c7baa55e8ddd070ec8aaf8c7fb1937e65449f3138f` |  |
| `P4_ReviewDev_20260927/symenum.c` | `8055e85adfbde8c6beee778576e754ae2a4e88c20d08d4d951d013bbd7d727b4` |  |
| `P4_ReviewDev_20260927/symenum_n2w8_20260927.log` | `e9f6a0bca5f91079c2ae1dfd2e118201d9e17c492e4b06da952afd9924573e04` |  |
| `P4_ReviewDev_20260927/symenum_n3w8_20260927.log` | `ee5509e9269770ab0763870ff9b1900128bd3a8acb2cc9d4bf33fc93a980647d` |  |
| `P4_ReviewDev_20260927/symenum_n4w6_20260927.log` | `adeb96ba049313da2939ca6c01b616931829df28c1d7b80d8f79d372f9da178f` |  |
| `P4_ReviewDev_20260927/vdf128_t4v4_standalone_linux_glibc_20260928.log` | `2baa6ed38868ba2188d7c2a2041750186567b1e6df431f2621b73b3b87909543` |  |
| `P4_ReviewDev_20260927/vdf128v4_kat_linux_glibc_20260928.log` | `933c8c00fea6926f4f003dc20057414d49e396673b40ea8716b40c8e3d1b45ea` |  |
| `P4_ReviewDev_20260927/vdf128v4_xplat_linux_glibc_20260928.log` | `e101ea2c0aa4895b1c646ebea9af1adb64026124f82217d84381d35aecf8d81c` |  |
| `P4_ReviewDev_20260927/walkdp_sim.c` | `4a2bed6acfcc056de5da13477d148ec1f41a1388191586906c6b7938a708ef77` |  |
| `P4_ReviewDev_20260927/walkdp_smallM_heavy_20260927.log` | `bd614fedf9cd9113791cadfc275d494fb0dabf0086641680ff50a08318c34740` |  |
| `P4_ReviewDev_20260927/walkdp_smallM_light_20260927.log` | `df5862f2e450440b07831996ad1c815dd807e9b1359cf5c89ce3fdd383746f2e` |  |

### P4_ReviewMeasurements_20260904  (28 files)

| File | SHA-256 | Note |
|---|---|---|
| `P4_ReviewMeasurements_20260904/README.md` | `1fdc33dfb01c135fe1f6875f8712eb305ebd51dc150b7d57db2d92298ddcc936` | P4 review measurements — 2026-09-04 |
| `P4_ReviewMeasurements_20260904/SHA256SUMS` | `0ff3cf81180350750cd75f11c1de17e83534d1cbc5c99bbc2b0af35ffed36b2d` |  |
| `P4_ReviewMeasurements_20260904/appendix_vectors_apple_20260904.log` | `6842ff30259895bb4836956b36518b4a5124c389ef106e6c4e8ad2a9feb18f20` |  |
| `P4_ReviewMeasurements_20260904/appendix_vectors_linux_glibc_20260904.log` | `c5b5a94512468305913eaa863d764a3518e835b0d5931049a24f6f9ea4f6bfd8` |  |
| `P4_ReviewMeasurements_20260904/det_ratio_apple_20260904.log` | `8b00e2651a4fba5f9ee595e061195d00a5cf2a6ae5dc6d722667bb5493d1c15a` |  |
| `P4_ReviewMeasurements_20260904/gs_jacobi_pearson_apple_20260904.log` | `e4c63f7170891a98f7cc858a635ce732697d9504fbe158cf0bea64e7f02916cc` |  |
| `P4_ReviewMeasurements_20260904/lut_digest_apple_20260904.log` | `0251d06c8c2bd85489c80cfbf49135a326156aec43e50f0503540ddbf8ea1620` |  |
| `P4_ReviewMeasurements_20260904/mcl_core.hpp` | `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80` |  |
| `P4_ReviewMeasurements_20260904/p4_appendix_vectors.cpp` | `e072a116d36a30341240ad9d9ad793692ba5f0ff132131e6751f9f9d1483f100` |  |
| `P4_ReviewMeasurements_20260904/p4_det_ratio.cpp` | `3ba54583d37308d5176747a78bd3ba755f3ee8c8ca6230cdcd5b1f95c482b984` |  |
| `P4_ReviewMeasurements_20260904/p4_gs_jacobi_pearson.cpp` | `85e40b0cbce20acd039923ec8a8cc2e705d09b4b101f343188b0d13a016b3944` |  |
| `P4_ReviewMeasurements_20260904/p4_lut_digest.cpp` | `8c817f40998bbc7de25227bd3ead440cf37aa7d563365c949dd4aff8b85d4d17` |  |
| `P4_ReviewMeasurements_20260904/p4_q30_matrix.cpp` | `65be7b88a9537ec345ebcd270a8844630cba63a2bbb27b727de086a5d0fafe5d` |  |
| `P4_ReviewMeasurements_20260904/p4_state_collision_1e7.cpp` | `050ddf7a0e6793c43144402bec4a43ce140da564f00b6f23ddba6b27768394b0` |  |
| `P4_ReviewMeasurements_20260904/p4_vdf128_kat_avalanche.cpp` | `419f5eb07ef8dc8fff17ce8e24b3a70bf3082e24508bf02f84304eea02487ac7` |  |
| `P4_ReviewMeasurements_20260904/q30_lut_int32le.bin` | `f78c9584e5686cb1f54f382b1bfcf87c3399ae19f987e7761f339bdb3bd7dd1d` |  |
| `P4_ReviewMeasurements_20260904/q30_matrix_cells.log` | `1e084995a673a37608d54f019771f0c14ed95c25cfed860f9d6ef8d016f22b11` |  |
| `P4_ReviewMeasurements_20260904/q30_matrix_cells_linux.log` | `7c495aa9bcfd26f2dc183895dc3f51d20bcb92bd1cd7033c9eb3be2c27356e4c` |  |
| `P4_ReviewMeasurements_20260904/q30_matrix_summary_apple_20260904.log` | `430de4d58ce4a45038a80f44cecbc86aaf407bdec82be1bb2260cd1fe3f5f7c7` |  |
| `P4_ReviewMeasurements_20260904/run_q30_matrix.sh` | `d0cea058997ee21255b798bce59e5968e1dfc3a950bcf3009a869aad4c872f16` |  |
| `P4_ReviewMeasurements_20260904/run_q30_matrix_linux.sh` | `530a7beb178154c8e94554dbc9a846c74474b13bf7a5627609f9b115d43517b5` |  |
| `P4_ReviewMeasurements_20260904/state_collision_1e7_apple_20260904.log` | `161c1b9627c47f9eddb6904ff0c1cb1c2e2c0a0fbe064d6507f5f519009e5590` |  |
| `P4_ReviewMeasurements_20260904/vdf128_kat_avalanche_apple_20260904.log` | `e148858693921e1c54f471a4da5062ee86f84a743936b08cb5f8aaf4a5259caf` |  |
| `P4_ReviewMeasurements_20260904/vdf128_kat_avalanche_linux_glibc_20260904.log` | `d8c35c188875760f7325b8982eed4a16415fa781f5a7ceb1157b2033b1084680` |  |
| `P4_ReviewMeasurements_20260904/vdf128_t4_standalone.cpp` | `2398f65bd750e44165f80c1f3c1f2fa189cffb409d7cbeab19d8d28fc28d400a` |  |
| `P4_ReviewMeasurements_20260904/vdf128_t4_standalone_apple_20260904.log` | `891957959b26a304c73c757c749b4f5f8b692da48f4cbc44fdbff71fe0a3a799` |  |
| `P4_ReviewMeasurements_20260904/vdf128_t4_standalone_linux_glibc_20260904.log` | `1dd0e0df47b2e18a7be786575e0bc00b7f8698b5f14f0faf7e4e724ccdc960e9` |  |
| `P4_ReviewMeasurements_20260904/vector4_q30_linux_glibc_20260904.log` | `d39449f0df98ddc25b78b8f31f8558ebd69822fccaa123fde495b216c1f7d5eb` |  |

### P4_ReviewMeasurements_20260905  (62 files)

| File | SHA-256 | Note |
|---|---|---|
| `P4_ReviewMeasurements_20260905/README.md` | `3507fc4c78d475fb1d92d873fd4c3c1066c51da427f419c3db1f2ae516fea625` | P4 review measurements — 2026-09-05 (referee-eye round R4: VDF128-T4 **version 2**, per-input weights) |
| `P4_ReviewMeasurements_20260905/SHA256SUMS` | `e8411af1969771ac0f63a8ecac979182e6b03ab41bd3ea697185bb860201a03b` |  |
| `P4_ReviewMeasurements_20260905/linux_env_gha_20260905v3.txt` | `5b249afb3b6d63d3d3205f24a9ea6421211976e5de064d9b548441e3031a38bb` |  |
| `P4_ReviewMeasurements_20260905/linux_provenance_20260905v3.txt` | `2c893eb49813088c136fdbf087dc93d623e8a7c5610fabca06bfd0c3b7cceade` |  |
| `P4_ReviewMeasurements_20260905/mcl_core.hpp` | `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80` |  |
| `P4_ReviewMeasurements_20260905/mcl_keyed_q30.hpp` | `71a0dbaf84725ac77d0b3f1eab5a40ba90c088e88df7d41aab19aed39a6f6512` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128_t4.hpp` | `e08f702e2da92221588285a6a61ee2e48edfb63afbde8220fc3632fd2180ed0d` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128_t4_v2.hpp` | `41171250455fa33e311c1484f4d5d4fb67699e2f6275551224f1d06c1f63716f` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128_t4_v3.hpp` | `b46f1a1329ccbc4dc4eac02b930be7b71f74847800ed7c01358163d80f615439` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128v2_battery.cpp` | `08c532c3a510bf7a9c1912dbabc4306d405e7230356af1274b0c3c8dc3a8685b` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128v2_bench.cpp` | `c109f8e008a4bff73459391b4a44262d344a49e738d24642ab33a26935121d9f` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128v2_cyclecheck.cpp` | `7515bba87b0bf3218c9199308774adcff24e0474a6407dd57bcf0c193555de85` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128v2_xplat.cpp` | `f465117c06ec2f8b27d0f455ca55f260eaf286dd4ac396aa36d55c8fa6a0b014` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128v3_battery.cpp` | `2425b901f6e2db208edced7740fe454bd5775b183fc50443fd300a1c00e2b0ed` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128v3_bench.cpp` | `0f580565e502915fee694b8a2586c22e9f74f6e1d94ed008314b3b23262cfdb3` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128v3_cyclecheck.cpp` | `eefeed0bcf670a5db76f536ca7bff4e30bff2176949f5b443b512e55ad959159` |  |
| `P4_ReviewMeasurements_20260905/mcl_vdf128v3_xplat.cpp` | `57feeb1680d4af37b748077d710947459ade0c76639c57f2eed01189540ac95f` |  |
| `P4_ReviewMeasurements_20260905/p4_sha256_chain_bench.cpp` | `872662766e34f7a5e2f67b1a4fc9e4a382a250edf0a1fbca6bf6d906563e546c` |  |
| `P4_ReviewMeasurements_20260905/p4_sha256_vs_t4_bench.cpp` | `d38320478d230291bebc3e5b1b2d289cb6f972c894b0745dcc8a6429af04e98a` |  |
| `P4_ReviewMeasurements_20260905/p4_sha256_vs_t4v3_bench.cpp` | `df4dd3b6e8de13685e19ac3ec438d217e3355e9a067611855f3c4de0f9de488d` |  |
| `P4_ReviewMeasurements_20260905/p4_tmto_toy.py` | `df1377d4b62f5bae92bb531a93dc357e0bc6162960e17de4c97bb8dcd81c5e6f` |  |
| `P4_ReviewMeasurements_20260905/p4_vdf128v2_kat.cpp` | `28f38551f00005d27634d4547552fd8eb4d616018186dee9a68ac12709fdba58` |  |
| `P4_ReviewMeasurements_20260905/p4_vdf128v2_weaklane.cpp` | `3a71f26cea40ec43f3f09a9a9a16a16cd9b9be04d6324e60b6f24a6ef381e3d5` |  |
| `P4_ReviewMeasurements_20260905/p4_vdf128v2_weakpair.cpp` | `a3e9fdf9acbca7370c479a630e0e7fe402ea5f8923d2f2eba32798c23756c76a` |  |
| `P4_ReviewMeasurements_20260905/p4_vdf128v3_distinguisher.cpp` | `c0cb7bb956681a99df2cd5edc64e1db020f77377b4eb50f96e89206ca18c819a` |  |
| `P4_ReviewMeasurements_20260905/p4_vdf128v3_kat.cpp` | `c263f9c44d5cc656cd208d64d83fb466dd6d71ebf0e21bef3cea801e867941ae` |  |
| `P4_ReviewMeasurements_20260905/p4_vdf128v3_weaklane.cpp` | `7ad87bcc590444a09fe2a5b98c7b84297ebca866a74d895242119537dcad92e7` |  |
| `P4_ReviewMeasurements_20260905/p4_vdf128v3_weakpair.cpp` | `4f374c2b8e6a154a4932781e910f771af4053f6fcf8969d1b6ba535640f2f167` |  |
| `P4_ReviewMeasurements_20260905/q30_lut_int32le.bin` | `f78c9584e5686cb1f54f382b1bfcf87c3399ae19f987e7761f339bdb3bd7dd1d` |  |
| `P4_ReviewMeasurements_20260905/run_v3_all.sh` | `fed8b5fe4477d931d59b70d016350f64406ad01bae1b67c9fbd5041a69156ca0` |  |
| `P4_ReviewMeasurements_20260905/sha256_chain_bench_apple_20260905.log` | `239a4a7fbb810b510b9ebf6d8ff07dd60b361aabef55d2468316fa959bf98a87` |  |
| `P4_ReviewMeasurements_20260905/sha256_vs_t4_bench_apple_20260905.log` | `a0331d60e0d388e0bc26f7d5b7156f2e1de36aa6f4c6f9cff9b7093478be3c6a` |  |
| `P4_ReviewMeasurements_20260905/sha256_vs_t4_bench_idle_apple_20260905.log` | `14f35a587d371a5729d79c344645da549778c519337fa859d31d3563bbb883e9` |  |
| `P4_ReviewMeasurements_20260905/sha256_vs_t4v3_bench_apple_20260905v3.log` | `23234fdec89fbadbad8b074f8a100f6a9082fd2e1263c14901aa1c977061ebd2` |  |
| `P4_ReviewMeasurements_20260905/tmto_toy_apple_20260905.log` | `2272e3c16cbe8201855c32a911cf45a70ae79fe61e9602eaa2b78068c3da9fe7` |  |
| `P4_ReviewMeasurements_20260905/vdf128_t4v2_standalone.cpp` | `3b7f28a5ac73c97245c3f50e03aab74dc10385f369e8b9341e93dba376f0e7d2` |  |
| `P4_ReviewMeasurements_20260905/vdf128_t4v2_standalone_apple_20260905.log` | `db6ace2a3197549100b1fd02f9c1b23228abb33ffa9a1b6f1a43e47c6720d4ce` |  |
| `P4_ReviewMeasurements_20260905/vdf128_t4v3_standalone.cpp` | `34906621a6aeabf8284a341d993f73e144d5898a1c3cc22b3078b93726034ae5` |  |
| `P4_ReviewMeasurements_20260905/vdf128_t4v3_standalone_apple_20260905v3.log` | `8e049b6474e7afa4019f8de2ae33dd556bdc7dceb1ba8aa26644a87669516941` |  |
| `P4_ReviewMeasurements_20260905/vdf128_t4v3_standalone_linux_glibc_20260905v3.log` | `8e049b6474e7afa4019f8de2ae33dd556bdc7dceb1ba8aa26644a87669516941` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_battery_apple_20260905.log` | `c11dbe50318ddc6d34a9f10fd86aabb47e14799f5aab9e9eca3446a75a4500d0` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_bench_apple_20260905.log` | `ba35222678ef737eb7f2f2238ecfedc94970d662157600c8f7ae1765d8c47e9f` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_cycleprobe_apple_20260905.log` | `5150cbd452b67ca05c03c6bcb5f40bc23615215751612a40307585f485b4e358` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_kat_apple_20260905.log` | `ad25753aa01278a6679b89b8ab887a6e7da2632ab6ce37f17e5a11af58d58be0` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_kat_linux_glibc_20260905.log` | `ad25753aa01278a6679b89b8ab887a6e7da2632ab6ce37f17e5a11af58d58be0` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_weaklane_apple_20260905.log` | `9573e8b90e34c709c5344f6a834291fc4acf8198890a47bb0a82858b9931a1e6` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_weakpair_apple_20260905.log` | `d237035e216be8acb54e0ce41f32301062b8b54c2d60d6311e223773fa3027e7` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_weakpair_grind_apple_20260905.log` | `1ef86035ef568b4704c2784221c739a93545ab222f5fc1563695e25e5c99fe4d` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_xplat_apple_20260905.log` | `3e934b09990f744f849e8d7533006dc1b5d6c88d5f7f02f235e54202133ee795` |  |
| `P4_ReviewMeasurements_20260905/vdf128v2_xplat_linux_glibc_20260905.log` | `9016a4fa2ed1b1594457fdf3ae17fed38f20cf996b141ee4eb4441d6ec8d3a18` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_battery_apple_20260905v3.log` | `e852542032c6a58137f312eded0f2f0f7423502031e5c7ffe221d62ca3745b15` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_bench_apple_20260905v3.log` | `23800077453eba4342768b78fe440c9b3e01164671296b8ead8a97f9aea64af1` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_cycleprobe_apple_20260905v3.log` | `c5cae69affd019ff0126c90d968955632f55878235e57f20866416c7f5b85dcf` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_distinguisher_apple_20260905v3.log` | `8308128c267c43e6376bc5d17594f13e4a2e2d9231291e7e955d18879954cf98` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_kat_apple_20260905v3.log` | `7c2905397cb81f03019708fe72ec5f0e04fb0304d7b378ce52d2502d81b65b0e` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_kat_linux_glibc_20260905v3.log` | `7c2905397cb81f03019708fe72ec5f0e04fb0304d7b378ce52d2502d81b65b0e` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_weaklane_apple_20260905v3.log` | `6c5caccf76603d18f1b9c6db3fafa02a1735834ae8d0a9137b41d0cd06cda828` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_weakpair_apple_20260905v3.log` | `e22fc09dff3244245cacec62924b00d390c5f4473a3a43f33c3027f5b4e3b5ee` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_weakpair_grind_apple_20260905v3.log` | `f66687c58741f1a2aa3390eda14fe44cf94d44658ad15d6efb73561fd61354a2` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_xplat_apple_20260905v3.log` | `01468d7882a04fe10c64dda48e4c0dc1c5b4bc4236c4dafbbf8e4e84195a01c4` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_xplat_cell_arm64_O3_20260905v3.txt` | `a67ceae452df0d0d1ef92ab409d33124363bdc20173061c654badfe9450d6843` |  |
| `P4_ReviewMeasurements_20260905/vdf128v3_xplat_linux_glibc_20260905v3.log` | `d308f061a3b5e1d21c069bdd5193416bba5ee8c88db771ce9223de2f369b57f8` |  |

### P4_ReviewMeasurements_20260925  (36 files)

| File | SHA-256 | Note |
|---|---|---|
| `P4_ReviewMeasurements_20260925/README.md` | `da37c30419a132cf317f6aa3056e9c57f7404e99565f563d75a836e9875913eb` | P4 review measurements — 2026-09-25 (ت-134(أ): VDF128-T4 **version 4**, clocked map) |
| `P4_ReviewMeasurements_20260925/SHA256SUMS` | `610f317ac4bf239e6ef093fc96d4140cc83b4603a9d1fac6dca4762c4cbcd545` |  |
| `P4_ReviewMeasurements_20260925/_run1_direct_clock/vdf128v4_battery_apple_20260925v4.log` | `e6d824ad68e5cf259cc7b39e0616e0ade27d3f5c71c684858dda7593a1121dc6` |  |
| `P4_ReviewMeasurements_20260925/_run1_direct_clock/vdf128v4_bench_apple_20260925v4.log` | `bbb80939cd7115081f41861179451091e41e203ae5254796020f13f4ed804e61` |  |
| `P4_ReviewMeasurements_20260925/_run1_direct_clock/vdf128v4_kat_apple_20260925.log` | `933c8c00fea6926f4f003dc20057414d49e396673b40ea8716b40c8e3d1b45ea` |  |
| `P4_ReviewMeasurements_20260925/_run2_incremental_clock/mcl_vdf128_t4_v4_incremental.hpp` | `311d646bbcddef20e52237780a46aa574eb92f22030dd03c783229366b36f956` |  |
| `P4_ReviewMeasurements_20260925/_run2_incremental_clock/mcl_vdf128v4_bench_incremental.cpp` | `7d143ba571ecb813513fbf40eeaf8e5afb2248e05ba2f3341ca639bfbb3abb86` |  |
| `P4_ReviewMeasurements_20260925/_run2_incremental_clock/vdf128v4_battery_incrementalclock_apple_20260925v4.log` | `d122433a7227aca73091360bf836d1173f57e8bb581a61d045c5ea10e12a2a2d` |  |
| `P4_ReviewMeasurements_20260925/_run2_incremental_clock/vdf128v4_bench_incrementalclock_apple_20260925v4.log` | `7958b7e478b5ced9238afac23d176ac278aab8cd7d9e19157eaa3768479ccc71` |  |
| `P4_ReviewMeasurements_20260925/mcl_core.hpp` | `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80` |  |
| `P4_ReviewMeasurements_20260925/mcl_keyed_q30.hpp` | `71a0dbaf84725ac77d0b3f1eab5a40ba90c088e88df7d41aab19aed39a6f6512` |  |
| `P4_ReviewMeasurements_20260925/mcl_vdf128_t4.hpp` | `e08f702e2da92221588285a6a61ee2e48edfb63afbde8220fc3632fd2180ed0d` |  |
| `P4_ReviewMeasurements_20260925/mcl_vdf128_t4_v2.hpp` | `41171250455fa33e311c1484f4d5d4fb67699e2f6275551224f1d06c1f63716f` |  |
| `P4_ReviewMeasurements_20260925/mcl_vdf128_t4_v3.hpp` | `b46f1a1329ccbc4dc4eac02b930be7b71f74847800ed7c01358163d80f615439` |  |
| `P4_ReviewMeasurements_20260925/mcl_vdf128_t4_v4.hpp` | `209458cd6e04c56895f93ebf4131528d8b69ff6bac29ac87b07578c9047ce9a2` |  |
| `P4_ReviewMeasurements_20260925/mcl_vdf128v4_battery.cpp` | `40c7268b37290b80cd7fbf354cc3b113cf1f9c27ad8690abca07892b264eef53` |  |
| `P4_ReviewMeasurements_20260925/mcl_vdf128v4_bench.cpp` | `2753c39a4698c538246784cfd8b446ed5be2fe8b56487e446b07ad0e86b2f4f8` |  |
| `P4_ReviewMeasurements_20260925/mcl_vdf128v4_xplat.cpp` | `05ea43751e42c9c6022c2d38297c56144bee8163a238cbb85f725e061429b947` |  |
| `P4_ReviewMeasurements_20260925/p4_vdf128v4_distinguisher.cpp` | `8653b85685f57d9d2ba93e1e32ae40224b7adef475daae832d041bc1ef9c8f5b` |  |
| `P4_ReviewMeasurements_20260925/p4_vdf128v4_kat.cpp` | `86b46950565fc1ca4e1d40ae5573da11004b1fcbe65a1ac0f08295c00919b04b` |  |
| `P4_ReviewMeasurements_20260925/p4_vdf128v4_weaklane.cpp` | `b3f84f7a38b557466c2c9410c5f65853d1a98b92420f0702fe05bc1005cda481` |  |
| `P4_ReviewMeasurements_20260925/p4_vdf128v4_weakpair.cpp` | `cbf8b36a8c6133faf8357ebde1ce52687143603fa35c10352fd82c8e250d8198` |  |
| `P4_ReviewMeasurements_20260925/q30_lut_int32le.bin` | `f78c9584e5686cb1f54f382b1bfcf87c3399ae19f987e7761f339bdb3bd7dd1d` |  |
| `P4_ReviewMeasurements_20260925/run_v4_all.sh` | `8324345d4955b8f6eceffa39974658c467507022351dc2fee7e2053a5018f9e1` |  |
| `P4_ReviewMeasurements_20260925/run_v4_all_20260925.log` | `edf5b68edec7e5352c2ce812f23708559281533e562d5e1c1917a85048ce5ac9` |  |
| `P4_ReviewMeasurements_20260925/vdf128_t4v4_standalone.cpp` | `167d3639bbd9ee7a76c17e2bec37e0fea4b4b016e5d4ec122dcd4d9e67d96812` |  |
| `P4_ReviewMeasurements_20260925/vdf128_t4v4_standalone.template.cpp` | `37118377338f663af1591fa2ac4b3c0c02269e4724a771e2725e216c4263d618` |  |
| `P4_ReviewMeasurements_20260925/vdf128_t4v4_standalone_apple_20260925v4.log` | `2baa6ed38868ba2188d7c2a2041750186567b1e6df431f2621b73b3b87909543` |  |
| `P4_ReviewMeasurements_20260925/vdf128v4_battery_apple_20260925v4.log` | `e6d824ad68e5cf259cc7b39e0616e0ade27d3f5c71c684858dda7593a1121dc6` |  |
| `P4_ReviewMeasurements_20260925/vdf128v4_bench_apple_20260925v4.log` | `bbb80939cd7115081f41861179451091e41e203ae5254796020f13f4ed804e61` |  |
| `P4_ReviewMeasurements_20260925/vdf128v4_distinguisher_apple_20260925v4.log` | `ee0666c7d078bc3589dcd0da80f236945b968e2f142abee456ceb0f4027d751c` |  |
| `P4_ReviewMeasurements_20260925/vdf128v4_kat_apple_20260925.log` | `933c8c00fea6926f4f003dc20057414d49e396673b40ea8716b40c8e3d1b45ea` |  |
| `P4_ReviewMeasurements_20260925/vdf128v4_weaklane_apple_20260925v4.log` | `61bd99f3a82028b609e87a26015626ce7a5cade19378b4a3ac812dab343d604d` |  |
| `P4_ReviewMeasurements_20260925/vdf128v4_weakpair_apple_20260925v4.log` | `b68e866f4e65f65367423b4440063ee639faccee68189505dd06195bb30e7521` |  |
| `P4_ReviewMeasurements_20260925/vdf128v4_weakpair_genuine_apple_20260925v4.log` | `901e80de93ce168fa0ae3237f18e4a03ae12b665de0e8754b016b28df80bf0d2` |  |
| `P4_ReviewMeasurements_20260925/vdf128v4_xplat_apple_20260925v4.log` | `beb84830be44353cb899f0bfbb16ae5931489b24d13f3bba451da12c959f2371` |  |

### P5_HDVerify_FULL_20260904  (6 files)

| File | SHA-256 | Note |
|---|---|---|
| `P5_HDVerify_FULL_20260904/README.md` | `ec89b56572427f07ccf414a3be831391a0920995676cf415376284523ad983be` | P5 §IV.E — حملة FULL (9,702 مرشّحاً) على محرّك السجل v8.1.3 |
| `P5_HDVerify_FULL_20260904/coprime_frac.cpp` | `13b5a35c58f29dfa9e745dc0794af30cbc5e33bc86b270374281f3dce9250d48` |  |
| `P5_HDVerify_FULL_20260904/coprime_frac_2e5.log` | `492a54a6847e75e3d2f5f8707fb19bad8bf0dba0bcf7b3bccf99feb6d6fe8126` |  |
| `P5_HDVerify_FULL_20260904/hd_throughput_v8.1.3_M1Pro_20260904_run1.log` | `129820ecec072eee763c17681b9b98d7bb7c6f26038bef1cce34e51883af37e9` |  |
| `P5_HDVerify_FULL_20260904/hd_throughput_v8.1.3_M1Pro_20260904_run2.log` | `fdc0166e1c7c7fc77b555e09b7a7be961fa45bc259b9f364f086be5856841335` |  |
| `P5_HDVerify_FULL_20260904/hd_verify_FULL_v8.1.3_20260904.log` | `dc7e440a5f757d8e1c202bc83c7af6e8f93e9222952d20b8fa91c5943f074ec0` |  |

### P5_ReviewMeasurements_20260905  (33 files)

| File | SHA-256 | Note |
|---|---|---|
| `P5_ReviewMeasurements_20260905/G_entropy_20260905.log` | `c3bace30d5eb921d5e689fa06e807992afce63d87a1f87e4ef861d5c28687225` |  |
| `P5_ReviewMeasurements_20260905/README.md` | `604c944cb798a6711ff063c3ab6423121d4c212dd01cb110d0abcc533c01b5cb` | P5 review measurements — 2026-09-05 (TOPS-referee items Q3, Q4) |
| `P5_ReviewMeasurements_20260905/README_EN.md` | `c8f8d557d47afaa899cb7bc377d854598d56134c32a8df59af31d672e2132293` | P5 review measurements — 2026-09-05 (English summary; Arabic detail in README.md) |
| `P5_ReviewMeasurements_20260905/SHA256SUMS` | `64100640b3cd5f65e8ec986dd7946e08d334616e55522350d5c317ed1f1f69ab` |  |
| `P5_ReviewMeasurements_20260905/adversarial_20260905.log` | `91d8551f6bfae8ed65dd48c1296c6c8816cbd58e40f20802b58568106dacfe4e` |  |
| `P5_ReviewMeasurements_20260905/adversarial_20260930.log` | `3b6a5fd80e5582d6283562fb9d89a30d682f1046528646b5e9130db9c8b90c79` |  |
| `P5_ReviewMeasurements_20260905/burnin_curve_20260905.log` | `3755e13cceef723688d1716518a52d1bf35c9590047e019660c049fea5c5cf57` |  |
| `P5_ReviewMeasurements_20260905/burnin_curve_v2_20260905.log` | `2898fa58a7fa45afff950cccdb2b282a853a71a63b0f15f9d25c9abcd39b709e` |  |
| `P5_ReviewMeasurements_20260905/ct_sine_cost_20260905.log` | `08af81ad5332b04c1fe62a15a9c7269d925d51d9ab81219b3a85e178cabc585e` |  |
| `P5_ReviewMeasurements_20260905/hd_throughput_v1_quiet_20260905.log` | `243f8f170162352d16b23195effd591fec66f96f804003b1e9eaf0d39bcab6c3` |  |
| `P5_ReviewMeasurements_20260905/hd_throughput_v2_quiet_20260905.log` | `1c07ef2e3fcb2507f977905319287afc2786799165f5e8a938f453793122f165` |  |
| `P5_ReviewMeasurements_20260905/header_patch.diff` | `1a06b57111ab4ec4a27d3c4d3a31a791157817ec2b5fa29fddb8af80d93575d3` |  |
| `P5_ReviewMeasurements_20260905/mcl_hd_throughput.cpp` | `7d922b50ea6b6d041f8a8a5a978f4dce48757d0352b6b2fff9f7c22320caebd4` |  |
| `P5_ReviewMeasurements_20260905/p5_G_entropy.cpp` | `d8232c4eecb747ae7ec07ee6f7d5c28096fb95413aec467f2de9a5f5879440d9` |  |
| `P5_ReviewMeasurements_20260905/p5_adversarial.cpp` | `c1c7925899d6962b71ac12df4635455c6bd8e87b5e836eea182ace22e2d111bf` |  |
| `P5_ReviewMeasurements_20260905/p5_burnin_curve.cpp` | `99cadc2c5956b2a4bfd2a0ba72c2eaa186f4861829d02b9b1cb740326f3719b0` |  |
| `P5_ReviewMeasurements_20260905/p5_burnin_curve_v2.cpp` | `f2c39c4936f4cec3ed5b15c800c5de5f96e62fa3ffd0bf9a2ddef8a081563a2e` |  |
| `P5_ReviewMeasurements_20260905/p5_ct_sine_cost.cpp` | `32b5a2bb058169eacb6598d75d260e5c002b62c5284a05f28f00ed33ad71518b` |  |
| `P5_ReviewMeasurements_20260905/p5_parity_lock.cpp` | `80e447142df634d6742be9395cdb6b1f31205a4e215b9c6f97210bc841c72642` |  |
| `P5_ReviewMeasurements_20260905/p5_resonance_control.cpp` | `aed41340b9385ff47b72e94f11e30df644b916d467ac1b58f8d33044b07e5691` |  |
| `P5_ReviewMeasurements_20260905/p5_system_eval.cpp` | `9c95a26e2830932eaed838a226b22bd653987eddb37f2a6479932c4f14942ba0` |  |
| `P5_ReviewMeasurements_20260905/p5_v2_coprime_parity.cpp` | `38eb19642c0d1171c3f600cc1039c85265ec6efad4f2d272b0369f53d7ea6949` |  |
| `P5_ReviewMeasurements_20260905/p5_weight_probe.cpp` | `08a270fa30d6db9bbc8deeaceb8cac7aa28c21e4ae6daa73e55205f02945a75a` |  |
| `P5_ReviewMeasurements_20260905/redraw_rate.cpp` | `674a1140c67efcb0d72bab48ee0d4cdabc3119fa4b0b8ef5007a3eaa4e1d4fce` |  |
| `P5_ReviewMeasurements_20260905/resonance_control_20260905.log` | `fa44244a920762747ea9f0f81cbb250ccf4315ed85105eab9d6dee4e9279473d` |  |
| `P5_ReviewMeasurements_20260905/results_v3_battery_q30_v8.1.3_20260905_arm64.txt` | `e063f867f69b6fe135d0bcdd9249763b867d85f01ffa28c857920016b22c5add` |  |
| `P5_ReviewMeasurements_20260905/results_v3_battery_q30_v8.1.3_20260905_x86_64.txt` | `0b7b9ebbe7a1890d1f7df10fe0116f18e6b815abecd693a4136e6c075075c9bb` |  |
| `P5_ReviewMeasurements_20260905/sibling_recovery.cpp` | `6e7a6f60c26ca907cefe7f00153eed9be416c4b1894ab62e9e75a923b2e241bb` |  |
| `P5_ReviewMeasurements_20260905/sibling_recovery.log` | `dda8d28f2226beb2fdc60f59718aaf7e3cf6d6f3ad8fe99bf821384e6da1597c` |  |
| `P5_ReviewMeasurements_20260905/system_eval_20260905.log` | `199730e36baa526c82980c3da0cf7fe6488890cd910b6cb274dab029a3ffd01a` |  |
| `P5_ReviewMeasurements_20260905/v2_coprime_parity_20260905.log` | `021b8c1307227f57b71167e7e3e6e2f863ab89b0413c1307c324eee268a5e0d5` |  |
| `P5_ReviewMeasurements_20260905/weight_probe_20260905.log` | `9d41d84e3f0cb88cba6330a3fd64ca31f66cc579abe2f63eb0afd5df9f38b782` |  |
| `P5_ReviewMeasurements_20260905/weight_probe_sidecar_scratch_ctor.diff` | `b10a8d5135577bbc0b3f55a8a0bd4341eb2129c3a83d31bd519ca495e496c53c` |  |

### P5_ReviewMeasurements_20260925  (4 files)

| File | SHA-256 | Note |
|---|---|---|
| `P5_ReviewMeasurements_20260925/README.md` | `5a30cd7724ff989c83a455c57b2049081736fa5a1f7e8c3773b1ee3c251d8b1a` | P5_ReviewMeasurements_20260925 — Paper 5 §V.A verifier under state loss |
| `P5_ReviewMeasurements_20260925/SHA256SUMS` | `3ead0d6cf6d595046c682f922819736ae6e7ef1832f8e11ba023e3d8dff730d2` |  |
| `P5_ReviewMeasurements_20260925/mcl_txauth_verifier_state.cpp` | `905ce2c1718cce6c966b8659e7eaf2a352ba6a4e68751ea266ee9a8079fb57d1` |  |
| `P5_ReviewMeasurements_20260925/verifier_state_apple_20260925.log` | `7d985522aa1dc0b314fa750442d759548c59da466e5f131e2f09b18150629b6d` |  |

### P5_ReviewMeasurements_20260930  (8 files)

| File | SHA-256 | Note |
|---|---|---|
| `P5_ReviewMeasurements_20260930/README.md` | `2164e19c2679425931215e38ca2da3a3edba2171503de57b39be3a0f5217db39` | P5_ReviewMeasurements_20260930 — records produced during the fresh-examiner read of Paper 5 (2026-09-30) |
| `P5_ReviewMeasurements_20260930/SHA256SUMS` | `b8164ea6a2f2ae004c9c0d0b459180f1986941d079997ba949fb803d27855ffe` |  |
| `P5_ReviewMeasurements_20260930/derive_v2_identity_collision.py` | `d91c358c1547dc4eb52b583b2119cb66d5963c8f276c1be5ba8970376d7045ee` |  |
| `P5_ReviewMeasurements_20260930/derive_v2_identity_collision_20260930.txt` | `1929a83f8314c5771a8c68cb21c6c92e3b9393073f43fb1dc01f80ee1b3a3fc6` |  |
| `P5_ReviewMeasurements_20260930/parity_lock_20260930.log` | `451fc6353438458eeaa3f4cb081741e743fef40a5db81993bee6e87e6b938393` |  |
| `P5_ReviewMeasurements_20260930/redraw_rate_20260930.log` | `55f240e70ac52da48b809ac5cc60597a7e95c3a7f57352afcecfed5dc17d47f9` |  |
| `P5_ReviewMeasurements_20260930/redraw_rate_v2_20260930.log` | `24a7adca0ccf8959828bc1b6ae4ac31c39b116689ec768205bdf0df6b440c43d` |  |
| `P5_ReviewMeasurements_20260930/results_v32_q30_native_arm64_FAR1e6_20260930.txt` | `79f882424a313bd3575d42f5e7211bc290d2c20cb1091bccfee3ec207d4f2598` |  |

### Quantum_Structural_Analysis_20260927  (11 files)

| File | SHA-256 | Note |
|---|---|---|
| `Quantum_Structural_Analysis_20260927/README.md` | `477aa67a5fdb71782c74648b718342bd9426bd2ace6000a62ce7dfca1f1e27d2` | Quantum_Structural_Analysis — structural inventory and Grover resource model |
| `Quantum_Structural_Analysis_20260927/SHA256SUMS.txt` | `77c2551f0715a3b16616511b38259546d326462fd1c0dbb55ce8be4491ca3f2d` |  |
| `Quantum_Structural_Analysis_20260927/grover_ref.py` | `785068b07f3c07398fa14676b0f028e6ff05989fd99e857b1aa32bed8fbbd57b` |  |
| `Quantum_Structural_Analysis_20260927/grover_ref_check_20260928.log` | `4307e2142678e07d03deb2a04e52c2a80cffe352968be4de0f2e5eb7e9357df2` |  |
| `Quantum_Structural_Analysis_20260927/grover_rev3_20260928.log` | `a2b4b511a167a30787c22a1a53714a6826bf0992af28ee5d696fc4d559bbf24e` |  |
| `Quantum_Structural_Analysis_20260927/host_20260928.txt` | `38d5e7e4adb0c8e7be170738ed9759f20e0a18ab32a8e0080bcdedceb9ed5e5f` |  |
| `Quantum_Structural_Analysis_20260927/mcl_grover_resource_estimate.cpp` | `e6d72996ee1bb57a5462717a802945faadea54032956a508d311ce32a9a17325` |  |
| `Quantum_Structural_Analysis_20260927/mcl_qstruct_inventory.cpp` | `50c745ac48fcb46da98ff5d5bcd2f878fad05309a890744da2944317e2d4ab26` |  |
| `Quantum_Structural_Analysis_20260927/qstruct_rev3_20260928.log` | `6e028fa9ffed609b577708b9f4bc1a3e22870a2c3cd8bed23cd3366bae6c50bf` |  |
| `Quantum_Structural_Analysis_20260927/theory_rank_enumeration.py` | `4cb15218d19849c3e5c0dc60e8e1b3bc76ab9a3ca8e1e9da274bf0418a392e64` |  |
| `Quantum_Structural_Analysis_20260927/theory_rank_enumeration_20260928.log` | `7283ebc28998f208431d97e7d025d2f31e7401c474c04d8ea687d8bc7e5e95b1` |  |

### hd_v2  (5 files)

| File | SHA-256 | Note |
|---|---|---|
| `hd_v2/README.md` | `00ce5e1bff39ef63e9682faad18783132df0f41cbe210acc815da5d15284702c` | hd_v2 — Hierarchical channel-identity derivation, version 2 (additive sidecar) |
| `hd_v2/hd_verify_v2_FULL_v8.1.3_20260905.log` | `c6657165de79147c7b88bbf275825bd83c0ac69089ec9e14f3811094782c8260` |  |
| `hd_v2/mcl_hd_throughput_v2.cpp` | `96fbe730155af70ecc8c31930e63d9ce57801d05c096d30b7e84b655fc8022a8` |  |
| `hd_v2/mcl_hd_v2.hpp` | `e000af267d131e734d4c84a49272acaa7c6a6c53519d9d580a1feb7cbce97b7c` |  |
| `hd_v2/mcl_hd_verify_v2.cpp` | `12f9d5f868ec6959907db243be4e2ee77086338154632d986b09faa66b56532a` |  |

---
*Generated by `gen_manifest.py` (kept in the staging `_build/` folder, not part of the repository). The 23 root `.cpp` files differ from v0.1.0 only in the `Patent Pending` banner line(s) (+ PCT/IB2026/058860), except `mcl_postquantum.cpp`, which is version 6.1.0 since v0.2.15, and `mcl_txn_verify.cpp`, whose comments were reworded in v0.2.16 (no code change).*
