# MCL — Public Code Archive · MANIFEST (v0.2.8, 2026-09-06)

**Engine:** `mcl_core.hpp` — Version **8.1.3** (2026-08-22) — SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80` — MD5 `5d8b49ee11aa0bfb8b0bda3f47fa16e3`  
**Keyed integer sidecar:** `keyed_q30_PQ/mcl_keyed_q30.hpp` — **v1.0.6** — SHA-256 `71a0dbaf84725ac77d0b3f1eab5a40ba90c088e88df7d41aab19aed39a6f6512`  
**VDF128-T4 header:** `VDF128_T4/mcl_vdf128_t4.hpp` — SHA-256 `e08f702e2da92221588285a6a61ee2e48edfb63afbde8220fc3632fd2180ed0d`  
**Author:** Madeeh Ibrahim · ORCID 0009-0002-8562-8325 · madeeh.chaotic.lock@gmail.com  
**License:** PolyForm-Noncommercial-1.0.0 + Security Research & Evaluation Grant · Patent Pending PCT/IB2026/052737, 053253, 053673, **058860**

Open reference engine + every verification / reproduction program and evidence record cited by Papers 1–5, plus published self-cryptanalysis (including negative findings). Active dual-use attack tooling is NOT here (gated per `TOOLKIT_ACCESS_POLICY.md`, 7 files). Previous release: v0.1.0 (2026-06-01, engine 6.0.0 MD5 `241db79ecf8a42897eb9a8399cf37929`); see `CHANGELOG.md`.

## Cross-platform reproducibility anchors (re-verified on 8.1.3, 2026-08-22)
- Float64 CRC-32 (T2 default (3,5) 10KB): Linux `0xF5E977E0` · macOS `0x1A734C6F` (libm-dependent, non-normative) — `results/kat_gen_macos_v8.1.3_20260822.txt`.
- Q30 fixed-point (bit-exact NORMATIVE): init `0xC8AFD74A`/`0x0DB2BAC6`, 10k-iter `0x6F88C52E`/`0xE06C516C`, LUT CRC `0xDE1340CF` — `results/q30_macos_validation_v8.1.3_20260822.txt`.
- Keyed T4-Q30 (sidecar v1.0.6): commit CRC `0x58C99E3E`, cascade(m=7) `0xF7C81BC4` — suite 9/9 PASS — `results/keyed_q30_test_v1.0.6_20260822.txt`.
- Engine self-test: 7/7 KATs PASS — `results/self_test_v8.1.3_20260822.txt`.

## Build
```
g++ -O3 -std=c++17 -march=native -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
    -DMCL_UNSAFE_ALLOW_INVALID -o <name> <name>.cpp -lm   # root programs (+ -lpthread where noted)
clang++ -std=c++17 -O3 -I. -I keyed_q30_PQ -I VDF128_T4 <folder>/<name>.cpp -o <name>   # sub-folder programs
```
Build notes (syntax-checked 2026-08-22, Apple clang 16, all 87 `.cpp` files): `keyed_q30_PQ/mcl_keyed_q30_lyap_sweep.cpp` and `mcl_keyed_q30_mpfr_lyap.cpp` need GNU MPFR/GMP (`-I/opt/homebrew/include -L/opt/homebrew/lib -lmpfr -lgmp` on macOS); `keyed_q30_PQ/mcl_keyed_q30_dump_weights.cpp` needs `-DHDR='"mcl_keyed_q30.hpp"'`; all programs in `p2_hardened_auth/`, `p5_hardened_txauth/` and `P3_CrossPrediction/mcl_gen_series.cpp` use Apple CommonCrypto (macOS only — the engine itself is portable). Python helpers need numpy (and scikit-learn for `xpred.py`). The `results/*.txt` of the 23 root programs are the June-2026 records (engine 6.0.0, KAT-identical to 8.1.3); only the 8.1.3 / v1.0.6 re-runs named above were regenerated.

## NOT in this archive
- Gated adversarial toolkit (7 files; `TOOLKIT_ACCESS_POLICY.md`): `mcl_attack_suite`, `mcl_steganalysis`, `mcl_adv_attack`, `mcl_simswap_verify`, `mcl_extraction_security`, `mcl_neural_distinguish.py`, `mcl_simswap_v3` (record + logs of the last one ARE public in `p2_hardened_auth/`).
- Out of scope (as in v0.1.0): June-2026 lattice/return-map attack scripts, `SideChannel_Screen/` CPA tooling, the nine `VDF_security/` probe programs. Compiled binaries and the duplicate v6.0.0 engine copy of `M1_M2_apple_verification/` are not shipped.

## File inventory — 585 files (+ this MANIFEST), SHA-256 of every file

### (root)  (46 files)

| File | SHA-256 | Note |
|---|---|---|
| `.gitignore` | `ff986180e02708b88a774a1f0b60785b5c1b6d15db371d8b992b198fcf3fdb57` |  |
| `APPLY_GUIDE.md` | `754cbc1d15713c292648e686d643e919882653dfe2cd88fc791c641baa96b957` |  |
| `CHANGELOG.md` | `889ee9dcfe3eaa0c2d7e4795d8bba3a308181816a1aea850dc99814cc156bd70` |  |
| `CITATION.cff` | `65b632e43fc33e0cb8b85f6aac84f49533856249178b3e8421b58f8b05856362` |  |
| `CLA.md` | `975fe9c31ca4bb96cdcb427f2c62ed2fb46a3df443bff8a80f294aa619d06129` |  |
| `CODE_OF_CONDUCT.md` | `da98355a1277938de1cfededa9beaaa2a56e63dba34f97f65e5a05a2d3102c43` |  |
| `COMMERCIAL.md` | `712b2c98fcfb0a75f80df9c4f0ab3461339777da9e57b5408974ca83a22a97e5` |  |
| `CONTRIBUTING.md` | `238434c313a101b7ada8073ddfbf5fd4eec0b2248f4d3932641249dba1e705b9` |  |
| `GOVERNANCE.md` | `4e1cf312a4805452d4f41c9bc402add0b0e8547cc24b1cb64a7eea9c0704c1e6` |  |
| `HALL_OF_FAME.md` | `fb4eaf6b0b33659a57d9f553efb09e5c9c3e98fd19702275433d5fd30d911117` |  |
| `LICENSE` | `839932d57880e179074222334b1a3d1ae7117feaea0f36020580dc73f6a9f76f` |  |
| `NOTICE` | `2c5b00f021de5d1a79bcd5598a46f2cf62e4738a2719025850479fdead8e6399` |  |
| `PATENTS.md` | `c8034b61bd795351ae67d04395940de782c5e82f9cf2856a3f7d03cf2a101bb3` |  |
| `README.md` | `836ae4cc7137ed946d09caee028d42b9d4695e3d0cb07d42f0df369cf536ec00` |  |
| `RETIRED_mcl_txn_verify.md` | `589742fcc12b80332c2478e21e51658bd243e6de9308e08ac22d90d1bffbddd0` |  |
| `REUSE.toml` | `805bea6173d163f417b8097f162d2978deae445f1c21e3ea62cd284c2b40768b` |  |
| `SECURITY-RESEARCH-GRANT.md` | `24a8609549aec66bbb18126a015e3513332bc665b7dd1154501707e70ac816e3` |  |
| `SECURITY.md` | `fb923ca3236106a55b6c62e9ba404a46b1054b9f6338884425af82af0048dd37` |  |
| `TOOLKIT_ACCESS_AGREEMENT.md` | `3cf1b9ac0ecf0b2b3aeebb98728dbedaabb1e9342106662fd661215b16d7c08e` |  |
| `TOOLKIT_ACCESS_POLICY.md` | `83a93bc5db57c8a49c18df96a36772c725fab173984fca543dac525d618e1433` |  |
| `TOOLKIT_ACCESS_REQUEST_TEMPLATE.md` | `2da1c63b20eadbb243d187550b0f7372ebaccebb16a56abccb57eb1ee4ef9225` |  |
| `add_spdx_headers.sh` | `74ee8ace7e6a8f65957d57b6860acfd7f4eebc370d0f8e46a9b9cbd793cc7c2b` |  |
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
| `mcl_postquantum.cpp` | `9d0cabcd21b9d9556d5bca5de352d50328151abf4855b220d2f6b5590244ee62` | Verify MCL's resistance to quantum computing attacks. |
| `mcl_practrand.cpp` | `0371f203f1993ece26347395a192ee8f71a2992c0a44111ac9ccfa621ecefb57` | Stream cryptographic-quality bytes from the MCL_T2 engine to |
| `mcl_reference.cpp` | `140ee9a39a3224e8faf9c0323fc0ba66f5eaadaf23fce6c33e6bcf28dea9167d` | Canonical reference implementation of the MCL coupled chaotic |
| `mcl_safe_zone_verify.cpp` | `13e2893008f1591bf9bf88943a99de6ea0e80b5b3d43c930ee2a1377f5569214` | Empirically characterizes the Safe Zone bit-extraction regions of |
| `mcl_scale.cpp` | `740a207f27e301b8650c74ffc4f0502eff3a73083c389c32dc41a7c08c988526` | Verify MCL scales from 20 to 1M+ simultaneous orthogonal |
| `mcl_txn_verify.cpp` | `b839edf5edebeac19ba6861100c80975ea4ad27f0f254c070cb46f775697c1b7` | Experimental verification of non-replayable transaction |
| `mcl_vdf_falsification.cpp` | `25f24508227e4e41481291976d350e370d7291d1c1c3bdf6e1000df2aa9fa40c` | Four-attack falsifiability battery for MCL-VDF open problems OP1 (sequentiality), |
| `mcl_vdf_verify.cpp` | `c7e517e33647d802f8f485e5e2104d838b70de059fb32a1e29c24e339008e1ac` | Experimental verification of the MCL Verifiable Delay Function |
| `q30_macos_validation.cpp` | `d58b0c11796a4036e6b3a216b1a4d4784d7840385358b10c9a30c93fd32354f3` | Validate MCL Q30 (fixed-point engine) cross-platform bit-exactness |
| `self_test.cpp` | `9971324ad99bde6dea410b2f969443b85db07b77600ca797dd6d2eb2c9ca53bd` | Run the MCL engine built-in self-test verifying all Known Answer |

### results  (29 files)

| File | SHA-256 | Note |
|---|---|---|
| `results/MCL_Scale_v2.2.0_Test_Results_20260519.md` | `463fa96454594d69b7fcd6de7b8b3200049c27eed0cc8204834b4579b9ed68d4` | Consolidated documentation of FOUR independent runs of mcl_scale |
| `results/beff_deep_audit.txt` | `0fa5baf9f152d39af5b23f3bd3d2602d326ea141198a144ad272f9d436ecd11e` |  |
| `results/kat_gen_macos.txt` | `959fa8bde760d0957c18e5617c251025b012d21665f1d9e56fd89f9cbfe01733` |  |
| `results/kat_gen_macos_v8.1.3_20260822.txt` | `00732e5077696d503de2f01b31f3facf51c44bdf8f7230d98f3409a3a4a07f34` |  |
| `results/keyed_q30_test_v1.0.6_20260822.txt` | `bdd7b17d4b5c3ed7431da2cd37336ac4a4110f0dd48bc9bb6f07b020e944c17f` |  |
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
| `results/mcl_postquantum.txt` | `365f1bd4693015bd736f678b8063006dd7a53cee2d404d9602f4fdacbe795f4a` |  |
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

### keyed_q30_PQ  (33 files)

| File | SHA-256 | Note |
|---|---|---|
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
| `keyed_q30_PQ/NOSYM_V106_RECORD_20260822.md` | `bc56e7eb28a32ccf61947d87a1417ae87eba7c57e80cfe34a85ea6df9ce1abdb` | sidecar v1.0.6 — رفض التناظر القابل للوصول من البذرة في `mcl_t4_q30_params_from_key` — 2026-08-22 |
| `keyed_q30_PQ/README.md` | `7bc88cc5244b9882f8184dd1b2bb7f1531a7dca42307cbc9923df9cf232c9567` | MCL Keyed Q30 — FPU-free, key-bound, post-quantum extension |
| `keyed_q30_PQ/STATUS.md` | `4eb95618e0dd0163c1a9aa87a74fffa3af3a391dcac38958bf2c163e3184cc88` | MCL Post-Quantum / Keyed-Q30 — STATUS truth table |
| `keyed_q30_PQ/dump_keyN.cpp` | `ef0a8649cd46f413b631188b12b8457457b51464d0aca832a587010675d11672` |  |
| `keyed_q30_PQ/lyap_2osc_signcheck.py` | `c34b8e36fcbc2c773ad444e7f7b676a01789c32704873a0b66aa328d3922291d` |  |
| `keyed_q30_PQ/lyap_independent_check.py` | `77199d6bf3d0a46250daede2a1019eb5af03d5b17508a5cb1ce0730aebc5d8fc` |  |
| `keyed_q30_PQ/m0_codegen_probe.c` | `80c52b0977ec2fd6d35e7888685568c6fb7e237468f36bc117cd6b4cc9516606` |  |
| `keyed_q30_PQ/m0_probe.s` | `68dd9d08e9ec22bed614d9971d3b0d72163d26f8cb7dd711e0c9eca2ab04df50` |  |
| `keyed_q30_PQ/mcl_capacity_realization.cpp` | `a8fd2f87517f7ef13d19a51fa10ae4af236ec55343d4b83c4e535771b0041fc1` |  |
| `keyed_q30_PQ/mcl_keyed_q30.hpp` | `71a0dbaf84725ac77d0b3f1eab5a40ba90c088e88df7d41aab19aed39a6f6512` |  |
| `keyed_q30_PQ/mcl_keyed_q30_ct_test.cpp` | `6a56233a56c3ce1574cdc23f0d04e688bda2b73ab7441df75b97847137999db3` |  |
| `keyed_q30_PQ/mcl_keyed_q30_dump_weights.cpp` | `f09a2460cdf8e8e26d2f200363e16125949da1cd777db1337521148b0fd07f79` |  |
| `keyed_q30_PQ/mcl_keyed_q30_lyap_sweep.cpp` | `f354a9c90fea2484f848361e78bf8b1cfcb46bd3b8134e26391a050d0661cf72` |  |
| `keyed_q30_PQ/mcl_keyed_q30_measure.cpp` | `9eac29e89a6ebaa0311dd779f8333c1275b393b32254e4902e38b4bc6a9ad356` |  |
| `keyed_q30_PQ/mcl_keyed_q30_mpfr_lyap.cpp` | `20c29a2a9b3e913cd7b6490febf0f0c7263ed197272fbaa7387e5b3f79d4343b` |  |
| `keyed_q30_PQ/mcl_keyed_q30_nosym_verify.cpp` | `95551bcc1a48c8921184375e64e85fa64f12b4e915aa1edf83e4622458536ee2` |  |
| `keyed_q30_PQ/mcl_keyed_q30_science.cpp` | `5a33ab998204419c5eb608e9671f5dd9b55e59024c6651b83f90434fe1b0c6ac` |  |
| `keyed_q30_PQ/mcl_keyed_q30_science2.cpp` | `87e4b9ef6e2580b1642b5deba531d02f7c66310314b0ef2aad254493a43342dd` |  |
| `keyed_q30_PQ/mcl_keyed_q30_science3.cpp` | `9ca5703dc844fec31302e0f35b417afb502f3c3062646ab6b6881815e7d232d3` |  |
| `keyed_q30_PQ/mcl_keyed_q30_test.cpp` | `a123a0a667a8612f9b6e2092c72fc935807a0bc2fd82ee0deb781ccd8bc3d273` |  |

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
| `T4_CycleStructure/README.md` | `dc74d47a8cb0894dec7e771e03da8fc132d460485f50368d60ca77c5c725ae0d` | T4_CycleStructure — دراسة دورات محرك T4-Q30 بعرض حالة مُصغَّر |
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
| `ReturnMap_Attack/README.md` | `e7c890c3e0765571dea9ea094b18d256f4cced0c81e7301db5c1af33c5e40f55` | ReturnMap_Attack — محاولات الهجمات الخاصة بالفوضى (Rule 13 / Rule 7) |
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
| `p2_hardened_auth/SIMSWAP_V3_RECORD_20260821.md` | `28377126f3ea52f419335b58fae94daba561f0664a6594d45c5efb9393511744` | حملة SIM-swap على مسار الاشتقاق — الورقة 2 §V.B — 2026-08-21 |
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
| `p2_hardened_auth/mcl_auth_far_v4_keyed.cpp` | `905342683fbb07c142ba85124479668d1d2c059a92cf06b71c13d1b9733517d7` |  |
| `p2_hardened_auth/mcl_auth_hardened.cpp` | `8823800937297dafcbdd0cdfb04f00db46668e66859e936046f48d8d6da0a1cc` |  |
| `p2_hardened_auth/mcl_engine_sensitivity.cpp` | `5f89de5413a606bde798194fa20a7f67f2e956b5292e4b45e46b524f13385564` |  |
| `p2_hardened_auth/results_20260821.txt` | `bf65fa9fc185d4f9e9e22d5f47374bb0e04908f6978944b208d5604b079fc905` |  |

### p5_hardened_txauth  (25 files)

| File | SHA-256 | Note |
|---|---|---|
| `p5_hardened_txauth/ARCHITECTURAL_FINDING_20260821.md` | `6157f5386b774fb27e981bed15b37169ed5233dfdecc663ac663ab3ceb389ffe` | الإصلاح المطلوب وأثره على البراءة — الورقة 5 (والورقة 2 بالقياس) — 2026-08-21 |
| `p5_hardened_txauth/ARCHITECTURAL_FINDING_20260821_SUPERSEDED.md` | `491a17e6231b7737cdd8b60431f19de82ccd7a5dd67e7f2c56c429163abd3eeb` | نتيجة معمارية لازمة عن إصلاح D1 — الورقة 5 (والورقة 2 بالقياس) |
| `p5_hardened_txauth/README.md` | `f42a00c3d4ff3188118ae4311a3053288f3c8023dbba6a2bd9dad8c7f65b2b27` | p5_hardened_txauth — مسار الورقة 5 المصلَّد (v2) + بطاريته الكاملة |
| `p5_hardened_txauth/_v311_backup_mcl_txauth_v3_battery_q30.cpp.txt` | `e825f1daaa6f7053a751fe0242a13d805f88b1ef40e87d22185266fab0006a29` |  |
| `p5_hardened_txauth/_v31_backup_mcl_txauth_v3_battery.cpp.txt` | `f9ac7d3e2e8e12a83ff1e1aa61cccdc1fb0dd00f56c1d8a1c564ea7b75a40e30` |  |
| `p5_hardened_txauth/d1_collision_20260821.log` | `4c59d1fe0824525316554bce3cd6d7aa72aca0700bca51235ce545dfcf47d087` |  |
| `p5_hardened_txauth/mcl_d1_collision.cpp` | `6eedb6294d75d9020401f1f026e5806af56267e5d267a05fb0467e0673ae3b88` |  |
| `p5_hardened_txauth/mcl_txauth_hardened.cpp` | `1c8d66d063e18fb1b2673a55073de00da149301ffbf03e5be8354cb2d538af04` |  |
| `p5_hardened_txauth/mcl_txauth_v3_battery.cpp` | `c3909a1fbc0ec2da19c2b05f6bee04fb703f8816d8e6b765efdbd83e997e21cc` |  |
| `p5_hardened_txauth/mcl_txauth_v3_battery_q30.cpp` | `35009daa07447cd28ac680cf0bb2e191678b762b9f9af098fc23a0407dc96fd2` |  |
| `p5_hardened_txauth/mcl_txauth_v3_claim4.cpp` | `016843ee8949e0bac4bbcf21ca17f0e4cb1ef40147f08f4482ce99f8f72806ca` |  |
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

### M1_M2_apple_verification  (38 files)

| File | SHA-256 | Note |
|---|---|---|
| `M1_M2_apple_verification/NIST_STS_CAMPAIGN_README_20260721.md` | `f98279254621d763e51b22632219e6bad81879b9b16524c602619d636016a4cd` | NIST SP 800-22 Full Campaign — Doc ID MCL-NIST-STS-2026-0721-001 |
| `M1_M2_apple_verification/PAPER2_L2_VERIFY_RESULTS.md` | `ea19992131a69107115f9cc96f940ab4e6067f9c0e82270cbd3ff556016e390c` | Paper-2 L2 re-verification — definitive results (2026-07-06) |
| `M1_M2_apple_verification/README.md` | `40e9c0c006ba44c2f77dee66620fc8aec94935d18d01b20cb6260a60273aa3af` | M1/M2 Apple-libm Verification — Paper 1 §III.B.3 |
| `M1_M2_apple_verification/bifsweep_coarse_apple_20260719.csv` | `a96837f02b60f6fe9669cb65d8156ab4ca9ef0d56934532d6908226efa2d3fcb` |  |
| `M1_M2_apple_verification/bifsweep_fine_apple_20260719.csv` | `ebd7d1a3fbc58dc7952eda3e1148df94fb011de69eeb9a69e2737be3d6e73376` |  |
| `M1_M2_apple_verification/bytezone_scan_apple_20260704.log` | `39eebdc634d11186de5331e7759cce4f9e1b3f7b725b92b8a7aa3f79cf7094fb` |  |
| `M1_M2_apple_verification/detj_verify_apple_20260703.log` | `6e498469a9c65a0f51b782f7a3792f4003c82097d07b1d14b9e649858aa30ee2` |  |
| `M1_M2_apple_verification/fig1_arnold_sweep_apple_20260817.csv` | `c3e5c1a81eb4fe7d6d4680d221b9ec76008fe621ec560d68191f438761de57e4` |  |
| `M1_M2_apple_verification/hd_throughput_apple_20260817.log` | `79e302bc35e2da6b6d02cfbaf7adf97b501672c2e46d488e1e35e434f30b7a44` |  |
| `M1_M2_apple_verification/make_paper3_fig1_20260817.py` | `18a23837eb019afdff99f884c74d339cd190936a4d15ddfe2e58b9aff6e03b6f` |  |
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
| `M1_M2_apple_verification/nist_sts_finalAnalysisReport_apple_20260721.txt` | `9a03c1bf939b433bb0a1e4d7067b27e6a48f50ee67d82434e96dcc1a8143767f` |  |
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

### Verification_Suite  (29 files)

| File | SHA-256 | Note |
|---|---|---|
| `Verification_Suite/README.md` | `ac6a8505bfc877ff059054bf73e47cc5520ae8b9b5fe54487d7687ae8b470a8e` | Verification_Suite — legacy science/verification tests |
| `Verification_Suite/bench_diagnose.cpp` | `5852bf88575ff5011cd098b40a00ad14de278713bb50cafa31a6ecc0c726b330` |  |
| `Verification_Suite/mcl_auth_verify.cpp` | `6290a40aa40ccd0c306f324cad7716c40ef186aff7b5ae2b61b4bdf515e7ec7e` |  |
| `Verification_Suite/mcl_burnin_sweep.cpp` | `24982c1da2f41cc85d6e1f69e303b0f1c7fd934a832b3cc8d887cc2562ab1207` |  |
| `Verification_Suite/mcl_decimation_sweep.cpp` | `758875ed7676185f9bc3340982ccc8a0e3f4e94d5850cd6b2ac481f175223df6` |  |
| `Verification_Suite/mcl_gs_jacobi_independence.cpp` | `58a61680ce293f34a455367644fee005adb1fcabada260fd05b08164a34451ae` |  |
| `Verification_Suite/mcl_hex7_proto.cpp` | `2cc74f70b92b6074140c8e350ed72f4e45eb1f808d480c7aac2024a2fe83e5a8` |  |
| `Verification_Suite/mcl_hop_unified.cpp` | `c1d4d892bd001c4603f99bf0e44e03ac08ee37da417578c0a818159523f9adaf` |  |
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
| `Verification_Suite/results/mcl_hop_unified.txt` | `93126ee31ddee46bc0fefb8ea1660eaa3875809462f8fdd70b56612a248c76e2` |  |
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

### P3_DeskRejectMeasurements_20260905  (93 files)

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
| `P3_DeskRejectMeasurements_20260905/pairs_dist/__pycache__/pairs_ks.cpython-313.pyc` | `074a20d0a1ee9acf7b2198de85e1b42a9907e6c47bb5e9b66a5aefc476523c01` |  |
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

### P3_Fig3_Regeneration_20260903  (5 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_Fig3_Regeneration_20260903/RECORD_FIG3_20260903.md` | `08fa9679d5d004cf5842934cf371d4a33d40bd7138f43cc3b2ef059513d1e3a1` | Paper 3 — Figure 3 regeneration record — 2026-09-03 |
| `P3_Fig3_Regeneration_20260903/fig3_matrix.cpp` | `02ca769f39eaf06cb83149ef9a9c99af432ee5cbe81a7f4b22ea28235df3c181` |  |
| `P3_Fig3_Regeneration_20260903/fig3_matrix_seed12345678901234_20260903.csv` | `173db621c18f09fe1b4ac385cbb37ead93e996e1a48e065fafcf0b409d99c25d` |  |
| `P3_Fig3_Regeneration_20260903/make_paper3_fig3.py` | `3281ce36d30f47b1a8c6f6fd963f99ecd1397d39bdbcdf3a55d991deea827182` |  |
| `P3_Fig3_Regeneration_20260903/paper3_fig3.png` | `110cc7b0de4bfcea428acfdca99267cd7e505427422c5f86c33d7fbe21b8092a` |  |

### P3_NonlinearDependence_20260603  (15 files)

| File | SHA-256 | Note |
|---|---|---|
| `P3_NonlinearDependence_20260603/.DS_Store` | `cb462ff909e4a54f274ed4db9088836bfb5a08f38361b5219f9cdc64f0a7fc63` |  |
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

### P4_ReviewMeasurements_20260904  (27 files)

| File | SHA-256 | Note |
|---|---|---|
| `P4_ReviewMeasurements_20260904/README.md` | `52971016848040c4e9bfdb82b81174bbb77f8da802d210aeb20755dcffcbc6e1` | P4 review measurements — 2026-09-04 |
| `P4_ReviewMeasurements_20260904/SHA256SUMS` | `de56565726bba2617fbc856f9ed8aaa1805ebf91faf34a68c70c2722e32cc5d8` |  |
| `P4_ReviewMeasurements_20260904/appendix_vectors_apple_20260904.log` | `6842ff30259895bb4836956b36518b4a5124c389ef106e6c4e8ad2a9feb18f20` |  |
| `P4_ReviewMeasurements_20260904/appendix_vectors_linux_glibc_20260904.log` | `c5b5a94512468305913eaa863d764a3518e835b0d5931049a24f6f9ea4f6bfd8` |  |
| `P4_ReviewMeasurements_20260904/det_ratio_apple_20260904.log` | `8b00e2651a4fba5f9ee595e061195d00a5cf2a6ae5dc6d722667bb5493d1c15a` |  |
| `P4_ReviewMeasurements_20260904/gs_jacobi_pearson_apple_20260904.log` | `e4c63f7170891a98f7cc858a635ce732697d9504fbe158cf0bea64e7f02916cc` |  |
| `P4_ReviewMeasurements_20260904/lut_digest_apple_20260904.log` | `0251d06c8c2bd85489c80cfbf49135a326156aec43e50f0503540ddbf8ea1620` |  |
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

### P4_ReviewMeasurements_20260905  (63 files)

| File | SHA-256 | Note |
|---|---|---|
| `P4_ReviewMeasurements_20260905/README.md` | `98f24f93d171296b0df30ab50b46481df7cc6715ff411d39f97b13e1fd31f556` | P4 review measurements — 2026-09-05 (referee-eye round R4: VDF128-T4 **version 2**, per-input weights) |
| `P4_ReviewMeasurements_20260905/SHA256SUMS` | `29793f78b120ab923423623207efa4959b59560c4b109aa3ec049d14e1dd9710` |  |
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
| `P4_ReviewMeasurements_20260905/run_v3_all.out` | `bacc1be72b258a9cea61eba86c60ff4618c1d2f187aa36177a2413e18d55c8ce` |  |
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

### P5_HDVerify_FULL_20260904  (6 files)

| File | SHA-256 | Note |
|---|---|---|
| `P5_HDVerify_FULL_20260904/README.md` | `6cc92fcb144f4d7baa09f308fa5947a9c0fb21c64af82e4a7fe1366c5dcde642` | P5 §IV.E — حملة FULL (9,702 مرشّحاً) على محرّك السجل v8.1.3 |
| `P5_HDVerify_FULL_20260904/coprime_frac.cpp` | `13b5a35c58f29dfa9e745dc0794af30cbc5e33bc86b270374281f3dce9250d48` |  |
| `P5_HDVerify_FULL_20260904/coprime_frac_2e5.log` | `492a54a6847e75e3d2f5f8707fb19bad8bf0dba0bcf7b3bccf99feb6d6fe8126` |  |
| `P5_HDVerify_FULL_20260904/hd_throughput_v8.1.3_M1Pro_20260904_run1.log` | `129820ecec072eee763c17681b9b98d7bb7c6f26038bef1cce34e51883af37e9` |  |
| `P5_HDVerify_FULL_20260904/hd_throughput_v8.1.3_M1Pro_20260904_run2.log` | `fdc0166e1c7c7fc77b555e09b7a7be961fa45bc259b9f364f086be5856841335` |  |
| `P5_HDVerify_FULL_20260904/hd_verify_FULL_v8.1.3_20260904.log` | `dc7e440a5f757d8e1c202bc83c7af6e8f93e9222952d20b8fa91c5943f074ec0` |  |

### P5_ReviewMeasurements_20260905  (32 files)

| File | SHA-256 | Note |
|---|---|---|
| `P5_ReviewMeasurements_20260905/G_entropy_20260905.log` | `c3bace30d5eb921d5e689fa06e807992afce63d87a1f87e4ef861d5c28687225` |  |
| `P5_ReviewMeasurements_20260905/README.md` | `ee5f4b82c1706617f44fab35389026c1349b662aad3aba40bcc57d539c13d144` | P5 review measurements — 2026-09-05 (TOPS-referee items Q3, Q4) |
| `P5_ReviewMeasurements_20260905/README_EN.md` | `6dae4e849ca2716ea92683526277eaa13951895ebb19423e823f22022193192e` | P5 review measurements — 2026-09-05 (English summary; Arabic detail in README.md) |
| `P5_ReviewMeasurements_20260905/SHA256SUMS` | `3f0908cc80caf56f28f4c5e4ebb96cf3d1fb439e912a376f4b1a65f33a1692ff` |  |
| `P5_ReviewMeasurements_20260905/adversarial_20260905.log` | `91d8551f6bfae8ed65dd48c1296c6c8816cbd58e40f20802b58568106dacfe4e` |  |
| `P5_ReviewMeasurements_20260905/burnin_curve_20260905.log` | `3755e13cceef723688d1716518a52d1bf35c9590047e019660c049fea5c5cf57` |  |
| `P5_ReviewMeasurements_20260905/burnin_curve_v2_20260905.log` | `2898fa58a7fa45afff950cccdb2b282a853a71a63b0f15f9d25c9abcd39b709e` |  |
| `P5_ReviewMeasurements_20260905/ct_sine_cost_20260905.log` | `08af81ad5332b04c1fe62a15a9c7269d925d51d9ab81219b3a85e178cabc585e` |  |
| `P5_ReviewMeasurements_20260905/hd_throughput_v1_quiet_20260905.log` | `243f8f170162352d16b23195effd591fec66f96f804003b1e9eaf0d39bcab6c3` |  |
| `P5_ReviewMeasurements_20260905/hd_throughput_v2_quiet_20260905.log` | `1c07ef2e3fcb2507f977905319287afc2786799165f5e8a938f453793122f165` |  |
| `P5_ReviewMeasurements_20260905/header_patch.diff` | `1a06b57111ab4ec4a27d3c4d3a31a791157817ec2b5fa29fddb8af80d93575d3` |  |
| `P5_ReviewMeasurements_20260905/mcl_hd_throughput.cpp` | `7d922b50ea6b6d041f8a8a5a978f4dce48757d0352b6b2fff9f7c22320caebd4` |  |
| `P5_ReviewMeasurements_20260905/p5_G_entropy.cpp` | `d8232c4eecb747ae7ec07ee6f7d5c28096fb95413aec467f2de9a5f5879440d9` |  |
| `P5_ReviewMeasurements_20260905/p5_adversarial.cpp` | `9c28e9ed8b840a3fafa08dddd661a9413b52aad75bdb70b1fbc07c4d05ddc7ab` |  |
| `P5_ReviewMeasurements_20260905/p5_burnin_curve.cpp` | `99cadc2c5956b2a4bfd2a0ba72c2eaa186f4861829d02b9b1cb740326f3719b0` |  |
| `P5_ReviewMeasurements_20260905/p5_burnin_curve_v2.cpp` | `f2c39c4936f4cec3ed5b15c800c5de5f96e62fa3ffd0bf9a2ddef8a081563a2e` |  |
| `P5_ReviewMeasurements_20260905/p5_ct_sine_cost.cpp` | `32b5a2bb058169eacb6598d75d260e5c002b62c5284a05f28f00ed33ad71518b` |  |
| `P5_ReviewMeasurements_20260905/p5_parity_lock.cpp` | `80e447142df634d6742be9395cdb6b1f31205a4e215b9c6f97210bc841c72642` |  |
| `P5_ReviewMeasurements_20260905/p5_resonance_control.cpp` | `aed41340b9385ff47b72e94f11e30df644b916d467ac1b58f8d33044b07e5691` |  |
| `P5_ReviewMeasurements_20260905/p5_system_eval.cpp` | `2cb19ed21fb5744bf98442e55c99c2138b4cd25787e680f62547701cf37d9f3c` |  |
| `P5_ReviewMeasurements_20260905/p5_v2_coprime_parity.cpp` | `38eb19642c0d1171c3f600cc1039c85265ec6efad4f2d272b0369f53d7ea6949` |  |
| `P5_ReviewMeasurements_20260905/p5_weight_probe.cpp` | `08a270fa30d6db9bbc8deeaceb8cac7aa28c21e4ae6daa73e55205f02945a75a` |  |
| `P5_ReviewMeasurements_20260905/redraw_rate.cpp` | `d2973fc15160973aa998657485c6ee7951bd6cee80cc66a5c3ed257ce68cdab0` |  |
| `P5_ReviewMeasurements_20260905/resonance_control_20260905.log` | `fa44244a920762747ea9f0f81cbb250ccf4315ed85105eab9d6dee4e9279473d` |  |
| `P5_ReviewMeasurements_20260905/results_v3_battery_q30_v8.1.3_20260905_arm64.txt` | `e063f867f69b6fe135d0bcdd9249763b867d85f01ffa28c857920016b22c5add` |  |
| `P5_ReviewMeasurements_20260905/results_v3_battery_q30_v8.1.3_20260905_x86_64.txt` | `0b7b9ebbe7a1890d1f7df10fe0116f18e6b815abecd693a4136e6c075075c9bb` |  |
| `P5_ReviewMeasurements_20260905/sibling_recovery.cpp` | `6e7a6f60c26ca907cefe7f00153eed9be416c4b1894ab62e9e75a923b2e241bb` |  |
| `P5_ReviewMeasurements_20260905/sibling_recovery.log` | `dda8d28f2226beb2fdc60f59718aaf7e3cf6d6f3ad8fe99bf821384e6da1597c` |  |
| `P5_ReviewMeasurements_20260905/system_eval_20260905.log` | `199730e36baa526c82980c3da0cf7fe6488890cd910b6cb274dab029a3ffd01a` |  |
| `P5_ReviewMeasurements_20260905/v2_coprime_parity_20260905.log` | `021b8c1307227f57b71167e7e3e6e2f863ab89b0413c1307c324eee268a5e0d5` |  |
| `P5_ReviewMeasurements_20260905/weight_probe_20260905.log` | `9d41d84e3f0cb88cba6330a3fd64ca31f66cc579abe2f63eb0afd5df9f38b782` |  |
| `P5_ReviewMeasurements_20260905/weight_probe_sidecar_scratch_ctor.diff` | `617f1ef29095331a96ce1c598553762b4c1b324e45065eb4b745b7c6a7e5dfc4` |  |

### hd_v2  (5 files)

| File | SHA-256 | Note |
|---|---|---|
| `hd_v2/README.md` | `00ce5e1bff39ef63e9682faad18783132df0f41cbe210acc815da5d15284702c` | hd_v2 — Hierarchical channel-identity derivation, version 2 (additive sidecar) |
| `hd_v2/hd_verify_v2_FULL_v8.1.3_20260905.log` | `c6657165de79147c7b88bbf275825bd83c0ac69089ec9e14f3811094782c8260` |  |
| `hd_v2/mcl_hd_throughput_v2.cpp` | `62bb756009c16d20bdc8eb4f0b6091863efd75bbbfdfe47707e3b85ae34e1405` |  |
| `hd_v2/mcl_hd_v2.hpp` | `e000af267d131e734d4c84a49272acaa7c6a6c53519d9d580a1feb7cbce97b7c` |  |
| `hd_v2/mcl_hd_verify_v2.cpp` | `984b5ff1d35f2f8f8ea7bd349fb8f8384ae56ba12965dbfc57c247a791a321af` |  |

---
*Generated 2026-08-22 by `gen_manifest.py` (kept in the staging `_build/` folder, not part of the repository). The 23 root `.cpp` files differ from v0.1.0 only in the `Patent Pending` banner line(s) (+ PCT/IB2026/058860).*
