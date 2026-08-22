# MCL — Public Code Archive · MANIFEST (v0.2.0, 2026-08-22)

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

## File inventory — 258 files (+ this MANIFEST), SHA-256 of every file

### (root)  (45 files)

| File | SHA-256 | Note |
|---|---|---|
| `.gitignore` | `ff986180e02708b88a774a1f0b60785b5c1b6d15db371d8b992b198fcf3fdb57` |  |
| `APPLY_GUIDE.md` | `754cbc1d15713c292648e686d643e919882653dfe2cd88fc791c641baa96b957` |  |
| `CHANGELOG.md` | `e55582884b8b210f6a3ee7ae4f5745e02cddd3cd720d2fc94b31f5b54ea32446` |  |
| `CITATION.cff` | `6fc946e2c618db429e62af521f851e4a2aa91a1dc1db461d59ed98e053dbfee5` |  |
| `CLA.md` | `975fe9c31ca4bb96cdcb427f2c62ed2fb46a3df443bff8a80f294aa619d06129` |  |
| `CODE_OF_CONDUCT.md` | `da98355a1277938de1cfededa9beaaa2a56e63dba34f97f65e5a05a2d3102c43` |  |
| `COMMERCIAL.md` | `712b2c98fcfb0a75f80df9c4f0ab3461339777da9e57b5408974ca83a22a97e5` |  |
| `CONTRIBUTING.md` | `238434c313a101b7ada8073ddfbf5fd4eec0b2248f4d3932641249dba1e705b9` |  |
| `GOVERNANCE.md` | `4e1cf312a4805452d4f41c9bc402add0b0e8547cc24b1cb64a7eea9c0704c1e6` |  |
| `HALL_OF_FAME.md` | `fb4eaf6b0b33659a57d9f553efb09e5c9c3e98fd19702275433d5fd30d911117` |  |
| `LICENSE` | `839932d57880e179074222334b1a3d1ae7117feaea0f36020580dc73f6a9f76f` |  |
| `NOTICE` | `2c5b00f021de5d1a79bcd5598a46f2cf62e4738a2719025850479fdead8e6399` |  |
| `PATENTS.md` | `c8034b61bd795351ae67d04395940de782c5e82f9cf2856a3f7d03cf2a101bb3` |  |
| `README.md` | `d9d0ef572555deb38d8c315f7b720eed9c94cc2319d9feaf9248a73d46b5ab68` |  |
| `REUSE.toml` | `805bea6173d163f417b8097f162d2978deae445f1c21e3ea62cd284c2b40768b` |  |
| `SECURITY-RESEARCH-GRANT.md` | `24a8609549aec66bbb18126a015e3513332bc665b7dd1154501707e70ac816e3` |  |
| `SECURITY.md` | `fb923ca3236106a55b6c62e9ba404a46b1054b9f6338884425af82af0048dd37` |  |
| `TOOLKIT_ACCESS_AGREEMENT.md` | `e8fbc3509ccca828e4c1f7c22cd82635801efd0516726f21074ecb29c3a7a7c8` |  |
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

### results  (27 files)

| File | SHA-256 | Note |
|---|---|---|
| `results/beff_deep_audit.txt` | `0fa5baf9f152d39af5b23f3bd3d2602d326ea141198a144ad272f9d436ecd11e` |  |
| `results/kat_gen_macos.txt` | `959fa8bde760d0957c18e5617c251025b012d21665f1d9e56fd89f9cbfe01733` |  |
| `results/kat_gen_macos_v8.1.3_20260822.txt` | `00732e5077696d503de2f01b31f3facf51c44bdf8f7230d98f3409a3a4a07f34` |  |
| `results/keyed_q30_test_v1.0.6_20260822.txt` | `bdd7b17d4b5c3ed7431da2cd37336ac4a4110f0dd48bc9bb6f07b020e944c17f` |  |
| `results/mcl_beff_compounding.txt` | `2e4d0c2e8cbe02895e15de7404670062f39b989ca1441acc2ac5875d6c5a086c` |  |
| `results/mcl_benchmark.txt` | `2b4b54303dd163df0df7b4abc98ae033007c53ab078baa8c51a1503f55b5d2b4` |  |
| `results/mcl_dynamical_signatures.txt` | `4ae1450f5a1c8308d63685a1ac54eb4b2de6973911f28087beb5f4697978747d` |  |
| `results/mcl_generality.txt` | `70fafa524cd44e84cf35eee5e764d007860b1ae7e660b133ebd21a84161d04b9` |  |
| `results/mcl_hd_verify.txt` | `a59a830313f1303117b1df372cd7b0ad39db86d6531a08b27b5caf6d2756aa1d` |  |
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

### keyed_q30_PQ  (32 files)

| File | SHA-256 | Note |
|---|---|---|
| `keyed_q30_PQ/M0_CODEGEN_CLAIM13_20260612.txt` | `94091cd667e5dce60ede9e292741d19c112cc4a68b53c190feb01100cd3e67ac` |  |
| `keyed_q30_PQ/MCL_CAPACITY_REALIZATION_20260812.txt` | `1e40229ab6b8c2e65d8a4e13e38ab1cdead5f5e707dbf6e965507ad4c22206c9` |  |
| `keyed_q30_PQ/MCL_CAPACITY_REALIZATION_20260812_v1.1.0.txt` | `672535dc365e7046bf88065efa44a56146ce949b5579c8d3fa4ddc68ca636726` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_BEFF_RECHECK_20260611.txt` | `212fecde6d6bc6d10c4bca9a1624f50bc3ed1baf0130425774f8438030e9a38c` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_DIEHARDER_20260611.txt` | `2a2e214691216e44dc438ba975e301fe2d5045682c345f226e25ad6022e13d53` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_LYAP_SWEEP_20260616.txt` | `b8b6f9afe37f87ac344714fceac94a8b712143f86469b93b1f8300a4c0643998` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_MEASURE_20260612.txt` | `771226a6ace705e00513eaa4ac6298ec7a28fcf9fb402c4a05a51b5b65cf33c3` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_MPFR_LYAP_20260611.txt` | `a540c45c7e97e716b53a7ea3dee41d4d700e69640065f5a114f672e2059bf4d7` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_RESULTS_20260611.txt` | `a9177690e18bfed15ef04e97491467f1db9ba37d065978c41af3c2035523570a` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_SCIENCE2_20260611.txt` | `1606151b0d449f346857b7f0f3d5b9b625788b8dbd7ecec55c474f7d73d439e2` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_SCIENCE3_20260611.txt` | `861b4247ca3f2983beacc7c1593c03ca6b1cd9414218758a16cc5ea3d577dec6` |  |
| `keyed_q30_PQ/MCL_KEYED_Q30_SCIENCE_20260611.txt` | `e7d1b57a3cdcd5c272048efc298a0335882df04dd27b2d6b2bc0739da1dcb36e` |  |
| `keyed_q30_PQ/NOSYM_V106_RECORD_20260822.md` | `bc56e7eb28a32ccf61947d87a1417ae87eba7c57e80cfe34a85ea6df9ce1abdb` | sidecar v1.0.6 — رفض التناظر القابل للوصول من البذرة في `mcl_t4_q30_params_from_key` — 2026-08-22 |
| `keyed_q30_PQ/README.md` | `e4c8f8279e9210cb1f3ecfff8fa5ca42943da35cd9ef5b9d5cc471a9081a7c8a` | MCL Keyed Q30 — FPU-free, key-bound, post-quantum extension |
| `keyed_q30_PQ/STATUS.md` | `9f48d84b610daa26b1aae507abb604d1fcaf52dfbd77b71c17c2c505f655af76` | MCL Post-Quantum / Keyed-Q30 — STATUS truth table |
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

### VDF128_T4  (12 files)

| File | SHA-256 | Note |
|---|---|---|
| `VDF128_T4/BENCH_RECORD_20260821.md` | `1d48424b0bfd9a3555a4c3a21a8c3ed32db29d3f201c98cbc6e093ea486cf3c6` | VDF128-T4 — قياس Eval/Verify على المعالج — 2026-08-21 |
| `VDF128_T4/README.md` | `b9fd67b9309fae98824ac6548d41511bc79df9e20aaa79a6185a2709e3739928` | VDF128_T4 — 128-bit-state integer VDF path (Paper 4 path-A rebuild, 2026-08-17) |
| `VDF128_T4/kat345.cpp` | `0e3b99af92ad721645775bd40cfc8d0639c39f33dce80a0235b42d203c8fff63` |  |
| `VDF128_T4/mcl_vdf128_battery.cpp` | `e69aea857f34a1eb3e894ee2b1afeaf2b4ee66a7cdd2f5445554d57c514bd7d9` |  |
| `VDF128_T4/mcl_vdf128_bench.cpp` | `2a43c33da96b8979d64ff7e727a602ab5d899fbe601d88741808cbe700a8390b` |  |
| `VDF128_T4/mcl_vdf128_cyclecheck.cpp` | `fb5dc4a9e06d59e88c79808444817461c43d334355f755886819bd7d21456496` |  |
| `VDF128_T4/mcl_vdf128_t4.hpp` | `e08f702e2da92221588285a6a61ee2e48edfb63afbde8220fc3632fd2180ed0d` |  |
| `VDF128_T4/mcl_vdf128_xplat.cpp` | `36a9c5878030ddf40dd2808ab58259d50b993f2f53a2e07b5411593259e51ebc` |  |
| `VDF128_T4/vdf128_battery_apple_20260817.log` | `35fd9d87066e1fa6c82fde0a9861f7e7e29a2835920915a3b4a1aa2e15f75c09` |  |
| `VDF128_T4/vdf128_bench_apple_20260821.log` | `40a9e3f4b7622358309b858a798c2ff3a1857ed9d6c6552ba8dead36414adacd` |  |
| `VDF128_T4/vdf128_cycleprobe_apple_20260817.log` | `6d3c1301b1a2c746b485c604aa7c1b7e6e2091d6fe893c18e3c003b5cc33be7e` |  |
| `VDF128_T4/vdf128_xplat_apple_20260817.log` | `46f75037747dfabfcac9170de2fb7070e5e89ee68b6f6f388ffb5af2b147567d` |  |

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

### p5_hardened_txauth  (11 files)

| File | SHA-256 | Note |
|---|---|---|
| `p5_hardened_txauth/ARCHITECTURAL_FINDING_20260821.md` | `6157f5386b774fb27e981bed15b37169ed5233dfdecc663ac663ab3ceb389ffe` | الإصلاح المطلوب وأثره على البراءة — الورقة 5 (والورقة 2 بالقياس) — 2026-08-21 |
| `p5_hardened_txauth/ARCHITECTURAL_FINDING_20260821_SUPERSEDED.md` | `491a17e6231b7737cdd8b60431f19de82ccd7a5dd67e7f2c56c429163abd3eeb` | نتيجة معمارية لازمة عن إصلاح D1 — الورقة 5 (والورقة 2 بالقياس) |
| `p5_hardened_txauth/README.md` | `0a4eae6e7fe965189775b677b0daafbadd11274b15557a4505bbe454a4bbd364` | p5_hardened_txauth — مسار الورقة 5 المصلَّد (v2) + بطاريته الكاملة |
| `p5_hardened_txauth/d1_collision_20260821.log` | `4c59d1fe0824525316554bce3cd6d7aa72aca0700bca51235ce545dfcf47d087` |  |
| `p5_hardened_txauth/mcl_d1_collision.cpp` | `6eedb6294d75d9020401f1f026e5806af56267e5d267a05fb0467e0673ae3b88` |  |
| `p5_hardened_txauth/mcl_txauth_hardened.cpp` | `1c8d66d063e18fb1b2673a55073de00da149301ffbf03e5be8354cb2d538af04` |  |
| `p5_hardened_txauth/mcl_txauth_v3_battery.cpp` | `1e627d8c136c2fc7aee44e58154e1e7861987c9611bc3a56454e8bd260547ecb` |  |
| `p5_hardened_txauth/mcl_txauth_v3_claim4.cpp` | `016843ee8949e0bac4bbcf21ca17f0e4cb1ef40147f08f4482ce99f8f72806ca` |  |
| `p5_hardened_txauth/results_20260821.txt` | `c127d31be9ac8758c02dbd7e729e662d7f8f65ff7b533f4782d8b934824f2ed8` |  |
| `p5_hardened_txauth/results_v3_20260821.txt` | `0329d38aa78a2552f24bda89cfa8b1a9c2a4e7d9f25da1885177416518cb4cb7` |  |
| `p5_hardened_txauth/results_v3_battery_20260821.txt` | `3facb57c4d38217a7e50c2052d8b413e32e42b767780131101c58f241c18c614` |  |

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
| `Verification_Suite/README.md` | `d3cdf396c6edfcd27b96aa4493fad4e8d54eefb534c0531acb3d01b6c1018a49` | Verification_Suite — legacy science/verification tests |
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

---
*Generated 2026-08-22 by `gen_manifest.py` (kept in the staging `_build/` folder, not part of the repository). The 23 root `.cpp` files differ from v0.1.0 only in the `Patent Pending` banner line(s) (+ PCT/IB2026/058860).*
