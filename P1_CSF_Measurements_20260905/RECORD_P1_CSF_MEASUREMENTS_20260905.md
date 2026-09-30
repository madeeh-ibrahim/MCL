# RECORD — P1 CS&F revision measurements · 2026-09-05 / audited and re-run canonically 2026-09-06

**Platform:** MacBook Pro 18,3 (Apple M1 Pro, 16 GB), macOS 14.5, Apple clang 16.0.0, Apple libm. **Engine of record for the MCL runs:** `mcl_core.hpp` v6.0.0, MD5 `241db79ecf8a42897eb9a8399cf37929` (frozen M1_M2_apple_verification copy). Non-MCL maps need no engine.

**Canonical logs = the `-ffp-contract=off` builds (prefix `nofma_`, `audit_`), 2026-09-06.** The 2026-09-05 logs (prefix `thirdmap_`, `xorctl_`, `logistic_cycles_`) were produced by default-contraction builds; for the XOR tool and the MCL engine they are bit-identical to the canonical runs, but for the third-map tool the seed-to-x₀ line was contracted into a fused multiply-add, so for three of eight seeds x₀ differed by one ulp from plain IEEE semantics and the transient/cycle of the logistic orbit differed (seed 17320508075688: 14,632,801-cycle instead of 5,638,349; seed 27182818284590: fixed point instead of a 5,638,349-cycle after 8.5×10⁷). Those logs are retained for the audit trail but **every number in Paper 1 and Supplement S6 is taken from the canonical logs**.

## Audit trail (2026-09-06)
| Check | Result |
|---|---|
| Positive control A: MCL θ₁/θ₂ single streams through `mcl_thirdmap_safezone` (map 4) vs holdout log 2026-07-19 (M2 Max) | max Δχ² = **0.0** at all 45 positions, both streams |
| Positive control B: MCL θ₁⊕θ₂ through `mcl_xor_control` vs holdout XOR column 2026-07-19 | max Δχ² = **0.0** at all 45 positions, both builds |
| Independent implementation: CPython Brent on the binary64 logistic map (no FMA), seeds 12345678901234 / 27182818284590 / 17320508075688 | μ and λ **identical** to the canonical C++ tool (57,551,136/5,638,349; 84,949,303/5,638,349; 19,075,508/5,638,349) |
| Lap-inflation model χ² ≈ 255·(μ + k²λ)/N vs measured median χ² over P∈[5,20] | agreement within 2–4% for all cycling seeds (962/952, 298/290, 793/780, 1176/1155, 3258/3205, 1717/1739 on the 09-05 logs) |
| FMA sensitivity | `objdump` shows fused ops in the contracted builds; `-ffp-contract=off` builds have none; XOR tool and engine results unchanged (Δχ² = 0); third-map single streams change at the bit level (orbits differ) but zone widths stay in the same ranges |
| Contiguity-rule sensitivity | strict longest run is split by single marginal failures (χ² 311–400) in Hénon/standard-map streams; relaxed widths (failures < 1.3×crit tolerated) are stable (25–28); MCL XOR has no marginal positions (neighbours 1.5–1.9×crit) |
| Decimal x₀ sweep, logistic r=4, N=10⁸ (0.1, 0.2, 0.3, 0.4, 0.6, 0.7, 0.8, 0.9, 0.123456789, 0.314159265) | zones 0–6 positions; none reproduces [19,31]=13; symmetric pairs 0.1/0.9 and 0.4/0.6 give identical results (x→1−x symmetry, sanity check) |
| Cycle-free logistic scans (N < μ) | intrinsic profile: positions 0–21 pass, failure from ≈22–25 upward — no low-band contamination; [19,31] lies inside the failing band |
| Brent cycle search, full binary64 state, canonical seed, cap 2×10⁹ | MCL: no cycle; standard map: no cycle |
| Invariant-density stripes (Fig. 1b) | dominant FFT modes ±(3,−5), ±(6,−10) identical at 32/64/128 grids and for seed 98765432109876 → property of the invariant measure, not of the grid |

| Doc ID | Tool | Purpose | Canonical logs |
|---|---|---|---|
| MCL-ATTRACTOR-DUMP-2026-0905-001 | `mcl_attractor_dump.cpp` | Fig. 1 data: 2×10⁵ (θ₁,θ₂) points, occupancy grids 32/64/128 (TV 0.0455/0.0577/0.0668), ψ₁ 256-bin marginal (TV 0.004803 = 2026-07-03 M2 Max value) | `attractor_dump_seed12345678901234_M1Pro_20260905.log`, `density{32,64,128}_12345678901234.csv`, `density64_98765432109876.csv`, `psi1_hist_12345678901234.csv` |
| MCL-THIRDMAP-SAFEZONE-2026-0905-001 | `mcl_thirdmap_safezone.cpp` | §3.3 protocol on logistic r=4 (8 seeds) / r=3.99 (4), standard map K=12 (4), Hénon (4), MCL positive control (map 4), explicit-x₀ sweep, cycle-free scans | `nofma_map{0,1,2,3}_seed*.log`, `nofma_map0_cyclefree_*.log`, `audit_map4_MCL_*.log`, `audit_logistic_x0_*.log` |
| MCL-LOGISTIC-CYCLE-2026-0905-001 | `mcl_logistic_cycle.cpp` (+ `brent_logistic_check.py`) | Brent cycle detection, r=4 and 3.99, 8 seeds | `nofma_logistic_cycles.log`, `audit_python_brent.log` |
| MCL-XOR-CONTROL-2026-0905-001 | `mcl_xor_control.cpp` | XOR-healing control, 5 cases × 2 seeds | `nofma_xor{0..4}_seed*.log` |
| MCL-CYCLE-SEARCH-2026-0906-001 | `mcl_cycle_search.cpp` | Brent on full state, MCL and standard map, cap 2×10⁹ | `audit_cycle_MCL_seed12345678901234.log`, `audit_cycle_std_seed12345678901234.log` |

**Build line (canonical):** `c++ -O3 -std=c++17 -ffp-contract=off -o <tool> <tool>.cpp -lm` (binaries `*_nofma`; `x0_hex_nofma` prints the exact initial conditions).

**Headline outcome (classified per 08_PROGRESS_VS_CONTRADICTION):** the Paper-1 statement «single logistic map (r = 4.0) Safe Zone [19, 31] = 13, seed-stable» and the derived «+161% architectural advantage» are **not reproducible under the stated protocol** (فئة 1): eight seed-derived and ten decimal initial conditions give 0–7 positions at N = 10⁸ because the binary64 orbit enters a 5,638,349-cycle or a fixed point (Persohn–Povinelli [40]); scanned cycle-free, the map has a clean low band and fails from ≈22 upward, so [19,31] is inside its failing band. XOR of two standard-map streams gives 34–37 positions, i.e. the widening is generic (piling-up lemma), not architectural. Paper 1 §6.2 withdraws the figure.

## File hashes (MD5)

| File | MD5 |
|---|---|
| `attractor_dump_seed12345678901234_M1Pro_20260905.log` | `9b77eba90170ec79b2a4afe8e041d424` |
| `attractor_points_12345678901234.csv` | `fc05033c4c8a1becf4178b7e716d73cc` |
| `attractor_points_98765432109876.csv` | `ddbec51ad6911f79c955dca77c5e38b5` |
| `audit_cycle_MCL_seed12345678901234.log` | `82d7c89f447558fb6c07fc23540325f3` |
| `audit_cycle_std_seed12345678901234.log` | `b9aecc4477ad5a930febea99a1f3ddeb` |
| `audit_logistic_x0_0.1.log` | `ab96bc01786a2b6a8a06e09420fbfab3` |
| `audit_logistic_x0_0.123456789.log` | `3a2dc2fb8c7bc9162c09bab5819fd7a6` |
| `audit_logistic_x0_0.2.log` | `b36e05df9969cb55b7ff7ab4a8d5491a` |
| `audit_logistic_x0_0.3.log` | `5e065dde40b14dc9f47bebb76af7fb8b` |
| `audit_logistic_x0_0.314159265.log` | `493196fe2ce6f925862acea5bd688f9f` |
| `audit_logistic_x0_0.4.log` | `3d18693789dedc66c63b95fcf6b5562e` |
| `audit_logistic_x0_0.6.log` | `a6fa81e1f22847b509f600508ba2eae5` |
| `audit_logistic_x0_0.7.log` | `7a0be6d428311b3c34ec0c8b4209670b` |
| `audit_logistic_x0_0.8.log` | `657539294bc1543471123c0e3f2e5a70` |
| `audit_logistic_x0_0.9.log` | `d90d859373dfe7082e646410ca446744` |
| `audit_map4_MCL_seed12345678901234.log` | `7f485092a432aa77b352080ee6be85a6` |
| `audit_nofma_map0_seed12345678901234.log` | `cbe52c0d262629fd23eeae537431c482` |
| `audit_nofma_map1_seed12345678901234.log` | `460351aa743af1ab2df0ddab20304b1f` |
| `audit_nofma_map2_seed12345678901234.log` | `ed64ecee2aea85930b4a22957eb98430` |
| `audit_nofma_xor0_seed12345678901234.log` | `cfe158375375efa0adf2aa450929dc1b` |
| `audit_nofma_xor1_seed12345678901234.log` | `755cefde70ca28b0c7cbc815d1058607` |
| `audit_nofma_xor4_seed12345678901234.log` | `885f4df37b16a75422ddd7c02ecbb801` |
| `audit_python_brent.log` | `7180fa603db07a7525ff613441aea264` |
| `brent_logistic_check.py` | `b2c775d985dd66a85418c93fd27bc855` |
| `density128_12345678901234.csv` | `d215bfbb80d7cd0bcc57d2e81611edb5` |
| `density32_12345678901234.csv` | `02dd5c623d38d3b5b3de7e2fc1dfc528` |
| `density64_12345678901234.csv` | `4e250fa796977670c789e623f4ea276f` |
| `density64_98765432109876.csv` | `35fe3223e34a8d6f4f3f654da6e55f79` |
| `logistic_cycles_M1Pro_20260905.log` | `951d5095f3e740b48205de47d1f58334` |
| `mcl_attractor_dump.cpp` | `31fa470f8120ed6a1677270d1d4f399d` |
| `mcl_core.hpp` | `241db79ecf8a42897eb9a8399cf37929` |
| `mcl_cycle_search.cpp` | `89e32be7de0a23558101fe1cb9257334` |
| `mcl_logistic_cycle.cpp` | `c634e339755f7247986ae923b70211fc` |
| `mcl_thirdmap_safezone.cpp` | `16d6748a21746d9520a94349ac650776` |
| `mcl_xor_control.cpp` | `8252fcd74cd3073e72f63130ab222d5a` |
| `nofma_logistic_cycles.log` | `5a382a2edd53b5b78660e2481f48e1be` |
| `nofma_map0_cyclefree_seed27182818284590_N8.4e7.log` | `e34e70109310f938bcb0f8f139f01549` |
| `nofma_map0_cyclefree_seed70466644885213_N8.7e7.log` | `8a77b9475b4ab96de62f1beb68ce23cc` |
| `nofma_map0_seed12345678901234.log` | `cbe52c0d262629fd23eeae537431c482` |
| `nofma_map0_seed17320508075688.log` | `000d59a4cb0ff17a2756bc2fd2c2a009` |
| `nofma_map0_seed27182818284590.log` | `38e034676ac6ee70995451f358089af4` |
| `nofma_map0_seed31415926535897.log` | `4f10e41c2698133927e9ef92da4fff8c` |
| `nofma_map0_seed55129803364771.log` | `bbe01e827e7abf3106c2b3a0d85b1ffe` |
| `nofma_map0_seed70466644885213.log` | `87d38b93cd557fc20dedb325e5e3d5af` |
| `nofma_map0_seed89623471905588.log` | `827955a0a01674acb31c01956ad6d3da` |
| `nofma_map0_seed98765432109876.log` | `9b421e5deaf288386ac737fc2e22b417` |
| `nofma_map1_seed12345678901234.log` | `460351aa743af1ab2df0ddab20304b1f` |
| `nofma_map1_seed55129803364771.log` | `6269283c4606163e48b2606a512c842d` |
| `nofma_map1_seed70466644885213.log` | `38365305b616a45a3274902eae7e7dc0` |
| `nofma_map1_seed89623471905588.log` | `3a30bd337df043bef84cad680c7a28f9` |
| `nofma_map2_seed12345678901234.log` | `ed64ecee2aea85930b4a22957eb98430` |
| `nofma_map2_seed55129803364771.log` | `3c204c598f5a6fd797759092697bea22` |
| `nofma_map2_seed70466644885213.log` | `4b2b9fdb925994c933b822beec6e55f7` |
| `nofma_map2_seed89623471905588.log` | `dd06a619dde565b530ea7e42c3943130` |
| `nofma_map3_seed12345678901234.log` | `32edb73dc6150927041ccb24d4dbf42c` |
| `nofma_map3_seed55129803364771.log` | `88d0d8b5d0c71d6d3587fcb4d14a07cb` |
| `nofma_map3_seed70466644885213.log` | `7669cbc8a59fc886f90ae64b759ea56f` |
| `nofma_map3_seed89623471905588.log` | `827688c80345b853607eb1908dc55487` |
| `nofma_xor0_seed12345678901234.log` | `cfe158375375efa0adf2aa450929dc1b` |
| `nofma_xor0_seed70466644885213.log` | `ee04d5270905e3dc5fdf208b310afcff` |
| `nofma_xor1_seed12345678901234.log` | `755cefde70ca28b0c7cbc815d1058607` |
| `nofma_xor1_seed70466644885213.log` | `996f59392fb5768e53b9bd4c7aa8ba13` |
| `nofma_xor2_seed12345678901234.log` | `931bdcb934ae1de22925c9e0893fc9fb` |
| `nofma_xor2_seed70466644885213.log` | `b9cdc09c6cb5ed07472bb6d5e46cfa8c` |
| `nofma_xor3_seed12345678901234.log` | `f3211044aa649f7b5ff0a1f496d70a77` |
| `nofma_xor3_seed70466644885213.log` | `cfd66f763c21ba83ea91552e4c2d221f` |
| `nofma_xor4_seed12345678901234.log` | `885f4df37b16a75422ddd7c02ecbb801` |
| `nofma_xor4_seed70466644885213.log` | `fe8b65591b82861103d9d2ac7bb799ad` |
| `psi1_hist_12345678901234.csv` | `81a182057261f61d1de5c530972f1ab5` |
| `psi1_hist_98765432109876.csv` | `abfac6a836af20073570475322c2ff11` |
| `run_audit1.sh` | `fd1c31b64cab844c44a1eff3448cf276` |
| `run_nofma_campaign.sh` | `834ed91ec11d1539fa18ee8cffd7bbc4` |
| `run_round2.sh` | `85b60d10464d9ce82dda836aa462bf85` |
| `run_round3.sh` | `8be7a8a61d03a3e88495c03af2d1be5e` |
| `run_thirdmap_all.sh` | `57d7798c2a082c478368c108987c8467` |
| `run_xor.sh` | `b6a542b437989309dbd58a102732c9d3` |
| `thirdmap_map0_seed12345678901234_M1Pro_20260905.log` | `5836e8db651e882b9153e8f4e5adb43e` |
| `thirdmap_map0_seed17320508075688_M1Pro_20260905.log` | `1bfbdf69695860b50750f1c9705d2172` |
| `thirdmap_map0_seed27182818284590_M1Pro_20260905.log` | `0fd187f9c369f8e907ab3bf66efd1d3b` |
| `thirdmap_map0_seed31415926535897_M1Pro_20260905.log` | `08871a87b4f16ee75ee7f8efc68e1eda` |
| `thirdmap_map0_seed55129803364771_M1Pro_20260905.log` | `0e48a0be60d6db7390050332e91e968f` |
| `thirdmap_map0_seed70466644885213_M1Pro_20260905.log` | `c6dfb4165124e41e2c00e7c7c917a694` |
| `thirdmap_map0_seed89623471905588_M1Pro_20260905.log` | `ca1d46ab06edbdf6b4818e71eaea3402` |
| `thirdmap_map0_seed98765432109876_M1Pro_20260905.log` | `28b476cbd9772e60851baa63e405ae0f` |
| `thirdmap_map1_seed12345678901234_M1Pro_20260905.log` | `c2daaafcdb9bb75b6402a663f2b78f05` |
| `thirdmap_map1_seed55129803364771_M1Pro_20260905.log` | `ce5619b598dc64fd9d825e3d6a9c6e53` |
| `thirdmap_map1_seed70466644885213_M1Pro_20260905.log` | `d71e937c2c7c0d407853f9877ffd11d4` |
| `thirdmap_map1_seed89623471905588_M1Pro_20260905.log` | `a5a35d92dcd29506ce827d92db601f20` |
| `thirdmap_map2_seed12345678901234_M1Pro_20260905.log` | `d975c3f1e339a425c1f543c9dfd8c53a` |
| `thirdmap_map2_seed55129803364771_M1Pro_20260905.log` | `f1eabbb6129e7be69ed58dfbdd23de50` |
| `thirdmap_map2_seed70466644885213_M1Pro_20260905.log` | `47eca761258af8d80431bd90bea4bca4` |
| `thirdmap_map2_seed89623471905588_M1Pro_20260905.log` | `0235fc56052822ca64cacb56fcc18be8` |
| `thirdmap_map3_seed12345678901234_M1Pro_20260905.log` | `52900e9ededa442fbea461670303dd70` |
| `thirdmap_map3_seed55129803364771_M1Pro_20260905.log` | `c3c7242fd8ba500b95465840e2a39a10` |
| `thirdmap_map3_seed70466644885213_M1Pro_20260905.log` | `97369d500bb2c0737c636cd9fa61c971` |
| `thirdmap_map3_seed89623471905588_M1Pro_20260905.log` | `b55d740e4023374388e12434d459d8d9` |
| `x0_hex.cpp` | `0029c45bf750aa766a6819447a26c2d4` |
| `xorctl_case0_seed12345678901234_M1Pro_20260905.log` | `cfe158375375efa0adf2aa450929dc1b` |
| `xorctl_case0_seed70466644885213_M1Pro_20260905.log` | `ee04d5270905e3dc5fdf208b310afcff` |
| `xorctl_case1_seed12345678901234_M1Pro_20260905.log` | `755cefde70ca28b0c7cbc815d1058607` |
| `xorctl_case1_seed70466644885213_M1Pro_20260905.log` | `996f59392fb5768e53b9bd4c7aa8ba13` |
| `xorctl_case2_seed12345678901234_M1Pro_20260905.log` | `931bdcb934ae1de22925c9e0893fc9fb` |
| `xorctl_case2_seed70466644885213_M1Pro_20260905.log` | `b9cdc09c6cb5ed07472bb6d5e46cfa8c` |
| `xorctl_case3_seed12345678901234_M1Pro_20260905.log` | `f3211044aa649f7b5ff0a1f496d70a77` |
| `xorctl_case3_seed70466644885213_M1Pro_20260905.log` | `cfd66f763c21ba83ea91552e4c2d221f` |
| `xorctl_case4_seed12345678901234_M1Pro_20260905.log` | `885f4df37b16a75422ddd7c02ecbb801` |
| `xorctl_case4_seed70466644885213_M1Pro_20260905.log` | `fe8b65591b82861103d9d2ac7bb799ad` |
