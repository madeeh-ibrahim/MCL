# Changelog — MCL public repository

All notable changes to the **published** repository. Engine-level history is
kept verbatim in the `VERSION IDENTIFICATION` block of `mcl_core.hpp`; this file
summarises it at release granularity. Pin artefacts by **SHA-256**, never by
version string alone.

## v0.2.0 — 2026-08-22

### Engine `mcl_core.hpp`: 6.0.0 → **8.1.3** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`)

Every KAT, CRC and keystream of every pre-existing valid path is byte-identical
to 6.0.0 (re-verified on this release: `results/self_test_v8.1.3_20260822.txt`
PASS 7/7; `results/kat_gen_macos_v8.1.3_20260822.txt` reproduces the June CRCs;
`results/q30_macos_validation_v8.1.3_20260822.txt` reproduces the normative Q30
vectors `0xC8AFD74A/0x0DB2BAC6`, `0x6F88C52E/0xE06C516C`, LUT `0xDE1340CF`).

| Version | Date | Kind | Summary |
|---|---|---|---|
| 6.1.0 | 2026-06-11 | additive | 256-bit keyed path: SHA-256 KDF → keyed `MCL_T2_Omega` / `MCL_T4` weight derivation (§3.1, keyed factories). |
| 7.0.0 | 2026-07-06 | additive + stricter validation | `vdf_verify_transcript()` (seed-anchored, tamper-evident checkpoint transcripts; closes the fabricated-start-state gap of the segment API), `vdf_compute_checkpointed` out-param, T4 2⁶²-bound parity, fail-closed `distance_correlation`/`spectral_test`, heap-free streaming SHA-256 + secure_zero of key material, Q30 hot path in fully-defined unsigned arithmetic (bit-identical), new self-test controls, documentation corrections (integer-Q30 battery status, keyspace accounting). |
| 7.0.1 | 2026-07-07 | hardening | Unconditional null guards in `mcl_kdf256`, `mcl_sha256`, `vdf_compute_checkpointed`; sec.16 cross-reference to the keyed sidecar. |
| 7.0.2 | 2026-07-11 | docs/advisory | Periodic/quasi-periodic K-windows persist above K=1.0 for some topologies ((3,5) at K≈1.22, 2.595; (2,3) band 1.28–2.08): `MCL_K_RECOMMENDED_FLOOR` 1.0→6.0, `MCL_T2_K_RECOMMENDED` 2.0→6.0 (advisory; hard K_min sentinel unchanged). |
| 7.0.3 / 7.0.4 | 2026-07-12 | security hardening | F1–F7 + QA-1..3: NaN-K rejection in `mcl_q30_K_phase`, fail-closed `vdf_verify`/`vdf_verify_q30`, bounded verifiers (`*_bounded`, caller-policy N_delay/checkpoint ceilings against resource-exhaustion), KDF label/info 1 MiB cap, `mcl_make_validated_t2()` Lyapunov-validated factory, `#warning` when `MCL_UNSAFE_ALLOW_INVALID` is compiled in. |
| 8.0.0 | 2026-07-12 | renumbering | Release renumbering for the deposit package; no code/numerical change over 7.0.4. Document ID → `MCL-CORE-2026-0712-001`. |
| 8.1.0 | 2026-07-17 | additive | sec.4b device-bound keyed derivation: `mcl_keff_from_key_device`, `mcl_t2_params_from_key_device`, `mcl_t4_params_from_key_device` (256-bit device secret enters the **weight derivation**, not the seed). |
| 8.1.1 | 2026-08-21 | docs | Banner patent list: fourth application filed as PCT/IB2026/058860. |
| 8.1.2 | 2026-08-22 | docs | SECURITY WARNING on `vdf_compute_q30()` (retired two-oscillator raw path): seed-reachable translation symmetry (order-16 group for (3,5)) — see `T4_CycleStructure/T4_CYCLE_RECORD_20260822.md` §5a. |
| **8.1.3** | 2026-08-22 | contract narrowing | `MCL_PQ_MAX` 2⁶² → **2⁵³** (exact-integer bound of IEEE-754 double; inputs in (2⁵³, 2⁶²] previously lost precision silently and are now rejected). Header sweep count 919 → 489 (corrected figure of the 2026-07-11 periodic-window record). |

> Note: the free-text `Version:` line at the top of `mcl_core.hpp` still reads
> "8.1.1 … August 21, 2026" (the 8.1.2/8.1.3 bumps were recorded in the version
> macros and changelog block only). The macros `MCL_VERSION_STRING "8.1.3"` /
> `MCL_VERSION_DATE "2026-08-22"` are authoritative; the file is shipped
> byte-identical to the pinned SHA-256 above and will be reconciled in the next
> docs-only bump rather than altered here.

### Added — sidecar and evidence folders (all new to the public repository)

- `keyed_q30_PQ/` — `mcl_keyed_q30.hpp` **v1.0.6** (SHA-256 `71a0dbaf84725ac77d0b3f1eab5a40ba90c088e88df7d41aab19aed39a6f6512`): FPU-free keyed four-oscillator integer engine `MCL_T4_Q30` (12 integer weights, 256-bit key → NIST PQ Category 5 accounting) and `mcl_cascade_q30`; v1.0.6 adds `mcl_t4_q30_has_reachable_symmetry` + deterministic re-draw in `mcl_t4_q30_params_from_key` (rejects the ≈2⁻⁹ weak-key class; KATs `0x58C99E3E` / `0xF7C81BC4` unchanged; 125/65 536 test keys change one lane). Test suite 9/9 PASS on this release. Includes the capacity-realization experiment v1.1.0 (15/15), Dieharder / Lyapunov (MPFR) / M0 code-generation records.
- `VDF128_T4/` — `mcl_vdf128_t4.hpp` 128-bit-state integer sequential function (SHA-256 input injection into the 4×32-bit state, public nothing-up-my-sleeve weights with trivial symmetry group): property + falsification battery 14/14, cross-arch/cross-opt fingerprint 8/8, 2026-08-21 benchmark record.
- `T4_CycleStructure/` — reduced-width cycle study (λ₁₂₈ ≈ 2^62.3 ± 0.2), exact translation-symmetry group computation, symmetry impact on the retired raw VDF, weak-key parity check, Float64-path symmetry check (combinatorial class exists but is numerically unstable and not seed-reachable), full record `T4_CYCLE_RECORD_20260822.md`.
- `ReturnMap_Attack/` — Rule-13/Rule-7 chaos-specific attack battery (2-D return-map occupancy, conditional entropy, EFA) on the keyed stream, commit words and raw state; record `RETURNMAP_RECORD_20260822.md`.
- `p2_hardened_auth/` — Paper 2 hardened authentication profile v2 (12/12), keyed 12-weight credential FAR campaigns (10⁶/10⁷, keyed v4 4 devices × 10⁶/10⁷), avalanche 10⁶, engine-sensitivity 17 strategies × 2.5 M (0/42 500 002), records and logs. (`mcl_simswap_v3.cpp` gated — see `TOOLKIT_ACCESS_POLICY.md` addendum; its record/logs are here.)
- `p5_hardened_txauth/` — Paper 5 hardened transaction-authentication v2 (16/16), v3 Claim-4 route (11/11) and v3 battery (18/18), `mcl_d1_collision.cpp` Brent search (1.63×10¹⁰ trials) producing a real colliding payload pair on the retired 64-bit-fold path, architectural-finding record.
- `M1_M2_apple_verification/` — Paper 1 §III.B.3 (ψ-equidistribution, det-J), Tables 9/10 (multi-seed), Appendix A NIST STS campaign (188/188, archive zip), per-bit MSB flank, safe-zone hold-out, τ_int; Paper 3 Fig. 1 Arnold-tongue sweep generator + CSV. Engine copy of v6.0.0 omitted (it is git tag `v0.1.0`).
- `P3_CrossPrediction/` — ridge-regression cross-prediction (R²) sweep over K showing deterministic predictability at K=0.70 and none at K≥6 (record `XPRED_RECORD_20260822.md`).
- `Verification_Suite/` (14 legacy programs + results), `Layer_Combiner/` (robust-combiner demo).
- `results/` — three fresh 8.1.3 records (`self_test`, `kat_gen_macos`, `q30_macos_validation`) next to the June outputs.
- `CHANGELOG.md` (this file); `MANIFEST.md` regenerated with per-file SHA-256.

### Changed

- `PATENTS.md`, `CITATION.cff`, `README.md`, banners of all 23 root `.cpp` files: fourth application **PCT/IB2026/058860** (filed 21 August 2026) added. No other byte of the 23 programs changed.
- `CITATION.cff`: `version: 0.2.0`, `date-released: 2026-08-22`.
- `TOOLKIT_ACCESS_POLICY.md`: 2026-08-22 addendum (7th gated file; scope statement for the June attack scripts / CPA / VDF probes).
- `.gitignore`: exception for the NIST STS evidence archive.

### Not included (deliberately)

- Gated adversarial toolkit (7 files), the June-2026 lattice / return-map attack scripts, `SideChannel_Screen/` CPA tooling, the nine `VDF_security/` probe programs — per `TOOLKIT_ACCESS_POLICY.md`. Their findings are disclosed in the papers and the public records.
- Compiled binaries, `.DS_Store`, backups.

## v0.1.0 — 2026-06-01

Initial public package: engine 6.0.0 (MD5 `241db79ecf8a42897eb9a8399cf37929`),
23 reproduction / KAT / self-analysis programs with recorded outputs, governance
and licensing instruments, Zenodo concept DOI 10.5281/zenodo.20496569.
