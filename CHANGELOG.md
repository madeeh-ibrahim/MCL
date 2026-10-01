# Changelog — MCL public repository

All notable changes to the **published** repository. Engine-level history is
kept verbatim in the `VERSION IDENTIFICATION` block of `mcl_core.hpp`; this file
summarises it at release granularity. Pin artefacts by **SHA-256**, never by
version string alone.

## Unreleased — staged 2026-10-01 (licence notices)

**One wrong licence tag corrected; the patent lists of `NOTICE` and `COMMERCIAL.md` completed.** No code, engine, sidecar or measured value changes.

- **`results/MCL_Scale_v2.2.0_Test_Results_20260519.md`**: its header gave the SPDX licence identifier as `Apache-2.0 (test report only)`, the only Apache tag left in the repository after `add_spdx_headers.sh`, which covers source files and not this `.md` report. It now reads `PolyForm-Noncommercial-1.0.0`, and a dated line in the header says that copies published before 2026-10-01, including the archived releases, carry the Apache line in error. The same header's contact line, garbled into "[email protected]" by an e-mail obfuscator, now gives the address. The report body is unchanged.
- **`NOTICE`**: lists PCT/IB2026/058860 (filed 21 August 2026) beside the three earlier applications, as `PATENTS.md`, `README.md`, `CITATION.cff` and the engine header already do.
- **`COMMERCIAL.md`**: the commercial patent licence it describes now names PCT/IB2026/058860 beside the three earlier applications, by the owner's decision of 2026-10-01.
- **`add_spdx_headers.sh`**: wrapped in `REUSE-IgnoreStart` / `REUSE-IgnoreEnd`. The SPDX lines it contains are search patterns and templates, which `reuse lint` read as six invalid licence expressions. Behaviour unchanged.
- `reuse lint` now reports no invalid expression. The one remaining message, "unused license `LicenseRef-MCL-Security-Research-Grant`", follows from the deliberate choice recorded in `REUSE.toml` not to encode the grant as an SPDX expression.
- `MANIFEST.md`: the hashes of the four changed files and of this `CHANGELOG.md` are updated; no other row changes.

## Unreleased — staged 2026-09-30

**Quantum sequentiality of VDF128-T4 v4 (Paper 4, OP2; `QUANTUM_SCOPE_NOTE.md` §2.7).** Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar **v1.0.7 unchanged**; no header and no measured number of an earlier record changes. Draft for the author's review.

- **`P4_QuantumSequentiality_20260930/`** (new; Doc ID MCL-P4-QSEQ-2026-0930-001). `QSEQ_PROOF.md`: **Proposition Q1**. In the ideal model (a uniformly random round function shared by all positions, the clock added to its input, queries in superposition), an adversary of query depth d ≤ L − 1 outputs the final state with probability at most L(L−1)/2^(s+1) + (2^(−s/2) + 2Σ_k √(q_k(L−k)/2^s))², which is about 4·d·q·L/2^s. The proof uses one-way-to-hiding hybrids (Ambainis–Hamburg–Unruh 2019, Theorem 3) over a lazy form of the chain. The quantum bound is weaker than the classical one from the same proof by a factor of (32/9)·L; at s = 128 it certifies little for N ≥ 10^10 (`qseq_bound.py`, `qseq_bound_20260930.log`). Remark 5.1 notes that the single-function model carries a factor L that the figure (q+1)/2^s quoted for Paper 4's Theorem 1 does not; `qseq_lfactor.py` shows the factor is attained by a classical attack at toy size (a property of the model, not of the proof). `qseq_struct.cpp` and `qseq_struct_20260930.log` hold structural probes of the concrete map against known fast-forwarding mechanisms (translations, additive differences, full-width single-word image fractions, nonlinear amplitude, birthday). They also record a **new one-round relation**: about half of v4 weight sets (9,906 of 20,000 in a census) have a quarter- or half-turn offset δ with F(x + δ) = F(x) + δ on a fraction 2^−15 of states, measured at the rate the sine table predicts and never for two rounds running. It does not shorten depth; a derivation rule is proposed for the author's decision. Scope note §2.7 stays open for the concrete map; items 15 and 17 stay withdrawn.

## v0.2.16 — 2026-09-30

**Paper 5 review records · corrected labels · staged items of 2026-09-28.** Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar **v1.0.7 unchanged**. No measured number of an earlier record changes.

- **`P5_ReviewMeasurements_20260930/`** (new; Doc ID MCL-P5-FRESHEXAM-2026-0930-001): the 10⁶-trial wrong-device repetition on Q30 with harness v3.2 unchanged (`results_v32_q30_native_arm64_FAR1e6_20260930.txt`: 0 accepts, mean Hamming 127.982/256, z = −2.25); the §III.B parity-lock census record (`parity_lock_20260930.log`: 100,005 / 99,995 / 0; q odd 91.80 %) and the §X.9 re-draw census record (`redraw_rate_20260930.log`, `redraw_rate_v2_20260930.log`: 395 → 0) — the two programs had been archived in v0.2.15 without their outputs. Also the exact identity-collision constant of the version-2 derivation map (`derive_v2_identity_collision.py` and `_20260930.txt`: 2.146/M² per pair, ≈ 1.07 colliding pairs at 10⁶ identities with M = 10⁶), used in Paper 5 §VII.A.
- **`P5_ReviewMeasurements_20260905/`**: `p5_adversarial.cpp` prints the correct Bonferroni threshold (5.72σ; the 2026-09-05 record said "~4.6 sigma") and `adversarial_20260930.log` is its re-run — every A1 row and both A2 maxima byte-identical to the 2026-09-05 record, which is kept; `p5_system_eval.cpp` gains a comment on the tag row (K passed as both K and S_device; timing value-independent); `redraw_rate.cpp` v2 uses the engine's `mcl_sha256` (builds on Linux); README rows corrected (quiet-host derivation latencies; CT-sine 0.552 ms / ≈ 7,300×).
- **`keyed_q30_PQ/CT_SINE_CODE_EVIDENCE_20260919.txt`** (new): machine-code evidence that the opt-in constant-time sine is oblivious on arm64 only (x86-64 clang -O2/-O3 emits a secret-dependent branch); sidecar not changed.
- `hd_v2/` banners: the printed "6.0.0" is the verification program's document version, not the engine version (comment only).
- `P5_HDVerify_FULL_20260904/README.md`: note that (41475, 955466) is the version-1 child; the paper's §IV.E value is the version-2 child (827778, 933019).
- Staged on 2026-09-28 and now merged: `P4_ReviewDev_20260927/` clock-separation programs and logs, Linux cell for VDF128-T4 v4, GS/Jacobi divergence figure data; `keyed_q30_PQ/CASCADE_GUARD_V107_RECORD_20260928.md` interoperability paragraph; local-path clean-ups in READMEs and a diff header; `P4_ReviewMeasurements_2026090{4,5}/`, `P4_ReviewMeasurements_20260925/` README/SHA256SUMS refreshes.
- **`P3_FamilyGeneralization_20260930/`** (new, from the Paper 3 stream): family-generalization measurements (decorrelation, mixing, window sweeps on further map families) — see `RECORD_P3_FAMILY_GENERALIZATION_20260930.md`.
- `P4_ReviewMeasurements_20260904/mcl_core.hpp` (added): the read-only engine copy that the folder's README and `SHA256SUMS` already listed (sha256 `416ad145e79c095b…`, identical to the root engine 8.1.3) but that earlier releases did not ship.
- Wording: comments, printed program banners and folder notes in `p5_hardened_txauth/`, `p2_hardened_auth/`, `keyed_q30_PQ/`, `P5_ReviewMeasurements_20260925/`, `P1_CSF_Measurements_20260905/`, `Verification_Suite/mcl_auth_verify.cpp` and `mcl_txn_verify.cpp` now describe the transaction-authentication route and the engine properties by function ("derivation route", "public challenge", "device secret") instead of by document references; the two internal design memos `p5_hardened_txauth/ARCHITECTURAL_FINDING_20260821*.md` are withdrawn (their conclusion is Paper 5 §V). No computed value, no engine or sidecar byte and no measurement record changes; the two affected folder `SHA256SUMS` files are updated.
- `CITATION.cff` 0.2.16; MANIFEST regenerated (repository files only).

## v0.2.15 — 2026-09-28

**Scope of the quantum statements · keyed sidecar v1.0.7 · structural inventory and Grover resource model.**
Engine `mcl_core.hpp` **8.1.3 unchanged**. No measured number of an earlier record changes.

### Changed

- **`keyed_q30_PQ/mcl_keyed_q30.hpp` → v1.0.7** (SHA-256 `05c01cf8a156…`; v1.0.6 was `71a0dbaf8472…`).
  (a) The symmetry check that v1.0.6 applied to the four-oscillator path now covers the epoch lists of the
  cascade: when every epoch of a key has p ≡ q (mod 2) — about 2^−14 of keys at m = 7 — the seeds s and
  s + 2^31 gave raw states that differ by the constant translation (2^31, 2^31). The relation never reached
  the output, which is SHA-256 of the raw states. Such lists are re-drawn deterministically (q of the first
  epoch advances until the list is clear). (b) An opt-in seed rule, `MCL_Q30_SeedInit::Hashed`; the default
  rule is unchanged, and under it only the seed modulo 2^32 enters the state. (c) `mcl_keyed_q30_self_test()`
  with six known-answer values. **Default behaviour is that of v1.0.6 for every key outside that class**:
  the known-answer values of record are unchanged (`0x58C99E3E`, `0xF7C81BC4`) and the four-oscillator path
  is byte-identical (65,536 weight sets and 1,024 engine runs compared, 0 differ). Record:
  `keyed_q30_PQ/CASCADE_GUARD_V107_RECORD_20260928.md`.
  *Earlier measurements:* `P4_ReviewMeasurements_20260905/` and `P4_ReviewMeasurements_20260925/` carry their
  own copy of v1.0.6 and are unaffected; the scratch-constructor patch of `P5_ReviewMeasurements_20260905/`
  applies to v1.0.7 and reproduces its log byte for byte. The header of v1.0.6 is the file of tag `v0.2.14`.
- **`mcl_postquantum.cpp` → version 6.1.0** (file name kept so that existing references resolve). The program
  is what its measurements are: classical diagnostics of the two-oscillator engine — negative control, spectral
  test, period scan, update-order divergence, sensitivity — and an accounting of the size of the secret under
  generic key search. Version 6.0.0 printed conclusions about quantum attacks that its measurements do not
  support; they are withdrawn: the verdict "resists all known quantum attacks", the "quantum algorithm
  completeness" table, "aperiodic ⇒ Shor inapplicable", the "PQ security 73.6 / 105.6 bits" figures (they
  counted the seed as secret), the "T-gates per Grover oracle" figure, and the comparison with third-party
  schemes. Every measured number of Parts 1–4B is identical, digit for digit, to the June output (in
  particular the mean divergence 2.0888 of Part 4). **`results/mcl_postquantum.txt`** is the output of
  version 6.1.0.
- **`Verification_Suite/mcl_hop_unified.cpp` → version 6.1.0** — the labels of Part B and nothing else:
  "forward secrecy" is named inter-segment separation, "topology hidden" is named after the correlation test
  that was run, and the accounting of B10 prints the pair alone (9.6 bits after halving) beside the figures
  that assume an independent key, which the program does not contain. 22 of 22 checks as before; every
  measured number unchanged. **`Verification_Suite/results/mcl_hop_unified.txt`** is the output of version
  6.1.0; one row of `Verification_Suite/README.md` follows.
- **`keyed_q30_PQ/STATUS.md`**, **`keyed_q30_PQ/README.md`** — a scope line, respectively an update note, at
  the top and one history line at the end; the bodies are left as the records of June 2026.
- **`MANIFEST.md`** — regenerated; it now lists the files of the repository only. Earlier manifests also
  listed seven local files that `.gitignore` excludes (five `*.out` console logs, one `.pyc`, one `.DS_Store`).
  `CITATION.cff` is 0.2.15.

### Added

- **`QUANTUM_SCOPE_NOTE.md`** (`MCL-QSCOPE-2026-0928-001`) — lists every sentence of this repository that
  states more about quantum attacks than the measurements behind it support, says what is withdrawn and what
  stands, and gives the governing position. It also covers three lines of the comment block "Post-quantum
  posture" in `mcl_core.hpp`; the header is left byte-identical.
- **`Quantum_Structural_Analysis_20260927/`** (10 files) — `MCL-QSTRUCT-2026-0927-001` rev 3 and
  `MCL-GROVER-RES-2026-0927-001` rev 3. (1) A classical probe that maps the attack surface of four families
  of quantum attack on the live integer maps: exact translation groups by 2-adic lifting with every element
  run on the engine, period and collision structure of four input channels, the FX shape of a legacy tag
  variant, generic collision bounds. Record run: 8 of 8 controls, 88,048 consistency checks, 27 expectations
  written before the run, 0 differ. (2) A resource model of Grover key search on the keyed four-oscillator
  path beside the published AES-256 figures; 64 values matched by an independent reference. **Neither shows
  quantum security**; both state their limits.
- **`keyed_q30_PQ/mcl_keyed_q30_v107_verify.cpp`** (36 expectations, 0 failed; byte-identical output on
  arm64 -O0 / -O3, x86-64 and under sanitizers), **`mcl_keyed_q30_v107_dump.cpp`** with
  **`mcl_keyed_q30_v107_compare.py`** (differential comparison of v1.0.6 and v1.0.7), their two logs, and
  the record named above.
- **`results/keyed_q30_test_v1.0.7_20260928.txt`** — the harness on v1.0.7: 9 passed, 0 failed; identical to
  the v1.0.6 output except timing lines.
- **`results/mcl_postquantum_v6.0.0_20260526.txt`**, **`Verification_Suite/results/mcl_hop_unified_v6.0.0_20260526.txt`**
  — the outputs of the versions 6.0.0 as published in June 2026, unmodified.
- **`P4_ReviewDev_20260927/`** (9 files + `SHA256SUMS_16.txt`) — `MCL-P4-DEV-2026-0927-001`: exhaustive
  enumeration of the translation symmetries of reduced-width replicas of the unclocked map (n = 4, w = 6;
  n = 3, w = 8; n = 2, w = 8): in every configuration the commuting translations are exactly the
  argument-preserving ones, and no translation is a period; and the small-memory walk-collision count under
  light and heavy merging.

## v0.2.14 — 2026-09-26

**Paper 4 version 4 — VDF128-T4 becomes a *clocked* map.** Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar v1.0.6 unchanged.
Additive only (plus `CITATION.cff`, `MANIFEST.md`, this file).

### Added

- **`P4_ReviewMeasurements_20260925/`** (34 files + `SHA256SUMS`) — `MCL-P4-REVIEWMEAS-2026-0925-004`:
  `mcl_vdf128_t4_v4.hpp` (the 64-bit iteration number enters every iteration through an injective
  encoding τ(i) = (lo, lo·A+hi, lo·B+hi·A, lo·C+hi·B) mod 2³² before the four Gauss-Seidel word updates;
  weight derivation, initialisation and table byte-identical to v3; output tag `VDF128-T4-v4-out`) with
  the version-4 harnesses and logs: known-answer vector (Vector 5 v4), engine-free re-implementation
  (reproduces the vector from the table file and from a sin()-regenerated table), property/falsification
  battery (21/22), differential/linear/cube-sum distinguisher, weak-lane and weak-pair probes on the v4 map,
  eight macOS cross-platform cells, and the benchmark (29.2 M iterations/s, 34.3 ns; checkpoint verification
  1.00/1.97/3.83/5.98/6.39× for k = 1/2/4/8/16). `_run2_incremental_clock/` documents a faster-clock variant
  that was measured (36.3 ns) and not adopted. Builds against the repository-root engine (`-I..`).
- **`P4_ReviewDev_20260925/`** (18 files + `SHA256SUMS_20260925.txt`) — `MCL-P4-DEV-2026-0925-001`: the toy
  random-mapping measurements behind the corrected memory-bounded floor of Proposition 3(a) (a walk that
  touches the honest path follows it and is recognised at the next stored point; success 366–1,286× the
  earlier count, ≈ N² scaling), the unclocked-vs-clocked comparison (8.56% → 0.015% at s = 28), the
  real-scale evaluation, the parity-pattern census (0.374% overlap), the argument-state rewrite and the
  shift search.

*Post-release addendum (main, 2026-09-26): the driver's console log `run_v4_all.out` was excluded from the
v0.2.14 tag by the repository's `*.out` ignore pattern although `SHA256SUMS` listed it; it is published as
`run_v4_all_20260925.log` with `SHA256SUMS` and the folder README updated accordingly. No other file changed.*

## v0.2.13 — 2026-09-25

*Re-issue of v0.2.12 with identical repository content: Zenodo's GitHub webhook answered the v0.2.12
release with a server error (HTTP 500) and refused every retry as a duplicate (409), so no archive
version was minted for that tag; the `v0.2.12` git tag remains for reference.*

**Paper 5 §V.A verifier-state record.** Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar v1.0.6 unchanged.
Additive only (plus `CITATION.cff`, `MANIFEST.md`, this file).

### Added

- **`P5_ReviewMeasurements_20260925/`** (3 files + `SHA256SUMS`) — `MCL-P5-VERIFIERSTATE-2026-0925-001`:
  the reference verifier of Paper 5 §V.A (device model, ctx, tag_v3, constant-time compare and
  `struct Verifier` copied verbatim from harness v3.2 in `p5_hardened_txauth/`) exercised under state
  loss — unsynchronised replicas, a crash before the accepted counter is persisted, a restore from an
  older backup, a lost acknowledgement, a device restored from an old snapshot — 21 deterministic
  observations (`verifier_state_apple_20260925.log`): replay protection holds only while `c_last` is
  durable, updated atomically before the acceptance takes effect, and shared by every replica.
  Builds against the repository-root engine (`-I..`); no frozen engine copy.

## v0.2.11 — 2026-09-16

**`M1_M2_apple_verification/` made self-consistent and buildable as shipped.** Engine `mcl_core.hpp`
**8.1.3 unchanged**; no measurement, log or result file changed.

### Fixed

- The directory's README (and the NIST campaign README) described a "frozen v6.0.0 engine copy in this
  directory" that the public repository has never contained (the 2026-08-22 publication note at the top of
  the same README already said it is not duplicated). All thirteen tools `#include "mcl_core.hpp"`, so they
  did not build in place. The build lines now read `c++ -O3 -std=c++17 -I.. …` (repository-root engine),
  and the false file-table row is replaced.

### Added

- `M1_M2_apple_verification/_engine_equivalence_20260916/` — every runnable tool of the directory built
  twice, against the v6.0.0 engine of record (archive v0.1.0, MD5 `241db79ecf8a42897eb9a8399cf37929`) and
  against the repository-root v8.1.3, from the Zenodo v0.2.10 archive: **12/12 numerically identical**;
  the only differing lines are a version banner (`mcl_paper2_L2_verify`) and wall-clock timings
  (`mcl_hd_throughput`), both shown in full. No frozen engine copy is shipped; the root engine is the
  reference for rebuilding.
- `M1_M2_apple_verification/SHA256SUMS` — SHA-256 of every file in the directory (recursive), as the
  other Paper 1 measurement directories already carry.

### Changed

- `CITATION.cff` 0.2.11; `MANIFEST.md` regenerated (`SHA256SUMS_MCL_v0.2.11.txt` in the build directory).

## v0.2.10 — 2026-09-16

**Paper 1 review-round measurements (external reviews #2 and #5) and one record correction.**
Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`);
keyed sidecar v1.0.6 unchanged. Additive except the three files listed under *Changed*.

### Added

- **`P1_ReviewMeasurements_20260909/`** (4 files + `SHA256SUMS`) — `MCL-P1-GOLDBIT-SEG-2026-0909-001`:
  ten pre-specified consecutive segments of N = 1e8 output samples of the seed-12345678901234 stream at
  decimation D = 2. The +1.739e-04 frequency residual of emitted bit 5 (found in v0.2.9's
  `MCL-P1-GOLDBIT-2026-0907-001`) reproduces exactly in segment 1 and is absent from segments 2–10
  (|P(1) − ½| ≤ 9.5e-05), i.e. it is transient, not a stationary bias. Tool `mcl_p1_goldbit_segments.cpp`,
  log, frozen engine-of-record copy v6.0.0 (MD5 `241db79ecf8a42897eb9a8399cf37929`).
- **`P1_ReviewMeasurements_20260909b/`** (8 files + `SHA256SUMS`) — three records against the same
  engine of record:
  - `MCL-P1-SINGLEWIN-2026-0909-001` — single-window controls of the dual-window extractor (Eq. 5 of
    Paper 1): windows [20, 27], [36, 43] and their XOR, six seeds, N = 1e8 at D = 2; all pass the
    byte-level test (`mcl_p1_singlewindow_bytes.cpp`, `singlewindow_apple_20260909.log`).
  - `MCL-P1-LSBPARADOX-2026-0909-001` — the measured replacement of Paper 1's Figure 5: per-bit
    single-ULP avalanche of the Float64 path versus the deterministic carry chain of the Q30 path, plus
    the per-position byte-level test of both paths (`mcl_p1_lsb_paradox_measure.cpp`,
    `lsb_paradox_apple_20260909.log`).
  - `MCL-P1-INITCONV-2026-0909-001` — the Table 6 single-extractor scan repeated under three
    initial-state conventions; all three give the [6, 39] XOR boundary and the same window-start-0
    statistic to three significant figures (`mcl_p1_init_convention_scan.cpp`,
    `initconv_apple_20260909.log`).

### Changed

- `P1_ReviewMeasurements_20260907/RECORD_P1_REVIEW_MEASUREMENTS_20260907.md` — a prose sentence
  misdescribed the Table 3 re-measurement log ("eleven of fourteen rows agree to ≤ 0.0006 … three
  significant figures"); corrected in place with a dated note (four rows exceed 0.0006, the largest
  −0.0012; the correct statement is agreement within 0.03 % relative throughout). The log, the tool and
  the headline figures 0.50 % / 12.73 % are unaffected. `SHA256SUMS` updated for that one file.
- `M1_M2_apple_verification/README.md` — documents the 2026-07-19 per-bit two-stride scan already in
  that directory (`mcl_perbit_msb_flank.cpp` and its two logs, Table 7 of Paper 1), including how to
  read the tool's own validation footer.
- `CITATION.cff` — version 0.2.10 (the v0.2.9 tag shipped with the 0.2.8 metadata; corrected here).
- `MANIFEST.md` regenerated (`SHA256SUMS_MCL_v0.2.10.txt` in the build directory).

Compiled binaries are not shipped; each directory's README carries the build line
(`c++ -O3 -std=c++17 -ffp-contract=off … -lm`).

## v0.2.9 — 2026-09-07

**Paper 1 reproduction artifacts** — the two directories the paper's Data and Code Availability
statement promises, now actually present. Engine `mcl_core.hpp` **8.1.3 unchanged**
(SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar
v1.0.6 unchanged. Additive only — no existing file changed except `MANIFEST.md`.

### Added

- **`P1_CSF_Measurements_20260905/`** (109 files + `SHA256SUMS`) — the cross-system campaign behind
  Paper 1 §6.2–§6.3, Fig. 1 and Supplementary S6: `mcl_attractor_dump`, `mcl_thirdmap_safezone`,
  `mcl_logistic_cycle`, `mcl_xor_control`, `mcl_cycle_search` with their logs, the `-ffp-contract=off`
  control campaign (`nofma_*`, `audit_*`), the density and coupling-phase CSVs, and the full record
  `RECORD_P1_CSF_MEASUREMENTS_20260905.md`. Engine of record for this campaign is v6.0.0
  (MD5 `241db79ecf8a42897eb9a8399cf37929`), included.
- **`P1_ReviewMeasurements_20260907/`** (7 files + `SHA256SUMS`) — two measurements from the
  2026-09-07 review round of Paper 1:
  - `MCL-P1-TABLE3-LAMBDA-2026-0907-001`: all 14 configurations of Table 3 re-measured
    (analytical-Jacobian sequential QR, 1e7 iterations, three seeds). λ₁ = 4.4165 at (3, 5, K = 6),
    the row that sets the paper's 0.50% figure, reproduces to four decimals; the maximum errors
    12.73% (empirical fit) and 0.50% (semi-analytical form) are unchanged.
  - `MCL-P1-GOLDBIT-2026-0907-001`: 0/1 frequency of every emitted bit of the Goldilocks byte
    (Eq. 5) over N = 1e8 output samples per seed at D = 2, six seeds. Output bit 5 — the
    (mantissa 25, mantissa 41) pair — carries a frequency deviation of +1.739e-04 (χ² = 12.096)
    in seed 12345678901234, the largest of the 48 statistics and above the Bonferroni threshold
    for them (10.752), and does not recur in the other five seeds; the byte-level test passes in
    all six. Reported in the paper as a measured residual of the dual-window variant rather than
    as a fluctuation.

Compiled binaries are not shipped in either directory; both carry a README with the build line.

## v0.2.8 — 2026-09-06

Joint release of three sessions' staged work — **Paper 3** records, **Paper 4** round 6 (VDF128-T4 v3), and **Paper 5** TOPS-readiness. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged. Additive only.

<!-- 2026-09-06: the P3 block (staged as v0.2.8) and the P4 round-6 block (staged as v0.2.9) were merged with the P5 block under this single v0.2.8 entry before the push, as the P4 note invited; Paper 5 cites release v0.2.8 for its §VI.E and §VII.B records. -->

### Paper 3 (records completed)

Paper 3 v3 records completed after the referee-eye and external review rounds of the evening (engine `mcl_core.hpp` 8.1.3 unchanged; keyed sidecar v1.0.6 unchanged).

### Added / Changed (`P3_DeskRejectMeasurements_20260905/`)

- `decorr_time/decorr_time.cpp` — `DECORR_BURNIN=<steps>` option (a common on-attractor burn-in before the two trajectories split); `res_{omega,K}_35_K12_gs_burnin1e4_{summary,steps}.csv` — the control cited in Paper 3 v3 §V.K (iv): growth rates 5.74–5.79 and identical t_sat / t_dec at every δ with and without the burn-in.
- `RECORD_P3_DESKREJECT_MEASUREMENTS_20260905.md` — addendum: the burn-in control and the note that for a K change the measured first-step separation is ≈ 9.6 ΔK (sequential substitution), which corrected §IV.D of the paper.
- `decorr_time/plot_decorr_steps.py`, `window_control/analyze_trace.py` and the two figure PNGs — regenerated at 320 dpi for the journal's ≥ 300 dpi requirement (data unchanged).
- `SHA256SUMS` regenerated (90 files).
- Housekeeping: the scratch-directory path printed in the header of `M1_M2_apple_verification/nist_sts_finalAnalysisReport_apple_20260721.txt` was replaced by a neutral placeholder (the 188 NIST STS results and the stream SHA-256 in the campaign README are unchanged); an obsolete `.gitignore` entry and an attribution note in `keyed_q30_PQ/STATUS.md` were removed.
- `results/MCL_Scale_v2.2.0_Test_Results_20260519.md` — the Stage-1 channel-scaling record (runs A–D, 20 → 10⁷ channels, two Apple Silicon machines, verbatim outputs) behind Paper 3 Table IV, previously outside the public bundle.
- `P3_DeskRejectMeasurements_20260905/tableVI_lyap/` — re-measurement of Paper 3 Table VI (λ₁, λ₂ vs K for (2,3); 3 seeds × 10⁷ QR iterations; record MCL-P3-TABLEVI-2026-0906-001) — the old table had no archived record.

### Paper 4 (round 6)

Paper 4 round 6 ("a superior paper for the journal"). Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar v1.0.6 unchanged.

### Added

- `VDF128_T4/mcl_vdf128_t4_v3.hpp` — **VDF128-T4 version 3** (Doc ID MCL-VDF128-T4-2026-0905-003): project-neutral domain strings (`VDF128-T4-v3-kdf`, `VDF128-T4-v3-out`, KAT input `VDF128-T4-KAT-01`) and a **full-rank parity-matrix re-draw rule** that excludes every translation symmetry of the map. Reason: the new single-bit differential probe found on the version-2 battery instance a probability-one differential — all six weights touching one state word were even, so the half-turn shift of that word commuted with every coupling argument; the exact criterion is a rank-deficient 12×4 parity matrix over GF(2), present on 6.96% of version-2 weight sets (5.63% single-word, 1.37% global) and on 0.0000% under the new rule. Map, initialization and table unchanged; version-2 files kept for the record. Vector 5 v3: y = `75d76880369509b4…`.
- `VDF128_T4/p4_vdf128v3_distinguisher.cpp` — differential (single- and two-bit), linear (two-bit masks), cube-sum profile (6 instances × r = 1…6 × d = 12/16/20) and translation-symmetry statistics. Findings reported in the paper: one-iteration non-propagation of a word's top bits through even weights (832/16,384 pairs at r = 1, none at r ≥ 2); one-iteration cube-sum imbalance (43–58/128 at d = 20), balanced from r = 2.
- `VDF128_T4/mcl_vdf128v3_{battery,cyclecheck,bench,xplat}.cpp`, `p4_vdf128v3_{kat,weaklane,weakpair}.cpp`, `p4_sha256_vs_t4v3_bench.cpp`, `vdf128_t4v3_standalone.cpp`, `run_v3_all.sh` + logs — every VDF128-T4 measurement re-run on v3: battery 21/22 (the cube-sum balance at one iteration is the recorded finding), no orbit closure within 2³³ × 3 inputs, weak-lane/weak-pair probes incl. a genuine both-lanes-<2¹⁶ input, 9-cell fingerprint (the Linux/GCC cell from GitHub Actions run 33981717768, branch `p4-linux-check`, because Docker Desktop was blocked), quiet-host timings T4 28.9 ns vs SHA-256 37.5 ns (SHA-2 instructions) / 135 ns (library), checkpoint Verify 6.59× at k = 8.
- `P4_ReviewMeasurements_20260905/` — round-6 sources and logs added (62 files, `SHA256SUMS` regenerated; README section "Round 6").

### Paper 5 (TOPS-readiness round)

The two evaluation campaigns the revised Paper 5 depends on, plus a licence header.

- `P5_ReviewMeasurements_20260905/p5_system_eval.cpp` + `system_eval_20260905.log` (Doc ID MCL-P5-SYSEVAL-2026-0905-001) — **the system evaluation behind Paper 5 §VII.B**: the three wallet roles (enrollment, authentication, generation) measured in one process against a hash-based stack (KDF1/SHA-256 + HMAC-SHA-256 + SHA-256 counter DRBG) on an idle host, MCL rows n = 400 and hash rows n = 400,000. Enrollment 0.862 ms vs 0.459 µs (≈ 1,880×; 20.62 ms with the Step-4 screen, ≈ 44,900×); tag 0.295 ms vs 2.02 µs (≈ 146×); 1 KiB 0.351 ms vs 13.87 µs (≈ 25×); mutable state 72 B vs ≈ 104 B; read-only table 262,144 B vs 0; stored secrets 1 vs 1; **primitives required 2 vs 1** — the MCL stack needs the engine *and* SHA-256 for its own KDF. **The result refutes the consolidation motivation, and Paper 5 retracts it rather than repeating it.**
- `P5_ReviewMeasurements_20260905/p5_adversarial.cpp` + `adversarial_20260905.log` (Doc ID MCL-P5-ADVERSARIAL-2026-0905-001) — **the two attempted attacks behind Paper 5 §VI.E**, both negative. A1 per-field context binding: one random bit flipped in each ctx field alone, 2,000 trials per field, all six fields within 1.6 standard errors of the 128/256 null, repeated at B = 0. A2 first-order weight leak (the §X.12 concern): 20,000 keys × 360 weight bits × 256 tag bits = 92,160 point-biserial correlations at B = 10,000 and B = 0; max |r| 0.0309 (4.37σ) and 0.0298 (4.22σ) against a noise floor 0.00707 and an expected null maximum ≈ 4.92σ — no first-order weight leak at either burn-in. Uses the scratch burn-in-override engine copy; the engine of record is untouched.
- Quiet-host re-measurement of the derivation throughput (`hd_throughput_v{1,2}_quiet_20260905.log`): v2 bare 0.820–0.833 ms, with the Step-4 screen 20.60–20.61 ms (96.0 % of the safe path); v1 0.819–0.822 / 20.56–20.58 ms. These supersede the loaded-host figures of the v0.2.7 records.
- `hd_v2/mcl_hd_v2.hpp` — added the standard SPDX copyright/licence header and the four-PCT patent notice, matching `mcl_core.hpp` and the keyed sidecar. **No code change**: the derivation is byte-identical and the v2 campaign record stands.
- `P5_ReviewMeasurements_20260905/README.md` and `SHA256SUMS` regenerated.

### Changed (release)

- `CITATION.cff`: `version: 0.2.8`, `date-released: 2026-09-06`. `MANIFEST.md` and `SHA256SUMS_MCL_v0.2.8.txt` regenerated.

## v0.2.7 — 2026-09-05

<!-- 2026-09-05: the P4 round-5, P5 round-3 and P3 post-desk-reject blocks were merged under this one v0.2.7 entry by the P5 session before the push. -->

Joint release — **Paper 4 referee-eye review round 5** (re-review after round 4), **Paper 5 referee round 3** (`Paper_5_HD_Keys_TxAuth`, ACM TOPS submission) and **Paper 3 post-desk-reject measurements**. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged; VDF128-T4 v2 unchanged. Everything below is additive.

### Paper 4 (round 5)

### Added

- `VDF128_T4/p4_vdf128v2_weaklane.cpp` + `P4_ReviewMeasurements_20260905/vdf128v2_weaklane_apple_20260905.log` — **weak-lane instances** of the per-input map: 40 M inputs ground through the v2 derivation (a lane below 2²⁰ in 1.17% of inputs, below 2¹⁶ in 0.07%); the structural probes (avalanche profile r = 1…8 with per-word split, single-bit linear correlations r = 1, 2, cube/degree sums) on the maps of ground inputs whose smallest lane is 506,386 / 31,590 / 6, against the battery input. A lane of 6 delays the diffusion of one state word by about one iteration (61.1/128 after one, 63.4 after two, ≈64 from the third); no linear pair above 4.5σ; every cube sum non-zero.
- `VDF128_T4/p4_vdf128v2_weakpair.cpp` + log — **weak-pair instances** (one pair with both lanes small; expected once per ≈2²⁵ inputs, hence adversary-selectable): constructed sets (both < 2¹⁶ — indistinguishable from control; (6, 31590); (6, 7) extreme) with the re-draw rules re-checked; `--grind` mode searches for a genuine input.
- `VDF128_T4/p4_sha256_vs_t4_bench.cpp` + `sha256_vs_t4_bench_apple_20260905.log` — same-host interleaved best-of-5 bench of the VDF128-T4 iterate against a SHA-256 chain through the ARMv8 SHA-2 instructions (cross-checked against CommonCrypto: identical after 1000 links) and through the system library. Two runs: at load 5.9 with two foreign jobs present (ratios only) and on an idle host (`…_idle_…log`): **T4 29.2 ns / SHA-2-instruction compression 38.0 ns / library call 136.1 ns** — one iteration = 0.77 hardware SHA-256 compressions; a library call = 4.7 iterations; the idle absolutes are the ones the paper quotes.
- `VDF128_T4/vdf128v2_weakpair_grind_apple_20260905.log` — a genuine input whose pair (1,2) has both lanes below 2¹⁶ (`weak-lane-180785906`, found after 140,785,907 candidates) probed identically: indistinguishable from the control.

### Changed (Paper 4)

- `P4_ReviewMeasurements_20260905/README.md`, `SHA256SUMS` regenerated.

### Paper 5 (round 3) — security note: `derive_child` (Paper 5 §III, "HD derivation") is not one-way as published

In `derive_child` (v1, unchanged in `mcl_core.hpp`) the 32 raw bytes of the parent run are the same for every index and the index enters as a **public, invertible XOR mask** (`fmix64(i)`, `fmix64(i)·0x9E3779B97F4A7C15`). Consequences, both measured (`P5_ReviewMeasurements_20260905/`): **(a) sibling recovery** — from the p-values of three observed children the parent block `R_lo` is recovered by enumerating 2⁶⁴/(M−2) candidates (23.8 s single-thread at M = 10⁹) and every other sibling is then computable without the seed or the parent pair (`sibling_recovery.cpp`); **(b) parity lock** — `parity(p) XOR parity(q)` is constant per parent (`p5_parity_lock.cpp`). Do not use v1 where sibling secrecy matters. The Tech Guide had recorded the fix as "recommended, not yet implemented" since rev. 1.2.

### Added (Paper 5)

- `hd_v2/mcl_hd_v2.hpp` (v1.0.0, Doc ID MCL-HD-V2-2026-0905-001) — `derive_child_v2` / `derive_child_safe_v2`: the index is mixed one-way, `d = SHA-256("MCL-HD-v2" ‖ R[0:32] ‖ LE64(i))`, `c₁ = LE64(d[0:8])`, `c₂ = LE64(d[8:16])`; range map, p ≠ q bump, coprimality loop and the Step-4 resonance screen are the v1 code verbatim. Include after `mcl_core.hpp`.
- `hd_v2/mcl_hd_verify_v2.cpp` + `hd_verify_v2_FULL_v8.1.3_20260905.log` — the Paper-5 §IV campaign (135 pairs, global Bonferroni, 9,702-candidate collision check, resonance screen at K = 1.0, three map families) re-run on v2: **0 rejections**. `hd_v2/mcl_hd_throughput_v2.cpp` + re-timing of v1 and v2.
- `p5_hardened_txauth/` **harness v3.2** (`mcl_txauth_v3_battery.cpp`, `mcl_txauth_v3_battery_q30.cpp`; Doc IDs MCL-P5-V32BATTERY-2026-0905-001 / -Q30-2026-0905-002): portable (engine SHA-256, no CommonCrypto — builds on Linux); avalanche test flips a uniformly random bit of `canon(TX)` (384 positions; v3.1 exercised 16); weak-set re-draw census; `-DMCL_TX_COMBINER` builds the **PRF-XOR combiner** `Tag = HMAC-SHA-256(K_mac, ctx) XOR G(KDF(S_device, ctx))`, `K_mac = KDF(K, "MCL-TxMAC-v1", "")` (Paper 5 §V.E). Records `results_v32_{double_native, double_combiner, q30_native_arm64, q30_native_x86_64, q30_combiner_arm64}_20260905.txt` — all PASS; Q30 fingerprint identical across arm64 / x86_64. The constant-time-sine build (an oblivious 65,536-entry scan per sine) is timed separately by `P5_ReviewMeasurements_20260905/p5_ct_sine_cost.cpp` (identical tags, ≈ 4.0 s per tag vs 0.39 ms). v3.1/v3.1.1 sources kept as `_v31_backup_*.txt`.
- `P5_ReviewMeasurements_20260905/` — the round-3 measurements with `README.md` (Arabic), `README_EN.md` and `SHA256SUMS`: `sibling_recovery.cpp/.log`, `p5_parity_lock.cpp`, `redraw_rate.cpp` (395/200,000 raw symmetric weight sets → 0 after the sidecar's deterministic re-draw), `p5_v2_coprime_parity.cpp/.log` (v2: 39.29 % raw non-coprime vs 39.21 % expected; no parity lock), `p5_burnin_curve_v2.cpp` + log (B = 0…10,000: every first-order statistic at its null value; MDE ≈ 0.45 bit), `p5_G_entropy.cpp` + log (**birthday estimate of the collision entropy of the key→tag map G(U)**, 2²⁵ keys, 42-bit truncation — the one engine-dependent term of Paper 5's Theorem 1), `p5_resonance_control.cpp` + log (positive control of the χ² screen on the (3,5) window at K ≈ 1.22), `p5_weight_probe.cpp` + log + diff (wrong-weight flatness measured on the weights themselves, both realizations), `header_patch.diff` (the real scratch-engine diff for the burn-in knob), `mcl_hd_throughput.cpp` + logs.
- `P5_HDVerify_FULL_20260904/` — the **version-1** FULL campaign record on engine 8.1.3 (`hd_verify_FULL_v8.1.3_20260904.log`, throughput logs, `coprime_frac.cpp` 59.47 %): the provenance of the earlier draft's §IV numbers and the baseline the v1 break was measured against (staged for v0.2.3 but not pushed then).
- `RETIRED_mcl_txn_verify.md` — `mcl_txn_verify.cpp` implements the superseded input-composition tag; kept only as the provenance of its 2026-06 record. Paper 5's protocol is the `p5_hardened_txauth` harness.

### Changed (Paper 5)

- Paper 5 (text, not in this repository): §V now carries **Theorem 1** — the engine is a public post-processing of a single-use KDF output, so tx-auth unforgeability reduces to KDF-PRF + CR(H) + q_V·2^(−H∞(G(U))) with **no assumption on the map**; the "assumption diversity" claim of earlier drafts is withdrawn for the engine-native tag and holds only for the combiner.

### Paper 3 (measurements after the PRE desk rejection)
Paper 3 v3 measurements after the Physical Review E desk rejection (04 Sep 2026): the paper is reframed as *parameter-induced decorrelation with a Lyapunov time scale and a boundary at the phase-locking windows* (target: Chaos, AIP). Engine `mcl_core.hpp` **8.1.3 unchanged** (MD5 `5d8b49ee11aa0bfb8b0bda3f47fa16e3`); keyed sidecar v1.0.6 unchanged. No header patch: every tool calls the engine's own iteration, Lyapunov and statistics routines and asserts bit-identity where it re-implements a step.

### Added (Paper 3)

- `P3_DeskRejectMeasurements_20260905/` — record MCL-P3-{DECORR,WINDOWCTRL,JACOBI,PAIRDIST}-2026-0905-001 with `SHA256SUMS`, `RECORD_P3_DESKREJECT_MEASUREMENTS_20260905.md` and the run log:
  - `decorr_time/` — **decorrelation time of two same-seed trajectories under a parameter perturbation** (δω₂ = 10⁻¹²…10⁻¹, δK, adjacent integer weights; 16,384 seeds; (3,5) at K = 6/12/20 with Gauss–Seidel and Jacobi; (2,3), (7,11), (17,23) at K = 12): separation growth rate / λ₁ = 0.9968–1.0013 in 14 configurations; t_dec linear in ln(1/δ₁) with slope 1/λ₁ (Paper 3 v3 Eq. 9, Fig. 5).
  - `window_control/` — **the decorrelation fails inside the phase-locking windows**: ΔK = 0.01 on the Fig. 1 grid ((2,3),(3,5), K = 0.30…1.00): 36/36 locked cells with a locked partner keep a deterministic relation (periodic: r ≈ 0.99, MI = log₂ period; quasi-periodic: ensemble correlation oscillates without decaying), 0/32 chaotic cells; `window_trace` r_ens(t) traces (Paper 3 v3 §III.C, Fig. 4); `cell_check` for the four edge cells.
  - `jacobi_orth/` — **§V.B protocol with the Jacobi update**: 0/3,800 Pearson, 0/3,800 Hamming, 0/3,800 raw-phase rejections (max |r| = 0.001339); same-tool Gauss–Seidel control reproduces the published campaign exactly (0.001138 / 0.000249 / 3.18e-4 / 49.9999 %); λ_J for the 20 topologies; **fresh-seed replicate** (`SEED_OFFSET=1000003`, full precision): 0/3,800, max |r| = 0.001255, |z| half-normal by KS (p = 0.69) and Anderson–Darling (0.62).
  - `pairs_dist/` — `mcl_orth_verify --full --evidence-file` re-run on 8.1.3 (VERDICT PASS, values identical to the June record) + `pairs_ks.py` (KS/AD/CvM/Shapiro–Wilk on the pair statistics; rounded-null calibration: a 6-dp evidence file inflates Anderson–Darling under the null — median A² 4.9 — so tail tests need full-precision output, which the v3 tools print).

### Changed (Paper 3)

- Nothing in the engine or in previously published records.

### Changed (release)

- `CITATION.cff`: `version: 0.2.7`, `date-released: 2026-09-05`. `MANIFEST.md` and `SHA256SUMS_MCL_v0.2.7.txt` regenerated.

## v0.2.6 — 2026-09-05

Paper 4 referee-eye review round 4: **VDF128-T4 version 2 (per-input coupling weights)**. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged; the v1 header `VDF128_T4/mcl_vdf128_t4.hpp` is kept unmodified for the record.

### Added

- `VDF128_T4/mcl_vdf128_t4_v2.hpp` — additive v2 header (Doc ID MCL-VDF128-T4-2026-0905-002): the twelve weights are derived from `SHA-256(x)` through the sidecar's audited `mcl_t4_q30_params_from_key`, so each input evaluates its own map; output tag `MCL-VDF128-T4-v2-out`. Reason: a fixed public 128-bit map admits a generic Hellman/distinguished-point precomputation with jump-ahead probability ≈ N·W₀/2¹²⁸ (≈ 2⁻⁸ at N = 2⁴⁰, W₀ = 2⁸⁰), far above the term the v1 conjecture stated; the toy reproduction is `P4_ReviewMeasurements_20260905/p4_tmto_toy.py` (measured 2.27e-2 vs the v1 term 7.3e-6 on a 32-bit map).
- `VDF128_T4/mcl_vdf128v2_battery.cpp`, `…v2_cyclecheck.cpp`, `…v2_bench.cpp`, `…v2_xplat.cpp`, `p4_vdf128v2_kat.cpp` + logs — every VDF128-T4 measurement re-run on v2: battery **22/22** (10 properties, 4 attacks, 3 new structural probes: single-bit linear correlations at r = 1/2/4 indistinguishable from an independent control, cube sums non-zero at dimension 20 after one iteration, avalanche profile 63.2 → 64.5/128 over r = 1…8); **no orbit closure within 2³³ steps × 3 inputs**; 34.2 M iter/s; checkpoint Verify 6.70× at k = 16 on 8 cores; **9-cell cross-platform fingerprint identical** (arm64, x86_64/Rosetta, Linux GCC).
- `P4_ReviewMeasurements_20260905/` — record MCL-P4-REVIEWMEAS-2026-0905-002 with `SHA256SUMS`: the above sources and logs, `vdf128_t4v2_standalone.cpp` (engine-free re-implementation of Algorithm 1 v2; reproduces Vector 5 v2 — y = `1d0f60cc602b12ed…` — on macOS and on x86_64 Linux/glibc 2.36, from the table file and from a `sin()`-regenerated table), the normative sine table, the TMTO toy script, and a SHA-256 hash-chain rate on the same host (7.3 M hashes/s vs 34 M iter/s) for the paper's comparison table.

## v0.2.5 — 2026-09-04

Paper 4 external-review round 2. Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar v1.0.6 unchanged.

### Added

- `P4_ReviewMeasurements_20260904/vdf128_t4_standalone.cpp` — an **engine-free re-implementation of Paper 4's Algorithm 1 (VDF128-T4)** with its own SHA-256, KDF, weight derivation, table loader, four-oscillator Gauss-Seidel iterate and finalization (shares no code with the engine). Reproduces Appendix Vector 5 exactly on macOS and on x86_64 Linux/glibc 2.36 (logs included).
- `P4_ReviewMeasurements_20260904/q30_lut_int32le.bin` — the **normative sine table as a byte sequence** (65,536 × int32 little-endian, 256 KB; SHA-256 `f78c9584e5686cb1f54f382b1bfcf87c3399ae19f987e7761f339bdb3bd7dd1d`, CRC-32 0xde1340cf) with `p4_lut_digest.cpp`. Regenerating the table with `sin()` on Apple-libm and on glibc 2.36 yields the same digest.

### Changed

- `CITATION.cff`: `version: 0.2.5`. `MANIFEST.md` regenerated.

## v0.2.4 — 2026-09-04

Paper 4 external-review records. Engine `mcl_core.hpp` **8.1.3 unchanged**; keyed sidecar v1.0.6 unchanged.

### Added

- `P4_ReviewMeasurements_20260904/p4_vdf128_kat_avalanche.cpp` + logs (macOS and Linux/glibc, byte-identical): a **complete VDF128-T4 known-answer vector** with every intermediate — SHA-256(x), K_pub, the twelve public weights, ω₁..ω₄, K_phase, LUT CRC-32, initial state, C₀…C₄, the 80-byte SHA-256 preimage and y (x = "MCL-VDF128-KAT-1", B = 10⁴, N = 10³; y = `3059e862…`) — plus per-iteration avalanche on the T4 map (one-bit state flip → 63.27 / 63.88 / 64.19 / 64.02 of 128 bits after 1–4 iterations). This is Paper 4's Vector 5 and its Algorithm 1 reference.
- `P4_ReviewMeasurements_20260904/vector4_q30_linux_glibc_20260904.log`: the Appendix Vector-4 program re-run natively on Linux/glibc — bit-identical to macOS.

### Changed

- `CITATION.cff`: `version: 0.2.4`, `date-released: 2026-09-04`. `MANIFEST.md` regenerated.

## v0.2.3 — 2026-09-04

Paper 4 (IACR Communications in Cryptology) pre-publication records. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged.

### Added

- `P4_ReviewMeasurements_20260904/` (record MCL-P4-REVIEWMEAS-2026-0904-001) — five single-file harnesses with logs: Gauss-Seidel-vs-Jacobi Pearson |r| and Hamming distance on 10⁶ extracted bytes (replica extractor self-checked byte-for-byte against `MCL_T2::gen_byte`; |r| = 0.000456, Hamming 49.969 %); a 10⁷-iteration exact state-collision search (0 repeats); orbit-averaged log-determinants and the determinant-ratio estimator (6.797 / 6.352 / 0.4459 vs the closed form 0.4463); the Appendix test vectors regenerated on macOS Apple-libm **and** on x86_64 Linux glibc 2.36 / GCC 13.4 (Debian 12 container) with θ bit patterns and CRC-32s; and a 36-cell Q30 determinism matrix — {arm64, x86_64/Rosetta} × {-O0…-O3} × {none, UBSan, ASan} on macOS plus {-O0…-O3} × {none, UBSan, ASan} with GCC on Linux — all cells byte-identical (aggregate CRC `0xD9FE9B13`; raw state-word bytes: entropy 7.999801, χ² 275.35).
- Finding recorded in the same folder: the Float64 (`MCL_T2`) stream is libm-**build**-dependent, not merely OS-dependent — glibc 2.36 gives CRC-32 `0xD65C897C` for the reference seed, the May-2026 glibc build gave `0xF5E977E0`, Apple-libm gives `0x1A734C6F`. The Q30 integer path is identical on all of them.

### Changed

- `CITATION.cff`: `version: 0.2.3`, `date-released: 2026-09-04`. `MANIFEST.md` regenerated with per-file SHA-256.

## v0.2.2 — 2026-09-03

Paper 3 (Physical Review E) pre-publication records. Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80`); keyed sidecar v1.0.6 unchanged.

### Added

- `P3_ReviewMeasurements_20260903/` — direct phase-locking diagnostics on the Paper 3 Fig. 1 grid (`phaselock/`: unwrapped winding ratio W, order parameter R_α of the coupling argument, exact period, λ₁, byte-level χ²; 144 cells; record MCL-P3-PHASELOCK-2026-0903-001) and raw-phase cross-dependence tests (`rawphase/`: Pearson on cos/sin θ, lagged cross-correlation, mutual information, joint-density χ², distance correlation on 8 channel pairs plus identical / next-state / noisy controls; record MCL-P3-RAWPHASE-2026-0903-001). The two C++ tools read the engine's phases through a one-line read-only patch to a scratch copy of the header (`header_patch.diff` in each folder); no engine arithmetic is touched.
- `P3_WindowSweep_6_20_20260903/` — K ∈ [6, 20] at step 0.005 for (2,3), (3,5), (5,7), (7,11), 2 × 10⁵ QR iterations per point, criterion λ₁ ≤ 0.02: zero periodic windows (record MCL-P3-WINSWEEP-2026-0903-001).
- `P3_Fig3_Regeneration_20260903/` — Paper 3 Fig. 3 regenerated from a real run (20 canonical coprime channels × 10⁷ bytes, seed 12345678901234, K = 12): pairwise-|r| CSV, generator, figure script and PNG (record MCL-P3-FIG3-2026-0903-001; max |r| = 0.000870, mean 0.000265).
- `P3_NonlinearDependence_20260603/` — the June-2026 nonlinear-dependence campaign cited in Paper 3 §V.I: five test programs (mutual information, distance correlation, lagged cross-correlation, block-joint χ², lag autocorrelation), 66 channel pairs, `results_v3/` records and campaign manifest. Engine copy of 6.0.0 omitted (git tag `v0.1.0`; KAT-identical T2 path to 8.1.3).
- `results/mcl_k_independence.txt` — first archived run of `Verification_Suite/mcl_k_independence.cpp` on engine 8.1.3 (1,137 pairs, 0 rejections; the 22 per-configuration maxima are bit-identical to the April and June 2026 records). Built with `-DMCL_UNSAFE_ALLOW_INVALID` because the wide-K sweep starts below the runtime sentinel.

### Changed

- `Verification_Suite/README.md`: build flag and result path for `mcl_k_independence.cpp`.
- `keyed_q30_PQ/`: full `dieharder -a` battery on engine 8.1.3 + sidecar 1.0.6 — **117 PASSED / 0 WEAK / 0 FAILED** (`MCL_KEYED_Q30_DIEHARDER_20260903.txt`, dieharder 3.31.1); `README.md` and `STATUS.md` updated (the 13-test June subset is retained unchanged as a historical record).
- SPDX short headers (the `add_spdx_headers.sh` form) added to the six new tool files.
- `CITATION.cff`: `version: 0.2.2`, `date-released: 2026-09-03`. `MANIFEST.md` regenerated with per-file SHA-256.

## v0.2.1 — 2026-09-02 (metadata only; no code change)

* `CITATION.cff` and the README DOI badge now cite the Zenodo **concept DOIs**
  (`10.5281/zenodo.20496568` for this repository; `…20496684`, `…20496909`,
  `…20496911`, `…20496913`, `…20496915` for the five companion papers). A concept
  DOI is stable across versions and always resolves to the latest one; the
  version DOIs cited before (`…20496569`, `…20496685`, …) point permanently at the
  2026-06-01 v0.1.0 / v1 records. `CITATION.cff` `version`/`date-released` bumped.
* Engine `mcl_core.hpp` **8.1.3 unchanged** (SHA-256 `416ad145e79c…`, MD5
  `5d8b49ee11aa0bfb8b0bda3f47fa16e3`); every KAT/keystream identical to v0.2.0.
  Paper 1 pins its measurements to the engine of record 6.0.0 (MD5
  `241db79ecf8a42897eb9a8399cf37929`, release v0.1.0) and cites this release as
  the current, byte-identical implementation.
* `MANIFEST.md`: SHA-256 rows of the three edited files refreshed.

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
- `p5_hardened_txauth/` — Paper 5 hardened transaction-authentication v2 (16/16), v3 derivation route (11/11) and v3 battery (18/18), `mcl_d1_collision.cpp` Brent search (1.63×10¹⁰ trials) producing a real colliding payload pair on the retired 64-bit-fold path.
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
