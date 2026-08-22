<!-- SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com> -->
<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# MCL — Madeeh Chaotic Lock

A new primitive built on **coupled chaotic oscillators** (nonlinear dynamics),
with applications to **pseudorandom generation and authentication** — i.e., a
cryptographic primitive — published for **independent verification and
adversarial analysis**.

[![License: PolyForm NC 1.0.0](https://img.shields.io/badge/license-PolyForm--NC--1.0.0-blue)](LICENSE)
[![Security research: encouraged](https://img.shields.io/badge/security%20research-encouraged-brightgreen)](SECURITY.md)
[![Status: experimental](https://img.shields.io/badge/status-experimental-orange)](#-experimental--not-yet-audited)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.20496569.svg)](https://doi.org/10.5281/zenodo.20496569)

---

> ## ⚠️ EXPERIMENTAL — NOT YET SECURITY-AUDITED — DO NOT USE IN PRODUCTION
>
> MCL is a **new** cryptographic primitive that has **not** undergone
> independent third-party security review. Until at least two unrelated
> qualified teams have published positive cryptanalysis-and-audit results,
> MCL **must not** be used to protect:
> - real secrets, money, or production systems;
> - human-rights-critical communications;
> - medical, legal, or financial data;
> - anything you cannot afford to have compromised.
>
> For production needs today, use a standardized primitive appropriate to your
> use case — for example, **AES-GCM** or **ChaCha20-Poly1305** for authenticated
> encryption, **HMAC** or **KMAC** for message authentication, a NIST/FIPS DRBG
> for random generation, or **ML-KEM / ML-DSA** for post-quantum public-key
> needs. MCL is offered for study and validation, not deployment.

---

## What's new in v0.2.0 (22 August 2026)

The June-2026 release (`v0.1.0`) shipped engine **6.0.0**. This release ships
the engine that the revised companion papers were measured on, plus the
evidence folders those papers cite. Nothing in the original bundle was removed;
every pre-existing known-answer test (KAT) is **byte-identical** across
6.0.0 → 8.1.3. Details: [`CHANGELOG.md`](CHANGELOG.md); per-file hashes:
[`MANIFEST.md`](MANIFEST.md).

| Component | v0.1.0 (June 2026) | **v0.2.0 (this release)** |
|---|---|---|
| `mcl_core.hpp` reference engine | 6.0.0 | **8.1.3** — adds the 256-bit keyed (SHA-256 KDF) weight-derivation paths, device-bound derivation, seed-anchored VDF transcript verification, fail-closed verifiers, hardening guards; `MCL_PQ_MAX` narrowed 2⁶² → 2⁵³ (exact-double bound) |
| `keyed_q30_PQ/` FPU-free keyed integer engine (`MCL_T4_Q30`, 12 integer weights, sidecar header) | — | **v1.0.6** — with symmetry-class rejection in key→weight derivation; KATs `0x58C99E3E` / `0xF7C81BC4` |
| `VDF128_T4/` 128-bit-state integer sequential-function path (Paper 4 normative) | — | new; 14/14 property+falsification battery, 8/8 cross-arch fingerprint |
| Self-analysis records (cycle structure, translation symmetry, return-map attacks, weak-key class) | — | `T4_CycleStructure/`, `ReturnMap_Attack/` — **including the negative findings** (see "Known limitations") |
| Protocol-hardening batteries for Papers 2 and 5 | — | `p2_hardened_auth/`, `p5_hardened_txauth/` |
| Paper 1 / Paper 3 measurement provenance | — | `M1_M2_apple_verification/`, `P3_CrossPrediction/` |
| Legacy verification programs | — | `Verification_Suite/`, `Layer_Combiner/` |
| Patent notice | 3 PCT applications | **4** — PCT/IB2026/058860 filed 21 August 2026 (`PATENTS.md`) |

**Known limitations disclosed with this release** (all measured on the shipped
code; records in the folders named): the Q30 integer map has an exact
**translation symmetry** in its coupling arguments, which (i) breaks the *retired*
two-oscillator raw VDF path by related inputs — superseded by `VDF128_T4` — and
(ii) produced a ≈2⁻⁹ **weak-key class** in the keyed T4-Q30 derivation, rejected
since sidecar v1.0.6; the measured cycle structure of the 128-bit T4-Q30 map is
λ₁₂₈ ≈ 2^62.3 ± 0.2 (a factor ≈ 2 below the random-mapping model). See
`T4_CycleStructure/T4_CYCLE_RECORD_20260822.md`, `keyed_q30_PQ/NOSYM_V106_RECORD_20260822.md`
and the engine changelog (`mcl_core.hpp`, VERSION IDENTIFICATION block).

## What MCL Is

MCL is a reference implementation of a cryptographic construction built on the
dynamics of coupled chaotic oscillators. It targets several use cases described
in the companion papers (e.g., pseudorandom generation, authentication, key
derivation). It is published so the community can study it, reproduce its
claimed properties, and — most importantly — **try to break it.**

## What MCL Is Not

MCL is **not** a finished, audited, or standardized cryptosystem, and it is
**not** a drop-in replacement for established primitives. It is a research
artifact under active validation.

## Repository layout

| Path | Contents |
|---|---|
| `mcl_core.hpp` | Header-only reference engine, **v8.1.3** (SHA-256 `416ad145e79c095b…`) |
| `*.cpp` (repository root) | The 23 reproduction / KAT / self-analysis programs of the June release (unchanged except for the patent line in each banner) |
| `results/` | Their recorded outputs (June 2026, engine 6.0.0) + fresh 8.1.3 re-runs of `self_test`, `kat_gen_macos`, `q30_macos_validation` |
| `keyed_q30_PQ/` | FPU-free keyed integer engine `mcl_keyed_q30.hpp` v1.0.6 + its test/measurement programs and records |
| `VDF128_T4/` | 128-bit-state integer sequential function (`mcl_vdf128_t4.hpp`), battery, cross-platform fingerprint, bench |
| `T4_CycleStructure/` | Reduced-width cycle study, translation-symmetry group, weak-key parity check, float-path symmetry check (+ logs) |
| `ReturnMap_Attack/` | Chaos-specific attack attempts (return-map reconstruction, conditional entropy, EFA) against the keyed stream and raw state |
| `p2_hardened_auth/` | Paper 2 hardened authentication profile (v2) + FAR / avalanche / engine-sensitivity / keyed-FAR campaigns and records |
| `p5_hardened_txauth/` | Paper 5 hardened transaction-authentication path (v2, v3 / Claim-4 route) + batteries + D1 collision evidence |
| `M1_M2_apple_verification/` | Paper 1 §III.B.3 / Tables 9–10 / Appendix A provenance logs (Apple-libm), NIST STS campaign archive, Paper 3 Fig. 1 sweep |
| `P3_CrossPrediction/` | Paper 3 cross-prediction (R²) experiment: determinism vs. apparent randomness |
| `Verification_Suite/`, `Layer_Combiner/` | Legacy verification programs (burn-in / decimation / K sweeps, T3/T4, hopping) and the robust-combiner demo |
| `MANIFEST.md`, `CHANGELOG.md` | Per-file SHA-256 table and engine pins; release history |

## Build & Run

```bash
# Header-only core; example build of a verification tool (repository root):
g++ -std=c++17 -O2 mcl_lyapunov.cpp -o mcl_lyapunov
./mcl_lyapunov

# Sub-folder programs include "../mcl_core.hpp" or "mcl_core.hpp" — build with -I:
clang++ -std=c++17 -O3 -I. keyed_q30_PQ/mcl_keyed_q30_test.cpp -o keyed_test && ./keyed_test
clang++ -std=c++17 -O3 -I. -I VDF128_T4 VDF128_T4/mcl_vdf128_battery.cpp -o vdf128_battery
```

Strict IEEE-754 is required (`-ffast-math` / `-Ofast` are rejected at compile
time). Known-answer test data is generated by the KAT tools in the repository;
`self_test.cpp` verifies all embedded KATs. Every program was syntax-checked
against the shipped engine on 2026-08-22 (see `MANIFEST.md` → Build notes):
the only external dependencies are GNU MPFR for the two `*_mpfr_*` / `*_lyap_sweep`
programs and Apple CommonCrypto (macOS) for the `p2_hardened_auth/`,
`p5_hardened_txauth/` and `P3_CrossPrediction/` harnesses.

## 🔨 We Invite You to Break This

MCL is published for **adversarial validation**. We actively invite academic
cryptanalysts, industry security teams, and independent researchers to:

- search for distinguishers, statistical biases, or structural weaknesses;
- mount key-recovery, state-recovery, or related-key attacks;
- study side-channel and fault-injection behavior of the reference code;
- publish negative **or** positive results — both are valuable.

**Companies are explicitly welcome to do this.** Free security research and
break-attempts — including by commercial organizations — are permitted under the
**Security Research & Evaluation Grant** (`SECURITY-RESEARCH-GRANT.md`), at no
charge. (Commercial *deployment* is separate; see Licensing below.)

The reference implementation, the verification and measurement tools, the
known-answer test generators, the self-analysis records, and the five companion
papers (DOIs in `CITATION.cff`) are **fully public** and contain everything
needed to study, reproduce, and independently reimplement MCL and its
cryptanalysis.

**Adversarial toolkit (gated).** Seven files implementing general, transferable
cryptanalytic methods pointed at MCL — `mcl_attack_suite`, `mcl_adv_attack`,
`mcl_steganalysis`, `mcl_simswap_verify`, `mcl_extraction_security`,
`mcl_neural_distinguish`, and (since v0.2.0) `mcl_simswap_v3` — are released on
request to identifiable researchers, rather than by anonymous public download.
Every method they use is described in the public papers and their *results* are
public in this repository, so a qualified researcher can also reconstruct them
independently. To request the toolkit, see `TOOLKIT_ACCESS_POLICY.md` and
`TOOLKIT_ACCESS_REQUEST_TEMPLATE.md`. This is an access-management and
traceability measure, not concealment.

**Found a break?** Please follow `SECURITY.md` for coordinated disclosure. We
will credit serious findings (with your consent) in `HALL_OF_FAME.md`, and we
ask that publications cite the work per `CITATION.cff`.

## Licensing

This is a **source-available** project (not "open source" in the OSI sense). It
is offered under **two** instruments — rely on whichever covers your activity:

| You are… | Use this | Cost |
|---|---|---|
| An academic, student, nonprofit, or public institution (research/teaching) | PolyForm Noncommercial 1.0.0 | Free |
| **Anyone (including a company) doing security research / break-attempts** | Security Research & Evaluation Grant | Free |
| A company wanting **commercial production/integration** use | A paid commercial license | Paid — see `COMMERCIAL.md` |

See `LICENSE` for the full cover-note and the verbatim PolyForm text, and
`SECURITY-RESEARCH-GRANT.md` for the research grant. Citation is required for
research use (`CITATION.cff`).

## Patents

The methods in this repository are the subject of four pending PCT patent
applications (PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673, and
PCT/IB2026/058860 — filed 21 August 2026). A noncommercial patent license, and a
patent license for security research, are granted; commercial use requires a
separate license. See `PATENTS.md`.

## Citing MCL

Please cite using `CITATION.cff` (GitHub's "Cite this repository" button) and
cite the companion paper indicated as the preferred citation.

## Companion Papers

Five companion papers are archived on Zenodo (DOIs listed in `CITATION.cff`);
revised versions accompany this release and are being submitted to their
venues. Where a paper cites a file path under `02_Engine_Code/…`, that path
maps to the same folder name at the root of this repository.

## Security

See `SECURITY.md` for the coordinated-disclosure policy and security contact.

## Project Authorship

MCL is owned and authored by **Madeeh Ibrahim** (sole inventor and project
owner). The reference implementation and the design described in the companion
papers are his own work.

**Researchers are warmly invited to use and test the code.** Any party —
including commercial organizations — may **download, compile, run, benchmark,
evaluate, and attempt to cryptanalyze** the software, and **publish their
results**, free of charge, under the **Security Research & Evaluation Grant**
(see `SECURITY.md` and `LICENSE`), subject only to a citation requirement.
Commercial *production* use requires a separate license (see `COMMERCIAL.md`).

**External code contributions** (pull requests) **are currently paused** (see
`CONTRIBUTING.md`) while specialist legal advice on contribution arrangements is
obtained — this pause concerns contributing code, not using or analyzing it,
which remain fully open. Any contribution that is accepted is taken under a
**copyright-assignment** agreement (`CLA.md`), so the project owner remains the
sole owner and licensor of the project as a whole. This is an interim,
conservative policy and may be revised after review.

## Contact

**Madeeh Ibrahim** — Independent Researcher, Cairo, Egypt
ORCID: https://orcid.org/0009-0002-8562-8325
Email: madeeh.chaotic.lock@gmail.com
