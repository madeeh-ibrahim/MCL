# MCL — Adversarial Toolkit Access Policy (Gated Release)

**Version 1.0 — 2026 · Maintainer: Madeeh Ibrahim (madeeh.chaotic.lock@gmail.com)**

## Why this policy exists

The public MCL repository contains the reference implementation (`mcl_core.hpp`),
the verification and measurement tools, the KAT (known-answer test) generators,
and the five companion papers. Everything needed to **study, reproduce, and
independently reimplement** MCL and its cryptanalysis is public.

A separate set of six **adversarial toolkit** files —
`mcl_attack_suite`, `mcl_adv_attack`, `mcl_steganalysis`,
`mcl_simswap_verify`, `mcl_extraction_security`, and `mcl_neural_distinguish` —
implement general, published cryptanalytic methods (linear-complexity /
Berlekamp–Massey analysis, differential analysis, known-plaintext analysis,
steganalysis, machine-learning distinguishers, state-recovery and
extraction/inversion search). Because these techniques are general-purpose and
transferable, they are released under a **gated model**: available on request to
identifiable researchers for security evaluation, rather than by anonymous
public download.

This is a deliberate, documented choice. It preserves genuine adversarial
validation (any serious cryptanalyst can obtain the toolkit) while reducing the
risk that the same general, transferable tools are redistributed without
context. It is **not** a secrecy measure: the *methods* are fully described in
the public papers, and a qualified researcher can reconstruct the toolkit from
them. The gate manages distribution and documents purpose; it does not hide the
science.

Three of the self-analysis files (`mcl_vdf_falsification.cpp`,
`beff_deep_audit.cpp`, `mcl_beff_compounding.cpp`) attack only MCL itself and are
**published openly** as self-analysis evidence (they strengthen credibility and
are not transferable weapons against third-party systems). A further set of nine
VDF probe files plus a `Bee Finder` tool are **out of scope** for this release
and are not published.

## What is public vs. gated vs. out-of-scope

Three states. Every file in the gated group carries the Acceptable-Use / No-Misuse
notice (see the Security Research & Evaluation Grant §8); the three public
self-analysis files carry it too.

**Public** — anyone may download:

| Component | Availability |
|---|---|
| `mcl_core.hpp` (reference implementation) | **Public** |
| Cited verification / measurement / benchmark binaries | **Public** |
| KAT (known-answer test) generators | **Public** |
| Self-analysis: `mcl_vdf_falsification.cpp`, `beff_deep_audit.cpp`, `mcl_beff_compounding.cpp` | **Public** |
| Five companion papers (full method descriptions) | **Public** |

**Gated — adversarial toolkit (6 files), on request via this policy.** General,
transferable cryptanalytic tools; require an access request and a signed
`TOOLKIT_ACCESS_AGREEMENT.md`:

| # | File | What it does |
|---|---|---|
| 1 | `mcl_attack_suite.cpp` | Suite of cryptanalytic attack classes against MCL |
| 2 | `mcl_adv_attack.cpp` | Advanced cryptanalytic attack vectors (audit) |
| 3 | `mcl_steganalysis.cpp` | Steganalysis — detection of hidden-information signalling |
| 4 | `mcl_simswap_verify.cpp` | SIM-swap threat-model evaluation |
| 5 | `mcl_extraction_security.cpp` | Key/state extraction-resistance analysis |
| 6 | `mcl_neural_distinguish.py` | Machine-learning distinguisher (MCL vs. reference stream) |

**Out of scope — not published.** Nine VDF probe files plus a `Bee Finder` tool
are not part of this release. They are kept local and are not distributed (not
even on request). They are listed here only for transparency:

| # | File |
|---|---|
| 1 | `mcl_vdf_koopman_scan.cpp` |
| 2 | `mcl_vdf_koopman_edmd.cpp` |
| 3 | `mcl_vdf_algebraic_structure.cpp` |
| 4 | `mcl_vdf_algebraic_degree.cpp` |
| 5 | `mcl_vdf_reachable_set.cpp` |
| 6 | `mcl_vdf_output_entropy.cpp` |
| 7 | `mcl_vdf_output_collision.cpp` |
| 8 | `op1_parallel_adversary.cpp` |
| 9 | `op5_cheating_prover.cpp` |
| — | `Bee Finder` (internal tool) |

*Note: `mcl_steganalysis` (was `mcl_stego_attack`) and `mcl_vdf_falsification`
(was `mcl_vdf_break_v3`) were renamed to the precise field terms before
publication. `mcl_txn_verify` is referenced by name in PCT/IB2026/053673 and is
**not** renamed.*

## Who may request access

Access is granted, free of charge, to identifiable persons or organizations
intending to use the toolkit for lawful security research and evaluation of MCL,
consistent with the Security Research & Evaluation Grant (including its
Acceptable Use and No Misuse section). Typical requesters: academic
cryptographers, university research groups, corporate security/cryptography
teams, and independent researchers with a verifiable identity.

## How to request access

Email **madeeh.chaotic.lock@gmail.com** with subject
`MCL Adversarial Toolkit Access Request`, using the template in
`TOOLKIT_ACCESS_REQUEST_TEMPLATE.md`. Provide:

1. Your name and a verifiable identity (institutional email, ORCID, ResearchGate,
   GitHub profile, company page, or equivalent).
2. Affiliation (institution / company / independent).
3. The intended purpose (what you intend to test or analyze).
4. Acknowledgment that you accept the Security Research & Evaluation Grant,
   including the Acceptable Use / No Misuse section, and that you will use the
   toolkit only against your own copy of MCL or systems you are authorized to test.

## How access is granted

Before delivery, the requester signs the `TOOLKIT_ACCESS_AGREEMENT.md` (electronic signature acceptable). On a satisfactory request, the maintainer will provide the toolkit by one of:
- an invitation to a private GitHub repository (`MCL-adversarial-toolkit`), or
- a time-limited signed download link, or
- a direct encrypted transfer.

The maintainer aims to respond within 7 calendar days. Access may be declined or
revoked at the maintainer's discretion (for example, where identity cannot be
verified, or where the stated purpose is inconsistent with lawful research).
A decision to decline is not a judgment about any person; it reflects this
distribution policy.

## Conditions of access

By receiving the toolkit you agree that:
- your use is governed by the Security Research & Evaluation Grant, including the
  Acceptable Use / No Misuse section;
- you will not use the toolkit against any system you do not own or are not
  authorized to test;
- you will not redistribute the toolkit publicly; you may share findings and
  cite the work per `CITATION.cff`, and may publish your own analysis and code,
  provided you do not republish the maintainer's toolkit files verbatim for
  anonymous public download;
- you will report any vulnerability found via the process in `SECURITY.md`.

## Transparency

This policy, the request template, and the list of gated files are public. The
existence and purpose of the toolkit are openly stated. The maintainer keeps a
private log of access grants. Aggregate, anonymized statistics (number of access
requests and grants) may be published periodically to document that the gate is
an access-management measure, not concealment.

## Relationship to the papers

Every attack the toolkit performs is described in the public companion papers.
If you do not wish to request toolkit access, you can reconstruct the analyses
from the papers and the public reference implementation. The gate adds
convenience and traceability; it does not gate the underlying knowledge.
