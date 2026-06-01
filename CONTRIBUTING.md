# Contributing to MCL

Thank you for your interest in MCL (Madeeh Chaotic Lock). This is a
source-available cryptographic research project published for **adversarial
public validation**. Contributions, cryptanalysis, and break-attempts are all
welcome.

## Two Ways to Participate

1. **Cryptanalysis / security findings** — you do **not** need to sign anything.
   Just follow the coordinated-disclosure process in `SECURITY.md`. Publishing
   attacks and analyses is governed by the Security Research & Evaluation Grant
   (`SECURITY-RESEARCH-GRANT.md`); please cite the work per `CITATION.cff`.

2. **Code or documentation contributions** (pull requests) — these require a
   signed **Contributor License Agreement (CLA)**; see below.

## Why a CLA?

MCL is offered under a noncommercial source-available license today, and the
owner intends to offer paid commercial licenses and to keep the option of
selling or transferring the project cleanly in the future. To keep ownership
unambiguous, the project currently uses a **copyright-assignment** CLA (`CLA.md`):
any accepted contribution is transferred in full to the project owner. A
Developer Certificate of Origin (DCO) alone is not sufficient for this. This is
an interim, conservative policy pending specialist legal review.

By signing the CLA you **assign** your contribution to the project owner (full
copyright transfer), so that ownership of the project is unambiguous; see
`CLA.md` §2. This is an interim, deliberately conservative policy.

> ## ⛔ External code contributions are currently PAUSED
>
> While the project owner obtains specialist legal advice on contribution and
> ownership arrangements, **external code/documentation pull requests are not
> being accepted into the main project at this time.** This is a temporary,
> precautionary measure to keep ownership fully clear — not a judgment about any
> contributor.
>
> **You can still:** report bugs and non-security issues, suggest ideas in
> issues, and — most importantly — conduct cryptanalysis and report findings via
> `SECURITY.md` (no agreement needed for security research; see
> `SECURITY-RESEARCH-GRANT.md`).
>
> If you have a contribution you believe is valuable, open an issue to discuss it
> first; the owner may, case by case, accept it under the assignment CLA
> (`CLA.md`). This policy will be revisited after the legal review.

**Authorship and ownership of the project.** MCL is owned and authored by the
project owner (Madeeh Ibrahim). Under the assignment CLA, any accepted
contribution is transferred to the owner and does not create joint authorship or
joint ownership of the project, nor any consent rights over the owner's
licensing, sale, or commercial use of the project. Your moral rights, where law
recognizes them, and your attribution are preserved. If you are not comfortable
assigning a contribution, please do not submit one.

## How to Contribute Code

1. Open an issue first to discuss non-trivial changes.
2. Fork, branch, and make your change with clear commits.
3. Add or update tests and, where relevant, test vectors.
4. Ensure every new source file carries the SPDX header (see below) and that
   `reuse lint` passes.
5. Open a pull request. The CLA-assistant bot will require you to sign the
   assignment CLA **before the pull request can be merged** — no contribution is
   merged without a signed CLA on file (this is what makes the assignment, not
   GitHub's default license rule, apply to your contribution).

> **Note on forking.** Because this is a public repository, GitHub's Terms of
> Service let any GitHub user *fork* it (make a copy within GitHub). That is
> normal and expected. Forking does not grant rights beyond what the project
> license (PolyForm Noncommercial 1.0.0 + the Security Research & Evaluation
> Grant) allows; it does not permit commercial use or any use outside those
> terms.

## SPDX Header for New Files

Every source file must begin with:

```
SPDX-FileCopyrightText: 2026 <Your Name> <your@email>
SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
```

(The additional Security Research & Evaluation Grant applies to the whole
repository and is documented in `LICENSE`, `NOTICE`, and
`SECURITY-RESEARCH-GRANT.md`; it does not need to be repeated in each file's
SPDX tag.)

## Code of Conduct

This project follows the Contributor Covenant; see `CODE_OF_CONDUCT.md`.

## Security

Never report a vulnerability in a public PR or issue. Use the private process in
`SECURITY.md`.
