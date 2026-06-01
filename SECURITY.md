# Security Policy — MCL (Madeeh Chaotic Lock)

## Status of the Primitive

MCL is a **new, not-yet-independently-audited cryptographic primitive.**
**Do NOT use MCL in production systems** that protect real secrets, money,
health, legal, or financial data, or human-rights-critical communications.
This repository exists for **adversarial public validation**: we explicitly
invite academic and industry cryptanalysts to attempt to break it.

## Reporting a Vulnerability or Cryptanalytic Finding

Please report privately via either channel:

1. **GitHub Private Vulnerability Reporting** (preferred):
   `https://github.com/madeeh-ibrahim/MCL/security/advisories/new`
2. **Email:** madeeh.chaotic.lock@gmail.com
   (If you require encrypted email, request a PGP key in your first message.)

Please do **not** open a public issue for security or cryptanalytic findings;
use the private channels above so we can coordinate disclosure.

## Service-Level Targets

| Stage                          | Target            |
|--------------------------------|-------------------|
| Acknowledgement of report      | 72 hours          |
| Initial triage & severity      | 7 calendar days   |
| Fix or mitigation drafted      | 30 calendar days  |
| Coordinated public disclosure  | 90 calendar days  |

The 90-day target follows the widely used coordinated-disclosure norm. Day-90
disclosure may be extended by mutual agreement when a fix is actively in
progress, or shortened if a finding is already public or being exploited.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| `main`  | ✅                 |
| `0.x`   | ✅ (experimental)  |

## In Scope

- All source in this repository: the reference engine (`mcl_core.hpp`), all
  verification and analysis tools, the known-answer test generators, and the
  artefacts of the companion papers. The gated adversarial toolkit (see
  `TOOLKIT_ACCESS_POLICY.md`) is also in scope for researchers who hold it.

## Out of Scope

- Denial-of-service via resource exhaustion of any demo service.
- Social engineering of the maintainer or third parties.
- Findings in third-party dependencies (please report those upstream).

## Safe Harbor

When you conduct security research and vulnerability disclosure in good-faith
compliance with this policy, the project's position is as follows:

- We consider such research to be authorized by the project, and we will not
  initiate or support a complaint or legal action against you, arising under any
  applicable computer-misuse, anti-circumvention, or copyright laws, for
  accidental, good-faith violations of this policy.
- We waive, on a limited basis and to the extent within the project's control,
  any provision of the project's own terms that would otherwise prohibit the
  technical research activities permitted by the Security Research & Evaluation
  Grant (`SECURITY-RESEARCH-GRANT.md`).
- We consider your research lawful, welcome, and helpful to the security of
  cryptography generally.

You remain responsible for complying with all laws that apply to you. This Safe
Harbor reflects only the project's own position and cannot, and does not, bind
any independent third party, court, or government. If a third party initiates
action against you in connection with research you conducted in good-faith
compliance with this policy, we will take reasonable steps to make known that
your actions were authorized under this policy.

*(This Safe Harbor is adapted from the jurisdiction-neutral disclose.io Core
Terms. It deliberately avoids citing the statutes of any single country.)*

## CVE / GHSA Workflow

GitHub is a CVE Numbering Authority (CNA). For confirmed vulnerabilities, the
maintainer will open a GitHub Security Advisory (GHSA) and may request a CVE
identification number through GitHub's draft-advisory workflow.

## Cryptanalysis Is Encouraged

MCL invites cryptanalytic attack. We welcome and will credit (with your consent)
any substantive cryptanalytic result — including distinguishers, reduced-round
attacks, statistical biases, and side-channel or fault observations — even where
the result is not a "vulnerability" in the conventional sense. See
`HALL_OF_FAME.md`. If you publish, please cite the work per `CITATION.cff`.

## Machine-Readable Contact

See `/.well-known/security.txt` (RFC 9116).
