# MCL — Scope of the quantum statements in this repository

**Document ID:** MCL-QSCOPE-2026-0928-001 · **Date:** 2026-09-28 · **Author:** Madeeh Ibrahim
**Applies to:** every release of this repository up to and including v0.2.14, and their archived copies.

---

## 1. Why this note exists

Some files published here between June and August 2026 state conclusions about
quantum attacks more strongly than the measurements behind them support. This
note lists each such sentence, says what is withdrawn and what stands, and
gives the position that governs from now on.

The engine `mcl_core.hpp` does not change, and no measured number changes. What
changes is what the numbers are said to show. The keyed sidecar is revised in
the same release for a reason of its own, recorded in
`keyed_q30_PQ/CASCADE_GUARD_V107_RECORD_20260928.md`.

Earlier releases and their archived copies cannot be edited. They are to be read
together with this note.

---

## 2. The governing position

1. **Generic key search.** The secret of the 256-bit keyed configuration
   (`keyed_q30_PQ/`) is a 256-bit key. Generic quantum key search needs about
   2^128 evaluations of the keyed map. This is an accounting of the size of the
   secret — the accounting that anchors NIST Category 5 to key search on
   AES-256 — and not a proof of security. The engine header says the same of
   its own helper: `mcl_pq_security()` "does NOT certify against structural
   cryptanalysis". A model of the resources of that search is in
   `Quantum_Structural_Analysis_20260927/`; its figures are outputs of a model,
   neither upper nor lower bounds.

2. **A pair (p, q) alone is not enough.** The number of coprime pairs with
   p, q ≤ N is about 6N²/π². After halving, that is 29.5 bits at N = 10^9 and
   52.6 bits at the engine's cap N = 2^53 — below the 64-bit level of Category 1
   at every admissible range.

3. **The seed is not a secret.** In authentication the seed is the public
   challenge. No figure that counts seed bits as secret bits is valid. Under
   the default seed rule of the keyed integer engines, and for seeds up to
   2^52, only the seed modulo 2^32 enters the state
   (`keyed_q30_PQ/CASCADE_GUARD_V107_RECORD_20260928.md`).

4. **Structure is not claimed to be absent.** The integer map has an exact
   translation symmetry of its state, measured in `T4_CycleStructure/` and
   mapped, with three other families of attack, in
   `Quantum_Structural_Analysis_20260927/`. Since sidecar v1.0.6 the key
   derivation rejects the weight sets that admit a symmetry reachable from the
   seed (`keyed_q30_PQ/NOSYM_V106_RECORD_20260822.md`), and since v1.0.7 the
   same check covers the epoch lists of the cascade; the check covers the
   reachable case, as its records say. Whether any quantum algorithm exploits
   structure of the map is not settled by anything in this repository.

5. **Factoring and discrete logarithms.** The construction has no public key,
   no modulus and no discrete logarithm, so Shor's algorithms for factoring and
   for discrete logarithms have no target. This is read off the construction.
   It is not a measurement, and it is narrower than "no hidden-subgroup
   structure".

6. **Periods.** Every finite-precision realization is eventually periodic. A
   spectral test and a period scan over a few hundred thousand bytes cannot show
   the absence of periods. The retired 64-bit-state integer path closes its
   orbit with cycle length 1,671,196,332 (`T4_CycleStructure/`, `VDF128_T4/`).

7. **Sequential depth.** Whether a quantum algorithm shortens the sequential
   depth of the iteration is **open**. That Grover's algorithm speeds up search
   and not depth is a heuristic about one algorithm. It is not a bound.

8. **What does not exist.** There is no proof, no reduction to a standard
   assumption, and no independent cryptanalysis of the map.

---

## 3. Sentences withdrawn or narrowed

Line numbers refer to the files as published in v0.2.14.

### 3.1 `mcl_postquantum.cpp` v6.0.0 and `results/mcl_postquantum.txt`

| # | Where | As published | Status |
|---|---|---|---|
| 1 | verdict, line 219 | "VERDICT: PASS — MCL resists all known quantum attacks" | **Withdrawn.** The program runs no quantum algorithm and bounds none. |
| 2 | Part 5, line 90 | "MCL has: positive Lyapunov exponents → chaotic (aperiodic)." | **Withdrawn.** See §2.6. |
| 3 | Part 5, lines 97–99 | "CONCLUSION: Shor's algorithm is INAPPLICABLE to MCL. The quantum Fourier transform finds no period to exploit." | **Withdrawn as a conclusion of the measurements.** What stands is §2.5. |
| 4 | Part 4, lines 55–56 | "A quantum oracle must simulate sequential updates, increasing depth beyond simple key enumeration." | **Withdrawn.** Part 4 measures the difference between two update orders of the classical map (mean divergence 2.0888). It carries no statement about a quantum oracle. |
| 5 | Part 6, line 106 | "This is the same as for AES — and is the BEST known quantum attack." | **Narrowed** to §2.1: the best *generic* attack. |
| 6 | Part 6, line 108 | "T-gates per Grover oracle: 8.27e+07" | **Withdrawn.** The formula behind the figure models no circuit. |
| 7 | Part 6, lines 110–116 | "Oracle structure (SEQUENTIAL — cannot be parallelized)" … "Implication: no quantum parallelism within the oracle" | **Withdrawn.** Inferred from the update order of the classical map; see §2.7. |
| 8 | Part 6, lines 118–134 | the two configuration tables; "Standard PQ security: 73.6 bits (conservative)"; "Standard PQ security: 105.6 bits (enhanced)" | **Withdrawn.** The figures count a 128-bit or 256-bit seed, and 64 or 128 further "phase" bits, as secret. See §2.2 and §2.3. |
| 9 | Part 6, lines 132 and 136–148 | "Exceeds Kyber-768 (~180)"; the table "COMPARISON WITH ESTABLISHED SYSTEMS" | **Withdrawn.** The MCL rows rest on item 8. |
| 10 | Part 7, lines 155–172 | "Systematic analysis of ALL known quantum algorithms"; the rows Simon, BHT, quantum walks, QAOA/VQE, QML and quantum simulation, each marked "NO"; "CONCLUSION: Only Grover applies"; "symmetric primitives resist all quantum algorithms except Grover" | **Withdrawn.** No test stands behind any row. |
| 11 | Part 8, lines 178–199 | the "CONTEXT" remarks about third-party schemes; "These caveats apply equally to ALL post-quantum schemes."; "MCL's position: empirically strong (full attack suite passes, all statistical batteries clean)" | **Withdrawn.** Remarks about other schemes are outside what this repository measures. The caveats C1–C3 themselves stand and are restated in §2.8. The words "full attack suite passes" are superseded: attacks on the bare two-oscillator map and on the retired sequential path succeeded and are documented in `keyed_q30_PQ/STATUS.md` §7 and `T4_CycleStructure/`. |
| 12 | Parts 2 and 3, lines 37 and 46 | "no exploitable periodicity"; "no periodicity found" | **Narrowed** to what was tested: no spectral peak above the threshold in 65,536 bytes; no period between 2 and 20,000 in 200,000 bytes. |
| 13 | summary, lines 209–216 | "(no periodicity)", "(aperiodic)", "(non-parallelizable)", "PQ security: 73.6 bits conservative / 105.6 bits enhanced", "Quantum attacks: only Grover applies", "Caveats: C1-C3 documented (same as NIST PQC)" | **Withdrawn**, for the reasons of items 2–12. |

The program is replaced by version 6.1.0, which keeps Parts 1–4B and reports
them as what they are — classical diagnostics. Every measured number of those
parts is unchanged, digit for digit. The June output is kept, unmodified, as
`results/mcl_postquantum_v6.0.0_20260526.txt`.

### 3.2 `mcl_core.hpp` v8.1.3 — comment block "Post-quantum posture", lines 3950–3959

| # | As published | Status |
|---|---|---|
| 14 | "Shor is INAPPLICABLE: MCL is symmetric -- no factoring / discrete-log / lattice / hidden-subgroup structure for period-finding to attack." | **Narrowed** to §2.5. The words "lattice / hidden-subgroup structure" are withdrawn; see §2.4. |
| 15 | "VDF SEQUENTIALITY is quantum-robust: Grover speeds up SEARCH, not the DEPTH of an inherently sequential recurrence, so the delay survives." | **Withdrawn.** See §2.7. |
| 16 | "(up to ~119/~59 at [2,1e18])" | **Superseded.** The engine caps the weights at 2^53 since v8.1.3; the figures at the cap are 105.3 and 52.6 bits. |

The rest of that block — the secret is the coupling weights or the key, the seed
is the public challenge, a pair alone is below Category 1 — stands.

These are comments. No code is affected. The header is left byte-identical in
this release, because its hash identifies the engine in records already
published; the comment will be corrected at the next revision of the engine.

### 3.3 `keyed_q30_PQ/STATUS.md`

| # | Where | As published | Status |
|---|---|---|---|
| 17 | §1, table row | "VDF sequentiality quantum-robust \| ✅ \| Grover does not parallelize sequential depth ⇒ the delay property survives quantum adversaries." | **Withdrawn.** See §2.7. |
| 18 | "Bottom line", first item | "Shor inapplicable; VDF quantum-robust; default (p,q) is sub-PQ." | "VDF quantum-robust" **withdrawn**. "Shor inapplicable" **narrowed** to §2.5. The third clause stands. |
| 19 | "Disclosure / filing rule" | "Claim the green rows (Shor-inapplicable, VDF-robust, Category-5-via-256-bit-key, …)" | "VDF-robust" **withdrawn**. "Category-5-via-256-bit-key" stands as accounting (§2.1). |

The body of the file is the record of what was written in June 2026 and is left
as it was. A scope line at its top points here.

### 3.4 `Verification_Suite/mcl_hop_unified.cpp` and `Verification_Suite/results/mcl_hop_unified.txt`

| # | Where | As published | Status |
|---|---|---|---|
| 20 | B10, lines 109–112 and 135 | "PQ (conservative): 73.6 bits"; "PQ (enhanced): 105.6 bits"; "[PASS] B10: PQ security above AES-128" with "73.6 bits > 64 (AES-128 PQ)" | **Withdrawn as a statement about the program.** The figures add 128 key bits, and 64 further bits, that the program does not contain: its schedule is a fixed public cycle and its seed is public. For a schedule derived from an independent hop key, carried outside the engine input and searched jointly with the pair, the first figure is the design target stated in Paper 2, §VII.D — not a measured bound and not a proven one. The pair alone, p, q ≤ 1000, is 9.6 bits after halving. |
| 21 | B5, line 90 | "[PASS] B5: Grover cost increased" with "102.2x oracle cost (+3.34 PQ bits)" | **Narrowed.** The ratio of iteration counts, 102.2, is arithmetic on the protocol parameters and stands as such. Its conversion into "PQ bits" is withdrawn: a costlier trial is a constant factor in the work, not additional key bits. |
| 22 | B4, line 88 | "[PASS] B4: Schedule entropy > 128" with "cycle=1292 bits, capacity=9607 bits" | **Narrowed.** The figures count the possible schedules. The entropy of a schedule derived from a key is bounded by the length of that key. |
| 23 | B6, line 91; summary, line 132 | "[PASS] B6: Forward secrecy (4-sigma threshold)"; "Forward secrecy H" | **Narrowed.** The measurement compares a segment of the hopping stream with a fresh generator run on that segment's parameters. Paper 2, §VII.C names the property inter-segment key separation and states that it is not forward secrecy. |

The program is replaced by version 6.1.0, which changes the labels of Part B
and nothing else. Tests A1–A12, B1–B3 and B6–B9 are measurements; every number
they print is unchanged. B3 and B7 are named after what was measured, a
correlation test. The June output is kept, unmodified, as
`Verification_Suite/results/mcl_hop_unified_v6.0.0_20260526.txt`.

### 3.5 Category labels elsewhere

Wherever a file of this repository assigns a NIST category — `keyed_q30_PQ/README.md`,
`keyed_q30_PQ/STATUS.md`, section [7] of `keyed_q30_PQ/mcl_keyed_q30_test.cpp` and
the outputs of that program under `results/`, the helper `mcl_pq_security()` —
the label is accounting in the sense of §2.1. The figure "207 (joint)" given
for the cascade assumes that the search over its epochs must be joint; its
README calls that "empirical, not a proof", and that remains its status.

---

## 4. What is unchanged

- The engine (`mcl_core.hpp` v8.1.3) and every known-answer value of record.
  The keyed sidecar is v1.0.7 in the release that carries this note; its
  default behaviour is that of v1.0.6 for every key outside the class of
  cascade keys described in its record.
- Every measured number in every record. In particular the mean divergence
  2.0888 of `mcl_postquantum` Part 4 is reproduced identically by version 6.1.0.
- The disclosures already published: the symmetry and weak-key records, the
  cycle-structure measurements, the parameter-recovery attack on the bare
  two-oscillator map.

---

## 5. Files that accompany this note

| File | What it is |
|---|---|
| `mcl_postquantum.cpp` | version 6.1.0 — classical diagnostics; the file name is kept so that existing references resolve |
| `results/mcl_postquantum.txt` | output of version 6.1.0 |
| `results/mcl_postquantum_v6.0.0_20260526.txt` | output of version 6.0.0 as published in June 2026, unmodified |
| `keyed_q30_PQ/STATUS.md` | scope line added at the top; body unchanged |
| `Verification_Suite/mcl_hop_unified.cpp` | version 6.1.0 — labels of Part B |
| `Verification_Suite/results/mcl_hop_unified.txt` | output of version 6.1.0 |
| `Verification_Suite/results/mcl_hop_unified_v6.0.0_20260526.txt` | output of version 6.0.0 as published in June 2026, unmodified |
| `Quantum_Structural_Analysis_20260927/` | structural inventory over four families of attack, and the resource model of generic key search |
| `keyed_q30_PQ/CASCADE_GUARD_V107_RECORD_20260928.md` | record of sidecar v1.0.7, cited in §2.3 and §2.4 |

---

*MCL-QSCOPE-2026-0928-001 · Madeeh Ibrahim, Cairo*
