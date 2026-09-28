# Quantum_Structural_Analysis — structural inventory and Grover resource model

**Doc IDs:** MCL-QSTRUCT-2026-0927-001 rev 3 · MCL-GROVER-RES-2026-0927-001 rev 3
**Date:** 2026-09-28 · **Author:** Madeeh Ibrahim
**Engine:** `../mcl_core.hpp` v8.1.3 (SHA-256 `416ad145e79c…`), `../keyed_q30_PQ/mcl_keyed_q30.hpp`
v1.0.7 (`05c01cf8a156…`), `../VDF128_T4/mcl_vdf128_t4.hpp` (`e08f702e2da9…`),
`../VDF128_T4/mcl_vdf128_t4_v3.hpp` (`b46f1a1329cc…`) — none of them modified.

> **Neither program shows quantum security.** The first maps the attack
> surface of four named families of attack. The second is a cost model of
> generic key search. Whether a quantum algorithm exploits structure of the
> map, or shortens the sequential depth of the iteration, stays open
> (Paper 4, open problem OP2). Governing text: `../QUANTUM_SCOPE_NOTE.md`.

---

## 1. Files

| File | What it is |
|---|---|
| `mcl_qstruct_inventory.cpp` | program 1 — structural inventory, a **classical** probe |
| `qstruct_rev3_20260928.log` | its record run |
| `theory_rank_enumeration.py`, `theory_rank_enumeration_20260928.log` | theory anchor for the population row of program 1; shares no code with it |
| `mcl_grover_resource_estimate.cpp` | program 2 — resource model of Grover key search on the keyed four-oscillator path |
| `grover_rev3_20260928.log` | its record output |
| `grover_ref.py`, `grover_ref_check_20260928.log` | independent reference for program 2, written from the formulas and not from the C++ source |
| `host_20260928.txt` | platform, compiler, hashes of the sources and headers before and after the runs |
| `SHA256SUMS.txt` | hashes of the files of this folder |

---

## 2. Tags — every printed row of program 1 carries one

| Tag | Meaning |
|---|---|
| `[MEASURED]` | obtained by running the unmodified engine map or an engine class; could have come out otherwise |
| `[COMPUTED]` | exact algebra on weights that the engine's own derivation produced; where it matters a `[MEASURED]` row checks it |
| `[INSPECTION]` | read off the source code; no run can change it |
| `[CONSTRUCTION]` | forced by how the object was built — a consistency check, **not evidence** |
| `[CONTROL]` | a case whose answer is known in advance, run through the **same** code path |
| `[GENERIC]` | a bound that holds for any function of that size |
| `[DERIVED]` | arithmetic on a cited theorem |
| `[NOT MEASURABLE HERE]` | a property of the protocol or of the adversary's access |

**Rule.** A run in which a control or a consistency check fails must not be
quoted. The program then exits with a non-zero code.

---

## 3. Program 1 — `mcl_qstruct_inventory.cpp`

### 3.1 Families covered

| | Family | Part | What is produced |
|---|---|---|---|
| F1 | hidden translation subgroup of the state map (abelian hidden subgroup; hidden shift over Z/2^32) | 1 | the **exact** translation group of each weight set by 2-adic lifting, every element run on the engine, and which elements a **public seed** can reach |
| F2 | period and collision structure of the input channel (Simon) | 2 | structured candidates over the **full 64-bit word**, and a birthday search that covers **every** period inside a 32-bit sub-domain with a stated confidence |
| F3 | FX / Grover-meets-Simon on a legacy form of the transaction tag | 3 | the conditions of Theorem 2 of Leander and May as they apply, and the classical-query model |
| F4 | generic collision search | — | bounds tagged `[GENERIC]` |

### 3.2 Families not covered

Nothing here supports any statement about them: quantum differential and
linear cryptanalysis; quantum slide and related-key attacks; claw finding and
meet-in-the-middle on the cascade; any reduction of the **sequential depth** of
the iteration; Grover key search itself (program 2).

### 3.3 Constructions and channels

| | Construction |
|---|---|
| C1 | two-oscillator (3, 5) raw integer map — a **retired** path |
| C2 | keyed four-oscillator path (weight derivation of sidecar v1.0.6, unchanged in v1.0.7) |
| C3 | public weights of VDF128-T4 |
| C4 | per-input weights of VDF128-T4 v3 and v4 |
| C5 | keyed cascade, **before and after** the symmetry check of sidecar v1.0.7 |

| | Channel — the input that varies |
|---|---|
| CH-A | the public seed of the keyed four-oscillator path |
| CH-B | the challenge, which enters the key derivation |
| CH-C | the public seed of the cascade |
| CH-D | the engine-input word of the legacy tag variant |

### 3.4 A limit stated once

Finding an unknown XOR period over n input bits costs a classical prober about
2^(n/2) evaluations. That gap **is** Simon's speed-up. No classical probe can
therefore exclude a period over 64 bits. And periodicity of the raw function is
neither necessary nor sufficient for an attack of Simon's type: in an FX
construction the raw function has no period and the attack builds one; a
period that does not depend on the key gives the attacker nothing.

### 3.5 Record run — 2026-09-28

```sh
clang++ -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -pthread -I.. \
    mcl_qstruct_inventory.cpp -o mcl_qstruct_inventory
./mcl_qstruct_inventory --threads 8 > qstruct_rev3_20260928.log
```

| | Result |
|---|---|
| exit code | 0 |
| controls | 8 of 8 |
| internal consistency checks | 88,048 run, 0 failed |
| expectations written into the program before the run | 27 compared, 0 differ |
| wall time | 79.5 s on eight cores |

Most of the expectations were known from earlier, smaller runs. They are
documented expectations, not blind predictions.

| Row | Result | Tag |
|---|---|---|
| C1, retired path | translation group of order 16; 15 of 15 non-trivial elements commute on the engine; 15 of 15 are reached by a public seed | computed, measured |
| C2, 20,000 keys | parity rank 4 / 3 / 2 / 1 / 0 = 18,568 / 1,284 / 137 / 11 / 0: **1,432 weight sets (7.16%) admit a translation symmetry of the state** (theory 6.93%) | computed |
| C2, reachable from a public seed | **0 of 20,000**; seed offsets 2^31 … 2^28 on the engine: 0 of 1,024 commute | computed, measured |
| C3, C4 | trivial group; 2,000 of 2,000 inputs | computed, measured |
| C5 before the check | 12 of 200,000 keys (0.0060%) have a cascade that commutes with the seed offset 2^31; on the engine the raw states of the two seeds differ by that translation in 64 of 64 pairs; SHA-256 of the raw states differs in 120 of 256 bits | computed, measured |
| C5 after the check | **0 of 200,000**; the check changed the epoch lists of the 12 keys and of no other key; the relation holds in 0 of 64 pairs | computed, measured |
| reflection t → −t | impossible as an exact symmetry (bound 2,359,308 against 844,933,146); after two iterations nothing of it is left | inspection, measured |
| CH-A, CH-C | exact XOR periods at the seed bits 32 … 51, for seeds below 2^52; **identical under two keys** | measured |
| CH-B, CH-D | no period among the candidates | measured |
| birthday search, four channels | 0 colliding pairs at N = 2^18; a period inside the sub-domain would have produced one with probability 99.97% | measured |

**Reading of the seed rows.** The period at the bits 32 … 51 is public and does
not depend on the key: under the default seed rule only the seed modulo 2^32
enters the state. Simon's algorithm would recover a period that the attacker
already knows. The consequence is classical — two seeds equal modulo 2^32 give
the same keystream. Sidecar v1.0.7 offers a second seed rule,
`MCL_Q30_SeedInit::Hashed`, which this program does not scan
(`../keyed_q30_PQ/CASCADE_GUARD_V107_RECORD_20260928.md`).

**Reading of the C2 rows.** A weight set with a symmetry is not a weak key in
this sense: no pair of public seeds is related by the symmetry. It is a
structural fact of the state map, reported as such.

**Replications.** The same configuration with one thread, and in an x86-64
build run under Rosetta 2, gives the same log except the `[time]` lines and the
value of `threads=`.

### 3.6 Part 3 concerns a legacy form only

Part 3 examines `Tag = MCL_T2(hash(tx) XOR nonce(ctr) XOR W, p, q)`, a variant of
the superseded input-composition form in which a 64-bit word W folded from a
device secret is XORed into the engine input. The published
`../mcl_txn_verify.cpp` has no such word. The protocol of Paper 5 carries the
secret in the twelve weights and has no whitening of the seed; nothing in
Part 3 applies to it.

The variant has the FX shape. In the model of chosen inputs in superposition
the word W adds nothing over Grover on (p, q). What stands between that
statement and a deployed token is the access model — the counter is held by
the device and only moves forward — and not a property of the map.

---

## 4. Program 2 — `mcl_grover_resource_estimate.cpp`

A resource model of Grover key search on the keyed four-oscillator path, set
beside the published figures for AES-256.

**What is priced** is a reversible circuit arranged for the attacker, not a
literal count of the operations of the engine.

| per iteration | literal in the engine | priced, WIDE | priced, NARROW |
|---|---|---|---|
| multiplications | 36 | 24 | 48 |
| additions and subtractions | 28 | 12 | 12 |
| table look-ups | 12 | 12 | 12, and 8 uncomputations |
| garbage | — | 768 qubits | 128 qubits |

Three circuit configurations by two garbage strategies give six figures. The
honest output is the band between them.

| | keyed path, T gates only | AES-256, NIST | AES-256, Jaques et al. |
|---|---|---|---|
| Grover calls | 2^127.65 | 2^127.65 | 2^127.65 |
| oracle | 2^32.2 … 2^38.5 T | — | 2^17.2 T |
| MAXDEPTH 2^40 | 2^274.9 … 2^289.7 | 2^258 | 2^245.5 |
| MAXDEPTH 2^64 | 2^250.9 … 2^265.7 | 2^234 | 2^221.5 |
| MAXDEPTH 2^96 | 2^218.9 … 2^233.7 | 2^202 | 2^190.5 |

**What the model supports.** The number of Grover calls depends on the length
of the key alone, so the keyed path and AES-256 share that exponent. The
difference lies in the oracle, which runs 10,080 serial iterations: a constant
factor, not an exponent.

**What it is not.** It is a bound in neither direction: better arithmetic or
pebbling would lower the figures; error correction and routing would raise
them. The AES columns count all gates and full depth while the model counts
T gates, so the ratios understate the cost of the keyed path. It does not say
that the keyed path is stronger than AES, and it says nothing about a
structural attack.

```sh
clang++ -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -I.. \
    mcl_grover_resource_estimate.cpp -o mcl_grover_resource_estimate
./mcl_grover_resource_estimate > grover_rev3_20260928.log
python3 grover_ref.py grover_rev3_20260928.log      # 64 values, 0 mismatches
```

The program is pure arithmetic: no randomness, no threads, a deterministic
output.

---

## 5. Running program 1

| Command | What it does | Time, Apple M1 Pro |
|---|---|---|
| `./mcl_qstruct_inventory --selftest --threads 8` | controls and every part at reduced size; exit code 0 when all pass | about 3 s |
| `./mcl_qstruct_inventory --threads 8` | the record configuration | 79.5 s |
| `./mcl_qstruct_inventory` | the same with one thread | about 8 minutes |

Defaults: `--keys 20000` · `--v3-inputs 2000` · `--cascade-keys 200000` ·
`--engine-states 64` · `--refl 100000` · `--verify 32` · `--random-s 64` ·
`--birthday-log2 18` · `--whiten-log2 22` · `--seed 0xC0FFEE`. An unknown
option or a value out of range is an error (exit code 2). The number of
threads does not change the results.

---

## 6. Limits

1. The inventory maps the attack surface of **four families**. The absence of
   structure in a row excludes no attack outside what was measured.
2. Part 2 does not exclude a period over 64 bits (§3.4). It covers the
   structured candidates over the full word, and every period inside a 32-bit
   sub-domain with detection probability 1 − e^(−N²/2^33).
3. The exact group is a sufficient condition verified on the engine. Its
   necessity — no symmetry without invariance of the arguments — is assumed up
   to a coincidence of table sums, as in the records of `../T4_CycleStructure/`.
4. Part 3 concerns a legacy variant only (§3.6).
5. The access model of Part 3 cannot be measured here. It is a property of the
   protocol.
6. Program 2 is a model with adjustable constants. It counts T gates. It is a
   bound in neither direction.
7. One machine (Apple M1 Pro). The arm64 and x86-64 builds give the same
   output; the second ran under Rosetta 2, not on an Intel or AMD processor.
   No run on Linux. Both programs are integer arithmetic, except the
   floating-point path of `MCL_T2` in channel D.
8. Nothing here is a proof, a reduction to a standard assumption, or an
   independent cryptanalysis of the map.

---

## 7. References

Simon-type attacks: M. Kaplan, G. Leurent, A. Leverrier, M. Naya-Plasencia,
CRYPTO 2016 (arXiv:1602.05973) · G. Leander, A. May, ASIACRYPT 2017 (ePrint
2017/427) · X. Bonnetain, A. Hosoyamada, M. Naya-Plasencia, Y. Sasaki,
A. Schrottenloher, ASIACRYPT 2019 (ePrint 2019/614) · X. Bonnetain,
M. Naya-Plasencia, ASIACRYPT 2018 (ePrint 2018/432).

Collision search: G. Brassard, P. Høyer, A. Tapp, LATIN 1998
(quant-ph/9705002) · A. Chailloux, M. Naya-Plasencia, A. Schrottenloher,
ASIACRYPT 2017 (ePrint 2017/847).

Circuits: S. Cuccaro, T. Draper, S. Kutin, D. Moulton (quant-ph/0410184) ·
C. Gidney, Quantum 2, 74 (2018) (arXiv:1709.06648) · R. Babbush et al.,
Phys. Rev. X 8, 041015 (2018) (arXiv:1805.03662) · D. Berry et al., Quantum 3,
208 (2019) (arXiv:1902.02134) · M. Amy et al., SAC 2016 (arXiv:1603.09383).

AES-256: NIST, Submission Requirements and Evaluation Criteria for the
Post-Quantum Cryptography Standardization Process (December 2016), §4.A.5 ·
S. Jaques, M. Naehrig, M. Roetteler, F. Virdia, EUROCRYPT 2020
(arXiv:1910.01700).

Not covered: M. Kaplan, G. Leurent, A. Leverrier, M. Naya-Plasencia, IACR
Trans. Symmetric Cryptol. 2016(1), doi 10.13154/tosc.v2016.i1.71-94.

---

*MCL-QSTRUCT-2026-0927-001 · MCL-GROVER-RES-2026-0927-001 · Madeeh Ibrahim, Cairo*
