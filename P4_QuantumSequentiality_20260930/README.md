# P4_QuantumSequentiality_20260930 — quantum sequentiality of VDF128-T4 v4

**Doc ID:** MCL-P4-QSEQ-2026-0930-001 · **Date:** 2026-09-30 · **Status:** draft for the author's review
**Concerns:** Paper 4, open problem OP2 · `../QUANTUM_SCOPE_NOTE.md` §2.7 · `../Quantum_Structural_Analysis_20260927/README.md` §3.2 ("any reduction of the sequential depth" — not covered there)
**Engine:** `../mcl_core.hpp` 8.1.3 (`416ad145e79c…`), `../keyed_q30_PQ/mcl_keyed_q30.hpp` v1.0.7 (`05c01cf8a156…`), `../P4_ReviewMeasurements_20260925/mcl_vdf128_t4_v4.hpp` (`209458cd6e04…`) and the v3 and v1 headers beside it — none of them modified
**Platform of the record runs:** Intel Xeon @ 2.10 GHz, 4 cores, x86-64, Ubuntu 24.04, g++ 13.3.0, Python 3.11.15 (`host_20260930.txt`)

> **What this folder shows.** A proof that the clocked map is sequential against quantum
> adversaries **in an ideal model** (Proposition Q1), what that proof is worth at the parameters
> of Paper 4, and probes of the **concrete** map against the known ways of fast-forwarding an
> iteration.
>
> **What it does not show.** That the concrete map is quantum-sequential. That is hypothesis
> H-FF (`QSEQ_PROOF.md` §6). It is open, and with present methods it cannot be proved
> unconditionally (§1 there). Nothing here restores the phrase "VDF quantum-robust" withdrawn
> by items 15 and 17 of the scope note.

---

## 1. Files

| File | What it is |
|---|---|
| `QSEQ_PROOF.md` | model, **Proposition Q1** and its proof, remarks, hypothesis H-FF, status |
| `qseq_bound.py` | Q1 and its classical counterpart, evaluated at the parameters of Paper 4; self-checks against exact sums |
| `qseq_bound_20260930.log` | its record output |
| `qseq_struct.cpp` | structural probes of the v4 map (Parts 1, 1b, 2, 3, 4, 5); controls and consistency checks stop a bad run |
| `qseq_struct_20260930.log` | its record run |
| `qseq_lfactor.py` | classical "guess ahead" attack at toy size: is the factor L of Remark 5.1 a property of the model? |
| `qseq_lfactor_20260930.log` | its output |
| `host_20260930.txt` | platform, compiler, timings, hashes of sources and headers before and after the runs |
| `SHA256SUMS.txt` | hashes of the files of this folder |

Tags in the logs follow `../Quantum_Structural_Analysis_20260927/README.md` §2. A run in which a
`[CONTROL]` or `[CONSISTENCY]` row fails must not be quoted, and the program then exits non-zero.

---

## 2. Proposition Q1 (ideal model) — `QSEQ_PROOF.md` §3–§5

The round function is modelled as a uniformly random function on the 2^s states. It is shared
by all L = B + N positions, with the clock added to its input, as in v4. Consider an adversary
that queries it in superposition in d ≤ L − 1 layers of q_k queries each. It outputs the final
state with probability at most

    L(L−1)/2^(s+1) + min{ 2^−s + 2Σ , (2^(−s/2) + 2Σ)^2 },    Σ = Σ_k √(q_k (L−k) / 2^s)
    ≈ 4·d·q·L / 2^s.

The proof uses one-way-to-hiding hybrids, one query layer at a time (Ambainis–Hamburg–Unruh
2019, Theorem 3, reproduced in the document for checking), over a lazy form of the chain in
which the future chain values are independent of everything the adversary has seen.

**What it is worth** (`qseq_bound_20260930.log`, [DERIVED]):

| s | N | per-layer queries Q | bound, d = L − 1 | same proof, classical queries |
|---|---|---|---|---|
| 128 | 10^6 | 1 / 2^20 / 2^40 | 2^−67.3 / 2^−47.3 / 2^−27.3 | 2^−88.1 / 2^−69.1 / 2^−49.1 |
| 128 | 10^8 | 1 / 2^20 / 2^40 | 2^−47.4 / 2^−27.4 / 2^−7.4 | 2^−74.8 / 2^−55.8 / 2^−35.8 |
| 128 | 10^10 | 1 / 2^20 | 2^−27.5 / 2^−7.5 | 2^−61.6 / 2^−42.6 |
| 128 | 2^40 | 1 | 2^−7.2 | 2^−48.0 |
| 256 | 2^40 | 1 / 2^20 / 2^40 | 2^−135.2 / 2^−115.2 / 2^−95.2 | 2^−176.0 / 2^−157.0 / 2^−137.0 |

- The quantum proof pays a factor of (32/9)·L over the classical one. At s = 128 it certifies
  2^−40 only up to N ≈ 10^8 and a few parallel queries per layer, and nothing useful at
  N ≥ 10^10. At s = 256 it is strong everywhere in the table.
- Whether the factor is real or an artefact of the proof is **open**. No attack is known that
  beats the classical guessing strategy. The next step is a compressed-oracle proof aiming at
  q·L/2^s (`QSEQ_PROOF.md` §5.2).
- The single-function model carries a factor L even classically. The figure (q+1)/2^s quoted
  for Theorem 1 of Paper 4 v4 does not. Which idealization the construction instantiates should
  be stated in Paper 4 (`QSEQ_PROOF.md` §5.1).
- The factor is real, not an artefact of the proof. At s = 20, a classical attacker that queries
  Q random points first saves an iteration at the predicted rate 1 − (1 − (L−1)/2^s)^Q in the
  single-function model: 0.061 / 0.231 / 0.240 / 0.059 measured against 0.057 / 0.218 / 0.220 /
  0.060. In the per-position model it does so only at about Q/2^s (`qseq_lfactor_20260930.log`).

---

## 3. Structural probes of the concrete map — `qseq_struct_20260930.log`

Instances: the Vector 5 input "VDF128-T4-KAT-01" and the battery input
"VDF128-T4-battery-input". Clocks from 10,000.

| Part | Mechanism tested | Result | Tag |
|---|---|---|---|
| — | sine table = normative table file; word-level re-expression = engine | both hold (65,536 states) | consistency |
| 1 | commuting translations (hidden-shift / group structure) | parity rank 4 on both instances: no exact translation symmetry. 255 offsets with every word in {0,1,2,3}·2^30: none commutes on all 4,096 states. **One commuting state** on the second instance: the expectation written before the run **differs**, explained by Part 1b | computed, measured |
| 1b | offsets that move few coupling arguments | the relation F(x + δ) = F(x) + δ holds on a fraction 2^−15w of states, where w is the number of word updates the offset touches. Measured on every offset moving ≤ 2 arguments: 123–140 of 2^22 at w = 1 against 128 predicted from the table (\|z\| ≤ 1.1), and 0 at w = 2. **Never two rounds running.** Census of 20,000 v4 weight sets: w_min = 1 / 2 / 3 / 4 for 9,906 / 8,679 / 1,415 / 0 | computed, measured |
| 2 | affine or translation dynamics (matrix powering) | additive differences through r = 1, 2, 3 rounds, 207 differences × 2^14 states: largest multiplicity 1 or 2. Both affine controls give 16,384 | measured, control |
| 3 | contraction of the state space | all 2^32 inputs of each word update, four words × three contexts over both instances: image fraction **0.632111 … 0.632135** against 1 − 1/e = 0.632121 (largest \|z\| 3.1). Controls: bijection 1.000000, hashed random function 0.632116. The twelve z-scores scatter more than a random mapping's would (rms 1.68; χ² = 33.9 on 12 degrees of freedom, p ≈ 0.0007). So the word maps are not exactly random mappings at this resolution, but the effect is of order 10^−5 in the image fraction, with no collapse | measured, control |
| 4 | small-nonlinearity regime | one coupling term moves a phase by up to 1.91 turns, and three terms per word by up to 5.73 turns: the nonlinear term wraps the circle, and there is no regime in which the round is close to affine | computed |
| 5 | gross contraction of one round | 2^24 random states, one clocked round: **0** repeated outputs. Control (the same round cut to 20 output bits): 15,728,640 | measured, control |

Record run: exit code 0; controls 6 of 6; consistency checks 2 of 2; expectations 6 compared, **1 differs** (Part 1, explained by Part 1b, whose own expectation was written after the first trial run and is marked so in the log); 587.7 s wall on four cores.

**The one-round relation of Part 1b** is a new finding, set out in `QSEQ_PROOF.md` §6.2. It is
an iterative additive characteristic of probability about 2^−15 per round, caused by even
weights that hide an offset from most coupling arguments. It is not a symmetry of the iteration
and does not shorten depth. A derivation rule that would bound it by 2^−30 (keeping 50.5% of
draws) or 2^−45 (keeping 7.1%) is proposed there, for the author to decide.

---

## 4. Reproduce

```sh
# from this folder
g++ -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -Wshadow -pthread -I.. qseq_struct.cpp -o qseq_struct
./qseq_struct > qseq_struct_20260930.log       # about 12 min on 4 cores; 2 GiB of memory (Part 3)
python3 qseq_bound.py > qseq_bound_20260930.log
python3 qseq_lfactor.py > qseq_lfactor_20260930.log   # about 1 min
```

`qseq_struct` is deterministic apart from its `[time]` lines. Part 3 uses four threads with one
2^32-bit bitmap each.

---

## 5. Status of the question after this folder

| Item | Status |
|---|---|
| quantum sequentiality, ideal model | proved (Proposition Q1), subject to the reader's check of the reproduced lemma |
| tightness of Q1; depth (1 − δ)·L | open |
| concrete map (H-FF) | open; no probe found a fast-forwarding structure |
| one-round relation of probability 2^−15 | new; present in about half of v4 weight sets; proposed rule pending |
| `../QUANTUM_SCOPE_NOTE.md` §2.7; items 15 and 17 | unchanged: open / withdrawn |
