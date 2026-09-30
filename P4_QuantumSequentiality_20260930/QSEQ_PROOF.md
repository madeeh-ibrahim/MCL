# Quantum sequentiality of the clocked map — an ideal-model proposition and the hypothesis that remains

**Doc ID:** MCL-P4-QSEQ-2026-0930-001 · **Date:** 2026-09-30 · **Status:** draft for the author's review; not peer-reviewed
**Concerns:** VDF128-T4 **v4** (`../P4_ReviewMeasurements_20260925/mcl_vdf128_t4_v4.hpp`, MCL-VDF128-T4-2026-0925-004) ·
Paper 4, open problem OP2 · `../QUANTUM_SCOPE_NOTE.md` §2.7
**Companion files:** `qseq_bound.py` (the bound, evaluated), `qseq_struct.cpp` (structural probes of the concrete map), `README.md` (the record)

---

## 0. What this document establishes, and what it does not

1. **Proved, in an ideal model (Proposition Q1).** If the round function of the clocked map is a
   uniformly random function on the 2^s states and a quantum adversary may query it in
   superposition, then any adversary with fewer query layers than the number of iterations L
   outputs the final state with probability at most about **4·d·q·L / 2^s**, where d is its
   query depth and q its total number of queries. The exact statement is in §3.
2. **What the proof costs.** The same argument with classical queries gives about q·L / 2^s.
   The quantum statement is weaker by a factor of about (32/9)·L at the worst depth d = L − 1.
   At s = 128 that loss matters. For example, at N = 10^8 the proposition certifies 2^−40 only
   against adversaries with at most about 2^7 parallel queries per layer, and at N = 2^40 it
   certifies nothing useful (`qseq_bound.py`, Tables 1–2). At s = 256 it is strong at every
   deployment parameter in the tables. Whether the loss is real or an artefact of the proof is
   **open**. No attack that achieves it is known.
3. **Not proved: the concrete map.** Moving from the ideal model to the MCL round needs a
   structural hypothesis (H-FF, §6): the concrete map has no structure that lets a quantum
   computer fast-forward the iteration. That hypothesis cannot be proved with present methods
   (§1). `qseq_struct.cpp` tests five necessary conditions of it. None fails. One
   probabilistic one-round relation was found and is explained (§6.2): about half of v4 weight
   sets have an offset δ with F(x + δ) = F(x) + δ on a fraction 2^−15 of states. It never held
   for two rounds running, and it does not shorten depth.
4. **Status of OP2 / §2.7.** It stays **open** for the concrete map. Items 15 and 17 of the
   scope note stay withdrawn, and nothing here restores the phrase "VDF quantum-robust". What
   changes is that the ideal-model part now has a statement, a proof and a price.

---

## 1. Why the question cannot be settled unconditionally

A proof that no circuit of depth below L computes the L-th iterate of a concrete, efficiently
computable map would be an unconditional depth lower bound far above the logarithm of the input
length. No depth lower bound beyond logarithmic is known for any explicit function computable in
polynomial time, even against classical circuits of fan-in two. Every sequentiality result in
the literature is therefore one of two kinds:

- **idealized**: the iterated function is a random oracle. Examples are hash chains, which are
  sequential against quantum adversaries in the quantum random-oracle model [Unr15, CFHL21, BLZ21].
- **assumption-based**: sequentiality of a concrete algebraic problem is assumed. An example is
  repeated squaring in a group of unknown order [Pie19, Wes19].

The second kind shows what fast-forwarding looks like. In an RSA group, x^(2^T) mod n is
computed in a few steps once the group order is known (reduce 2^T modulo the order), and Shor's
algorithm computes the order. Those VDFs are **not** quantum-sequential. A structure that
shortens depth does not have to be visible as periodicity of the output. It can be a group law
under which the iteration is exponentiation.

The route taken here is the standard one: (a) a theorem in an ideal model (§3–§5), and (b) an
explicit structural hypothesis that carries it to the concrete map, together with tests of that
hypothesis's necessary conditions (§6).

---

## 2. The model Q-IM

**State space.** X = (Z/2^32)^4, so |X| = 2^s with s = 128. `⊞` is word-wise addition mod 2^32.

**Clock.** τ : {0, …, 2^64 − 1} → X is the public injective encoding of v4
(`mcl_vdf128v4_clock`: lo, lo·A + hi, lo·B + hi·A, lo·C + hi·B mod 2^32).

**Chain.** For an input x, y_0 = init(x) ∈ X is public. The round function R_x : X → X is the
v4 map without its clock: one four-word Gauss-Seidel sweep with the weights derived from x. For
i = 0, …, L − 1:

    z_i = y_i ⊞ τ(i),      y_{i+1} = R_x(z_i),        L = B + N.

**Ideal model.** R_x is a uniformly random function X → X, independent of everything else
(one independent function per input x). This idealizes both the weight derivation and the map.
It is the hypothesis §6 examines.

**Adversary.** A quantum oracle algorithm A. It receives x and has access to
O_R : |u⟩|w⟩ ↦ |u⟩|w ⊕ R_x(u)⟩. Its queries are arranged in d **layers**, and layer k holds
q_k parallel queries, with q = Σ q_k. Computation between layers is unlimited and free. A
outputs ŷ ∈ X and **succeeds** if ŷ = y_L. Query depth is the model's measure of sequential
time: an honest evaluation uses L layers of one query each.

The model keeps **one** round function shared by all positions, with the clock added to its
input, because that is how the construction is built. A single evaluation R_x(u) serves chain
position j whenever u = y_j ⊞ τ(j), for any j. This is the source of the factor L in the bounds
below (Remark 5.1).

---

## 3. Proposition Q1

> **Proposition Q1.** In model Q-IM, let A have query depth d ≤ L − 1 and make q_k queries in
> layer k. Put
>
>     Σ := Σ_{k=1..d} √( q_k (L − k) / 2^s ).
>
> Then
>
>     Pr[ŷ = y_L]  ≤  L(L−1)/2^(s+1)  +  min{ 2^−s + 2Σ ,  (2^(−s/2) + 2Σ)^2 }.
>
> **Corollary.** Since Σ ≤ √(d·q·L / 2^s) by Cauchy–Schwarz,
>
>     Pr[ŷ = y_L]  ≤  L^2/2^(s+1)  +  (2^(−s/2) + 2·√(d·q·L / 2^s))^2   ≈   4·d·q·L / 2^s.

---

## 4. Proof

### 4.1 The tool

**Lemma 2 (one-way to hiding; [AHU19], Theorem 3, reproduced).** Let S ⊆ X be random. Let
G, H : X → Y be random functions with G(u) = H(u) for all u ∉ S. Let z be a random bitstring.
(S, G, H and z may have any joint distribution.) Let A be a quantum oracle algorithm of query
depth d. Let B^H be the algorithm that picks i uniformly from {1, …, d}, runs A^H(z) until just
before the i-th query layer, measures all query input registers of that layer in the
computational basis, and outputs the set T of outcomes. Let

    P_left = Pr[b = 1 : b ← A^H(z)],   P_right = Pr[b = 1 : b ← A^G(z)],   P_guess = Pr[S ∩ T ≠ ∅ : T ← B^H(z)].

Then |P_left − P_right| ≤ 2d·√P_guess and |√P_left − √P_right| ≤ 2d·√P_guess.

(The statement is reproduced from the published paper. A reader should check it against the
paper before relying on this proof.)

### 4.2 A lazy form of the chain

Let R_0 : X → X be uniform, and let v_1, …, v_L ∈ X be uniform, all independent. Put v_0 := y_0
and ẑ_j := v_j ⊞ τ(j) for j = 0, …, L − 1. For 0 ≤ m ≤ L let **O_m** be R_0 reprogrammed at
ẑ_0, …, ẑ_{m−1} with the values v_1, …, v_m, in increasing order of index (a later index
overrides an earlier one at a repeated point). Let D be the event that ẑ_0, …, ẑ_{L−1} are
pairwise distinct.

**Lemma 1.**
(a) Pr[¬D] ≤ L(L−1)/2^(s+1).
(b) On D, the chain of O_L started at y_0 has query points ẑ_0, …, ẑ_{L−1} and values
v_1, …, v_L. In particular y_L(O_L) = v_L.
(c) For every adversary, |Pr[A^R → y_L(R)] − Pr[A^{O_L} → v_L]| ≤ Pr[¬D], where R is uniform.

*Proof.* (a) For j ≥ 1, ẑ_j = v_j ⊞ τ(j) is uniform and independent of ẑ_0, …, ẑ_{j−1}, which
depend on v_0, …, v_{j−1} only. So Pr[ẑ_j ∈ {ẑ_0, …, ẑ_{j−1}}] ≤ j/2^s, and summing over j
gives the claim. (b) By induction on j.
(c) Reveal the chain of a uniform R step by step. As long as the next query point is new, the
next value is uniform and independent of everything revealed so far, and the values of R off
the chain are uniform and independent of the chain. On D, O_L has the same description by
construction. So the joint law of (oracle, target) restricted to "the chain points are distinct"
is the same in both experiments, and that event has the same probability in both. The two
success probabilities therefore differ only on ¬D, which costs at most Pr[¬D]. ∎

### 4.3 Hybrids

For k = 0, …, d define game **Γ_k**: A runs with oracle O_i in layer i for every i ≤ k, and with
O_L in every layer i > k. Success means ŷ = v_L. Let W_k be the success probability in Γ_k.
Γ_0 is the game A^{O_L} of Lemma 1(c).

**The last game.** In Γ_d, layer i ≤ d uses O_i, which is determined by R_0 and v_0, …, v_i
(the points ẑ_0, …, ẑ_{i−1} use v_0, …, v_{i−1}; the values are v_1, …, v_i). Since
d ≤ L − 1, the whole run is independent of v_L, which is uniform. Hence **W_d = 2^−s**.

**One layer at a time.** Γ_{k−1} and Γ_k differ only in layer k, where one uses O_L and the
other O_k. These two functions agree outside T_k := {ẑ_k, …, ẑ_{L−1}}:

- off every chain point, both equal R_0;
- at a point that equals ẑ_i only for indices i < k, both carry the value of the largest such
  index.

Let A_k be the algorithm that receives z := (x, R_0, v_1, …, v_L). It simulates layers i < k
with O_i and layers i > k with O_L (both computable from z), sends only layer k to its oracle,
and outputs b = [ŷ = v_L]. A_k has query depth 1. Lemma 2 with H := O_L, G := O_k, S := T_k
gives

    |W_{k−1} − W_k| ≤ 2√P_k   and   |√W_{k−1} − √W_k| ≤ 2√P_k,

where P_k is the probability that the q_k inputs measured just before layer k meet T_k.

**The guessing probability.** The state before layer k depends only on the oracles O_1, …,
O_{k−1}, and so only on (x, R_0, v_1, …, v_{k−1}) and internal randomness. T_k depends only on
v_k, …, v_{L−1}, which are independent of that state. For any fixed u and any j ≥ k,
Pr[u = ẑ_j] = 2^−s. A union bound over the q_k measured inputs and the L − k points of T_k gives

    P_k ≤ q_k (L − k) / 2^s.

### 4.4 Conclusion

Summing the additive form gives W_0 ≤ W_d + 2Σ_k √P_k ≤ 2^−s + 2Σ. Summing the root form gives
√W_0 ≤ √W_d + 2Σ_k √P_k ≤ 2^(−s/2) + 2Σ. Adding Lemma 1(c) proves Proposition Q1. ∎

---

## 5. Remarks

**5.1 The classical bound from the same proof, and Paper 4's Theorem 1.** With classical
queries, each hybrid step costs at most the probability that a query hits T_k. That gives
Pr ≤ L(L−1)/2^(s+1) + 2^−s + Σ_k q_k (L − k)/2^s, which is about q·L/2^s. This carries a factor
of up to L that the figure **(q+1)/2^s** quoted for Theorem 1 of Paper 4 v4 (in the header of
`mcl_vdf128_t4_v4.hpp`) does not. The factor comes from modelling one round function shared by
all positions, which is what the construction does: the clock is **added** to the input, not
used as a separate domain. If Theorem 1 idealizes the clocked map as independent functions per
position, then the two models differ, and Paper 4 should state which one the construction
instantiates. Nothing here shows Theorem 1 wrong. Its model and proof are not in this repository.

The factor is not an artefact of the proof. `qseq_lfactor.py` runs a classical "guess ahead"
attacker at toy size (s = 20). It queries Q random points in its first layer, then follows the
chain and skips any step whose query point it already holds. In the single-function model it
saves an iteration at the rate 1 − (1 − (L−1)/2^s)^Q. In the per-position model it does so only
at the rate 1 − (1 − 2^−s)^Q (`qseq_lfactor_20260930.log`). This attack saves one iteration,
not a fraction of L (Remark 5.3).

**5.2 The price of the quantum proof.** At d = L − 1 with q_k = Q per layer, the dominant terms
are (16/9)·Q·L^3/2^s (quantum, root form) and Q·L^2/(2·2^s) (classical). The ratio is (32/9)·L,
which `qseq_bound.py` Table 3 reproduces numerically. The loss comes from summing amplitudes
coherently across the d hybrid steps. A tighter analysis with Zhandry's compressed oracle
[Zha19], of the kind used for hash chains in [CFHL21], is the natural next step. The target is a
bound of order q·L/2^s. **No quantum attack is known that does better than the classical
guessing strategy.** Grover-type amplification would need the marked set (the future chain
points) to be known and checkable, and in this problem it becomes known only after it is
reached.

**5.3 What "one iteration saved" means.** The proposition covers any depth below L, including
depth L − 1, where the adversary saves a single iteration. A VDF definition asks for failure at
depth (1 − δ)·L. Saving m iterations needs m independent "hits", and classically the
probability decays like (qL/2^s)^m. A quantum version of that multi-hit bound is not proved
here, and it would change the practical reading of Table 2 considerably.

**5.4 Finalization.** The VDF output is SHA-256 of the final state, the input and N
(`mcl_vdf128v4_output`). Modelling SHA-256 as an independent random oracle adds one more link to
the chain. The same argument applies with one more layer. It is not written out here.

**5.5 Outside the model.** Not covered here:
- preprocessing or quantum advice about the key derivation;
- adversaries who see more than x;
- the cost of evaluating the round coherently (`../Quantum_Structural_Analysis_20260927/`
  prices it at 2^17.9 … 2^24.2 T gates per iteration, model outputs);
- anything about the concrete map (§6).

---

## 6. From the ideal model to the concrete map

### 6.1 The hypothesis

> **H-FF.** For every input x, no quantum algorithm computes the concrete clocked chain of x
> with query-equivalent depth below L, except with the probability that Proposition Q1 allows
> in the ideal model.

H-FF would fail if the concrete round had a structure that lets the iteration be fast-forwarded.
The known mechanisms are listed below, each with the probe that tests a necessary condition
against it. The results are those of the record run in `qseq_struct_20260930.log`.

| | Mechanism | Where it works | Probe | Result on v4 |
|---|---|---|---|---|
| M1 | group law with computable order (exponent reduction) | RSA-group VDFs via Shor [Pie19, Wes19] | N1, N2 | no commuting translation (parity rank 4 on both instances; 0 of 255 offsets commute on all 4,096 states); no additive difference that passes deterministically (Part 2); a probabilistic one-round relation, §6.2 |
| M2 | affine or linear dynamics (matrix powering: depth log L) | linear recurrences, LFSRs | N2, N4 | multiplicity 1–2 of 16,384 at every r and every difference, against n = 16,384 for both affine controls; the nonlinear term moves a phase by up to 1.91 turns per coupling |
| M3 | small-nonlinearity regime (perturbative expansion, Carleman linearization) | weakly nonlinear dissipative dynamics [LKK+21] | N4 | no small parameter at K = 12: the nonlinear term wraps the circle |
| M4 | Hamiltonian fast-forwarding | commuting, quadratic (free-fermion) and some integrable Hamiltonians; generic ones cannot be fast-forwarded [BACS07, AA17] | N3 | the round is many-to-one (Part 3), so it has no unitary dynamics of its own; its reversible embedding carries garbage and matches none of the known fast-forwardable families |
| M5 | collapse of the state space (a small reachable set allows precomputation or guessing) | strongly contracting maps; short cycles of unclocked maps | N3, N5 | single-word image fractions 0.632111 … 0.632135 against 1 − 1/e = 0.632121 over all 2^32 inputs (a scatter of order 10^−5 beyond a random mapping's; README); 0 repeated outputs of one round on 2^24 states |
| M6 | short cycles of the iteration | unclocked maps (v3: memory-bounded attack, review #16) | construction | the v4 clock makes the map non-autonomous: there is no orbit to close |

A pass on every row is **evidence, not a proof** of H-FF. The table lists known mechanisms, and
an unknown one is not excluded.

### 6.2 A probabilistic one-round relation (found by Part 1, explained by Part 1b)

**What was observed.** Parity rank 4 excludes every **exact** translation symmetry. Even so, an
offset δ with every word in {0,1,2,3}·2^30 can move very few of the twelve coupling arguments.
An argument p·t_j − q·t_i does not see the offset when p·δ_j − q·δ_i ≡ 0 mod 2^32, which happens
often when weights are even. For the second instance ("VDF128-T4-battery-input"), two offsets
move a single argument and nine move two. For the first instance, the fewest is two arguments,
and they feed two different word updates.

**The mechanism.** Moving an argument by m quarter turns moves its sine-table index by exactly
m·2^14. A word update keeps its increment when the changes of its moved arguments cancel. With
one moved argument, that means inc(i) = inc(i + m·2^14), which holds for 2 of the 65,536
indices, so the probability is 2^−15. With two moved arguments in the same word update, the
probability computed from the table is again 2^−15.00. Word updates are independent here, so an
offset touching w word updates commutes with one round with probability about **2^−15w**.
Part 1b measures every offset that moves at most two arguments against that prediction. All
agree (|z| ≤ 1.1): about 128 of 2^22 states at w = 1, and 0 at w = 2. The relation **never held
for two consecutive rounds**.

**How common it is.** In a census of 20,000 inputs through the v4 weight derivation, the fewest
word updates touched by any offset was 1 for **9,906** weight sets (49.5%), 2 for 8,679, 3 for
1,415, and 4 for none. So about half of all v4 weight sets have a one-round relation
F(x + δ) = F(x) + δ of probability 2^−15.

**Reading.** This is an iterative additive characteristic of probability about 2^−15 per round,
and so about 2^−15r over r rounds. It is the additive counterpart of the "top-bit
non-propagation through even weights" of the XOR distinguisher of
`../P4_ReviewMeasurements_20260925/`. It is not a symmetry of the iteration, it does not shorten
depth, and it does not bear on M1. It is a measured deviation of one round from a random
function, and belongs in the list of one-round weaknesses of the map.

**A possible derivation rule** (for the author to decide): besides full parity rank, require
that every such offset touches at least w_0 word updates. By the census, w_0 = 2 keeps 50.5% of
draws and bounds the relation by about 2^−30. w_0 = 3 keeps 7.1% and bounds it by about 2^−45.
Neither rule is needed for Proposition Q1 or for the sequentiality question.

---

## 7. Status and next steps

| Item | Status after this record |
|---|---|
| Quantum sequentiality in the ideal model | **stated and proved** (Proposition Q1), subject to the reader's check of Lemma 2 as reproduced |
| Tightness of Q1 | **open**; target q·L/2^s via the compressed oracle |
| Depth (1 − δ)·L (saving many iterations) | **open**; a multi-hit version of Q1 is needed |
| s = 128 at N ≥ 10^10 | Q1 as proved certifies little (Table 2). A proven guarantee at those parameters needs either a tighter proof or a 256-bit state; the second is a design choice for the author |
| Concrete map (H-FF) | **open**; five necessary conditions tested, none fails |
| One-round relation of probability 2^−15 (§6.2) | **new finding**; present in 49.5% of v4 weight sets; a derivation rule is proposed for the author's decision |
| Scope note §2.7, items 15 and 17 | unchanged: open / withdrawn |

---

## References

- [AA17] Y. Atia, D. Aharonov. Fast-forwarding of Hamiltonians and exponentially precise measurements. *Nature Communications* 8, 2017.
- [AHU19] A. Ambainis, M. Hamburg, D. Unruh. Quantum security proofs using semi-classical oracles. CRYPTO 2019.
- [BACS07] D. W. Berry, G. Ahokas, R. Cleve, B. C. Sanders. Efficient quantum algorithms for simulating sparse Hamiltonians. *Commun. Math. Phys.* 270, 2007 (the no-fast-forwarding theorem).
- [BLZ21] J. Blocki, S. Lee, S. Zhou. On the security of proofs of sequential work in a post-quantum world. ITC 2021.
- [CFHL21] K.-M. Chung, S. Fehr, Y.-H. Huang, T.-N. Liao. On the compressed-oracle technique, and post-quantum security of proofs of sequential work. EUROCRYPT 2021.
- [LKK+21] J.-P. Liu, H. Ø. Kolden, H. K. Krovi, N. F. Loureiro, K. Trivisa, A. M. Childs. Efficient quantum algorithm for dissipative nonlinear differential equations. *PNAS* 118(35), 2021.
- [Pie19] K. Pietrzak. Simple verifiable delay functions. ITCS 2019.
- [Unr15] D. Unruh. Revocable quantum timed-release encryption. *J. ACM* 62(6), 2015 (EUROCRYPT 2014).
- [Wes19] B. Wesolowski. Efficient verifiable delay functions. EUROCRYPT 2019.
- [Zha19] M. Zhandry. How to record quantum queries, and applications to quantum indifferentiability. CRYPTO 2019.
