# SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""qseq_lfactor.py -- Doc ID MCL-P4-QSEQ-LFACTOR-2026-0930-001

Is the factor L of Remark 5.1 (QSEQ_PROOF.md) a property of the model or an artefact of the proof?
A small CLASSICAL simulation of the ideal model at toy size answers it.

Single-function model (as v4 is built): one random R on 2^s points; chain z_i = y_i + tau(i), y_{i+1} = R(z_i).
Per-position model (for comparison): an independent random function R_i for every position i.

Adversary ("guess ahead"): in layer 1 it queries z_0 and Q random points; afterwards it follows the
chain honestly, one query per layer, but whenever the next chain point was already queried it uses the
stored answer and moves on without spending a layer. It wins if it reaches y_L in at most L - 1 layers.
In the per-position model a random query (i, u) serves position i only, so the same attacker must pick a
position for each guess; it spreads its Q guesses over the positions.

Predictions: single-function 1 - (1 - (L-1)/2^s)^Q, about Q(L-1)/2^s; per-position 1 - (1 - 2^-s)^Q, about Q/2^s.
The chain can also meet itself (probability about L^2/2^(s+1), the term of Lemma 1(a)); s = 20 keeps that at or below about 3% (L = 256).
Usage: python3 qseq_lfactor.py
"""
import random


def run(s, L, Q, trials, per_position, seed):
    rnd = random.Random(seed)
    M = 1 << s
    wins = 0
    for _ in range(trials):
        tau = [rnd.randrange(M) for _ in range(L)]          # public clock values (injectivity immaterial at this size)
        y0 = rnd.randrange(M)
        table = {}                                            # lazily sampled random function(s)

        def R(pos, u):
            key = (pos, u) if per_position else u
            if key not in table:
                table[key] = rnd.randrange(M)
            return table[key]

        # layer 1: z_0 and Q guesses
        known = {}
        z = (y0 + tau[0]) % M
        known[(0, z) if per_position else z] = R(0, z)
        for g in range(Q):
            if per_position:
                pos = 1 + g % (L - 1)                         # spread guesses over positions 1..L-1
                u = rnd.randrange(M)
                known[(pos, u)] = R(pos, u)
            else:
                u = rnd.randrange(M)
                known[u] = R(None, u)
        layers = 1
        y = known[(0, z) if per_position else z]
        for i in range(1, L):
            z = (y + tau[i]) % M
            key = (i, z) if per_position else z
            if key in known:
                y = known[key]                                # free: answer already in hand
            else:
                layers += 1
                y = R(i, z)
                known[key] = y
        wins += (layers <= L - 1)
    return wins


def main():
    print("qseq_lfactor (MCL-P4-QSEQ-LFACTOR-2026-0930-001) -- classical 'guess ahead' attack, toy size")
    s, trials = 20, 5000
    print(f"s = {s} bits, {trials} trials per row; win = reach y_L within L - 1 layers\n")
    print("   L     Q   single-function: wins  rate    predicted             |  per-position: wins  rate    predicted")
    for (L, Q) in [(16, 4096), (64, 4096), (256, 1024), (64, 1024)]:
        a = run(s, L, Q, trials, False, 1000 + L * 7 + Q)
        b = run(s, L, Q, trials, True, 2000 + L * 7 + Q)
        pa, pb = 1 - (1 - (L - 1) / 2 ** s) ** Q, 1 - (1 - 2.0 ** -s) ** Q
        print(f"  {L:4d} {Q:5d}   {a:26d}  {a / trials:.5f}   {pa:.5f} [DERIVED]      |  {b:16d}  {b / trials:.5f}   {pb:.5f} [DERIVED]")
    print("\n[MEASURED] rows: the factor L appears in the single-function model and not in the per-position one.")
    print("It is a property of the model, attained by a classical attack, and not an artefact of the proof.")
    print("Saving one iteration is all this attack does; it says nothing about saving a fraction of L (QSEQ_PROOF.md 5.3).")


if __name__ == "__main__":
    main()
