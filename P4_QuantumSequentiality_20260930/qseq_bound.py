# SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""qseq_bound.py -- Doc ID MCL-P4-QSEQ-BOUND-2026-0930-001

Evaluates Proposition Q1 of QSEQ_PROOF.md (quantum sequentiality of the clocked
map in the ideal model) and, beside it, the classical bound that the same proof
gives. Pure arithmetic on a proven statement: every printed figure is [DERIVED].

    eps_Q <= L(L-1)/2^(s+1) + min( 2^-s + 2*S ,  (2^(-s/2) + 2*S)^2 )
    S      = sum_{k=1..d} sqrt( q_k (L-k) / 2^s )
    eps_C <= L(L-1)/2^(s+1) + 2^-s + sum_{k=1..d} q_k (L-k) / 2^s

s = state bits, L = B + N iterations, d = query depth (d <= L-1), q_k = queries
in layer k. The tables use q_k = Q in every layer and the worst depth d = L - 1.

Usage:  python3 qseq_bound.py [../Quantum_Structural_Analysis_20260927/grover_rev3_20260928.log]
"""
import math
import re
import sys

B = 10_000


def log2(x):
    return math.log2(x) if x > 0 else float("-inf")


def sum_sqrt_upper(L, d):
    """Upper bound on sum_{k=1..d} sqrt(L-k): the integral of sqrt(L-x) over [0, d] (the summand decreases)."""
    return (2.0 / 3.0) * (L ** 1.5 - (L - d) ** 1.5)


def sum_sqrt_exact(L, d):
    return sum(math.sqrt(L - k) for k in range(1, d + 1))


def eps_quantum(s, L, d, Q, exact=False):
    """Proposition Q1 with q_k = Q in every layer."""
    ss = sum_sqrt_exact(L, d) if exact else sum_sqrt_upper(L, d)
    S = math.sqrt(Q / 2.0 ** s) * ss
    notD = L * (L - 1) / 2.0 ** (s + 1)
    additive = 2.0 ** -s + 2 * S
    squared = (2.0 ** (-s / 2) + 2 * S) ** 2
    return notD + min(additive, squared), notD, additive, squared


def eps_classical(s, L, d, Q):
    notD = L * (L - 1) / 2.0 ** (s + 1)
    hits = Q * (d * L - d * (d + 1) / 2.0) / 2.0 ** s   # sum_{k=1..d} Q (L-k)
    return notD + 2.0 ** -s + hits


def q_max(s, L, d, kappa):
    """Largest Q (per layer) with eps_Q <= 2^-kappa, from the squared form; None if the L^2 term alone exceeds it."""
    notD = L * (L - 1) / 2.0 ** (s + 1)
    budget = 2.0 ** -kappa - notD
    if budget <= 0:
        return None
    root = math.sqrt(budget) - 2.0 ** (-s / 2)
    if root <= 0:
        return None
    return (root / (2.0 * sum_sqrt_upper(L, d))) ** 2 * 2.0 ** s


def t_band(path):
    """Per-iteration T-gate figures of the Grover resource model (model outputs, rev 3)."""
    vals = []
    try:
        with open(path) as f:
            for line in f:
                m = re.search(r"per-iteration T gates\s*:\s*2\^([0-9.]+)", line)
                if m:
                    vals.append(float(m.group(1)))
    except OSError:
        return None
    return (min(vals), max(vals), len(vals)) if vals else None


def fmt(x):
    return "   -inf" if x == float("-inf") else f"{x:7.1f}"


def main():
    print("qseq_bound (MCL-P4-QSEQ-BOUND-2026-0930-001) -- Proposition Q1 of QSEQ_PROOF.md, evaluated")
    print("all figures log2; [DERIVED] = arithmetic on the proposition; B = 10,000, L = B + N, worst depth d = L - 1\n")

    # ---- self-check: integral bound against the exact sum -------------------------------------------
    bad = 0
    for (L, d) in [(1000, 999), (1000, 500), (4097, 4096), (10_000, 1)]:
        ex, up = sum_sqrt_exact(L, d), sum_sqrt_upper(L, d)
        ok = ex <= up and up - ex <= math.sqrt(L) + 1e-9
        bad += not ok
        print(f"  [CONSISTENCY] L={L:6d} d={d:5d}: exact sum {ex:14.3f}  integral bound {up:14.3f}  {'ok' if ok else 'FAILED'}")
        e1 = eps_quantum(128, L, d, 7, exact=True)[0]
        e2 = eps_quantum(128, L, d, 7)[0]
        ok2 = e1 <= e2
        bad += not ok2
        print(f"  [CONSISTENCY]   eps_Q exact-sum {log2(e1):8.3f} <= integral-bound form {log2(e2):8.3f}  {'ok' if ok2 else 'FAILED'}")
    if bad:
        print("  A CONSISTENCY CHECK FAILED -- DO NOT QUOTE THIS RUN")
        sys.exit(2)

    # ---- table 1: the bound at deployment-like parameters ------------------------------------------
    print("\n== Table 1: success bound for depth d = L - 1 (one iteration saved), Q queries per layer ==")
    print("  s    N          Q     eps_Q(Q1)  [squared form | additive form]   eps_C(same proof, classical)   L^2 term")
    Ns = [("1e6", 10**6), ("1e8", 10**8), ("1e10", 10**10), ("2^40", 2**40)]
    for s in (128, 256):
        for (nn, N) in Ns:
            L = B + N
            d = L - 1
            for lq in (0, 20, 40):
                Q = 2.0 ** lq
                e, notD, add, sq = eps_quantum(s, L, d, Q)
                c = eps_classical(s, L, d, Q)
                print(f"  {s:3d}  {nn:>5}  2^{lq:<3d}  {fmt(log2(min(e, 1.0)))}   [{fmt(log2(sq))} | {fmt(log2(add))}]"
                      f"                  {fmt(log2(min(c, 1.0)))}              {fmt(log2(notD))}")
    print("  (a value 0.0 means the bound is vacuous: >= 1)")

    # ---- table 2: largest parallelism for a target -------------------------------------------------
    band = t_band(sys.argv[1] if len(sys.argv) > 1 else "../Quantum_Structural_Analysis_20260927/grover_rev3_20260928.log")
    print("\n== Table 2: largest queries per layer Q (and total q = d*Q) with eps_Q <= 2^-kappa, d = L - 1 ==")
    if band:
        print(f"  T gates per coherent round evaluation: 2^{band[0]:.2f} .. 2^{band[1]:.2f} "
              f"({band[2]} configurations of the Grover resource model rev 3 -- model outputs, neither bound)")
    print("  s    N      kappa   log2 Q_max   log2 q_total   log2 T gates for q_total")
    for s in (128, 256):
        for (nn, N) in Ns:
            L = B + N
            d = L - 1
            for kappa in (20, 40, 64):
                qm = q_max(s, L, d, kappa)
                if qm is None or qm < 1:
                    print(f"  {s:3d}  {nn:>5}  {kappa:5d}   below one query per layer: the bound cannot certify an honest-rate adversary")
                    continue
                lq = log2(qm)
                lt = lq + log2(d)
                tg = f"{lt + band[0]:6.1f} .. {lt + band[1]:6.1f}" if band else "-"
                print(f"  {s:3d}  {nn:>5}  {kappa:5d}   {lq:10.1f}   {lt:12.1f}   {tg}")

    # ---- table 3: price of the proof technique -----------------------------------------------------
    print("\n== Table 3: ratio eps_Q / eps_C (dominant terms) -- what the quantum proof costs over the classical one ==")
    for s in (128, 256):
        for (nn, N) in Ns[:2]:
            L = B + N
            d = L - 1
            Q = 2.0 ** 20
            e, notD, add, sq = eps_quantum(s, L, d, Q)
            c = eps_classical(s, L, d, Q) - notD - 2.0 ** -s
            print(f"  s={s} N={nn} Q=2^20: squared form {log2(sq):7.1f}, classical hit term {log2(c):7.1f}, ratio 2^{log2(sq) - log2(c):.1f} "
                  f"(closed form at d = L-1: (32/9) L = 2^{log2(32.0 / 9.0 * L):.1f})")
    print("\n[DERIVED] rows only. The proposition is a statement in the ideal model; the concrete map is covered by")
    print("the structural hypothesis H-FF, which this program does not touch (see qseq_struct and QSEQ_PROOF.md section 6).")


if __name__ == "__main__":
    main()
