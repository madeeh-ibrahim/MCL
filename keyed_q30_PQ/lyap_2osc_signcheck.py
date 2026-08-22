#!/usr/bin/env python3
# DECISIVE CONTROL for the q>p finding (re-examination, 2026-06-16).
# Independent 2-oscillator Lyapunov (mpmath) to (a) confirm the 2-osc sign law
# q>p <=> lambda_2>0, (b) verify the p/q labelling (q = self-coupling weight),
# and (c) contrast it with the 4-osc result.
#
# RESULT (reproduces): (3,5) q>p -> l2=+1.007 ; (5,3) q<p -> l2=-1.029 (matches white paper);
# key-0 pair0 (p=881430846,q=720797916) q<p -> l2=-0.402 = 2*ln(720797916/881430846) to 4 figs.
# => labelling correct; each key-0 pair is sub-hyperchaotic ALONE, yet the coupled
#    4-osc system (same pairs) is hyperchaotic (l2=+1.69, see mcl_keyed_q30_lyap_sweep).
#    Hyperchaos is EMERGENT from coupling, NOT from per-pair q>p ordering.
#
#   python3 lyap_2osc_signcheck.py        (needs: pip install mpmath)
from mpmath import mp, mpf, sin, cos, sqrt, log, fabs
mp.dps = 60
K = mpf(12); W1 = mpf('0.6180339887498949'); W2 = mpf('1.3247179572447460'); TP = 2*mp.pi

def m2(x):
    x = x % TP
    return x + TP if x < 0 else x

# 2-osc Gauss-Seidel; arg for updating osc i has q on SELF, p on OTHER
# (Tech Guide §1 / engine argf: arg = p*theta_other - q*theta_self)
def step2(t1, t2, p, q):
    a1 = p*t2 - q*t1; t1 = m2(t1 + W1 + K*sin(a1))     # update osc1 (self=t1 -> q*t1)
    a2 = p*t1 - q*t2; t2 = m2(t2 + W2 + K*sin(a2))     # Gauss-Seidel: uses updated t1
    return t1, t2

def jac2(t1, t2, p, q):                                # composed 2x2 GS Jacobian
    a1 = p*t2 - q*t1; c1 = cos(a1)
    J = [[1 - q*K*c1, p*K*c1], [mpf(0), mpf(1)]]
    t1n = m2(t1 + W1 + K*sin(a1))
    a2 = p*t1n - q*t2; c2 = cos(a2)
    r2 = [p*K*c2, 1 - q*K*c2]
    J = [J[0], [r2[0]*J[0][0] + r2[1]*J[1][0], r2[0]*J[0][1] + r2[1]*J[1][1]]]
    return J

def lyap2(p, q, burn=3000, N=4000, seed=12345678901234):
    t1 = m2(mpf(seed)*W1); t2 = m2(mpf(seed)*W2)
    for _ in range(burn): t1, t2 = step2(t1, t2, p, q)
    Q = [[mpf(1), mpf(0)], [mpf(0), mpf(1)]]; a = [mpf(0), mpf(0)]
    for _ in range(N):
        J = jac2(t1, t2, p, q)
        M = [[J[r][0]*Q[0][c] + J[r][1]*Q[1][c] for c in range(2)] for r in range(2)]
        QQ = [[M[r][c] for r in range(2)] for c in range(2)]; Rd = [mpf(0)]*2
        for c in range(2):
            for pp in range(c):
                d = sum(QQ[pp][r]*QQ[c][r] for r in range(2))
                for r in range(2): QQ[c][r] -= d*QQ[pp][r]
            nr = sqrt(sum(QQ[c][r]**2 for r in range(2))); Rd[c] = nr
            for r in range(2): QQ[c][r] /= nr
        Q = QQ
        for i in range(2): a[i] += log(fabs(Rd[i]))
        t1, t2 = step2(t1, t2, p, q)
    return a[0]/N, a[1]/N

if __name__ == "__main__":
    print("2-osc Lyapunov sign control (q = self-coupling weight):")
    for (p, q, note) in [(3, 5, 'q>p, ref l2~+1.02'), (5, 3, 'q<p, ref l2~-1.02'),
                         (881430846, 720797916, 'key0 pair0: q<p'),
                         (720797916, 881430846, 'swapped: q>p')]:
        l1, l2 = lyap2(mpf(p), mpf(q))
        print("  p=%-11d q=%-11d  l1=%+8.4f  l2=%+8.4f  %-18s  %s" % (
            p, q, float(l1), float(l2), note, 'HYPER' if l2 > 0 else 'l2<0'))
    print("\n  2*ln(720797916/881430846) =", mp.nstr(2*log(mpf(720797916)/mpf(881430846)), 8),
          "(matches the q<p key0-pair0 l2 above -> labelling confirmed)")
