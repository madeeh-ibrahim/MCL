# Theory anchor for the C2 population row of the record log of
# mcl_qstruct_inventory.   usage: python3 theory_rank_enumeration.py qstruct_rev3_20260928.log
# The parity rank of a weight set depends only on the PARITIES of its twelve
# weights, so its distribution over uniformly drawn weights is obtained by
# enumerating all 2^12 parity patterns. The sidecar guard (v1.0.6) re-draws a
# seed-reachable set by adding 1 to lane 11-k (k = 0,1,...), i.e. by flipping
# that lane's parity, until the set is no longer seed-reachable.
# Independent of the tool: shares no code with mcl_qstruct_inventory.cpp.
import sys
from itertools import product
from math import sqrt, log2
I = [0, 0, 0, 1, 1, 2]; J = [1, 2, 3, 2, 3, 3]
OMEGA_PARITY = [1, 1, 1, 0]          # odd, odd, odd, even -- printed in the log header
def rank(pat):
    rows = []
    for e in range(6):
        p, q = pat[2*e], pat[2*e+1]
        rows.append((q << I[e]) | (p << J[e])); rows.append((p << I[e]) | (q << J[e]))
    r = 0
    for bit in range(4):
        piv = next((i for i in range(r, 12) if (rows[i] >> bit) & 1), None)
        if piv is None: continue
        rows[piv], rows[r] = rows[r], rows[piv]
        for i in range(12):
            if i != r and (rows[i] >> bit) & 1: rows[i] ^= rows[r]
        r += 1
    return r
def reachable(pat):
    for e in range(6):
        p, q = pat[2*e], pat[2*e+1]
        if (p*OMEGA_PARITY[J[e]] - q*OMEGA_PARITY[I[e]]) % 2: return False
        if (p*OMEGA_PARITY[I[e]] - q*OMEGA_PARITY[J[e]]) % 2: return False
    return True
def guard(pat):
    pat = list(pat); k = 0
    while reachable(pat) and k < 96:
        pat[11 - (k % 12)] ^= 1; k += 1
    return tuple(pat)
raw = [0]*5; grd = [0]*5; nreach = 0
for pat in product([0, 1], repeat=12):
    raw[rank(pat)] += 1
    nreach += reachable(pat)
    grd[rank(guard(pat))] += 1
N = 4096
print("parity patterns: 4096")
print("seed-reachable before the guard: %d = 2^-%.1f" % (nreach, log2(N/nreach)))
print("rank 4/3/2/1/0 without the guard: %d / %d / %d / %d / %d   symmetric %d/4096 = %.3f%%"
      % (raw[4], raw[3], raw[2], raw[1], raw[0], N-raw[4], 100*(N-raw[4])/N))
print("rank 4/3/2/1/0 with the guard   : %d / %d / %d / %d / %d   symmetric %d/4096 = %.3f%%"
      % (grd[4], grd[3], grd[2], grd[1], grd[0], N-grd[4], 100*(N-grd[4])/N))
# compare with the log
import re
t = open(sys.argv[1]).read()
m = re.search(r'parity rank 4/3/2/1/0 : (\d+) / (\d+) / (\d+) / (\d+) / (\d+)', t)
meas = [int(x) for x in m.groups()]; n = sum(meas)
print("\nmeasured in %s: %s (n = %d)" % (sys.argv[1].split('/')[-1], " / ".join(map(str, meas)), n))
chi = 0.0
for r, mm in zip([4, 3, 2, 1, 0], meas):
    e = n*grd[r]/N
    if e > 0:
        chi += (mm-e)**2/e
        print("  rank %d: measured %6d  expected %9.1f  z = %+.2f" % (r, mm, e, (mm-e)/sqrt(e)))
    else:
        print("  rank %d: measured %6d  expected       0.0  (excluded by the guard)" % (r, mm))
p = (N-grd[4])/N
print("chi-square, 3 degrees of freedom: %.2f   (95%% critical value 7.81)" % chi)
print("symmetric fraction: measured %.3f%%, theory %.3f%%, binomial standard error %.3f%%, z = %+.2f"
      % (100*(n-meas[0])/n, 100*p, 100*sqrt(p*(1-p)/n), ((n-meas[0])/n - p)/sqrt(p*(1-p)/n)))
mc = re.search(r'epochs with p,q both odd: rate ([\d.]+) per epoch', t)
mk = re.search(r'C5 keyed cascade, m = (\d+) epochs: (\d+) keys', t)
mr = re.search(r'seed-reachable: (\d+) =', t)
rate = float(mc.group(1)); mep = int(mk.group(1)); nk = int(mk.group(2)); got = int(mr.group(1))
exp = nk*rate**mep
print("\ncascade, before the check of sidecar v1.0.7: per-epoch both-odd rate %.4f, %d epochs, %d keys\n  -> expected %.1f keys of the class; counted %d (Poisson sd %.1f)"
      % (rate, mep, nk, exp, got, sqrt(exp)))
