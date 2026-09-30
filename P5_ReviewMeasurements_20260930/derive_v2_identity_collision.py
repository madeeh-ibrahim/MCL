# Exact per-pair collision probability of the version-2 Step-3 map (Paper 5 §III.A) for a uniform raw pair:
# p = 2 + (c1 mod (M-2)); q = 2 + (c2 mod (M-2)); if q == p: q += 1 (wrap in [2, M-1]);
# while gcd(p, q) != 1 or q == p: q += 1 (wrap).  Returns R^2 * sum_i P(i)^2, R = M - 2
# (= 1 for a uniform map over all ordered pairs). Expected colliding pairs among n identities = n^2/2 * C / R^2.
from math import gcd
def coll_const(M):
    lo, hi = 2, M - 1; R = hi - lo + 1; tot = 0
    for p in range(lo, hi + 1):
        cnt = {}
        for q0 in range(lo, hi + 1):
            q = q0
            if q == p: q = lo + ((q - lo + 1) % R)
            while gcd(p, q) != 1 or q == p: q = lo + ((q - lo + 1) % R)
            cnt[q] = cnt.get(q, 0) + 1
        tot += sum(c * c for c in cnt.values())
    return tot / R**2
for M in (500, 1000, 2000):
    C = coll_const(M)
    print(f"M={M}: C = R^2*sum P^2 = {C:.4f}")
C = coll_const(2000)
for M, n in ((10**6, 10**6), (10**6, 10**7), (10**9, 10**9)):
    print(f"M={M:.0e}, n={n:.0e}: expected colliding pairs = {n*n/2*C/(M-2)**2:.3f} (uniform-over-all-pairs formula: {n*n/2/(M-2)**2:.3f})")
