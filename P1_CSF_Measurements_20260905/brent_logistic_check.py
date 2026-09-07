# Independent (CPython, no FMA) Brent cycle detection for the binary64 logistic map, same x0 rule as the C++ tool.
import math, sys, time
phi1 = 0.6180339887498949
def x0_of(seed): return 0.05 + 0.9 * math.fmod(seed * phi1, 1.0)
def brent(x0, r, cap):
    f = lambda x: r * x * (1.0 - x)
    power = lam = 1; tort = x0; hare = f(x0)
    while tort != hare:
        if power == lam: tort = hare; power *= 2; lam = 0
        hare = f(hare); lam += 1
        if power + lam > cap: return None, None
    mu = 0; tort = hare = x0
    for _ in range(lam): hare = f(hare)
    while tort != hare: tort = f(tort); hare = f(hare); mu += 1
    return mu, lam
for seed in [int(s) for s in sys.argv[1:]]:
    t = time.time(); mu, lam = brent(x0_of(seed), 4.0, 400_000_000)
    print(f"PYTHON r=4.00 seed={seed} x0={x0_of(seed):.6f} tail mu={mu} cycle lambda={lam}  ({time.time()-t:.0f}s)", flush=True)
