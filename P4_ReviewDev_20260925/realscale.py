# Real-scale evaluation of the merge-aware walk-collision attack (continuous form of E_det used in walkdp_sim.c)
# against SCIA-128's stated bound N(M+N)/2^127, at the paper's budgets P = M = 2^60, s = 128.
# E_det = P * N^2 * I(lam, eps) / 2^s, I = int int_{usable} (1 - exp(-lam * w)) , w = min(1-eps-b, 1-2b+a),
# usable: 0<=a<=1-eps, a+eps<=b<=1-eps, w>=0 ; memory: P*(1 + lam*(1-eps)) <= M, P <= Pmax.
import math
def I(lam, eps, n=600):
    s = 0.0; T = 1 - eps; h = T / n
    for i in range(n):
        a = (i + 0.5) * h
        for j in range(n):
            b = (j + 0.5) * h
            if b < a + eps: continue
            w = min(T - b, 1 - 2*b + a)
            if w <= 0: continue
            s += (1 - math.exp(-lam * w))
    return s * h * h
best = None
for eps in (0.05, 0.1, 1/6, 0.2, 0.25, 0.3):
    for lam in (0.25, 0.5, 1, 2, 4, 8, 16, 32):
        g = I(lam, eps, 300) / (1 + lam * (1 - eps))     # per unit of memory M
        if best is None or g > best[0]: best = (g, eps, lam)
        if lam in (1, 8) : print(f"eps={eps:.3f} lam={lam:>5}: I={I(lam,eps,300):.4f}  I/(1+lam(1-eps))={g:.5f}")
g, eps_b, lam_b = best
print(f"best memory-normalised factor g={g:.5f} at eps={eps_b:.3f}, lam={lam_b}")
s = 128; M = 2.0**60; Pmax = 2.0**60
print("\n N        | SCIA-128 bound N(M+N)/2^127 | attack E_det (P = M/(1+lam(1-eps)))  -> success ~ 1-exp(-E) | eps=1/4 variant")
for N in (1e4, 1e7, 1e8, 1e9, 1e10, 1e12, 2.0**40):
    bound = N * (M + N) / 2.0**127
    E = (M / (1 + lam_b*(1-eps_b))) * N * N * I(lam_b, eps_b, 300) / 2.0**s
    lam4 = 2.0; E4 = (M / (1 + lam4*0.75)) * N * N * I(lam4, 0.25, 300) / 2.0**s
    print(f" {N:9.3g} | 2^{math.log2(bound):7.2f}                 | E=2^{math.log2(E):7.2f}  success~{1-math.exp(-E):.3g} | eps=1/4: E=2^{math.log2(E4):7.2f}")
print("\nclocked ideal-model ceiling q/2^(s-1), q = P*(1-eps)N <= 2^60 N:")
for N in (1e7, 1e9, 1e12, 2.0**40):
    print(f" N={N:9.3g}: ceiling 2^{math.log2(Pmax*N/2.0**127):7.2f}  vs SCIA bound 2^{math.log2(N*(M+N)/2.0**127):7.2f}")
