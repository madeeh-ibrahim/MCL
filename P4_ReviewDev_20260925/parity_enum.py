# Exhaustive census of the 2^12 weight-parity patterns of Algorithm 1 (VDF128-T4 v3).
# Rows exactly as the paper and mcl_vdf128v3_parity_rank(): for pair e=(I,J) with weights (p,q):
#   row1 = (q mod 2) e_I + (p mod 2) e_J   (from a_IJ = p t_J - q t_I)
#   row2 = (p mod 2) e_I + (q mod 2) e_J   (from a_JI = p t_I - q t_J)
from itertools import product
I = [0,0,0,1,1,2]; J = [1,2,3,2,3,3]
def rows_of(bits):          # bits[2e]=p parity, bits[2e+1]=q parity
    R = []
    for e in range(6):
        p, q = bits[2*e], bits[2*e+1]
        R.append((q << I[e]) | (p << J[e]))
        R.append((p << I[e]) | (q << J[e]))
    return R
def rank(R):
    R = R[:]; r = 0
    for b in range(4):
        piv = next((k for k in range(r, len(R)) if (R[k] >> b) & 1), None)
        if piv is None: continue
        R[r], R[piv] = R[piv], R[r]
        for k in range(len(R)):
            if k != r and (R[k] >> b) & 1: R[k] ^= R[r]
        r += 1
    return r
def kernel(R):               # all nonzero v in GF(2)^4 with <row, v> = 0 for every row
    return [v for v in range(1, 16) if all(bin(row & v).count("1") % 2 == 0 for row in R)]
full = defi = single = glob = both = other = 0
kv_hist = {}
for bits in product((0,1), repeat=12):
    R = rows_of(bits); rk = rank(R)
    if rk == 4: full += 1; continue
    defi += 1
    K = kernel(R)
    sw = any(v in K for v in (1,2,4,8)); gl = 15 in K
    single += sw; glob += gl; both += (sw and gl); other += (not sw and not gl)
    for v in K:
        w = bin(v).count("1"); kv_hist[w] = kv_hist.get(w, 0) + 1
print(f"patterns 4096: full rank {full}, rank-deficient {defi} ({100*defi/4096:.4f}%)")
print(f"  single-word zero column : {single} ({100*single/4096:.4f}%)")
print(f"  global all-ones kernel  : {glob} ({100*glob/4096:.4f}%)")
print(f"  both                    : {both} ({100*both/4096:.4f}%)")
print(f"  neither (other kernels) : {other} ({100*other/4096:.4f}%)")
print(f"  kernel-vector weights over deficient patterns (weight: count): {dict(sorted(kv_hist.items()))}")
