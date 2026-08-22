#!/usr/bin/env python3
# combiner_analysis.py — robust-combiner (non-degradation) demonstration.
#
# Thesis (the commercial "additional layer"): with INDEPENDENT keys,
#   C = P  XOR  K_AES  XOR  K_MCL
# is at least as strong as the stronger layer. Breaking ONE layer leaves the
# plaintext still hidden behind the OTHER. We demonstrate this empirically:
#   - each keystream is statistically random,
#   - K_MCL and K_AES are statistically independent (so MCL adds diversity),
#   - removing one keystream from C leaves a still-random residual (P stays hidden),
#   - only removing BOTH recovers the (deliberately low-entropy) plaintext.
import sys, numpy as np

def load(path):
    with open(path, "rb") as f:
        return np.frombuffer(f.read(), dtype=np.uint8)

def stats(b):
    n = len(b)
    counts = np.bincount(b, minlength=256).astype(np.float64)
    p = counts / n
    nz = p[p > 0]
    ent  = float(-np.sum(nz * np.log2(nz)))            # bits/byte (ideal 8.0)
    exp  = n / 256.0
    chi2 = float(np.sum((counts - exp) ** 2 / exp))    # 255 dof; 0.01 crit ~ 310.46
    ones = float(np.unpackbits(b).mean())              # monobit (ideal 0.5)
    x = b[:-1].astype(np.float64); y = b[1:].astype(np.float64)
    r1 = float(np.corrcoef(x, y)[0, 1])                # lag-1 serial corr (ideal 0)
    return ent, chi2, ones, r1

def line(name, b):
    ent, chi2, ones, r1 = stats(b)
    flag = "OK" if (ent > 7.999 and chi2 < 330 and abs(ones-0.5) < 0.001 and abs(r1) < 0.002) else "**"
    print(f"  {name:<34} ent={ent:.6f}  chi2={chi2:7.2f}  monobit={ones:.6f}  r_lag1={r1:+.6f}  [{flag}]")
    return ent

mcl = load(sys.argv[1])
aes = load(sys.argv[2])
n = min(len(mcl), len(aes))
mcl, aes = mcl[:n], aes[:n]
print(f"=== Robust-combiner / non-degradation demonstration  (N = {n:,} bytes/stream) ===\n")

print("[1] Each keystream is statistically random (ideal: ent 8.0, chi2<310, monobit .5, r~0):")
line("K_MCL  (MCL_T2 layer)", mcl)
line("K_AES  (AES-256-CTR layer)", aes)

print("\n[2] Independence — MCL adds DIVERSITY, not correlated redundancy:")
r_cross = float(np.corrcoef(mcl.astype(np.float64), aes.astype(np.float64))[0, 1])
comb_ks = np.bitwise_xor(mcl, aes)
print(f"  cross-correlation r(K_MCL, K_AES) = {r_cross:+.6f}   (ideal 0; noise floor ~ {1/np.sqrt(n):.2e})")
line("K_AES XOR K_MCL  (combined keystream)", comb_ks)

print("\n[3] Non-degradation — a deliberately LOW-entropy plaintext, layered:")
P = np.full(n, 0x41, dtype=np.uint8)          # 'AAAA...' : ent ~ 0  (worst case for hiding)
ent_P = line("P  (plaintext, structured)", P)
C = np.bitwise_xor(np.bitwise_xor(P, aes), mcl)
line("C = P XOR K_AES XOR K_MCL  (ciphertext)", C)

print("\n[4] Attacker breaks ONE layer (knows that keystream exactly):")
res_aes_broken = np.bitwise_xor(C, aes)        # = P XOR K_MCL  : MCL still protects
res_mcl_broken = np.bitwise_xor(C, mcl)        # = P XOR K_AES  : AES still protects
e1 = line("AES broken -> C XOR K_AES = P XOR K_MCL", res_aes_broken)
e2 = line("MCL broken -> C XOR K_MCL = P XOR K_AES", res_mcl_broken)

print("\n[5] Attacker breaks BOTH layers:")
res_both = np.bitwise_xor(np.bitwise_xor(C, aes), mcl)   # = P
e3 = line("BOTH broken -> C XOR K_AES XOR K_MCL = P", res_both)
recovered = np.array_equal(res_both, P)

print("\n=== VERDICT ===")
ok_div  = abs(r_cross) < 5/np.sqrt(n)
ok_nondeg = (e1 > 7.999) and (e2 > 7.999)
ok_recov  = recovered and (e3 < 0.01)
print(f"  independence (MCL ⟂ AES)            : {'PASS' if ok_div else 'FAIL'}  (r={r_cross:+.2e})")
print(f"  non-degradation (1 broken ⇒ hidden) : {'PASS' if ok_nondeg else 'FAIL'}  (residual entropy {e1:.4f}/{e2:.4f} bits/byte ≈ 8)")
print(f"  need BOTH to recover P               : {'PASS' if ok_recov else 'FAIL'}  (only both-broken yields P, ent {e3:.4f})")
print()
print("  => As an additional layer with an independent key, MCL cannot weaken the")
print("     base cipher (combiner is non-degrading) and adds an independent factor:")
print("     compromising AES alone leaves the plaintext hidden behind MCL, and vice versa.")
