# Toy check: distinguished-point TMTO against a fixed random 32-bit mapping.
# Paper's generic term: M/(eps*2^s) counts only stored chain STARTS.
# Hellman/DP: every point on a precomputed chain is a usable hit.
import random
S_BITS=32; SPACE=1<<S_BITS
def f(s):  # random-looking 32->32 mapping (non-bijective: high half of a 64-bit mix)
    z=(s+0x9E3779B97F4A7C15)&0xFFFFFFFFFFFFFFFF
    z=((z^(z>>30))*0xBF58476D1CE4E5B9)&0xFFFFFFFFFFFFFFFF
    z=((z^(z>>27))*0x94D049BB133111EB)&0xFFFFFFFFFFFFFFFF
    z^=z>>31
    return (z>>32)&0xFFFFFFFF
random.seed(1)
CHAINS=1<<10; CLEN=1<<10; DP_MASK=(1<<6)-1   # W0 = 2^20 covered points, DP rate 2^-6
table={}   # dp -> (chain end, distance dp->end)
for c in range(CHAINS):
    s=random.getrandbits(32); pts=[s]
    for _ in range(CLEN): s=f(s); pts.append(s)
    end=pts[-1]
    for i,p in enumerate(pts):
        if (p&DP_MASK)==0 and p not in table: table[p]=(end,CLEN-i)
M_stored=len(table)
N=1<<10; eps=0.5; trials=20000; succ=0
for _ in range(trials):
    s=random.getrandbits(32); saved=0
    for u in range(N):
        if (s&DP_MASK)==0 and s in table:
            end,d=table[s]
            if d<=N-u: saved=d; break
        s=f(s)
    if saved>=eps*N: succ+=1
W0=CHAINS*CLEN
print(f"stored DP entries M = {M_stored} (~2^{M_stored.bit_length()-1}), covered W0 = 2^{W0.bit_length()-1}, N = 2^{N.bit_length()-1}, eps={eps}")
print(f"paper's generic term  M/(eps*2^s)        = {M_stored/(eps*SPACE):.3e}")
print(f"DP-TMTO prediction    (1-eps)*N*W0/2^s   = {(1-eps)*N*W0/SPACE:.3e}")
print(f"measured success rate                    = {succ/trials:.3e}   ({succ}/{trials})")
