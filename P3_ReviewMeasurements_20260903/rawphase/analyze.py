# SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# MCL Reference Implementation. Free security research / evaluation for all
# (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
# a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
import numpy as np, itertools, sys
rng=np.random.default_rng(20260903)
def load(p,q):
    a=np.fromfile(f"ph_{p}_{q}.bin",dtype=np.float64); return a[0::2],a[1::2]
chan={t:load(*t) for t in [(2,3),(3,5),(5,7),(7,11),(8,13),(6,10),(5,3),(4,6),(6,9)]}
N=len(chan[(2,3)][0])
def pearson(x,y): x=x-x.mean(); y=y-y.mean(); return float((x@y)/np.sqrt((x@x)*(y@y)))
def lagged_max(x,y,L=50):
    n=len(x); x=(x-x.mean())/x.std(); y=(y-y.mean())/y.std(); best=0; bl=0
    for l in range(-L,L+1):
        if l>=0: r=(x[l:]@y[:n-l])/(n-l)
        else:    r=(x[:n+l]@y[-l:])/(n+l)
        if abs(r)>best: best=abs(r); bl=l
    return best,bl
def mi_bits(x,y,b=64):
    H,_,_=np.histogram2d(x,y,bins=b,range=[[0,2*np.pi],[0,2*np.pi]]); P=H/H.sum()
    px=P.sum(1,keepdims=True); py=P.sum(0,keepdims=True); nz=P>0
    return float((P[nz]*np.log2(P[nz]/(px@py)[nz])).sum())
def joint_chi2(x,y,b=32):
    H,_,_=np.histogram2d(x,y,bins=b,range=[[0,2*np.pi],[0,2*np.pi]]); E=np.outer(H.sum(1),H.sum(0))/H.sum()
    chi=float(((H-E)**2/E).sum()); df=(b-1)**2; return chi,(chi-df)/np.sqrt(2*df)
def dcor2(X,Y):
    def dc(A):
        D=np.sqrt(((A[:,None,:]-A[None,:,:])**2).sum(-1)); return D-D.mean(0)-D.mean(1)[:,None]+D.mean()
    A=dc(X); B=dc(Y); return (A*B).mean()/np.sqrt((A*A).mean()*(B*B).mean()), A, B
def dcor_perm(X,Y,nperm=200):
    d,A,B=dcor2(X,Y); nulls=[]
    for _ in range(nperm):
        idx=rng.permutation(len(Y)); Bp=B[np.ix_(idx,idx)]; nulls.append((A*Bp).mean()/np.sqrt((A*A).mean()*(Bp*Bp).mean()))
    nulls=np.array(nulls); return d,(d-nulls.mean())/nulls.std(),(1+(nulls>=d).sum())/(nperm+1)
def emb(t1,t2,idx): return np.stack([np.cos(t1[idx]),np.sin(t1[idx]),np.cos(t2[idx]),np.sin(t2[idx])],1)
sub=np.arange(0,N,N//3000)[:3000]
def mi_perm(x,y,nperm=60):
    m=mi_bits(x,y); nulls=np.array([mi_bits(x,rng.permutation(y)) for _ in range(nperm)]); return m,(m-nulls.mean())/nulls.std()
pairs=[((2,3),(3,5)),((3,5),(5,7)),((3,5),(6,10)),((3,5),(5,3)),((4,6),(6,9)),((7,11),(8,13)),((2,3),(4,6)),((5,7),(7,11))]
sig=1/np.sqrt(N)
print(f"N={N} steps per channel (post burn-in), K=12, seed 12345678901234, engine public v0.2.1; sigma_null(Pearson)=1/sqrt(N)={sig:.5f}; lag-Bonferroni floor (101 lags, alpha=0.001) = {4.3*sig:.5f}")
print("pair | max|r| (cos/sin th1,th2; 8 combos) z | lagged max|r| (|lag|<=50) | MI bits (64x64) z_perm | joint chi2 32x32 z | dCor(n=3000) z_perm p_perm")
def row(name,A,B,ctrl=False):
    a1,a2=A; b1,b2=B
    rs=[pearson(f(a),g(b)) for a,b in [(a1,b1),(a2,b2),(a1,b2),(a2,b1)] for f,g in [(np.cos,np.cos),(np.sin,np.sin)]]
    mr=max(abs(r) for r in rs); lm,bl=lagged_max(np.sin(a1),np.sin(b1))
    m,mz=mi_perm(a1,b1); chi,cz=joint_chi2(a1,b1); d,dz,dp=dcor_perm(emb(a1,a2,sub),emb(b1,b2,sub))
    print(f"{name:22s} | {mr:.5f} z={mr/sig:5.2f} | {lm:.5f}@{bl:+d} | {m:.5f} z={mz:6.2f} | {chi:8.1f} z={cz:6.2f} | {d:.5f} z={dz:6.2f} p={dp:.4f}")
for A,B in pairs: row(f"{A} vs {B}",chan[A],chan[B])
print("--- controls ---")
row("(3,5) vs itself",chan[(3,5)],chan[(3,5)])
a1,a2=chan[(3,5)]; row("(3,5) vs itself lag1",(a1[:-1],a2[:-1]),(a1[1:],a2[1:]))
row("(3,5) vs +tiny noise",chan[(3,5)],((a1+rng.normal(0,0.3,N))%(2*np.pi),(a2+rng.normal(0,0.3,N))%(2*np.pi)))
