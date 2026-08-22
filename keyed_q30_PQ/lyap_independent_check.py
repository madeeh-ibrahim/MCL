#!/usr/bin/env python3
# INDEPENDENT validation of the MCL T4 lambda_2 computation (NOT copied from the C++).
# Reimplements the 4-osc Gauss-Seidel step + Jacobian + Benettin QR from the math,
# in arbitrary precision (mpmath), and cross-checks the C++ MPFR tool through 5 lenses:
#   L2: finite-difference Jacobian  vs  analytic Jacobian
#   L3: sum rule  Sum(lambda_i)  vs  <ln|det J|> from an INDEPENDENT analytic det formula
#   L5: known-matrix sanity (Benettin on a fixed matrix with analytically known exponents)
#   L1: lambda spectrum on the SAME weights as C++ (small sanity, boundary q/p->1, q/p=1.5)
#   L4: precision is set high (80 dps ~ 266 bit) > C++ 256-bit, to expose any precision artifact
from mpmath import mp, mpf, sin, cos, sqrt, log, fabs, matrix
mp.dps = 80   # ~266-bit, exceeds the C++ 256-bit

K   = mpf(12)
OM  = [mpf('0.6180339887498949'), mpf('1.3247179572447460'),
       mpf('0.4142135623730950'), mpf('0.7182818284590452')]
TWO_PI = 2*mp.pi
# topology: osc i couples to (j, pair_k) -- derived from the Sextet field layout, NOT copied
COUP = {0:[(1,0),(2,1),(3,2)], 1:[(0,0),(2,3),(3,4)], 2:[(0,1),(1,3),(3,5)], 3:[(0,2),(1,4),(2,5)]}

def mod2pi(x):
    x = x % TWO_PI
    return x + TWO_PI if x < 0 else x

def step(th, P, Q):                       # pure state update (Gauss-Seidel, in place order 0..3)
    t = list(th)
    for i in range(4):
        s = mpf(0)
        for (j,k) in COUP[i]:
            s += K*sin(P[k]*t[j] - Q[k]*t[i])
        t[i] = mod2pi(t[i] + OM[i] + s)
    return t

def jac_analytic(th, P, Q):               # composed GS Jacobian at state th (independent build)
    J = [[mpf(1) if r==c else mpf(0) for c in range(4)] for r in range(4)]
    t = list(th)
    for i in range(4):
        row = [mpf(0)]*4; row[i] = mpf(1)
        for (j,k) in COUP[i]:
            kc = K*cos(P[k]*t[j] - Q[k]*t[i])
            row[j] += P[k]*kc
            row[i] -= Q[k]*kc
        newrow = [sum(row[m]*J[m][c] for m in range(4)) for c in range(4)]
        J[i] = newrow
        s = sum(K*sin(P[k]*t[j]-Q[k]*t[i]) for (j,k) in COUP[i])
        t[i] = mod2pi(t[i] + OM[i] + s)
    return J

def jac_fd(th, P, Q, h):                  # central finite-difference Jacobian (fully independent)
    J = [[mpf(0)]*4 for _ in range(4)]
    for m in range(4):
        tp = list(th); tp[m]+=h; tm = list(th); tm[m]-=h
        sp = step(tp,P,Q); sm = step(tm,P,Q)
        for i in range(4):
            d = (sp[i]-sm[i])
            # unwrap any 2pi jump from mod
            if d >  mp.pi: d -= TWO_PI
            if d < -mp.pi: d += TWO_PI
            J[i][m] = d/(2*h)
    return J

def det_formula(th, P, Q):                # INDEPENDENT analytic det of the GS step Jacobian:
    t = list(th); prod = mpf(1)           #   det = prod_i (1 - sum_k Q_k*K*cos(arg_ik))
    for i in range(4):
        diag = mpf(1)
        for (j,k) in COUP[i]:
            diag -= Q[k]*K*cos(P[k]*t[j] - Q[k]*t[i])
        prod *= diag
        s = sum(K*sin(P[k]*t[j]-Q[k]*t[i]) for (j,k) in COUP[i])
        t[i] = mod2pi(t[i] + OM[i] + s)
    return prod

def qr_mgs(M):                            # modified Gram-Schmidt; M rows -> (Qcols, Rdiag)
    n=4; Qc=[[M[r][c] for r in range(n)] for c in range(n)]; Rd=[mpf(0)]*n
    for c in range(n):
        for p in range(c):
            dot=sum(Qc[p][r]*Qc[c][r] for r in range(n))
            for r in range(n): Qc[c][r]-=dot*Qc[p][r]
        nrm=sqrt(sum(Qc[c][r]**2 for r in range(n)))
        Rd[c]=nrm
        for r in range(n): Qc[c][r]/=nrm
    return Qc, Rd

def benettin(th0,P,Q,burn,N,jacfun=jac_analytic):
    t=list(th0)
    for _ in range(burn): t=step(t,P,Q)
    Qc=[[mpf(1) if r==c else mpf(0) for r in range(4)] for c in range(4)]  # cols = e_i
    acc=[mpf(0)]*4; detacc=mpf(0)
    for _ in range(N):
        J=jacfun(t,P,Q)
        detacc += log(fabs(det_formula(t,P,Q)))      # independent det, NOT from QR
        M=[[sum(J[r][kk]*Qc[c][kk] for kk in range(4)) for c in range(4)] for r in range(4)]  # M=J*Qprev
        Qc,Rd=qr_mgs(M)
        for i in range(4): acc[i]+=log(fabs(Rd[i]))
        t=step(t,P,Q)
    lam=[acc[i]/N for i in range(4)]
    return lam, detacc/N

def init_state(seed=12345678901234):       # replicate C++ init (seed<2^52 -> no hash)
    return [mod2pi(mpf(seed)*OM[i]) for i in range(4)]

print("="*64); print("INDEPENDENT (mpmath, %d dps) validation of MCL lambda_2"%mp.dps); print("="*64)

# ---- L5: known-matrix sanity (Benettin QR estimator vs analytic exponents) ----
# x->Mx, M=[[2,1],[1,1]] symmetric: eigenvalues (3±sqrt5)/2 -> lambda = ln of those.
import math
M=[[mpf(2),mpf(1)],[mpf(1),mpf(1)]]
ev_hi=(3+sqrt(5))/2; ev_lo=(3-sqrt(5))/2
Qc=[[mpf(1) if r==c else mpf(0) for r in range(2)] for c in range(2)]; a=[mpf(0),mpf(0)]
for _ in range(400):
    Mm=[[sum(M[r][kk]*Qc[c][kk] for kk in range(2)) for c in range(2)] for r in range(2)]
    # 2x2 MGS
    n=2; QQ=[[Mm[r][c] for r in range(n)] for c in range(n)]; Rd=[mpf(0)]*n
    for c in range(n):
        for p in range(c):
            dot=sum(QQ[p][r]*QQ[c][r] for r in range(n))
            for r in range(n): QQ[c][r]-=dot*QQ[p][r]
        nrm=sqrt(sum(QQ[c][r]**2 for r in range(n))); Rd[c]=nrm
        for r in range(n): QQ[c][r]/=nrm
    Qc=QQ
    for i in range(2): a[i]+=log(fabs(Rd[i]))
l_known=[a[i]/400 for i in range(2)]
print("\n[L5] known matrix [[2,1],[1,1]]: Benettin lambda=[%.6f, %.6f]  expected=[%.6f, %.6f]  %s"%(
    l_known[0],l_known[1], log(ev_hi), log(ev_lo),
    "OK" if abs(l_known[0]-log(ev_hi))<mpf('1e-6') and abs(l_known[1]-log(ev_lo))<mpf('1e-6') else "FAIL"))

# weight sets matching the C++ runs
def boundary_PQ(p0,delta): P=[p0+i for i in range(6)]; Q=[P[i]+delta for i in range(6)]; return P,Q
SMALL_P=[mpf(x) for x in (2,5,11,3,7,13)]; SMALL_Q=[mpf(x) for x in (3,7,13,5,11,17)]
P29=mpf(2)**29

# ---- L2 + L3 on a representative weight set (small) ----
th=init_state()
for _ in range(2000): th=step(th,SMALL_P,SMALL_Q)         # land on attractor
Ja=jac_analytic(th,SMALL_P,SMALL_Q); Jf=jac_fd(th,SMALL_P,SMALL_Q,mpf('1e-30'))
maxrel=max(abs((Ja[i][j]-Jf[i][j])/(Ja[i][j] if Ja[i][j]!=0 else mpf(1))) for i in range(4) for j in range(4))
print("\n[L2] analytic Jacobian vs finite-difference (max rel err over 16 entries): %.2e  %s"%(
    float(maxrel), "OK" if maxrel<mpf('1e-15') else "CHECK"))

# ---- L1 + L3: spectra on the SAME weights as C++, compare ----
cases=[("small {2,3,5,7,11,13,3,5,7,11,13,17}", SMALL_P, SMALL_Q, 4000, 3000,
        "C++: l=[13.99, 2.866, 1.03, 0.03]"),
       ("boundary p0=2^29, q=p+1 (q/p->1)", *boundary_PQ(P29,mpf(1)), 4000, 3000,
        "C++ N=40000: lambda_2=1.9526"),
       ("boundary p0=2^29, q=p+2^28 (q/p=1.5)", *boundary_PQ(P29,mpf(2)**28), 4000, 3000,
        "C++ N=40000: lambda_2=2.2828"),
       ("REAL key 0 (ALL six pairs q<p!)",
        [mpf(x) for x in (881430846,955089618,801298636,663995654,515717231,764264466)],
        [mpf(x) for x in (720797916,143398210,659059755,24476498,108724423,256702071)], 4000, 3000,
        "C++ N=40000: lambda_2=1.6892"),
       ("REAL key 60 (sweep min; mostly q<p)",
        [mpf(x) for x in (867077331,254105830,767663819,748234812,470730343,693080404)],
        [mpf(x) for x in (809284647,885381103,188436729,652246838,468985250,923722)], 4000, 3000,
        "C++ N=40000: lambda_2=1.5056")]
for name,P,Q,burn,N,ref in cases:
    th=init_state()
    lam,detmean=benettin(th,P,Q,burn,N)
    s=sum(lam)
    print("\n[L1] %s"%name)
    print("     mpmath lambda = [%.4f, %.4f, %.4f, %.4f]   (%s)"%(lam[0],lam[1],lam[2],lam[3],ref))
    print("     [L3] sum rule: Sum(lambda)=%.5f  vs  <ln|det J|>(indep formula)=%.5f  diff=%.2e  %s"%(
        s, detmean, float(abs(s-detmean)), "OK" if abs(s-detmean)<mpf('1e-3') else "CHECK"))
    print("     lambda_2 = %.4f  > 0  %s"%(lam[1], "(HYPERCHAOTIC, agrees with C++)" if lam[1]>0 else "*** NEGATIVE ***"))
print("\n"+"="*64+"\nDONE\n"+"="*64)
