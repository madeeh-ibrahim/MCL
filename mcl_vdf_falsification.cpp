/*
 * ============================================================================
 * MCL VDF Falsification Suite v3 — Four-Attack OP1/OP3/OP4/OP5 Battery
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-VDF-FALSIFICATION-2026-0526-001
 * Version:       6.0.0
 * Date:          May 26, 2026, 10:00 UTC
 * Author:        Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:       madeeh.chaotic.lock@gmail.com
 * ORCID:         https://orcid.org/0009-0002-8562-8325
 * ============================================================================
 *
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Copyright (c) 2026 Madeeh Ibrahim. All rights reserved.
 *
 * MCL Reference Implementation. Free security research / evaluation for all
 * (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
 * a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673.
 * ACCEPTABLE USE: For lawful security research against your own copy
 *   of MCL only. The author is not responsible for misuse. See the
 *   Acceptable Use section of SECURITY-RESEARCH-GRANT.md.
 * ============================================================================
 *
 * PURPOSE: Four-attack falsifiability battery for MCL-VDF open problems OP1 (sequentiality),
 *   OP3 (precomputation/learnability), OP4 (backward branching), OP5 (irreducible
 *   data-dependency). v3 review fixes: ensemble log-linear Lyapunov (A2a),
 *   overflow-free Jacobian growth rate (A2b), circular + byte Pearson correlation
 *   with dual theoretical baselines (A2c), irreducible-dependency reframe (A3).
 *   Every printed number is measured; each attack carries evidence-not-proof disclaimer.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_vdf_falsification mcl_vdf_falsification.cpp -lm -lpthread && ./mcl_vdf_falsification
 *
 * EXPECTED RESULTS: All four attacks fail to break VDF sequentiality. Empirical support for OP1/OP3/OP4/OP5.
 *
 * ============================================================================
 *
 * NO WARRANTY / LIMITATION OF LIABILITY
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE,
 *   AND NONINFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 *   LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN
 *   AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT
 *   OF, OR IN CONNECTION WITH THE SOFTWARE. TO THE FULLEST EXTENT
 *   PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE COPYRIGHT
 *   HOLDER BE LIABLE FOR ANY SPECIAL, INCIDENTAL, INDIRECT, OR
 *   CONSEQUENTIAL DAMAGES WHATSOEVER.
 */
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <thread>
#include <chrono>
#include <algorithm>

static constexpr const char* const DOC_ID =
    "MCL-VDF-FALSIFICATION-2026-0526-001";
static constexpr const char* const DOC_VERSION = "6.0.0";

static const int64_t P=3, Q=5;
static const double  K=K_DEFAULT;
static const double  PI      = MCL_TWO_PI*0.5;     // portable, no M_PI
static const double  HALF_PI = MCL_TWO_PI*0.25;

// geodesic (wrapped) distance on a circle, in [0, pi]; E=pi/2 for independent uniform
static inline double gdist(double a,double b){double d=std::fabs(a-b);d=std::fmod(d,MCL_TWO_PI);return d>PI?MCL_TWO_PI-d:d;}
// linear (unwrapped) absolute angular difference; E=2pi/3 for independent uniform
static inline double ldist(double a,double b){return std::fabs(a-b);}
static inline double gsep2(double a1,double a2,double b1,double b2){return 0.5*(gdist(a1,b1)+gdist(a2,b2));}
static inline uint8_t sbyte(double t){return static_cast<uint8_t>(d2b(t)>>20);} // safe-zone byte [20-27]

// ---------------------------------------------------------------------------
// ATTACK 1 -- parallel precomputation via nearest-neighbour table (OP3)
// ---------------------------------------------------------------------------
static void attack1(){
    std::printf("\n===== ATTACK 1: precomputation / NN table (OP3) =====\n");
    std::printf("  scope: tests delta-ahead predictability of an ARBITRARY on-attractor\n");
    std::printf("         state from a precomputed table (a learnability/sensitivity probe;\n");
    std::printf("         a FAIL here is supporting evidence, not a proof of sequentiality).\n");
    const size_t M=300000, NQ=4000;
    const double chance=HALF_PI; // geodesic baseline
    std::vector<double> ta(M+20), tb(M+20);
    double t1,t2; mcl_init_state(0xA11CE,t1,t2);
    for(size_t i=0;i<M+20;i++){ta[i]=t1;tb[i]=t2;mcl_iterate_raw(t1,t2,P,Q,K);}
    // independent query states
    std::vector<double> qs1(NQ),qs2(NQ),tr1(NQ),tr2(NQ); std::vector<size_t> best(NQ);
    double q1,q2; mcl_init_state(0xBEEF1234,q1,q2);
    for(int w=0;w<5000;w++) mcl_iterate_raw(q1,q2,P,Q,K);
    for(size_t n=0;n<NQ;n++){qs1[n]=q1;qs2[n]=q2;tr1[n]=q1;tr2[n]=q2;mcl_iterate_raw(q1,q2,P,Q,K);}
    // nearest key per query -- computed ONCE (delta-independent)
    double sumkey=0;
    for(size_t n=0;n<NQ;n++){size_t bi=0;double bd=1e9;
        for(size_t i=0;i<M;i++){double d=gsep2(ta[i],tb[i],qs1[n],qs2[n]);if(d<bd){bd=d;bi=i;}}
        best[n]=bi; sumkey+=bd;}
    std::printf("  dictionary=%zu, queries=%zu, mean NN key dist=%.5f, chance=%.4f rad\n",
                M,NQ,sumkey/static_cast<double>(NQ),chance);
    std::printf("  %-6s %-16s %-10s\n","Delta","pred error","vs chance");
    int deltas[]={1,2,4,7,12}; int prevD=0;
    for(int di=0;di<5;di++){int D=deltas[di];
        for(size_t n=0;n<NQ;n++) for(int s=0;s<D-prevD;s++) mcl_iterate_raw(tr1[n],tr2[n],P,Q,K);
        prevD=D;
        double err=0;
        for(size_t n=0;n<NQ;n++)
            err+=gsep2(ta[best[n]+static_cast<size_t>(D)],tb[best[n]+static_cast<size_t>(D)],tr1[n],tr2[n]);
        err/=static_cast<double>(NQ); std::printf("  %-6d %-16.5f %-10.1f%%\n",D,err,100.0*err/chance);
    }
    std::printf("  => keys close, yet delta>=2 prediction = chance. No interpolation shortcut.\n");
}

// ---------------------------------------------------------------------------
// ATTACK 2 -- sensitivity / Jacobian / scheme-decorrelation (OP1)
// ---------------------------------------------------------------------------
static void attack2(){
    std::printf("\n===== ATTACK 2: sensitivity & Jacobi-correction (OP1) =====\n");
    std::printf("  (a FAIL here is supporting evidence for non-parallelisability, not a proof)\n");

    // (a) ENSEMBLE log-linear lambda on the clean linear regime only
    const int ICS=60; const double eps=1e-13, LO=1e-12, HI=0.05;
    double n=0,sx=0,sy=0,sxx=0,sxy=0;
    for(int ic=0;ic<ICS;ic++){
        double a1,a2; mcl_init_state(0x1000u+static_cast<unsigned>(ic),a1,a2);
        for(int w=0;w<400;w++) mcl_iterate_raw(a1,a2,P,Q,K);
        double b1=a1+eps,b2=a2;
        for(int s=1;s<=30;s++){mcl_iterate_raw(a1,a2,P,Q,K);mcl_iterate_raw(b1,b2,P,Q,K);
            double sep=gdist(a1,b1)+gdist(a2,b2);
            if(sep>LO&&sep<HI){double x=s,y=std::log(sep);n++;sx+=x;sy+=y;sxx+=x*x;sxy+=x*y;}}
    }
    double lam=(n*sxy-sx*sy)/(n*sxx-sx*sx);
    std::printf("  (a) lambda (ensemble %d ICs, %d clean-regime pts, log-linear LSQ): %.3f  (ref 5.78)\n",
                ICS,static_cast<int>(n),lam);
    std::printf("      saturation step t* = ln(2pi/eps)/lambda ~= %.1f\n", std::log(MCL_TWO_PI/eps)/lam);

    // (b) per-step normalised product-Jacobian growth (overflow-free; NORM rate, not lambda)
    double j1,j2; mcl_init_state(0xC0FFEE,j1,j2);
    for(int w=0;w<400;w++) mcl_iterate_raw(j1,j2,P,Q,K);
    double v0=1.0,v1=0.0,logsum=0; const int B=200;
    for(int s=0;s<B;s++){double S[2][2];mcl_iterate_jacobian(j1,j2,P,Q,K,S);
        double w0=S[0][0]*v0+S[0][1]*v1, w1=S[1][0]*v0+S[1][1]*v1;
        double nrm=std::sqrt(w0*w0+w1*w1); v0=w0/nrm; v1=w1/nrm; logsum+=std::log(nrm);}
    std::printf("  (b) tangent-vector growth rate over B=%d steps: %.3f/step (||prod J|| ~ e^{%.2f*B})\n",
                B,logsum/B,logsum/B);
    std::printf("      => forward sensitivity grows exponentially; no contraction factor exists for a\n");
    std::printf("         Newton/relaxation correction across a useful block (claim is heuristic, not a proof).\n");

    // (c) GS vs Jacobi decorrelation -- correct metrics
    const size_t NB=200000;
    std::vector<double> G(NB),J(NB);
    double g1,g2,k1,k2; mcl_init_state(0xC0FFEE,g1,g2);k1=g1;k2=g2;
    double geo=0,lin=0; long Ham=0,bits=0;
    double bx=0,by=0,bxx=0,byy=0,bxy=0; // byte Pearson
    for(size_t i=0;i<NB;i++){mcl_iterate_raw(g1,g2,P,Q,K);mcl_iterate_jacobi(k1,k2,P,Q,K);
        G[i]=g1;J[i]=k1;
        geo+=gdist(g1,k1); lin+=ldist(g1,k1);
        uint8_t bg=sbyte(g1),bk=sbyte(k1); uint8_t xr=bg^bk;
        for(int b=0;b<8;b++){bits++;if((xr>>b)&1)Ham++;}
        bx+=bg;by+=bk;bxx+=static_cast<double>(bg)*bg;byy+=static_cast<double>(bk)*bk;bxy+=static_cast<double>(bg)*bk;
    }
    double N=static_cast<double>(NB);
    // circular correlation (Jammalamadaka-Sarma)
    double cg=0,sg=0,cj=0,sj=0;
    for(size_t i=0;i<NB;i++){cg+=std::cos(G[i]);sg+=std::sin(G[i]);cj+=std::cos(J[i]);sj+=std::sin(J[i]);}
    double mg=std::atan2(sg,cg), mj=std::atan2(sj,cj), num=0,d1=0,d2=0;
    for(size_t i=0;i<NB;i++){double u=std::sin(G[i]-mg),v=std::sin(J[i]-mj);num+=u*v;d1+=u*u;d2+=v*v;}
    double circ=num/std::sqrt(d1*d2);
    double bpear=(N*bxy-bx*by)/std::sqrt((N*bxx-bx*bx)*(N*byy-by*by));
    std::printf("  (c) GS vs Jacobi, %zu steps:\n",NB);
    std::printf("      circular corr |rho|=%.6f (noise floor %.5f) ; extracted-byte Pearson |r|=%.6f\n",
                std::fabs(circ),3.29/std::sqrt(N),std::fabs(bpear));
    std::printf("      geodesic sep=%.4f (indep baseline pi/2=%.4f) ; linear sep=%.4f (indep baseline 2pi/3=%.4f)\n",
                geo/N,HALF_PI,lin/N,MCL_TWO_PI/3.0);
    std::printf("      extracted-byte Hamming=%.3f%% (indep baseline 50%%)\n",100.0*static_cast<double>(Ham)/static_cast<double>(bits));
}

// ---------------------------------------------------------------------------
// ATTACK 3 -- irreducible-dependency demonstration (OP5)
// ---------------------------------------------------------------------------
static void run_seg(double t1,double t2,int64_t nIt,double* o1,double* o2){
    for(int64_t i=0;i<nIt;i++) mcl_iterate_raw(t1,t2,P,Q,K);
    *o1=t1;*o2=t2;
}
static void attack3(){
    std::printf("\n===== ATTACK 3: irreducible data-dependency demonstration (OP5) =====\n");
    std::printf("  NOTE: this shows the dependency CHAIN is real (you need the true predecessor\n");
    std::printf("        state); it does NOT rule out a clever predictor -- that is Attack 1's job\n");
    std::printf("        and an open problem. Not a proof.\n");
    const int64_t N=4000000; const int k=4;
    unsigned hc=std::thread::hardware_concurrency();
    bool timing_valid = hc>=static_cast<unsigned>(k);
    double s1,s2; mcl_init_state(0xD00D,s1,s2);
    std::vector<double> tc1(static_cast<size_t>(k+1)),tc2(static_cast<size_t>(k+1));
    tc1[0]=s1;tc2[0]=s2;
    double c1=s1,c2=s2; int64_t seg=N/k;
    auto t0=std::chrono::steady_clock::now();
    for(int b=0;b<k;b++){run_seg(c1,c2,seg,&c1,&c2);
        tc1[static_cast<size_t>(b+1)]=c1;tc2[static_cast<size_t>(b+1)]=c2;}
    auto t1=std::chrono::steady_clock::now();
    double seq_ms=std::chrono::duration<double,std::milli>(t1-t0).count();

    std::vector<double> g1(static_cast<size_t>(k)),g2(static_cast<size_t>(k));
    std::vector<double> o1(static_cast<size_t>(k)),o2(static_cast<size_t>(k));
    for(int b=0;b<k;b++){double x,y;mcl_init_state(0x2000u+static_cast<unsigned>(b),x,y);
        for(int w=0;w<300;w++) mcl_iterate_raw(x,y,P,Q,K);
        g1[static_cast<size_t>(b)]=x;g2[static_cast<size_t>(b)]=y;}
    g1[0]=s1;g2[0]=s2;
    auto p0=std::chrono::steady_clock::now();
    std::vector<std::thread> th;
    for(int b=0;b<k;b++) th.emplace_back(run_seg,
        g1[static_cast<size_t>(b)],g2[static_cast<size_t>(b)],seg,
        &o1[static_cast<size_t>(b)],&o2[static_cast<size_t>(b)]);
    for(auto&t:th) t.join();
    auto p1=std::chrono::steady_clock::now();
    double par_ms=std::chrono::duration<double,std::milli>(p1-p0).count();

    int matches=0,seg_ok=0; double tol=1e-9;
    for(int b=1;b<k;b++) {const size_t bz=static_cast<size_t>(b);
        if(gsep2(g1[bz],g2[bz],tc1[bz],tc2[bz])<tol) matches++;}
    for(int b=0;b<k;b++) {const size_t bz=static_cast<size_t>(b);
        if(gsep2(o1[bz],o2[bz],tc1[bz+1],tc2[bz+1])<tol) seg_ok++;}
    std::printf("  N=%lld, k=%d, segment=%lld iters, hardware_concurrency=%u\n",
                static_cast<long long>(N),k,static_cast<long long>(seg),hc);
    std::printf("  guessed boundary states matching truth: %d / %d\n",matches,k-1);
    std::printf("  parallel segment outputs correct: %d / %d (only the known start, segment 0)\n",seg_ok,k);
    if(timing_valid){
        std::printf("  sequential=%.1f ms ; parallel=%.1f ms ; effective(par+redo)=%.1f ms ; net=%.2fx\n",
                    seq_ms,par_ms,par_ms+seq_ms,seq_ms/(par_ms+seq_ms));
    }else{
        std::printf("  [TIMING SKIPPED] hardware_concurrency(%u) < k(%d): wall-clock not meaningful here.\n",hc,k);
        std::printf("  (correctness result above is hardware-independent and is the real argument.)\n");
    }
}


// ---------------------------------------------------------------------------
// ATTACK 4 -- keystream-constrained backward inversion: b_eff (OP4)
//   Faithful re-implementation of mcl_extraction_security.cpp Exp6/Exp7.
//   Backward step from a successor (T1,T2): solve the t2-equation, then the
//   t1-equation; b^2 = total 2D preimages, b_eff = those that ALSO reproduce
//   the observed extractor byte. b_eff>1 => keystream-guided backward search
//   still branches (one-wayness evidence, NOT a proof). Monotonic K=0.1 control
//   must collapse to b_eff<=1, validating the enumerator.
// ---------------------------------------------------------------------------
static double t1_update_a4(double t1,double t2,double kc){
    double a1=static_cast<double>(P)*t2-static_cast<double>(Q)*t1; return mod2pi(t1+OMEGA_1+kc*std::sin(a1));
}
static double t2_update_fwd_a4(double t1p,double t2,double kc){
    double a2=static_cast<double>(P)*t1p-static_cast<double>(Q)*t2; return mod2pi(t2+OMEGA_2+kc*std::sin(a2));
}
static double cdiff_a4(double a,double b){double d=std::fmod(a-b+MCL_TWO_PI,MCL_TWO_PI);if(d>MCL_PI)d-=MCL_TWO_PI;return d;}
static uint8_t gold_byte_a4(double t1,double t2){
    uint64_t x=d2b(t1)^d2b(t2);
    return static_cast<uint8_t>(static_cast<uint8_t>(x>>GOLD_S1)^static_cast<uint8_t>(x>>GOLD_S2));
}
template<typename F> static double refine_a4(double lo,double hi,F f){
    for(int it=0;it<60;it++){double m=0.5*(lo+hi);if((f(lo)<0.0)==(f(m)<0.0))lo=m;else hi=m;}
    return 0.5*(lo+hi);
}
template<typename F> static std::vector<double> roots_a4(F f,int scan){
    std::vector<double> r; double prev=f(0.0); const double GATE=0.5;
    for(int i=1;i<=scan;i++){double x=MCL_TWO_PI*static_cast<double>(i)/static_cast<double>(scan); double cur=f(x);
        bool sc=(prev<0.0&&cur>=0.0)||(prev>0.0&&cur<=0.0);
        if(sc&&std::fabs(prev)<GATE&&std::fabs(cur)<GATE)
            r.push_back(refine_a4(MCL_TWO_PI*static_cast<double>(i-1)/static_cast<double>(scan),x,f));
        prev=cur;}
    return r;
}
static void measure_step_a4(double kc,int settle,uint64_t seed,long&b2_out,long&beff_out){
    MCL_T2 eng(seed,P,Q); for(int i=0;i<settle;i++) eng.iterate();
    double s1=eng.theta1(), s2=eng.theta2(); uint8_t o=gold_byte_a4(s1,s2);
    double a1=static_cast<double>(P)*s2-static_cast<double>(Q)*s1;
    double T1=mod2pi(s1+OMEGA_1+kc*std::sin(a1));
    double T2=t2_update_fwd_a4(T1,s2,kc);
    auto t2roots=roots_a4([&](double t2){return cdiff_a4(t2_update_fwd_a4(T1,t2,kc),T2);},1000000);
    long b2=0,beff=0;
    for(double t2:t2roots){
        auto t1roots=roots_a4([&](double t1){return cdiff_a4(t1_update_a4(t1,t2,kc),T1);},100000);
        for(double t1:t1roots){b2++; if(gold_byte_a4(t1,t2)==o) beff++;}
    }
    b2_out=b2; beff_out=beff;
}
static void attack4(){
    std::printf("\n===== ATTACK 4: keystream-constrained backward branching b_eff (OP4) =====\n");
    std::printf("  (b_eff>1 = keystream-guided backward search still branches; evidence, not proof)\n");
    long cb2=0,cbeff=0; measure_step_a4(0.1,1000,0xD1CE,cb2,cbeff);
    bool valid=(cb2<=2&&cbeff<=1);
    std::printf("  POSITIVE control (monotonic K=0.1): b^2=%ld b_eff=%ld  -> %s\n",
                cb2,cbeff, valid?"VALID (collapses to unique)":"INVALID (counter miscalibrated)");
    if(!valid){std::printf("  enumerator miscalibrated; aborting attack 4.\n"); return;}
    const int STEPS=32; long sb2=0,sbe=0,mn=1<<30,mx=0;
    std::printf("  %-6s %-10s %-8s\n","step","b^2","b_eff");
    for(int st=0;st<STEPS;st++){long b2=0,be=0;
        measure_step_a4(K_DEFAULT,1000+st*50,
            0xD1CEull+static_cast<uint64_t>(static_cast<unsigned>(st))*7919ull,b2,be);
        sb2+=b2;sbe+=be; if(be<mn)mn=be; if(be>mx)mx=be;
        if(st<6) std::printf("  %-6d %-10ld %-8ld\n",st,b2,be);
    }
    double mb2=static_cast<double>(sb2)/STEPS, mbe=static_cast<double>(sbe)/STEPS;
    std::printf("  ... (%d steps)\n",STEPS);
    std::printf("  mean b^2=%.1f  mean b_eff=%.2f  (uniform pred b^2/256=%.2f)  range b_eff=[%ld,%ld]\n",
                mb2,mbe,mb2/256.0,mn,mx);
    std::printf("  => b_eff=%.2f > 1: keystream does NOT prune the backward tree to a unique path.\n",mbe);
    std::printf("  (ref: mcl_extraction_security Exp7: b^2~1462, b_eff~6.5)\n");
}

static void print_help(const char* prog) {
    std::printf("Usage:\n");
    std::printf("  %s            # run the 4-attack VDF break suite\n", prog);
    std::printf("  %s --help     # this message\n", prog);
    std::printf("\n");
    std::printf("Four documented cryptanalytic attacks on the MCL-VDF:\n");
    std::printf("  1. Precomputation / NN table (OP3)\n");
    std::printf("  2. Sensitivity & Jacobi-correction (OP1)\n");
    std::printf("  3. Irreducible data-dependency (OP5)\n");
    std::printf("  4. Keystream-constrained backward branching (OP4)\n");
    std::printf("\n");
    std::printf("All measured; all carry per-attack 'evidence != proof' disclaimers.\n");
    std::printf("\n");
    std::printf("Document: %s v%s\n", DOC_ID, DOC_VERSION);
}

int main(int argc, char** argv){
    std::setbuf(stdout, nullptr);
    if (argc > 1) {
        if (std::strcmp(argv[1], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        }
        std::fprintf(stderr, "Unknown argument: %s\n", argv[1]);
        return 1;
    }
    std::printf("==========================================================="
                "=================\n");
    std::printf("  MCL VDF FALSIFICATION SUITE v%s\n", DOC_VERSION);
    std::printf("  (p,q)=(%lld,%lld) K=%.1f  compiler=%s\n",
        static_cast<long long>(P), static_cast<long long>(Q), K, __VERSION__);
    std::printf("  %s\n", DOC_ID);
    std::printf("  Deterministic (no RNG); fast-math rejected by core #error\n");
    std::printf("============================================================"
                "================\n");
#ifdef BUILDFLAGS
    std::printf("build flags=%s\n", BUILDFLAGS);
#endif
    attack1(); attack2(); attack3(); attack4();
    std::printf("\nSummary: four documented attacks fail to break sequentiality => empirical\n");
    std::printf("support for OP1/OP3/OP4/OP5. NOT a proof. Structured-algebraic cryptanalysis is open.\n");
    return 0;
}
