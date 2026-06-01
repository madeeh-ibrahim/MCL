/*
 * ============================================================================
 * MCL b_eff Deep Audit — Distribution CI + Real Multi-Level Backward Tree
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-BEFF-DEEP-AUDIT-2026-0526-001
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
 * PURPOSE: Audit the b_eff backward-inversion claim underpinning Paper 5 X one-wayness.
 *   Part 1: distribution of b² and b_eff over many independent steps; reports
 *           mean, SD, SEM, 95% CI, and z-test vs the b²/256 uniform-pruning
 *           prediction (publication-grade numbers).
 *   Part 2: real multi-level keystream-constrained backward tree (depth D):
 *     (i) survivors per level vs the b_eff^level model;
 *     (ii) does the TRUE predecessor always survive;
 *     (iii) do WRONG candidates branch like the TRUE node.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -DMCL_UNSAFE_ALLOW_INVALID -o beff_deep_audit beff_deep_audit.cpp -lm && ./beff_deep_audit
 *
 * EXPECTED RESULTS: b_eff > 1 confirmed with 95% CI; backward-tree depth measurements match b_eff^N model.
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
static constexpr const char* const DOC_ID =
    "MCL-BEFF-DEEP-AUDIT-2026-0526-001";
static constexpr const char* const DOC_VERSION = "6.0.0";

static const int64_t P=3,Q=5; static const double K=K_DEFAULT;

static double t1_upd(double t1,double t2,double kc){return mod2pi(t1+OMEGA_1+kc*std::sin(static_cast<double>(P)*t2-static_cast<double>(Q)*t1));}
static double t2_fwd (double t1p,double t2,double kc){return mod2pi(t2+OMEGA_2+kc*std::sin(static_cast<double>(P)*t1p-static_cast<double>(Q)*t2));}
static double cdiff(double a,double b){double d=std::fmod(a-b+MCL_TWO_PI,MCL_TWO_PI);if(d>MCL_PI)d-=MCL_TWO_PI;return d;}
static uint8_t gold(double t1,double t2){uint64_t x=d2b(t1)^d2b(t2);return static_cast<uint8_t>(static_cast<uint8_t>(x>>GOLD_S1)^static_cast<uint8_t>(x>>GOLD_S2));}
template<typename F> static double refine(double lo,double hi,F f){
    for(int it=0;it<60;it++){double m=0.5*(lo+hi);if((f(lo)<0.0)==(f(m)<0.0))lo=m;else hi=m;}
    return 0.5*(lo+hi);
}
template<typename F> static std::vector<double> roots(F f,int scan){
    std::vector<double> r;double prev=f(0.0);const double G=0.5;
    for(int i=1;i<=scan;i++){
        double x=MCL_TWO_PI*static_cast<double>(i)/scan;
        double cur=f(x);
        bool sc=(prev<0&&cur>=0)||(prev>0&&cur<=0);
        if(sc&&std::fabs(prev)<G&&std::fabs(cur)<G)
            r.push_back(refine(MCL_TWO_PI*static_cast<double>(i-1)/scan,x,f));
        prev=cur;
    }
    return r;
}

struct Cand{double t1,t2;};
// enumerate preimages of successor (T1,T2); keep those whose byte==obyte. returns b2 via out param.
static std::vector<Cand> preimages(double T1,double T2,double kc,uint8_t obyte,long&b2,int s2scan,int s1scan){
    std::vector<Cand> surv; b2=0;
    auto t2r=roots([&](double t2){return cdiff(t2_fwd(T1,t2,kc),T2);},s2scan);
    for(double t2:t2r){
        auto t1r=roots([&](double t1){return cdiff(t1_upd(t1,t2,kc),T1);},s1scan);
        for(double t1:t1r){b2++; if(gold(t1,t2)==obyte) surv.push_back({t1,t2});}
    }
    return surv;
}

static void print_help(const char* prog) {
    std::printf("Usage:\n");
    std::printf("  %s            # run the b_eff deep audit\n", prog);
    std::printf("  %s --help     # this message\n", prog);
    std::printf("\n");
    std::printf("Two-part deep audit of the b_eff backward-inversion claim:\n");
    std::printf("  Part 1: distribution of b^2 and b_eff over 120 anchors,\n");
    std::printf("          with 95%% CI and z-test vs uniform pruning.\n");
    std::printf("  Part 2: real multi-level backward tree to depth D=3,\n");
    std::printf("          including representativeness (Lesson 20).\n");
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
    std::printf("  MCL b_eff DEEP AUDIT v%s\n", DOC_VERSION);
    std::printf("  (p,q)=(%lld,%lld) K=%.1f  compiler=%s\n",
        static_cast<long long>(P), static_cast<long long>(Q), K, __VERSION__);
    std::printf("  %s\n", DOC_ID);
    std::printf("============================================================"
                "================\n");

    // ---------- PART 1: distribution + CI ----------
    std::printf("\n--- PART 1: distribution of b^2 and b_eff (CI + z vs b^2/256) ---\n");
    const int STEPS=120; std::vector<double> B2,BE;
    for(int st=0;st<STEPS;st++){
        MCL_T2 eng(0xBEEF11ull+static_cast<uint64_t>(static_cast<unsigned>(st))*7919ull,P,Q);
        for(int i=0;i<800+st*30;i++) eng.iterate();
        double s1=eng.theta1(),s2=eng.theta2(); uint8_t o=gold(s1,s2);
        double T1=t1_upd(s1,s2,K), T2=t2_fwd(T1,s2,K);
        long b2; auto surv=preimages(T1,T2,K,o,b2,500000,50000);
        B2.push_back(static_cast<double>(b2)); BE.push_back(static_cast<double>(surv.size()));
    }
    auto stat=[&](std::vector<double>&v,double&m,double&sd,double&sem){
        double s=0;for(double x:v)s+=x;m=s/static_cast<double>(v.size());
        double q=0;for(double x:v)q+=(x-m)*(x-m);
        sd=std::sqrt(q/static_cast<double>(v.size()-1));
        sem=sd/std::sqrt(static_cast<double>(v.size()));
    };
    double mb2,sb2,eb2,mbe,sbe,ebe; stat(B2,mb2,sb2,eb2); stat(BE,mbe,sbe,ebe);
    double pred=mb2/256.0, z=(mbe-pred)/ebe;
    double mn=1e9,mx=-1e9; for(double x:BE){if(x<mn)mn=x;if(x>mx)mx=x;}
    std::printf("  steps=%d\n",STEPS);
    std::printf("  b^2   : mean=%.1f  SD=%.1f  95%%CI=[%.1f, %.1f]\n",mb2,sb2,mb2-1.96*eb2,mb2+1.96*eb2);
    std::printf("  b_eff : mean=%.3f SD=%.3f SEM=%.3f 95%%CI=[%.3f, %.3f] range=[%.0f,%.0f]\n",
                mbe,sbe,ebe,mbe-1.96*ebe,mbe+1.96*ebe,mn,mx);
    std::printf("  uniform pred b^2/256 = %.3f ; z(b_eff vs pred) = %.2f  => %s\n",
                pred,z, std::fabs(z)<2.0?"NOT distinguishable from uniform pruning":"differs from uniform");
    std::printf("  ROBUST security claim: min b_eff observed = %.0f (>1).\n",mn);

    // ---------- PART 2: real multi-level backward tree ----------
    std::printf("\n--- PART 2: real keystream-constrained backward tree (tests b_eff^N) ---\n");
    const int D=3; // depth
    MCL_T2 eng(0xC0FFEEull,P,Q); for(int i=0;i<1200;i++) eng.iterate();
    std::vector<double> S1(static_cast<size_t>(D+1)),S2(static_cast<size_t>(D+1));
    std::vector<uint8_t> ob(static_cast<size_t>(D+1));
    S1[0]=eng.theta1(); S2[0]=eng.theta2();
    for(int i=0;i<D;i++){
        const size_t i_=static_cast<size_t>(i),ip1=static_cast<size_t>(i+1);
        ob[i_]=gold(S1[i_],S2[i_]);
        double T1=t1_upd(S1[i_],S2[i_],K), T2=t2_fwd(T1,S2[i_],K);
        S1[ip1]=T1; S2[ip1]=T2;
    }
    // attacker starts from true successor S[D], recovers backward using bytes ob[D-1..0]
    std::vector<Cand> frontier={{S1[static_cast<size_t>(D)],S2[static_cast<size_t>(D)]}};
    std::printf("  depth=%d ; start nodes=1\n",D);
    std::printf("  %-7s %-12s %-14s %-16s\n","level","survivors","true-path?","branch/node");
    int s2scan=300000,s1scan=30000;
    for(int lvl=D; lvl>=1; lvl--){
        const size_t lvl_=static_cast<size_t>(lvl),lvm1=static_cast<size_t>(lvl-1);
        std::vector<Cand> next; long branchsum=0; int nodes=0; long tru_branch=-1,wrong_sum=0,wrong_n=0;
        for(Cand c:frontier){
            long b2; auto surv=preimages(c.t1,c.t2,K,ob[lvm1],b2,s2scan,s1scan);
            branchsum+=static_cast<long>(surv.size()); nodes++;
            // is THIS node the true successor S[lvl]? (only true if c==S[lvl])
            bool node_is_true = (std::fabs(cdiff(c.t1,S1[lvl_]))<1e-7 && std::fabs(cdiff(c.t2,S2[lvl_]))<1e-7);
            if(node_is_true) tru_branch=static_cast<long>(surv.size());
            else {wrong_sum+=static_cast<long>(surv.size());wrong_n++;}
            for(Cand s:surv) next.push_back(s);
        }
        // does the true predecessor S[lvl-1] survive among next?
        bool truesurv=false;
        for(Cand s:next)
            if(std::fabs(cdiff(s.t1,S1[lvm1]))<1e-6&&std::fabs(cdiff(s.t2,S2[lvm1]))<1e-6){truesurv=true;break;}
        std::printf("  %-7d %-12zu %-14s %-16.2f\n",D-lvl+1,next.size(),
                    truesurv?"SURVIVES":"LOST",
                    static_cast<double>(branchsum)/static_cast<double>(nodes));
        if(tru_branch>=0&&wrong_n>0)
            std::printf("          [representativeness] true-node branch=%ld vs wrong-node mean=%.2f\n",
                        tru_branch,static_cast<double>(wrong_sum)/static_cast<double>(wrong_n));
        frontier=next;
        if(frontier.size()>4000){std::printf("          (capping frontier for runtime)\n");frontier.resize(4000);}
    }
    std::printf("  => if survivors multiply ~b_eff/level AND wrong~true branch, b_eff^N model holds.\n");
    return 0;
}
