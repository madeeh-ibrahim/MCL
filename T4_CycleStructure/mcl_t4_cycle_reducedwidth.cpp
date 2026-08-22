// mcl_t4_cycle_reducedwidth.cpp — Doc ID MCL-T4-CYCLE-2026-0822-001
// ---------------------------------------------------------------------------
// Finite-precision (dynamical-degradation) study of the ACTUAL four-oscillator
// keyed Q30 engine (MCL_T4_Q30 / mcl_q30t4_iterate_raw) at REDUCED state width,
// in the manner of Li–Chen–Mou 2005 ("dynamical degradation of digital PWL
// chaotic maps") and C. Li 2019 ("state-mapping networks").  Closes the gap
// recorded in PCT_04_Defense_DynamicalDegradation_20260814.md L66: the T4
// rho = 2^63.33 figure was an EXTRAPOLATION from the random-mapping model —
// this tool measures the functional-graph statistics of the same map at
// widths w = 4..16 bits/angle (state = 4w bits), fits them to the
// random-mapping model, and extrapolates to w = 32 (128-bit state).
//
// ADDITIVE artifact: no engine file is modified.  The map is re-expressed
// here generically in WIDTH w, with TWO reduction semantics, both of which
// coincide EXACTLY with the production engine at w = 32 (self-test below):
//   R1 "truncated"  : full 32-bit engine arithmetic, then each angle is
//                     truncated to its top w bits after every iteration
//                     (a high-precision implementation with w-bit registers).
//   R2 "native"     : a native w-bit implementation (omega, K_phase, args all
//                     scaled to 2^w), i.e. what a w-bit datapath would do.
//
// PART A (exhaustive, w <= 6 by default; w = 7 with --allow-big, ~3.5 GB):
//   full state-mapping network: #components, #cycles, cycle lengths,
//   tail lengths, fixed points, in-degree distribution, largest-basin share.
//   Compared with random-mapping expectations (Flajolet–Odlyzko 1990):
//     E[#components] = (ln 2N + gamma)/2 ; E[lambda] = E[mu] = sqrt(pi N/8) ;
//     E[rho] = sqrt(pi N/2) ; E[#cyclic nodes] = sqrt(pi N/2) - 1/3 ;
//     P[in-degree 0] = e^-1 ; E[max cycle] = 0.78248 sqrt N ;
//     E[max tail] = 1.73746 sqrt N ; E[largest component] = 0.75782 N.
// PART B (sampled, w = 8..14 default, 16 max): Brent cycle detection from S
//   seeds per width and K weight sets: lambda, mu, rho = mu + lambda; number of
//   distinct terminal cycles; ratio rho / E[rho].  Budget-capped (16 sqrt N per
//   seed ~ 13x E[rho]); "no closure" is recorded, never silently dropped.
// PART C (fit): log2(mean lambda) and log2(mean rho) vs state bits -> slope &
//   intercept; predictions at 128-bit state compared LIKE WITH LIKE: the record's
//   2^63.33 is E[lambda] = sqrt(pi 2^128/8), so it is compared with the lambda fit.
// PART D (calibration, optional --mode calib|all): the 2-oscillator path
//   (mcl_q30_iterate_raw) at w = 32 has a MEASURED closure
//   lambda = 1,671,196,332 (Brent + Floyd, 4 seeds).  Re-measuring it here
//   validates the reduction harness against the engine of record at full
//   width, exactly where model and measurement were already compared.
//
// NOTHING is executed by building this file.  Run commands are in README.md.
// ---------------------------------------------------------------------------
#include "../mcl_core.hpp"
#include "../keyed_q30_PQ/mcl_keyed_q30.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <string>
#include <unordered_set>
#include <algorithm>
#include <chrono>
#include <type_traits>

using Clock = std::chrono::steady_clock;
static double now_s(){ static auto t0=Clock::now(); return std::chrono::duration<double>(Clock::now()-t0).count(); }

// ---------------------------------------------------------------------------
// Reduced-width T4 map.  w in [4,32].  State = four w-bit angles.
// ---------------------------------------------------------------------------
struct T4W {
    int w;                 // bits per angle
    uint32_t mask;         // (1<<w)-1  (all ones at w=32)
    MCL_Q30_Sextet wt;     // the twelve map-defining weights (key-derived)
    int64_t kp32;          // engine K_phase (32-bit scale)
    int64_t kpw;           // native K_phase at width w
    uint32_t om32[4];      // engine omegas
    uint32_t omw[4];       // native omegas at width w
    const MCL_Q30_Table* tab;

    void init(int width, const MCL_Q30_Sextet& weights, double K){
        w = width;
        mask = (w==32) ? 0xFFFFFFFFu : ((1u<<w)-1u);
        wt = weights;
        kp32 = mcl_q30_K_phase(K);
        kpw  = kp32 >> (32-w);                    // K*2^w/2pi (floor)
        om32[0]=mcl_q30_omega1(); om32[1]=mcl_q30_omega2();
        om32[2]=mcl_q30_omega3(); om32[3]=mcl_q30_omega4();
        for(int i=0;i<4;i++) omw[i] = om32[i] >> (32-w);
        tab = &mcl_q30_table();
    }
    // sin of a w-bit angle: index = top 16 bits of the angle expanded to 32 bits
    inline int32_t sinw(uint32_t a) const {
        uint32_t a32 = (w==32) ? a : (a << (32-w));
        return tab->sin_q30(a32);
    }
    // ---- R1: truncated (engine arithmetic, then truncate) ----
    inline void step_R1(uint32_t& t1,uint32_t& t2,uint32_t& t3,uint32_t& t4) const {
        uint32_t a=t1<<(32-w), b=t2<<(32-w), c=t3<<(32-w), d=t4<<(32-w);
        if (w==32){ a=t1;b=t2;c=t3;d=t4; }
        mcl_q30t4_iterate_raw(a,b,c,d,wt,kp32);   // the production map, verbatim
        if (w==32){ t1=a;t2=b;t3=c;t4=d; return; }
        t1=a>>(32-w); t2=b>>(32-w); t3=c>>(32-w); t4=d>>(32-w);
    }
    // ---- R2: native w-bit datapath ----
    inline uint32_t incw(uint32_t a) const {
        return (uint32_t)((uint64_t)((int64_t)kpw * (int64_t)sinw(a)) >> 30) & mask;
    }
    inline uint32_t argw(uint32_t p,uint32_t a,uint32_t q,uint32_t b) const {
        return (uint32_t)((uint64_t)p*a - (uint64_t)q*b) & mask;
    }
    inline void step_R2(uint32_t& t1,uint32_t& t2,uint32_t& t3,uint32_t& t4) const {
        const MCL_Q30_Sextet& s=wt;
        uint32_t a12=argw(s.p12,t2,s.q12,t1), a13=argw(s.p13,t3,s.q13,t1), a14=argw(s.p14,t4,s.q14,t1);
        t1 = (t1 + omw[0] + incw(a12) + incw(a13) + incw(a14)) & mask;
        uint32_t a21=argw(s.p12,t1,s.q12,t2), a23=argw(s.p23,t3,s.q23,t2), a24=argw(s.p24,t4,s.q24,t2);
        t2 = (t2 + omw[1] + incw(a21) + incw(a23) + incw(a24)) & mask;
        uint32_t a31=argw(s.p13,t1,s.q13,t3), a32=argw(s.p23,t2,s.q23,t3), a34=argw(s.p34,t4,s.q34,t3);
        t3 = (t3 + omw[2] + incw(a31) + incw(a32) + incw(a34)) & mask;
        uint32_t a41=argw(s.p14,t1,s.q14,t4), a42=argw(s.p24,t2,s.q24,t4), a43=argw(s.p34,t3,s.q34,t4);
        t4 = (t4 + omw[3] + incw(a41) + incw(a42) + incw(a43)) & mask;
    }
    inline void step(int mode, uint32_t& t1,uint32_t& t2,uint32_t& t3,uint32_t& t4) const {
        if (mode==1) step_R1(t1,t2,t3,t4); else step_R2(t1,t2,t3,t4);
    }
    // engine-faithful seed -> state (same formula as MCL_T4_Q30 ctor), truncated to w
    void seed_state(uint64_t seed, uint32_t& t1,uint32_t& t2,uint32_t& t3,uint32_t& t4) const {
        uint64_t s = hash_seed(seed);
        uint32_t f[4];
        for(int i=0;i<4;i++) f[i]=(uint32_t)((s*(uint64_t)om32[i]) & 0xFFFFFFFFULL);
        if (w==32){ t1=f[0];t2=f[1];t3=f[2];t4=f[3]; return; }
        t1=f[0]>>(32-w); t2=f[1]>>(32-w); t3=f[2]>>(32-w); t4=f[3]>>(32-w);
    }
    inline uint64_t pack(uint32_t t1,uint32_t t2,uint32_t t3,uint32_t t4) const {
        return ((uint64_t)t1<<(3*w)) | ((uint64_t)t2<<(2*w)) | ((uint64_t)t3<<w) | (uint64_t)t4;
    }
    inline void unpack(uint64_t x, uint32_t& t1,uint32_t& t2,uint32_t& t3,uint32_t& t4) const {
        t4=(uint32_t)(x & mask); x>>=w; t3=(uint32_t)(x & mask); x>>=w;
        t2=(uint32_t)(x & mask); x>>=w; t1=(uint32_t)(x & mask);
    }
};

// ---------------------------------------------------------------------------
// Reduced-width 2-oscillator map (calibration, PART D) — same two semantics.
// ---------------------------------------------------------------------------
struct T2W {
    int w; uint32_t mask; int64_t p,q; int64_t kp32,kpw; uint32_t om32[2],omw[2]; const MCL_Q30_Table* tab;
    void init(int width,int64_t P,int64_t Q,double K){
        w=width; mask=(w==32)?0xFFFFFFFFu:((1u<<w)-1u); p=P;q=Q;
        kp32=mcl_q30_K_phase(K); kpw=kp32>>(32-w);
        om32[0]=mcl_q30_omega1(); om32[1]=mcl_q30_omega2();
        omw[0]=om32[0]>>(32-w); omw[1]=om32[1]>>(32-w); tab=&mcl_q30_table();
    }
    inline int32_t sinw(uint32_t a) const { uint32_t a32=(w==32)?a:(a<<(32-w)); return tab->sin_q30(a32); }
    inline void step_R1(uint32_t& t1,uint32_t& t2) const {
        uint32_t a=(w==32)?t1:(t1<<(32-w)), b=(w==32)?t2:(t2<<(32-w));
        mcl_q30_iterate_raw(a,b,p,q,kp32);
        if (w==32){t1=a;t2=b;return;}
        t1=a>>(32-w); t2=b>>(32-w);
    }
    inline void step_R2(uint32_t& t1,uint32_t& t2) const {
        uint32_t a1=(uint32_t)((uint64_t)p*t2-(uint64_t)q*t1)&mask;
        t1=(t1+omw[0]+((uint32_t)((uint64_t)((int64_t)kpw*(int64_t)sinw(a1))>>30)&mask))&mask;
        uint32_t a2=(uint32_t)((uint64_t)p*t1-(uint64_t)q*t2)&mask;
        t2=(t2+omw[1]+((uint32_t)((uint64_t)((int64_t)kpw*(int64_t)sinw(a2))>>30)&mask))&mask;
    }
    inline void step(int mode,uint32_t& t1,uint32_t& t2) const { if(mode==1) step_R1(t1,t2); else step_R2(t1,t2); }
    void seed_state(uint64_t seed,uint32_t& t1,uint32_t& t2) const {
        uint32_t a,b; mcl_q30_init_state(seed,a,b);
        if(w==32){t1=a;t2=b;return;} t1=a>>(32-w); t2=b>>(32-w);
    }
};

// ---------------------------------------------------------------------------
// Random-mapping expectations (Flajolet & Odlyzko 1990) for N nodes
// ---------------------------------------------------------------------------
struct RMExpect { double rho, lambda, mu, cycles, cyclic_nodes, indeg0_frac, largest_comp_frac, max_cycle, max_tail; };
static RMExpect rm_expect(double N){
    // Flajolet & Odlyzko 1990 (random mapping on N nodes), as restated in
    // Cloutier & Holden, "Mapping the discrete logarithm", Thm 3:
    //   #components = (ln(2N)+gamma)/2 ; #cyclic nodes = sqrt(pi N/2) - 1/3 ;
    //   #terminal (in-degree 0) = N/e ; E[cycle] = E[tail] = sqrt(pi N/8) ;
    //   E[max cycle] ~ 0.78248 sqrt(N) ; E[max tail] ~ 1.73746 sqrt(N) ;
    //   largest component ~ 0.75782 N (FO90, OEIS A143297).
    RMExpect e;
    e.mu     = std::sqrt(M_PI*N/8.0);
    e.lambda = std::sqrt(M_PI*N/8.0);
    e.rho    = std::sqrt(M_PI*N/2.0);          // E[mu]+E[lambda]
    e.cycles = 0.5*(std::log(2.0*N) + 0.5772156649015329);
    e.cyclic_nodes = std::sqrt(M_PI*N/2.0) - 1.0/3.0;
    e.indeg0_frac = std::exp(-1.0);
    e.largest_comp_frac = 0.75782;   // OEIS A143297: 0.7578230112... (Flajolet–Odlyzko constant)
    e.max_cycle = 0.78248*std::sqrt(N);
    e.max_tail  = 1.73746*std::sqrt(N);
    return e;
}

// ---------------------------------------------------------------------------
// PART A — exhaustive functional graph
// ---------------------------------------------------------------------------
struct GraphStats {
    uint64_t N=0, components=0, cycles=0, cyclic_nodes=0, fixed_points=0;
    uint64_t min_cycle=0, max_cycle=0; double mean_cycle=0;
    uint64_t max_tail=0; double mean_tail=0;
    uint64_t indeg0=0, max_indeg=0, indeg_saturated=0; uint64_t largest_comp=0; uint64_t largest_cycle_nodes=0;
    double node_weighted_cycle=0;   // sum_x lambda(comp(x)) / N  == E[lambda] from a uniform start
    std::vector<uint64_t> cycle_lengths;
};

template<class MAP>
static GraphStats exhaustive_graph(const MAP& M, int mode, int w, int nvars){
    (void)nvars; // nvars is implied by MAP; kept for the printout
    const int sbits = (std::is_same<MAP,T4W>::value?4:2)*w;
    const uint64_t N = 1ULL<<sbits;
    GraphStats g; g.N=N;
    std::vector<uint32_t> next(N);
    // build successor table
    for(uint64_t x=0;x<N;x++){
        if constexpr (std::is_same<MAP,T4W>::value){ uint32_t a,b,c,d; M.unpack(x,a,b,c,d); M.step(mode,a,b,c,d); next[x]=(uint32_t)M.pack(a,b,c,d); }
        else { uint32_t a=(uint32_t)(x>>w)&((1u<<w)-1u), b=(uint32_t)x&((1u<<w)-1u); M.step(mode,a,b); next[x]=(uint32_t)(((uint64_t)a<<w)|b); }
    }
    // in-degree
    {
        std::vector<uint16_t> indeg(N,0);
        for(uint64_t x=0;x<N;x++){ uint16_t& c=indeg[next[x]]; if(c<65535) c++; }
        for(uint64_t x=0;x<N;x++){ if(indeg[x]==0) g.indeg0++; if(indeg[x]>g.max_indeg) g.max_indeg=indeg[x]; if(indeg[x]==65535) g.indeg_saturated++; }
    }
    // colour: 0 unvisited, 1 on stack, 2 done. comp[] = component id (uint32), tail[] = distance to cycle.
    std::vector<uint8_t> colour(N,0);
    std::vector<uint32_t> tail(N,0);
    std::vector<uint32_t> comp(N,0xFFFFFFFFu);
    std::vector<uint64_t> comp_size, comp_cycle;
    std::vector<uint64_t> path; path.reserve(1<<16);
    for(uint64_t s=0;s<N;s++){
        if(colour[s]) continue;
        path.clear();
        uint64_t x=s;
        while(colour[x]==0){ colour[x]=1; path.push_back(x); x=next[x]; }
        if(colour[x]==1){
            // new cycle: x is on the current path
            size_t k=0; while(path[k]!=x) k++;
            uint64_t L=path.size()-k;
            g.cycles++; g.cycle_lengths.push_back(L); g.cyclic_nodes+=L;
            if(L==1) g.fixed_points++;
            uint32_t cid=(uint32_t)comp_size.size(); comp_size.push_back(0); comp_cycle.push_back(L);
            for(size_t i=k;i<path.size();i++){ tail[path[i]]=0; comp[path[i]]=cid; }
            for(size_t i=k;i-- >0;){ tail[path[i]]=tail[path[i+1]]+1; comp[path[i]]=cid; }
            if(L>g.largest_cycle_nodes) g.largest_cycle_nodes=L;
        } else {
            // attached to an already-finished node x
            uint32_t cid=comp[x]; uint32_t d=tail[x];
            for(size_t i=path.size();i-- >0;){ d++; tail[path[i]]=d; comp[path[i]]=cid; }
        }
        for(uint64_t v: path) colour[v]=2;
        comp_size[comp[s]] += path.size();
    }
    g.components = comp_size.size();
    for(uint64_t c: comp_size) if(c>g.largest_comp) g.largest_comp=c;
    { double acc=0; for(size_t c=0;c<comp_size.size();c++) acc+=(double)comp_size[c]*(double)comp_cycle[c]; g.node_weighted_cycle=acc/(double)N; }
    double sumt=0; for(uint64_t x=0;x<N;x++){ sumt+=tail[x]; if(tail[x]>g.max_tail) g.max_tail=tail[x]; }
    g.mean_tail = sumt/(double)N;
    if(!g.cycle_lengths.empty()){
        g.min_cycle=*std::min_element(g.cycle_lengths.begin(),g.cycle_lengths.end());
        g.max_cycle=*std::max_element(g.cycle_lengths.begin(),g.cycle_lengths.end());
        double s=0; for(uint64_t L: g.cycle_lengths) s+=L; g.mean_cycle=s/g.cycle_lengths.size();
    }
    return g;
}

static void print_graph(const GraphStats& g, int w, int nvars, int mode, const char* tag){
    RMExpect e=rm_expect((double)g.N);
    std::printf("\n[PART A] %s  w=%d bits/angle  state=%d bits  N=2^%d  mode=%s\n", tag, w, nvars*w, nvars*w, mode==1?"R1-truncated":"R2-native");
    std::printf("  %-28s %14s %14s\n","statistic","measured","random-map E[]");
    std::printf("  %-28s %14llu %14.2f\n","components (=cycles)",(unsigned long long)g.components, e.cycles);
    std::printf("  %-28s %14llu %14.2f\n","cycles",(unsigned long long)g.cycles, e.cycles);
    std::printf("  %-28s %14llu %14.1f\n","cyclic nodes",(unsigned long long)g.cyclic_nodes, e.cyclic_nodes);
    std::printf("  %-28s %14llu %14s\n","fixed points",(unsigned long long)g.fixed_points,"~1");
    std::printf("  %-28s %14llu %14.1f\n","max cycle length",(unsigned long long)g.max_cycle, e.max_cycle);
    std::printf("  %-28s %14llu %14s\n","min cycle length",(unsigned long long)g.min_cycle,"-");
    std::printf("  %-28s %14.2f %14s\n","mean cycle len (per cycle)",g.mean_cycle,"-");
    std::printf("  %-28s %14.2f %14.2f\n","E[lambda] node-weighted",g.node_weighted_cycle, e.lambda);
    std::printf("  %-28s %14llu %14.1f\n","max tail",(unsigned long long)g.max_tail, e.max_tail);
    std::printf("  %-28s %14.2f %14.2f\n","mean tail (=rho-lambda)",g.mean_tail, e.mu);
    std::printf("  %-28s %14.5f %14.5f\n","in-degree-0 fraction",(double)g.indeg0/(double)g.N, e.indeg0_frac);
    std::printf("  %-28s %14llu %14s%s\n","max in-degree",(unsigned long long)g.max_indeg,"O(ln N/lnln N)", g.indeg_saturated?"  [SATURATED 65535 — value is a floor]":"");
    std::printf("  %-28s %14.5f %14.5f\n","largest component frac",(double)g.largest_comp/(double)g.N, e.largest_comp_frac);
    std::printf("  %-28s %14.5f %14.5f\n","largest cycle/cyclic (E-ratio)",(double)g.largest_cycle_nodes/(double)std::max<uint64_t>(1,g.cyclic_nodes), e.max_cycle/e.cyclic_nodes);
    // cycle-length histogram (top 8)
    std::vector<uint64_t> L=g.cycle_lengths; std::sort(L.rbegin(),L.rend());
    std::printf("  largest cycle lengths:");
    for(size_t i=0;i<L.size() && i<8;i++) std::printf(" %llu",(unsigned long long)L[i]);
    std::printf("\n");
}

// ---------------------------------------------------------------------------
// PART B — Brent sampling with budget; returns lambda, mu, closed flag, and a
// canonical cycle id (minimum packed state on the cycle) to count distinct cycles
// ---------------------------------------------------------------------------
struct BrentResult { bool closed; uint64_t lambda, mu, steps; uint64_t cycle_id; };

template<class STEP, class PACK>
static BrentResult brent_generic(STEP step, PACK pack, uint64_t budget){
    // step(x) advances the packed state in place; pack returns the packed state
    BrentResult r{false,0,0,0,0};
    uint64_t tort = pack(), hare;
    uint64_t power=1, lam=0, steps=0;
    step(); hare=pack(); lam=1; steps=1;
    while(steps<=budget){
        if(tort==hare){ r.closed=true; break; }
        if(lam==power){ power<<=1; lam=0; tort=hare; }
        step(); hare=pack(); lam++; steps++;
    }
    if(!r.closed){ r.steps=steps; return r; }
    r.lambda=lam; r.steps=steps;
    return r;
}

struct SampleRow { int w; int sbits; uint64_t seeds, closed; double mean_rho, mean_lambda, mean_mu, min_rho, max_rho; uint64_t distinct_cycles; double expect_rho; uint64_t dc_min=UINT64_MAX, dc_max=0; };

static uint64_t default_seeds(int sbits){
    if(sbits<=40) return 64; if(sbits<=52) return 32; if(sbits<=56) return 16; return 4;
}

static SampleRow sample_T4(const T4W& M, int mode, uint64_t seeds, uint64_t budget_mult, uint64_t key_index){
    const int sbits=4*M.w; const double N=std::ldexp(1.0,sbits);
    SampleRow row{M.w,sbits,seeds,0,0,0,0,1e300,0,0,rm_expect(N).rho};
    std::unordered_set<uint64_t> cyc_ids;
    double srho=0,slam=0,smu=0;
    for(uint64_t s=0;s<seeds;s++){
        uint32_t t1,t2,t3,t4;
        // seed = DEFAULT_SEED-derived, distinct per (key, seed index)
        M.seed_state(DEFAULT_SEED ^ (key_index*0x9E3779B97F4A7C15ULL) ^ (s*0xD1B54A32D192ED03ULL), t1,t2,t3,t4);
        uint32_t s1=t1,s2=t2,s3=t3,s4=t4;
        uint64_t budget = (uint64_t)(budget_mult*std::sqrt(N)) + 1000;
        auto step=[&](){ M.step(mode,t1,t2,t3,t4); };
        auto pack=[&](){ return M.pack(t1,t2,t3,t4); };
        BrentResult br=brent_generic(step,pack,budget);
        if(!br.closed) continue;
        // mu: tortoise from start, hare = start advanced lambda
        uint32_t a1=s1,a2=s2,a3=s3,a4=s4, b1=s1,b2=s2,b3=s3,b4=s4;
        for(uint64_t i=0;i<br.lambda;i++) M.step(mode,b1,b2,b3,b4);
        uint64_t mu=0;
        while(!(a1==b1&&a2==b2&&a3==b3&&a4==b4)){ M.step(mode,a1,a2,a3,a4); M.step(mode,b1,b2,b3,b4); mu++; }
        // canonical cycle id = min packed state over the cycle
        uint64_t cid=M.pack(a1,a2,a3,a4); uint32_t c1=a1,c2=a2,c3=a3,c4=a4;
        for(uint64_t i=0;i<br.lambda;i++){ M.step(mode,c1,c2,c3,c4); uint64_t v=M.pack(c1,c2,c3,c4); if(v<cid) cid=v; }
        cyc_ids.insert(cid);
        double rho=(double)mu+(double)br.lambda;
        row.closed++; srho+=rho; slam+=br.lambda; smu+=mu;
        if(rho<row.min_rho) row.min_rho=rho; if(rho>row.max_rho) row.max_rho=rho;
    }
    if(row.closed){ row.mean_rho=srho/row.closed; row.mean_lambda=slam/row.closed; row.mean_mu=smu/row.closed; }
    row.distinct_cycles=cyc_ids.size();
    return row;
}

static void print_row_header(){
    std::printf("  %-3s %-5s %-6s %-7s %-14s %-14s %-14s %-12s %-10s %-14s %-8s\n","w","state","seeds(tot)","closed","mean rho","mean lambda","mean mu","min/max rho","termcyc/key","E[rho]=sqrt(piN/2)","ratio");
    std::printf("  (termcyc/key = min..max number of DISTINCT terminal cycles reached by the seeds of ONE weight set; giant component => small numbers are EXPECTED)\n");
}
static void print_row(const SampleRow& r){
    std::printf("  %-3d %-5d %-6llu %-7llu %-14.1f %-14.1f %-14.1f %.0f/%.0f %3llu..%-5llu %-14.1f %-8.3f\n",
        r.w,r.sbits,(unsigned long long)r.seeds,(unsigned long long)r.closed,r.mean_rho,r.mean_lambda,r.mean_mu,
        r.closed?r.min_rho:0.0,r.closed?r.max_rho:0.0,(unsigned long long)(r.dc_min==UINT64_MAX?0:r.dc_min),(unsigned long long)r.dc_max,r.expect_rho,r.closed?r.mean_rho/r.expect_rho:0.0);
    if(r.closed<r.seeds) std::printf("      WARNING: %llu of %llu seeds did NOT close within budget — means above are over closed seeds only (biased LOW); raise --budget-mult\n",(unsigned long long)(r.seeds-r.closed),(unsigned long long)r.seeds);
}

// ---------------------------------------------------------------------------
// PART C — fit log2(rho) = a + b*log2(N) (least squares over closed rows)
// ---------------------------------------------------------------------------
static void fit_line(const std::vector<double>& xs,const std::vector<double>& ys,double& a,double& b){
    double sx=0,sy=0,sxx=0,sxy=0; const int n=(int)xs.size();
    for(int i=0;i<n;i++){ sx+=xs[i]; sy+=ys[i]; sxx+=xs[i]*xs[i]; sxy+=xs[i]*ys[i]; }
    b=(n*sxy-sx*sy)/(n*sxx-sx*sx); a=(sy-b*sx)/n;
}
static void fit_and_extrapolate(const std::vector<SampleRow>& rows, const char* tag){
    std::vector<double> x, yl, yr;
    for(const auto& r: rows){ if(!r.closed) continue; x.push_back(r.sbits); yl.push_back(std::log2(r.mean_lambda)); yr.push_back(std::log2(r.mean_rho)); }
    if(x.size()<2){ std::printf("[PART C] %s: fewer than 2 closed widths — no fit.\n",tag); return; }
    double al,bl,ar,br; fit_line(x,yl,al,bl); fit_line(x,yr,ar,br);
    std::printf("\n[PART C] %s least-squares fits over %zu widths (random-mapping slope = 0.5 for both):\n",tag,x.size());
    std::printf("  log2(mean lambda) = %.4f + %.5f * state_bits    [model intercept log2 sqrt(pi/8) = %.4f]\n",al,bl,0.5*std::log2(M_PI/8.0));
    std::printf("  log2(mean rho)    = %.4f + %.5f * state_bits    [model intercept log2 sqrt(pi/2) = %.4f]\n",ar,br,0.5*std::log2(M_PI/2.0));
    std::printf("  128-bit state (T4 w=32): predicted lambda 2^%.2f (record extrapolation 2^63.33 = sqrt(pi 2^128/8)), predicted rho 2^%.2f (model 2^%.2f)\n",
        al+bl*128.0, ar+br*128.0, 64.0+0.5*std::log2(M_PI/2.0));
    std::printf("   cross-map sanity check (NOT a control — different map): T4 fit at 64 state bits gives lambda 2^%.2f; 2-osc w=32 MEASURED 1,671,196,332 = 2^30.64 (model E[lambda] 2^31.33)\n", al+bl*64.0);
}

// ---------------------------------------------------------------------------
// PART D — 2-osc calibration at full width (known closure lambda=1,671,196,332)
// ---------------------------------------------------------------------------
static void calibrate_2osc(uint64_t seeds, uint64_t budget_mult, int mode){
    T2W M; M.init(32,3,5,K_DEFAULT);
    const double N=std::ldexp(1.0,64);
    std::printf("\n[PART D] 2-osc (p,q)=(3,5) K=12 at FULL width w=32, mode=%s, %llu seeds — seed 0 = DEFAULT_SEED = the record's TEST1 seed (must reproduce lambda 1,671,196,332); other seeds are expected to share it with prob ~0.76 each\n", mode==1?"R1":"R2",(unsigned long long)seeds);
    std::unordered_set<uint64_t> cyc;
    for(uint64_t s=0;s<seeds;s++){
        uint32_t t1,t2; M.seed_state(DEFAULT_SEED + s*7919ULL, t1,t2); uint32_t s1=t1,s2=t2;
        uint64_t budget=(uint64_t)(budget_mult*std::sqrt(N))+1000;
        auto step=[&](){ M.step(mode,t1,t2); }; auto pack=[&](){ return ((uint64_t)t1<<32)|t2; };
        double t0=now_s(); BrentResult br=brent_generic(step,pack,budget);
        if(!br.closed){ std::printf("  seed %llu: NO closure within budget %llu\n",(unsigned long long)s,(unsigned long long)budget); continue; }
        uint32_t a1=s1,a2=s2,b1=s1,b2=s2; for(uint64_t i=0;i<br.lambda;i++) M.step(mode,b1,b2);
        uint64_t mu=0; while(!(a1==b1&&a2==b2)){ M.step(mode,a1,a2); M.step(mode,b1,b2); mu++; }
        uint64_t cid=((uint64_t)a1<<32)|a2; uint32_t c1=a1,c2=a2; for(uint64_t i=0;i<br.lambda;i++){ M.step(mode,c1,c2); uint64_t v=((uint64_t)c1<<32)|c2; if(v<cid) cid=v; }
        cyc.insert(cid);
        std::printf("  seed %llu: lambda=%llu mu=%llu rho=%llu  (%.0f s)%s\n",(unsigned long long)s,(unsigned long long)br.lambda,(unsigned long long)mu,(unsigned long long)(mu+br.lambda),now_s()-t0, br.lambda==1671196332ULL?"  <== matches record":"");
    }
    std::printf("  distinct terminal cycles across seeds: %zu   E[rho]=%.3e\n",cyc.size(),rm_expect(N).rho);
}

// ---------------------------------------------------------------------------
// Self-test: at w=32 both reductions must equal the production engine exactly
// ---------------------------------------------------------------------------
static bool selftest(const MCL_Q30_Sextet& W){
    T4W M; M.init(32,W,K_DEFAULT);
    uint32_t e1,e2,e3,e4; M.seed_state(DEFAULT_SEED,e1,e2,e3,e4);
    uint32_t a1=e1,a2=e2,a3=e3,a4=e4, b1=e1,b2=e2,b3=e3,b4=e4;
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT);
    for(int i=0;i<100000;i++){ mcl_q30t4_iterate_raw(e1,e2,e3,e4,W,kp); M.step_R1(a1,a2,a3,a4); M.step_R2(b1,b2,b3,b4); }
    bool ok1=(e1==a1&&e2==a2&&e3==a3&&e4==a4), ok2=(e1==b1&&e2==b2&&e3==b3&&e4==b4);
    std::printf("[SELFTEST] w=32: R1==engine %s, R2==engine %s (100,000 iterations)  state=%08x %08x %08x %08x\n", ok1?"PASS":"FAIL", ok2?"PASS":"FAIL", e1,e2,e3,e4);
    // 2-osc
    T2W M2; M2.init(32,3,5,K_DEFAULT); uint32_t x1,x2; mcl_q30_init_state(DEFAULT_SEED,x1,x2); uint32_t y1=x1,y2=x2,z1=x1,z2=x2;
    for(int i=0;i<100000;i++){ mcl_q30_iterate_raw(x1,x2,3,5,kp); M2.step_R1(y1,y2); M2.step_R2(z1,z2); }
    bool ok3=(x1==y1&&x2==y2), ok4=(x1==z1&&x2==z2);
    std::printf("[SELFTEST] 2-osc w=32: R1==engine %s, R2==engine %s\n", ok3?"PASS":"FAIL", ok4?"PASS":"FAIL");
    return ok1&&ok2&&ok3&&ok4;
}

static void usage(){
    std::printf("usage: mcl_t4_cycle_reducedwidth [--mode exhaustive|brent|calib|all] [--keys K] [--seeds S]\n"
                "        [--wexh-max W (default 6; 7 needs --allow-big, ~3.5 GB RAM)] [--wbrent-min W (8)] [--wbrent-max W (14; 16 max, ~10 min/seed incl. mu + cycle-id)]\n"
                "        [--budget-mult M (default 16: budget = M*sqrt(N) per seed, ~13x E[rho])] [--reduction 1|2|both] [--allow-big]\n");
}

int main(int argc, char** argv){
    std::string mode="all"; int keys=4; uint64_t seeds_opt=0; int wexh_max=6, wb_min=8, wb_max=14; uint64_t budget_mult=16; int red=0; bool allow_big=false;
    for(int i=1;i<argc;i++){
        std::string a=argv[i];
        auto next=[&](){ if(i+1>=argc){usage();std::exit(2);} return std::string(argv[++i]); };
        if(a=="--mode") mode=next(); else if(a=="--keys") keys=std::atoi(next().c_str());
        else if(a=="--seeds") seeds_opt=std::strtoull(next().c_str(),nullptr,10);
        else if(a=="--wexh-max") wexh_max=std::atoi(next().c_str());
        else if(a=="--wbrent-min") wb_min=std::atoi(next().c_str());
        else if(a=="--wbrent-max") wb_max=std::atoi(next().c_str());
        else if(a=="--budget-mult") budget_mult=std::strtoull(next().c_str(),nullptr,10);
        else if(a=="--reduction"){ std::string r=next(); red=(r=="1")?1:(r=="2")?2:0; }
        else if(a=="--allow-big") allow_big=true;
        else { usage(); return 2; }
    }
    now_s();
    if(!(mode=="all"||mode=="exhaustive"||mode=="brent"||mode=="calib")){ std::fprintf(stderr,"unknown --mode '%s'\n",mode.c_str()); usage(); return 2; }
    if(keys<1||keys>64){ std::fprintf(stderr,"--keys must be in [1,64]\n"); return 2; }
    if(wb_min<8||wb_min>wb_max){ std::fprintf(stderr,"--wbrent-min must be in [8, wbrent-max]\n"); return 2; }
    if(wexh_max>7 || (wexh_max==7 && !allow_big)){ std::fprintf(stderr,"exhaustive w>6 needs --allow-big (w=7 ~3.5 GB RAM); w>7 refused\n"); return 2; }
    if(budget_mult<1||budget_mult>(1ULL<<20)){ std::fprintf(stderr,"--budget-mult must be in [1, 2^20]\n"); return 2; }
    if(wb_max>16){ std::fprintf(stderr,"--wbrent-max > 16 is a 2^64+ state: use Brent only with explicit --seeds and --budget-mult; refused by default\n"); return 2; }

    std::printf("================================================================\n");
    std::printf("  MCL T4-Q30 reduced-width cycle-structure study\n");
    std::printf("  MCL-T4-CYCLE-2026-0822-001   engine mcl_core %s (%s) UNMODIFIED + keyed sidecar\n", MCL_VERSION_STRING, MCL_VERSION_DATE);
    std::printf("  mode=%s keys=%d reduction=%s  exhaustive w<=%d  brent w=%d..%d  budget=%llu*sqrt(N)\n",
        mode.c_str(),keys,red==0?"both":(red==1?"R1":"R2"),wexh_max,wb_min,wb_max,(unsigned long long)budget_mult);
    std::printf("================================================================\n");

    // keyed weights: key k = bytes {k, k+1, ...} (public KAT-style keys; the weights are what matter)
    std::vector<MCL_Q30_Sextet> WS;
    for(int k=0;k<keys;k++){ uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)(i+k*0x11); WS.push_back(mcl_t4_q30_params_from_key(key,0)); }
    std::printf("weight sets (p12 q12 p13 q13 p14 q14 p23 q23 p24 q24 p34 q34):\n");
    for(int k=0;k<keys;k++){ const auto& W=WS[k]; std::printf("  key%d: %u %u %u %u %u %u %u %u %u %u %u %u\n",k,W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34); }

    if(!selftest(WS[0])){ std::fprintf(stderr,"SELFTEST FAILED — harness does not reproduce the engine at w=32; aborting.\n"); return 1; }

    const bool doA = (mode=="all"||mode=="exhaustive");
    const bool doB = (mode=="all"||mode=="brent");
    const bool doD = (mode=="all"||mode=="calib");
    std::vector<int> modes; if(red==0){modes={1,2};} else modes={red};

    if(doA){
        for(int k=0;k<keys;k++) for(int m: modes) for(int w=4;w<=wexh_max;w++){
            T4W M; M.init(w,WS[k],K_DEFAULT); char tag[32]; std::snprintf(tag,sizeof tag,"T4 key%d",k);
            double t0=now_s(); GraphStats g=exhaustive_graph(M,m,w,4); print_graph(g,w,4,m,tag); std::printf("  (%.1f s)\n",now_s()-t0);
        }
        // 2-osc exhaustive control (state 2w bits, w up to 14 -> 2^28 only with --allow-big)
        for(int m: modes) for(int w=8;w<=(allow_big?14:12);w+=2){
            T2W M; M.init(w,3,5,K_DEFAULT); double t0=now_s(); GraphStats g=exhaustive_graph(M,m,w,2); print_graph(g,w,2,m,"2-osc (3,5) control"); std::printf("  (%.1f s)\n",now_s()-t0);
        }
    }
    if(doB){
        for(int m: modes){
            std::printf("\n[PART B] Brent sampling, T4 keyed, mode=%s\n", m==1?"R1-truncated":"R2-native");
            print_row_header();
            std::vector<SampleRow> rows;
            for(int w=wb_min;w<=wb_max;w++){
                uint64_t seeds = seeds_opt? seeds_opt : default_seeds(4*w);
                SampleRow acc{w,4*w,0,0,0,0,0,1e300,0,0,rm_expect(std::ldexp(1.0,4*w)).rho};
                double srho=0,slam=0,smu=0; uint64_t dc=0;
                double t0=now_s();
                for(int k=0;k<keys;k++){
                    T4W M; M.init(w,WS[k],K_DEFAULT);
                    SampleRow r=sample_T4(M,m,seeds,budget_mult,(uint64_t)k);
                    acc.seeds+=r.seeds; acc.closed+=r.closed; srho+=r.mean_rho*r.closed; slam+=r.mean_lambda*r.closed; smu+=r.mean_mu*r.closed; dc+=r.distinct_cycles;
                    acc.dc_min=std::min(acc.dc_min,r.distinct_cycles); acc.dc_max=std::max(acc.dc_max,r.distinct_cycles);
                    if(r.closed){ acc.min_rho=std::min(acc.min_rho,r.min_rho); acc.max_rho=std::max(acc.max_rho,r.max_rho); }
                }
                if(acc.closed){ acc.mean_rho=srho/acc.closed; acc.mean_lambda=slam/acc.closed; acc.mean_mu=smu/acc.closed; }
                acc.distinct_cycles=dc; print_row(acc); std::printf("      (%.1f s)\n",now_s()-t0); std::fflush(stdout);
                rows.push_back(acc);
            }
            fit_and_extrapolate(rows, m==1?"R1":"R2");
        }
    }
    if(doD){
        uint64_t s = seeds_opt? seeds_opt : 4;
        calibrate_2osc(s, budget_mult, 1);   // R1 == R2 == engine at w=32 (selftest), so one run suffices
    }
    std::printf("\nDONE (%.0f s)\n", now_s());
    return 0;
}
