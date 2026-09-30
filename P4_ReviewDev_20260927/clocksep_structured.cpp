// Clock separation of VDF128-T4 version 4 at structured clock offsets.
// The same state z is advanced r = 1, 2, 3 iterations at clock i and at clock i + k; the two results are
// compared bit by bit. Offsets k: the small offsets of the first probe, and offsets of high 2-adic valuation,
// for which the clock encoding tau(i+k) - tau(i) = k*(1, alpha, beta, gamma) has its low bits zero.
// Per cell: 2^18 random states; mean Hamming distance with its z against 64 (standard error sqrt(32)/2^9);
// output bits whose flip frequency leaves 1/2 by more than the 4.5-sigma floor; bits that never or always flip;
// at r = 1 the bit of largest deviation (word 1..4, bit 0 = lowest) with its flip frequency.
// Controls: (P) the detector fires on the known one-iteration case; (N) it stays silent on independent states.
// Build (from this folder): clang++ -std=c++17 -O3 -DNDEBUG -I../P4_ReviewMeasurements_20260925 -I.. -o clocksep_structured clocksep_structured.cpp
// Run:   ./clocksep_structured > clocksep_structured_20260930.log        (deterministic; exit 0 iff both controls pass)
// 2026-09-30: forty inputs (the nine of the first run of 2026-09-28 are among them) after a referee-style rerun on other
// inputs found the one-iteration bias at further offsets; the offsets, states per cell and floors are unchanged.
#include "mcl_vdf128_t4_v4.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>
static uint64_t sm(uint64_t& z){z+=0x9E3779B97F4A7C15ull;uint64_t r=z;r=(r^(r>>30))*0xBF58476D1CE4E5B9ull;r=(r^(r>>27))*0x94D049BB133111EBull;return r^(r>>31);}
struct Cell { double mean, z; int above, det; double worst; int wbit; double wfreq; };
enum Wrap { ANY=0, NOWRAP=1, WRAP=2 };
static const int LOGT = 18; static const long T = 1L << LOGT;
static Cell run(const MCL_Q30_Sextet& W, int64_t kp, uint64_t k, int rnd, Wrap wr, int r, uint64_t seed, bool independent=false){
    static long cnt[128]; std::memset(cnt,0,sizeof(cnt)); uint64_t zz=seed; double hs=0;
    for(long t=0;t<T;t++){
        uint64_t a=sm(zz),b=sm(zz); VDF128_State u{(uint32_t)a,(uint32_t)(a>>32),(uint32_t)b,(uint32_t)(b>>32)}, v=u;
        if(independent){ uint64_t c=sm(zz),d=sm(zz); v=VDF128_State{(uint32_t)c,(uint32_t)(c>>32),(uint32_t)d,(uint32_t)(d>>32)}; }
        uint64_t kk = rnd ? 1+sm(zz)%1000 : k;
        uint64_t hi=sm(zz)%256, lo;
        if(wr==NOWRAP)      lo = sm(zz) % ((1ull<<32) - (kk & 0xFFFFFFFFull) - 8);        // lo + (k mod 2^32) + r stays below 2^32
        else if(wr==WRAP)   lo = ((1ull<<32) - (kk & 0xFFFFFFFFull)) + sm(zz) % ((kk & 0xFFFFFFFFull) - 8); // lo + (k mod 2^32) wraps
        else                lo = sm(zz) & 0xFFFFFFFFull;
        uint64_t ci=(hi<<32)|lo, cj = independent ? ci : ci+kk;
        for(int q=0;q<r;q++){ mcl_vdf128v4_iterate(u,W,kp,ci+(uint64_t)q); mcl_vdf128v4_iterate(v,W,kp,cj+(uint64_t)q); }
        uint32_t d[4]={u.t1^v.t1,u.t2^v.t2,u.t3^v.t3,u.t4^v.t4};
        for(int bit=0;bit<128;bit++) if((d[bit/32]>>(bit%32))&1){ cnt[bit]++; hs+=1; }
    }
    const double fl=4.5*0.5/std::sqrt((double)T); Cell c; c.mean=hs/T; c.z=(c.mean-64.0)/(std::sqrt(32.0)/std::sqrt((double)T)); c.above=0; c.det=0; c.worst=0; c.wbit=0; c.wfreq=0.5;
    for(int bit=0;bit<128;bit++){ double f=(double)cnt[bit]/T, dev=std::fabs(f-0.5); if(dev>fl) c.above++; if(cnt[bit]==0||cnt[bit]==T) c.det++; if(dev>c.worst){c.worst=dev;c.wbit=bit;c.wfreq=f;} }
    return c;
}
static void parity(const MCL_Q30_Sextet& W, int par[6]){ uint32_t w[12]={W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34}; for(int e=0;e<6;e++) par[e]=(int)((w[2*e]^w[2*e+1])&1u); }
int main(){
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT); const double fl=4.5*0.5/std::sqrt((double)T);
    std::printf("VDF128-T4 v4 -- clock separation at structured clock offsets (engine %d.%d.%d)\n",MCL_VERSION_MAJOR,MCL_VERSION_MINOR,MCL_VERSION_PATCH);
    std::printf("states per cell 2^%d; 4.5-sigma floor of a flip frequency %.5f; standard error of a mean Hamming distance %.4f\n",LOGT,fl,std::sqrt(32.0)/std::sqrt((double)T));
    std::printf("clock i = hi*2^32 + lo, hi uniform below 2^8; 'no wrap': lo + k stays below 2^32; 'wrap': lo + k passes 2^32\n\n");
    // inputs: the battery input, the known-answer input and thirty-eight numbered inputs (forty in all)
    std::vector<std::string> in={"VDF128-T4-battery-input","VDF128-T4-KAT-01"};
    for(int n=0;n<38;n++) in.push_back("VDF128-T4-clock-probe-"+std::to_string(n));
    struct Off{const char* name; uint64_t k; int rnd; Wrap wr;};
    const Off offs[]={
        {"k uniform in [1,1000]",0,1,ANY},{"k = 1",1,0,ANY},{"k = 2^16",1ull<<16,0,ANY},{"k = 2^24",1ull<<24,0,ANY},{"k = 2^28",1ull<<28,0,ANY},
        {"k = 2^29, no wrap",1ull<<29,0,NOWRAP},{"k = 2^30, no wrap",1ull<<30,0,NOWRAP},{"k = 3*2^30, no wrap",3ull<<30,0,NOWRAP},
        {"k = 2^31, no wrap",1ull<<31,0,NOWRAP},{"k = 2^31, wrap",1ull<<31,0,WRAP},{"k = 2^31, all clocks",1ull<<31,0,ANY},
        {"k = 2^32 (one wrap of lo)",1ull<<32,0,ANY},{"k = 2^33",1ull<<33,0,ANY}};
    const int NO=(int)(sizeof(offs)/sizeof(offs[0]));
    // controls
    { std::string x=in[0]; MCL_Q30_Sextet W=mcl_vdf128v4_weights((const uint8_t*)x.data(),x.size());
      Cell p=run(W,kp,1ull<<31,0,NOWRAP,1,0xC0117201ull), n=run(W,kp,0,0,ANY,1,0xC0117202ull,true);
      bool okp=(p.worst>0.49), okn=(n.above==0 && std::fabs(n.z)<4.5);
      std::printf("[CONTROL P] k = 2^31, no wrap, r = 1, battery input: largest deviation %.4f at w%d.b%d -> %s\n",p.worst,p.wbit/32+1,p.wbit%32,okp?"PASS":"FAIL");
      std::printf("[CONTROL N] two independent states at one clock, r = 1: mean %.3f (z %+.2f), bits above the floor %d -> %s\n\n",n.mean,n.z,n.above,okn?"PASS":"FAIL");
      if(!okp||!okn){ std::printf("CONTROL FAILED -- this run is not to be cited\n"); return 1; } }
    struct Agg { int inputs=0; long bits=0; double maxdev=0; int det=0; double lo=1e9, hi=-1e9, maxz=0; };
    static Agg agg[16][3];
    long cells=0, above_r1=0, above_r23=0, tests_r23=0; double maxz_r23=0, maxz_small=0; int struct_cells=0;
    for(size_t ii=0;ii<in.size();ii++){
        const std::string& x=in[ii]; MCL_Q30_Sextet W=mcl_vdf128v4_weights((const uint8_t*)x.data(),x.size()); int par[6]; parity(W,par);
        std::printf("input %zu \"%s\"   parity of p - q for the pairs 12 13 14 23 24 34: %s %s %s %s %s %s\n",ii,x.c_str(),par[0]?"odd":"even",par[1]?"odd":"even",par[2]?"odd":"even",par[3]?"odd":"even",par[4]?"odd":"even",par[5]?"odd":"even");
        for(int o=0;o<NO;o++){
            std::printf("   %-28s",offs[o].name);
            for(int r=1;r<=3;r++){
                Cell c=run(W,kp,offs[o].k,offs[o].rnd,offs[o].wr,r,0x5EED0000ull+(uint64_t)(ii*1000+o*10+r));
                std::printf("  r=%d mean %7.3f z %+6.1f above %3d det %2d maxdev %.4f",r,c.mean,c.z,c.above,c.det,c.worst);
                if(r==1){ if(c.above>0) std::printf(" (w%d.b%-2d f %.4f)",c.wbit/32+1,c.wbit%32,c.wfreq); else std::printf(" (none          )"); }
                cells++;
                { Agg& a=agg[o][r-1]; if(c.above>0) a.inputs++; a.bits+=c.above; if(c.worst>a.maxdev) a.maxdev=c.worst; if(c.det>a.det) a.det=c.det; if(c.mean<a.lo) a.lo=c.mean; if(c.mean>a.hi) a.hi=c.mean; if(std::fabs(c.z)>a.maxz) a.maxz=std::fabs(c.z); }
                if(r==1){ above_r1+=c.above; if(c.above>0) struct_cells++; if(o<=4 && std::fabs(c.z)>maxz_small) maxz_small=std::fabs(c.z); }
                else { above_r23+=c.above; tests_r23+=128; if(std::fabs(c.z)>maxz_r23) maxz_r23=std::fabs(c.z); }
            }
            std::printf("\n");
        }
    }
    std::printf("\nSUMMARY\n");
    std::printf("  inputs %zu, offset cells %d, iteration counts 3: %ld cells of 2^%d states\n",in.size(),NO,cells,LOGT);
    std::printf("  r = 1: cells with a bit above the floor: %d; bits above the floor in all: %ld\n",struct_cells,above_r1);
    std::printf("  r = 1, offsets up to 2^28: largest |z| of a mean Hamming distance: %.2f\n",maxz_small);
    std::printf("  r = 2 and 3: bit tests %ld, bits above the floor: %ld (expected by chance %.2f); largest |z| of a mean: %.2f\n",tests_r23,above_r23,tests_r23*6.8e-6,maxz_r23);
    std::printf("  controls: P PASS, N PASS\n");
    std::printf("\nPER OFFSET (over the %zu inputs): inputs with a bit above the floor / bits above the floor / largest deviation / most determined bits / range of the mean\n",in.size());
    for(int r=1;r<=3;r++){ std::printf("  r = %d\n",r);
        for(int o=0;o<NO;o++){ const Agg& a=agg[o][r-1]; std::printf("   %-28s inputs %d  bits %4ld  maxdev %.4f  det %2d  mean %.3f .. %.3f  max|z| %.1f\n",offs[o].name,a.inputs,a.bits,a.maxdev,a.det,a.lo,a.hi,a.maxz); } }
    return 0;
}
