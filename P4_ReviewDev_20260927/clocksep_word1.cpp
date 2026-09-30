// Clock separation of VDF128-T4 version 4 -- the first-updated word at the offsets of clocksep_structured.cpp
// that carry one-iteration structure (k = 2^31, 2^30, 3*2^30, 2^29; lo + k stays below 2^32).
// For each of the nine inputs and each offset, over 2^18 random states and one iteration:
//   - how often the arithmetic difference of word 1 (clock i + k minus clock i, mod 2^32) equals its most frequent value;
//   - the mean number of flipped bits in each of the four words;
//   - how often the two 128-bit outputs are equal.
// Build (from this folder): clang++ -std=c++17 -O3 -DNDEBUG -I../P4_ReviewMeasurements_20260925 -I.. -o clocksep_word1 clocksep_word1.cpp
// Run:   ./clocksep_word1 > clocksep_word1_20260930.log        (deterministic; forty inputs since 2026-09-30)
#include "mcl_vdf128_t4_v4.hpp"
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
static uint64_t sm(uint64_t& z){z+=0x9E3779B97F4A7C15ull;uint64_t r=z;r=(r^(r>>30))*0xBF58476D1CE4E5B9ull;r=(r^(r>>27))*0x94D049BB133111EBull;return r^(r>>31);}
int main(){
    const int64_t kp=mcl_q30_K_phase(K_DEFAULT); const long T=1L<<18;
    std::vector<std::string> in={"VDF128-T4-battery-input","VDF128-T4-KAT-01"};
    for(int n=0;n<38;n++) in.push_back("VDF128-T4-clock-probe-"+std::to_string(n));
    struct Off{const char* name; uint64_t k;}; const Off offs[]={{"2^31",1ull<<31},{"2^30",1ull<<30},{"3*2^30",3ull<<30},{"2^29",1ull<<29}};
    std::printf("VDF128-T4 v4 -- first-updated word at structured clock offsets, one iteration, 2^18 states per cell, lo + k below 2^32\n\n");
    long equal_all=0;
    for(size_t ii=0;ii<in.size();ii++){
        const std::string& x=in[ii]; MCL_Q30_Sextet W=mcl_vdf128v4_weights((const uint8_t*)x.data(),x.size());
        std::printf("input %zu \"%s\"   parity of p - q for the pairs 12 13 14: %s %s %s\n",ii,x.c_str(),((W.p12^W.q12)&1u)?"odd":"even",((W.p13^W.q13)&1u)?"odd":"even",((W.p14^W.q14)&1u)?"odd":"even");
        for(const Off& o:offs){
            uint64_t zz=0xC10C0000ull+(uint64_t)(ii*100)+(o.k>>29); long equal=0; long fl[4]={0,0,0,0}; std::unordered_map<uint32_t,long> h;
            for(long t=0;t<T;t++){
                uint64_t a=sm(zz),b=sm(zz); VDF128_State u{(uint32_t)a,(uint32_t)(a>>32),(uint32_t)b,(uint32_t)(b>>32)}, v=u;
                uint64_t hi=sm(zz)%256, lo=sm(zz)%((1ull<<32)-o.k-8); uint64_t ci=(hi<<32)|lo;
                mcl_vdf128v4_iterate(u,W,kp,ci); mcl_vdf128v4_iterate(v,W,kp,ci+o.k);
                h[v.t1-u.t1]++; if(u.t1==v.t1&&u.t2==v.t2&&u.t3==v.t3&&u.t4==v.t4) equal++;
                fl[0]+=__builtin_popcount(u.t1^v.t1); fl[1]+=__builtin_popcount(u.t2^v.t2); fl[2]+=__builtin_popcount(u.t3^v.t3); fl[3]+=__builtin_popcount(u.t4^v.t4);
            }
            uint32_t best=0; long bc=0; for(auto& e:h) if(e.second>bc||(e.second==bc&&e.first<best)){bc=e.second;best=e.first;}
            std::printf("   k = %-7s word-1 difference: most frequent 0x%08x in %6ld of %ld states (%zu distinct values)   flipped bits per word %5.2f %5.2f %5.2f %5.2f   equal outputs %ld\n",o.name,best,bc,T,h.size(),(double)fl[0]/T,(double)fl[1]/T,(double)fl[2]/T,(double)fl[3]/T,equal);
            equal_all+=equal;
        }
    }
    std::printf("\nSUMMARY: %zu inputs x 4 offsets x 2^18 states; equal outputs in all: %ld\n",in.size(),equal_all);
    return 0;
}
