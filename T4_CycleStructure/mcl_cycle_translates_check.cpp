// mcl_cycle_translates_check.cpp — Doc ID MCL-T4-CYCLE-2026-0822-005 (review-stage verification)
// Part D found 4 seeds on 3 DISTINCT terminal cycles of identical length lambda=1,671,196,332.
// Hypothesis (record §5): the cycles are translates of one another under the order-16 symmetry
// group G of the 2-osc (3,5) map.  Test: reach the cycle entry point c_s of each seed s (walk mu_s
// steps), then walk the FULL cycle of seed 0 once (lambda steps) and check, at every step, whether the
// current state equals c_s - g for some g in G (16 candidates, incl. identity), for s = 1,2,3.
// If found: cycle_s = cycle_0 + g (verified translate).  Cost ~ (sum mu_s) + lambda ~ 3.2e9 steps.
// ADDITIVE: engine untouched. Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_cycle_translates_check.cpp -o mcl_cycle_translates_check
#include "../mcl_core.hpp"
#include <cstdio>
#include <vector>
#include <unordered_map>
// v1.1: targets may COINCIDE across seeds (if entry_s - entry_s' is itself a group element), so keep ALL (s,k) per state.
int main(){
    const int64_t p=3,q=5,kp=mcl_q30_K_phase(K_DEFAULT); const uint64_t LAMBDA=1671196332ULL;
    const uint64_t mus[4]={75864346ULL,254734029ULL,763951021ULL,475182142ULL};   // from t4_cycle_calib_apple_20260822.log
    uint64_t entry[4];
    for(int s=0;s<4;s++){ uint32_t t1,t2; mcl_q30_init_state(DEFAULT_SEED+(uint64_t)s*7919ULL,t1,t2); for(uint64_t i=0;i<mus[s];i++) mcl_q30_iterate_raw(t1,t2,p,q,kp); entry[s]=((uint64_t)t1<<32)|t2;
        // sanity: entry must be on a cycle of length LAMBDA: iterate LAMBDA and compare (costly: do only for s=0 below as part of the walk)
    }
    std::printf("MCL-T4-CYCLE-2026-0822-005 cycle-translate check (2-osc (3,5), K=12)\n");
    for(int s=0;s<4;s++) std::printf("  seed %d entry state = %08x %08x\n",s,(uint32_t)(entry[s]>>32),(uint32_t)entry[s]);
    // group G: a = k*2^28, b = a*5*inv3 mod 2^32
    const uint32_t inv3=0xAAAAAAABu; std::unordered_map<uint64_t,std::vector<int>> targets; // packed (c_s - g) -> list of (s<<8)|k
    for(int s=1;s<4;s++) for(uint32_t k=0;k<16;k++){ uint32_t a=k<<28, b=(uint32_t)(a*5u*inv3); uint32_t c1=(uint32_t)(entry[s]>>32)-a, c2=(uint32_t)entry[s]-b; targets[((uint64_t)c1<<32)|c2].push_back((s<<8)|(int)k); }
    uint32_t t1=(uint32_t)(entry[0]>>32), t2=(uint32_t)entry[0]; bool found[4]={true,false,false,false}; int gk[4]={0,-1,-1,-1}; uint64_t at[4]={0,0,0,0};
    for(uint64_t i=0;i<LAMBDA;i++){
        uint64_t cur=((uint64_t)t1<<32)|t2; auto it=targets.find(cur); if(it!=targets.end()){ for(int v: it->second){ int s=v>>8, k=v&255; if(!found[s]){ found[s]=true; gk[s]=k; at[s]=i; } } }
        mcl_q30_iterate_raw(t1,t2,p,q,kp);
    }
    bool closed=(((uint64_t)t1<<32)|t2)==entry[0];
    std::printf("  seed 0 cycle walk of %llu steps returned to entry: %s\n",(unsigned long long)LAMBDA,closed?"YES (lambda confirmed)":"NO (?)");
    for(int s=1;s<4;s++) std::printf("  seed %d: %s\n",s, found[s]? (gk[s]==0?"SAME cycle as seed 0 (identity)":"TRANSLATE of seed-0 cycle"):"NOT a translate within G (hypothesis FALSE)");
    for(int s=1;s<4;s++) if(found[s]) std::printf("     seed %d: cycle_s = cycle_0 + g_k with k=%d (a=%08x), met at offset %llu\n",s,gk[s],(uint32_t)gk[s]<<28,(unsigned long long)at[s]);
    return 0;
}
