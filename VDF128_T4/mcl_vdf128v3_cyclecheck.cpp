// mcl_vdf128v3_cyclecheck.cpp — Doc ID MCL-VDF128-CYCLE-2026-0905-003 (v2 of MCL-VDF128-CYCLE-2026-0817-001)
//  Budgeted Brent cycle probe on VDF128-T4 v3 (per-input weights): 3 inputs, budget 2^33 each,
//  plus throughput and the v2 KAT. Each input evaluates its own map F_x.
#include "mcl_vdf128_t4_v3.hpp"
#include <cstdio>
#include <chrono>
using Clock = std::chrono::steady_clock;
int main(){
  const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
  const char* xs[3] = {"VDF128-T4-cycle-probe-A","VDF128-T4-cycle-probe-B","VDF128-T4-cycle-probe-C"};
  for (int c=0;c<3;c++){
    const MCL_Q30_Sextet W = mcl_vdf128v3_weights((const uint8_t*)xs[c], strlen(xs[c]));
    VDF128_State h = mcl_vdf128_init((const uint8_t*)xs[c], strlen(xs[c])), T = h;
    uint64_t power=1, lam=0, steps=1; bool closed=false; const uint64_t budget=(1ULL<<33);
    mcl_q30t4_iterate_raw(h.t1,h.t2,h.t3,h.t4,W,kp); lam=1;
    auto t0=Clock::now();
    while (steps <= budget) {
      if (T.t1==h.t1 && T.t2==h.t2 && T.t3==h.t3 && T.t4==h.t4) { closed=true; break; }
      if (lam==power) { power<<=1; lam=0; T=h; }
      mcl_q30t4_iterate_raw(h.t1,h.t2,h.t3,h.t4,W,kp); lam++; steps++;
    }
    double secs=std::chrono::duration<double>(Clock::now()-t0).count();
    if (closed) printf("TEST2 input %c (own map F_x): CLOSED at lambda=%llu (steps=%llu) *** PATHOLOGY ***\n", 'A'+c,(unsigned long long)lam,(unsigned long long)steps);
    else printf("TEST2 input %c (own map F_x): NO closure within 2^33 = 8,589,934,592 steps (%.0f s, %.1f M iter/s)\n", 'A'+c, secs, 8589.934592/secs);
    fflush(stdout);
  }
  { const char* x = "VDF128-T4-KAT-01";
    VDF128_State sF = mcl_vdf128v3_eval_state((const uint8_t*)x, strlen(x), 1000);
    printf("TEST5 KAT v2 final state (N=1e3): %08x %08x %08x %08x\n", sF.t1,sF.t2,sF.t3,sF.t4);
    uint8_t y[32]; mcl_vdf128v3_eval((const uint8_t*)x, strlen(x), 1000, y);
    printf("TEST5 KAT v2 y = "); for(int i=0;i<32;i++) printf("%02x", y[i]); printf("\n"); }
  return 0;
}
