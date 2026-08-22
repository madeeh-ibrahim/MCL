// mcl_vdf128_cyclecheck.cpp — Doc ID MCL-VDF128-CYCLE-2026-0817-001
// Path-A rebuild evidence for Paper 4:
//  TEST 1 (control): Brent cycle detection on the OLD 2-osc Q30 path
//          (mcl_q30_iterate_raw, 64-bit state) — expected to CLOSE with
//          lambda = 1,671,196,332 (4th independent confirmation).
//  TEST 2: budgeted Brent on the NEW 128-bit VDF128_T4 state — expected
//          NO closure within budget 2^33 (~4x beyond the old break point).
//  TEST 3: init distinctness & avalanche — x vs x+2^32 (old collapse case)
//          and 1-bit flip must produce ~64/128 differing state bits.
//  TEST 4: throughput of the T4 iterate (for the paper's delay table).
//  TEST 5: KAT — reference (x, N) with init/burn-in/final states and y.
#include "mcl_vdf128_t4.hpp"
#include <cstdio>
#include <chrono>
using Clock = std::chrono::steady_clock;

int main(){
  // ---- TEST 1: control (old 2-osc path, KAT seed) ----
  {
    uint32_t a1,a2,b1,b2;
    mcl_q30_init_state(12345678901234ULL, a1,a2);
    b1=a1; b2=a2;
    // Brent: power = 1; advance hare; tortoise teleports at powers of two.
    uint64_t power=1, lam=0; bool closed=false;
    uint64_t budget = (1ULL<<33);
    uint32_t T1=a1,T2=a2; // tortoise
    mcl_q30_iterate_raw(b1,b2,3,5,mcl_q30_K_phase(K_DEFAULT)); lam=1;
    uint64_t steps=1;
    while (steps <= budget) {
      if (T1==b1 && T2==b2) { closed=true; break; }
      if (lam==power) { power<<=1; lam=0; T1=b1; T2=b2; }
      mcl_q30_iterate_raw(b1,b2,3,5,mcl_q30_K_phase(K_DEFAULT)); lam++; steps++;
    }
    if (closed) printf("TEST1 control OLD path: CLOSED, cycle lambda = %llu (expected 1671196332)\n",(unsigned long long)lam);
    else        printf("TEST1 control OLD path: no closure in budget (UNEXPECTED)\n");
  }
  // ---- TEST 2: new 128-bit path, 3 inputs, budget 2^33 ----
  {
    static const MCL_Q30_Sextet W = mcl_vdf128_public_weights();
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const char* xs[3] = {"MCL-VDF128-cycle-probe-A","MCL-VDF128-cycle-probe-B","MCL-VDF128-cycle-probe-C"};
    for (int c=0;c<3;c++){
      VDF128_State h = mcl_vdf128_init((const uint8_t*)xs[c], strlen(xs[c])); // hare
      VDF128_State T = h;                                                     // tortoise
      uint64_t power=1, lam=0, steps=1; bool closed=false;
      uint64_t budget=(1ULL<<33);
      mcl_q30t4_iterate_raw(h.t1,h.t2,h.t3,h.t4,W,kp); lam=1;
      auto t0=Clock::now();
      while (steps <= budget) {
        if (T.t1==h.t1 && T.t2==h.t2 && T.t3==h.t3 && T.t4==h.t4) { closed=true; break; }
        if (lam==power) { power<<=1; lam=0; T=h; }
        mcl_q30t4_iterate_raw(h.t1,h.t2,h.t3,h.t4,W,kp); lam++; steps++;
      }
      double secs=std::chrono::duration<double>(Clock::now()-t0).count();
      if (closed) printf("TEST2 input %c: CLOSED at lambda=%llu (steps=%llu) *** PATHOLOGY ***\n", 'A'+c,(unsigned long long)lam,(unsigned long long)steps);
      else printf("TEST2 input %c: NO closure within 2^33 = 8,589,934,592 steps (%.0f s, %.1f M iter/s)\n", 'A'+c, secs, 8589.934592/secs);
    }
  }
  // ---- TEST 3: init distinctness / avalanche ----
  {
    uint8_t xa[8], xb[8];
    uint64_t s = 12345678901234ULL, s2 = s + (1ULL<<32);
    for(int i=0;i<8;i++){ xa[i]=(uint8_t)(s>>(8*i)); xb[i]=(uint8_t)(s2>>(8*i)); }
    VDF128_State A = mcl_vdf128_init(xa,8), B = mcl_vdf128_init(xb,8);
    int diff = __builtin_popcount(A.t1^B.t1)+__builtin_popcount(A.t2^B.t2)
             + __builtin_popcount(A.t3^B.t3)+__builtin_popcount(A.t4^B.t4);
    printf("TEST3 s vs s+2^32 (old collapse case): %d/128 state bits differ (old path: 0)\n", diff);
    xb[0]=xa[0]^1; for(int i=1;i<8;i++) xb[i]=xa[i];
    B = mcl_vdf128_init(xb,8);
    diff = __builtin_popcount(A.t1^B.t1)+__builtin_popcount(A.t2^B.t2)
         + __builtin_popcount(A.t3^B.t3)+__builtin_popcount(A.t4^B.t4);
    printf("TEST3 1-bit input flip: %d/128 state bits differ (expect ~64)\n", diff);
  }
  // ---- TEST 4: throughput ----
  {
    static const MCL_Q30_Sextet W = mcl_vdf128_public_weights();
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    VDF128_State s = mcl_vdf128_init((const uint8_t*)"tp",2);
    const uint64_t M=200000000ULL;
    auto t0=Clock::now();
    for(uint64_t i=0;i<M;i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
    double secs=std::chrono::duration<double>(Clock::now()-t0).count();
    printf("TEST4 throughput: %.1f M iter/s (%.1f ns/iter)  [state=%08x%08x%08x%08x]\n", M/1e6/secs, secs*1e9/M, s.t1,s.t2,s.t3,s.t4);
  }
  // ---- TEST 5: KAT ----
  {
    const char* x = "MCL-VDF128-KAT-1";
    VDF128_State i0 = mcl_vdf128_init((const uint8_t*)x, strlen(x));
    printf("TEST5 KAT init state : %08x %08x %08x %08x\n", i0.t1,i0.t2,i0.t3,i0.t4);
    VDF128_State sB = mcl_vdf128_eval_state((const uint8_t*)x, strlen(x), 0);
    printf("TEST5 KAT post-burnin: %08x %08x %08x %08x\n", sB.t1,sB.t2,sB.t3,sB.t4);
    uint8_t y[32];
    mcl_vdf128_eval((const uint8_t*)x, strlen(x), 100000, y);
    VDF128_State sF = mcl_vdf128_eval_state((const uint8_t*)x, strlen(x), 100000);
    printf("TEST5 KAT final state (N=1e5): %08x %08x %08x %08x\n", sF.t1,sF.t2,sF.t3,sF.t4);
    printf("TEST5 KAT y = "); for(int i=0;i<32;i++) printf("%02x", y[i]); printf("\n");
    // determinism: recompute
    uint8_t y2[32]; mcl_vdf128_eval((const uint8_t*)x, strlen(x), 100000, y2);
    printf("TEST5 determinism: %s\n", memcmp(y,y2,32)==0?"IDENTICAL":"MISMATCH");
  }
  return 0;
}
