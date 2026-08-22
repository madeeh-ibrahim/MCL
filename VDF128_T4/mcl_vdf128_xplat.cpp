/* mcl_vdf128_xplat.cpp — Doc ID MCL-VDF128-XPLAT-2026-0817-001
 * Cross-platform bit-exactness fingerprint for VDF128_T4.
 * Prints ONLY deterministic values: public-weight digest, KAT states, y, and a
 * long-run state fold. Identical output across arch/compiler/-O level is the
 * claim under test. No libm, no libc math, no wall-clock in the fingerprint. */
#include "mcl_vdf128_t4.hpp"
#include <cstdio>
#include <cstring>
int main(){
    std::printf("# arch=%s ptr=%zu\n",
#if defined(__x86_64__)
      "x86_64"
#elif defined(__aarch64__)
      "arm64"
#else
      "other"
#endif
      , sizeof(void*));
    // 1. public weights digest (nothing-up-my-sleeve derivation must be identical)
    MCL_Q30_Sextet W = mcl_vdf128_public_weights();
    std::printf("W  %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
      W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34);
    // 2. KAT chain
    const char* x = "MCL-VDF128-KAT-1";
    VDF128_State i0 = mcl_vdf128_init((const uint8_t*)x, std::strlen(x));
    std::printf("I  %08x %08x %08x %08x\n", i0.t1,i0.t2,i0.t3,i0.t4);
    VDF128_State sB = mcl_vdf128_eval_state((const uint8_t*)x, std::strlen(x), 0);
    std::printf("B  %08x %08x %08x %08x\n", sB.t1,sB.t2,sB.t3,sB.t4);
    VDF128_State sF = mcl_vdf128_eval_state((const uint8_t*)x, std::strlen(x), 100000);
    std::printf("F  %08x %08x %08x %08x\n", sF.t1,sF.t2,sF.t3,sF.t4);
    uint8_t y[32]; mcl_vdf128_eval((const uint8_t*)x, std::strlen(x), 100000, y);
    std::printf("Y  "); for(int i=0;i<32;i++) std::printf("%02x", y[i]); std::printf("\n");
    // 3. long-run fold over 5e6 iterations (catches any drift the KAT would miss)
    static const MCL_Q30_Sextet WW = mcl_vdf128_public_weights();
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    VDF128_State s = mcl_vdf128_init((const uint8_t*)"xplat-fold", 10);
    uint32_t fold = 0;
    for (int64_t i = 0; i < 5000000; i++) {
        mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,WW,kp);
        fold = (fold * 1000003u) ^ (s.t1 ^ s.t2 ^ s.t3 ^ s.t4);
    }
    std::printf("L  fold=%08x state=%08x %08x %08x %08x\n", fold, s.t1,s.t2,s.t3,s.t4);
    // 4. multi-input y digest
    uint32_t acc = 0;
    for (int k = 0; k < 8; k++) {
        char xi[32]; std::snprintf(xi,sizeof xi,"xplat-%d",k);
        uint8_t yy[32]; mcl_vdf128_eval((const uint8_t*)xi, std::strlen(xi), 25000, yy);
        for (int b = 0; b < 32; b++) acc = (acc*16777619u) ^ yy[b];
    }
    std::printf("M  multi-input-acc=%08x\n", acc);
    return 0;
}
