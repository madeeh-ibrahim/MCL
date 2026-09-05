/* mcl_vdf128v3_xplat.cpp — Doc ID MCL-VDF128-XPLAT-2026-0905-003 (v2 of MCL-VDF128-XPLAT-2026-0817-001)
 * Cross-platform bit-exactness fingerprint for VDF128_T4 v3 (per-input weights, neutral strings).
 * Prints ONLY deterministic values. Identical output across arch/compiler/-O level is the claim under test. */
#include "mcl_vdf128_t4_v3.hpp"
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
    const char* x = "VDF128-T4-KAT-01";
    MCL_Q30_Sextet W = mcl_vdf128v3_weights((const uint8_t*)x, std::strlen(x));
    std::printf("W  %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
      W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34);
    VDF128_State i0 = mcl_vdf128_init((const uint8_t*)x, std::strlen(x));
    std::printf("I  %08x %08x %08x %08x\n", i0.t1,i0.t2,i0.t3,i0.t4);
    VDF128_State sB = mcl_vdf128v3_eval_state((const uint8_t*)x, std::strlen(x), 0);
    std::printf("B  %08x %08x %08x %08x\n", sB.t1,sB.t2,sB.t3,sB.t4);
    VDF128_State sF = mcl_vdf128v3_eval_state((const uint8_t*)x, std::strlen(x), 100000);
    std::printf("F  %08x %08x %08x %08x\n", sF.t1,sF.t2,sF.t3,sF.t4);
    uint8_t y[32]; mcl_vdf128v3_eval((const uint8_t*)x, std::strlen(x), 100000, y);
    std::printf("Y  "); for(int i=0;i<32;i++) std::printf("%02x", y[i]); std::printf("\n");
    const MCL_Q30_Sextet WW = mcl_vdf128v3_weights((const uint8_t*)"xplat-fold", 10);
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    VDF128_State s = mcl_vdf128_init((const uint8_t*)"xplat-fold", 10);
    uint32_t fold = 0;
    for (int64_t i = 0; i < 5000000; i++) { mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,WW,kp); fold = (fold * 1000003u) ^ (s.t1 ^ s.t2 ^ s.t3 ^ s.t4); }
    std::printf("L  fold=%08x state=%08x %08x %08x %08x\n", fold, s.t1,s.t2,s.t3,s.t4);
    uint32_t acc = 0;
    for (int k = 0; k < 8; k++) { char xi[32]; std::snprintf(xi,sizeof xi,"xplat-%d",k); uint8_t yy[32]; mcl_vdf128v3_eval((const uint8_t*)xi, std::strlen(xi), 25000, yy); for (int b = 0; b < 32; b++) acc = (acc*16777619u) ^ yy[b]; }
    std::printf("M  multi-input-acc=%08x\n", acc);
    return 0;
}
