// Replicates census (E) of p4_vdf128v3_distinguisher.cpp exactly (same 2^18 inputs "sym-stat-%u",
// same old-rule derivation) and adds the counts the paper's sentence needs: overlap and "neither".
#include "mcl_vdf128_t4_v3.hpp"
#include <cstdio>
static int kernel_has(const int64_t w[12], unsigned v) {
    static const int I[6] = {0,0,0,1,1,2}, J[6] = {1,2,3,2,3,3};
    for (int e = 0; e < 6; e++) {
        unsigned p = (unsigned)(w[2*e] & 1), q = (unsigned)(w[2*e+1] & 1);
        unsigned r1 = (q << I[e]) | (p << J[e]), r2 = (p << I[e]) | (q << J[e]);
        if (__builtin_popcount(r1 & v) & 1) return 0;
        if (__builtin_popcount(r2 & v) & 1) return 0;
    }
    return 1;
}
int main() {
    const uint32_t NI = 1u << 18; uint32_t def = 0, sw_n = 0, gl_n = 0, both = 0, neither = 0, sw_def = 0, gl_def = 0;
    for (uint32_t i = 0; i < NI; i++) {
        char buf[32]; int L = std::snprintf(buf, sizeof buf, "sym-stat-%u", i); uint8_t h[32]; mcl_sha256((const uint8_t*)buf, (size_t)L, h);
        MCL_Q30_Sextet Wo = mcl_vdf128v3_params_from_key_oldrule(h, 0);
        int64_t wo[12] = {Wo.p12,Wo.q12,Wo.p13,Wo.q13,Wo.p14,Wo.q14,Wo.p23,Wo.q23,Wo.p24,Wo.q24,Wo.p34,Wo.q34};
        bool d = mcl_vdf128v3_parity_rank(wo) < 4;
        static const int I[6] = {0,0,0,1,1,2}, J[6] = {1,2,3,2,3,3}; bool sw = false;
        for (int word = 0; word < 4 && !sw; word++) { bool alleven = true; for (int e = 0; e < 6; e++) if (I[e] == word || J[e] == word) { if ((wo[2*e] & 1) || (wo[2*e+1] & 1)) alleven = false; } if (alleven) sw = true; }
        bool gl = true; for (int e = 0; e < 6; e++) if (((wo[2*e] ^ wo[2*e+1]) & 1)) gl = false;
        def += d; sw_n += sw; gl_n += gl; both += (sw && gl); neither += (d && !sw && !gl); sw_def += (sw && d); gl_def += (gl && d);
    }
    std::printf("old-rule census over %u inputs (identical inputs to the record):\n", NI);
    std::printf("  rank-deficient          %.3f%%  (%u)\n", 100.0*def/NI, def);
    std::printf("  single-word all-even    %.3f%%  (%u)\n", 100.0*sw_n/NI, sw_n);
    std::printf("  global equal-parity     %.3f%%  (%u)\n", 100.0*gl_n/NI, gl_n);
    std::printf("  single AND global       %.3f%%  (%u)   <- the paper states 0.04%%\n", 100.0*both/NI, both);
    std::printf("  deficient, neither case %.3f%%  (%u)\n", 100.0*neither/NI, neither);
    std::printf("  check: single + global - both + neither = %.3f%%\n", 100.0*(sw_n + gl_n - both + neither)/NI);
    std::printf("  (sanity: single subset of deficient %u/%u, global subset %u/%u)\n", sw_def, sw_n, gl_def, gl_n);
    return 0;
}
