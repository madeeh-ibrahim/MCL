/*
 * ============================================================================
 * MCL_VDF128_T4 v4 -- clocked map: the 64-bit iteration index enters every iteration
 * Doc ID: MCL-VDF128-T4-2026-0925-004  (additive over the v1/v2/v3 headers; engine untouched)
 * ============================================================================
 * v4 == v3 weights (the derivation, its KDF label "VDF128-T4-v3-kdf" included, is byte-identical,
 * so that every weight-distribution measurement of version 3 applies verbatim), v3 initialisation
 * and v3 table. What changes: (1) the iteration number i (64-bit, counted from 0 at the first
 * burn-in iteration) is injected into the state before the four Gauss-Seidel word updates of
 * iteration i, through an injective encoding tau(i) that touches every word (one modular add per
 * word on the dependency chain; the products depend on i alone and are off the chain);
 * (2) the output tag is "VDF128-T4-v4-out" (16 ASCII + 8 NUL).
 *   lo = i mod 2^32, hi = floor(i / 2^32);  A = 0x9E3779B1, B = 0x85EBCA77, C = 0xC2B2AE3D (odd)
 *   t1 += lo;  t2 += lo*A + hi;  t3 += lo*B + hi*A;  t4 += lo*C + hi*B        (all mod 2^32)
 * Why: a walk that touches the honest path is useful to a parallel adversary only if it touches it
 * at the same iteration number; in the ideal model the success of any q-query adversary at depth
 * below N is at most (q+1)/2^s (Paper 4 v4, Theorem 1). The unclocked map (v3) admits the generic
 * memory-bounded attack of order min(P,M)*N^2/2^s found in review #16 (2026-09-25).
 * ============================================================================
 */
#ifndef MCL_VDF128_T4_V4_HPP
#define MCL_VDF128_T4_V4_HPP
#include "mcl_vdf128_t4_v3.hpp"
#define VDF128_V4_OUT_TAG "VDF128-T4-v4-out"
static const uint32_t VDF128_V4_CLOCK_A = 0x9E3779B1u, VDF128_V4_CLOCK_B = 0x85EBCA77u, VDF128_V4_CLOCK_C = 0xC2B2AE3Du;
inline void mcl_vdf128v4_clock(VDF128_State& s, uint64_t i) {
    const uint32_t lo = (uint32_t)i, hi = (uint32_t)(i >> 32);
    s.t1 += lo;
    s.t2 += lo * VDF128_V4_CLOCK_A + hi;
    s.t3 += lo * VDF128_V4_CLOCK_B + hi * VDF128_V4_CLOCK_A;
    s.t4 += lo * VDF128_V4_CLOCK_C + hi * VDF128_V4_CLOCK_B;
}
// one clocked iteration: iteration number i (the clock), then the v3 four-word Gauss-Seidel update
inline void mcl_vdf128v4_iterate(VDF128_State& s, const MCL_Q30_Sextet& W, int64_t kp, uint64_t i) {
    mcl_vdf128v4_clock(s, i);
    mcl_q30t4_iterate_raw(s.t1, s.t2, s.t3, s.t4, W, kp);
}
// n clocked iterations starting at clock i0 (iterations i0, i0+1, ..., i0+n-1).
// The clock is maintained incrementally: tau(i+1) = tau(i) + (1, A, B, C) mod 2^32 while lo does not wrap,
// and is recomputed from (lo, hi) when it does (once per 2^32 iterations); the state sequence is identical
// to calling mcl_vdf128v4_iterate(s, W, kp, i0 + k) for each k (the KAT harness checks this identity).
inline void mcl_vdf128v4_run(VDF128_State& s, const MCL_Q30_Sextet& W, int64_t kp, uint64_t i0, uint64_t n) {
    uint32_t lo = (uint32_t)i0, hi = (uint32_t)(i0 >> 32);
    uint32_t c1 = lo, c2 = lo * VDF128_V4_CLOCK_A + hi, c3 = lo * VDF128_V4_CLOCK_B + hi * VDF128_V4_CLOCK_A, c4 = lo * VDF128_V4_CLOCK_C + hi * VDF128_V4_CLOCK_B;
    for (uint64_t k = 0; k < n; k++) {
        s.t1 += c1; s.t2 += c2; s.t3 += c3; s.t4 += c4;
        mcl_q30t4_iterate_raw(s.t1, s.t2, s.t3, s.t4, W, kp);
        if (++lo == 0u) { hi++; c1 = lo; c2 = lo * VDF128_V4_CLOCK_A + hi; c3 = lo * VDF128_V4_CLOCK_B + hi * VDF128_V4_CLOCK_A; c4 = lo * VDF128_V4_CLOCK_C + hi * VDF128_V4_CLOCK_B; }
        else { c1 += 1u; c2 += VDF128_V4_CLOCK_A; c3 += VDF128_V4_CLOCK_B; c4 += VDF128_V4_CLOCK_C; }
    }
}
inline MCL_Q30_Sextet mcl_vdf128v4_weights(const uint8_t* x, size_t xlen) { return mcl_vdf128v3_weights(x, xlen); }
inline VDF128_State mcl_vdf128v4_eval_state(const uint8_t* x, size_t xlen, uint64_t N, uint64_t B = 10000, double K = K_DEFAULT) {
    const MCL_Q30_Sextet W = mcl_vdf128v4_weights(x, xlen);
    const int64_t kp = mcl_q30_K_phase(K);
    VDF128_State s = mcl_vdf128_init(x, xlen);
    mcl_vdf128v4_run(s, W, kp, 0, B + N);
    return s;
}
inline void mcl_vdf128v4_output(const VDF128_State& s, const uint8_t* x, size_t xlen, uint64_t N, uint8_t y[32]) {
    uint8_t buf[16 + 32 + 8 + 24];
    auto put32 = [&](int o, uint32_t v) { buf[o]=(uint8_t)v; buf[o+1]=(uint8_t)(v>>8); buf[o+2]=(uint8_t)(v>>16); buf[o+3]=(uint8_t)(v>>24); };
    put32(0,s.t1); put32(4,s.t2); put32(8,s.t3); put32(12,s.t4);
    mcl_sha256(x, xlen, buf + 16);
    for (int i = 0; i < 8; i++) buf[48+i] = (uint8_t)(N >> (i*8));
    static const char otag[24] = VDF128_V4_OUT_TAG;   // 16 ASCII bytes + 8 NUL
    std::memcpy(buf + 56, otag, 24);
    mcl_sha256(buf, sizeof(buf), y);
}
inline void mcl_vdf128v4_eval(const uint8_t* x, size_t xlen, uint64_t N, uint8_t y[32], uint64_t B = 10000) {
    VDF128_State s = mcl_vdf128v4_eval_state(x, xlen, N, B); mcl_vdf128v4_output(s, x, xlen, N, y);
}
#endif
