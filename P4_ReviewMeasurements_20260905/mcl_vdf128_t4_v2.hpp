/*
 * ============================================================================
 * MCL_VDF128_T4 v2.0 -- 128-bit-state integer VDF path with PER-INPUT weights
 * Doc ID: MCL-VDF128-T4-2026-0905-002        (additive over v1, 2026-09-05)
 * ============================================================================
 * WHY v2
 *   v1 derived the twelve coupling weights from a fixed public constant, so the
 *   map F was the same for every input x. Against a fixed 128-bit map a generic
 *   Hellman / distinguished-point precomputation (W0 chain points, M stored
 *   distinguished points) lets an online walk of N steps jump ahead with
 *   probability ~ N*W0/2^128 -- for W0 = 2^80, N = 2^40 that is ~2^-8, far
 *   above the 2^-47 the v1 concrete conjecture claimed (Paper 4 referee-eye
 *   review 2026-09-05, R4-1). Nothing about the map is wrong; a 128-bit state
 *   is simply too small for a FIXED public map under preprocessing.
 *
 *   v2 removes the fixed map: the twelve weights are derived from
 *       h = SHA-256(x)
 *   through the sidecar's audited derivation mcl_t4_q30_params_from_key(h, 0)
 *   (KDF label "MCL-T4-Q30-v1", range [2, 2^30), p != q rule, seed-reachable
 *   translation-symmetry re-draw). Every input therefore evaluates its own
 *   map F_x; there is nothing input-independent left to precompute except
 *   SHA-256, the KDF and the sine table. The initial state is unchanged
 *   (t_i = LE32(h[4i..]) XOR LE32(h[16+4i..])); the output tag becomes
 *   "MCL-VDF128-T4-v2-out". Per-iteration cost is identical to v1.
 *
 * ADDITIVE: includes mcl_vdf128_t4.hpp (v1) read-only for VDF128_State and
 * mcl_vdf128_init; modifies NO existing function. Engine pins untouched.
 * ============================================================================
 */
#ifndef MCL_VDF128_T4_V2_HPP
#define MCL_VDF128_T4_V2_HPP

#include "mcl_vdf128_t4.hpp"

// Per-input weight derivation: W_x = params_from_key(SHA-256(x), challenge 0).
inline MCL_Q30_Sextet mcl_vdf128v2_weights(const uint8_t* x, size_t xlen) {
    uint8_t h[32];
    mcl_sha256(x, xlen, h);
    return mcl_t4_q30_params_from_key(h, /*challenge=*/0);
}

// Eval: burn-in B then N strictly sequential four-oscillator iterations of F_x.
inline VDF128_State mcl_vdf128v2_eval_state(const uint8_t* x, size_t xlen,
                                            uint64_t N, uint64_t B = 10000,
                                            double K = K_DEFAULT) {
    const MCL_Q30_Sextet W = mcl_vdf128v2_weights(x, xlen);
    const int64_t kp = mcl_q30_K_phase(K);
    VDF128_State s = mcl_vdf128_init(x, xlen);
    for (uint64_t i = 0; i < B + N; i++)
        mcl_q30t4_iterate_raw(s.t1, s.t2, s.t3, s.t4, W, kp);
    return s;
}

// Output finalization: y = SHA-256( state || SHA-256(x) || LE64(N) || tag ), tag = "MCL-VDF128-T4-v2-out" + 4 NUL.
inline void mcl_vdf128v2_output(const VDF128_State& s, const uint8_t* x,
                                size_t xlen, uint64_t N, uint8_t y[32]) {
    uint8_t buf[16 + 32 + 8 + 24];
    auto put32 = [&](int o, uint32_t v) {
        buf[o]=(uint8_t)v; buf[o+1]=(uint8_t)(v>>8);
        buf[o+2]=(uint8_t)(v>>16); buf[o+3]=(uint8_t)(v>>24);
    };
    put32(0,s.t1); put32(4,s.t2); put32(8,s.t3); put32(12,s.t4);
    mcl_sha256(x, xlen, buf + 16);
    for (int i = 0; i < 8; i++) buf[48+i] = (uint8_t)(N >> (i*8));
    static const char otag[24] = "MCL-VDF128-T4-v2-out\0\0\0";
    std::memcpy(buf + 56, otag, 24);
    mcl_sha256(buf, sizeof(buf), y);
}

inline void mcl_vdf128v2_eval(const uint8_t* x, size_t xlen, uint64_t N,
                              uint8_t y[32], uint64_t B = 10000) {
    VDF128_State s = mcl_vdf128v2_eval_state(x, xlen, N, B);
    mcl_vdf128v2_output(s, x, xlen, N, y);
}

#endif // MCL_VDF128_T4_V2_HPP
