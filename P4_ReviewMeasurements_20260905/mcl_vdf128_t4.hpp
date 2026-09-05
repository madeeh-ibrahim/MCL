/*
 * ============================================================================
 * MCL_VDF128_T4 v1.0 -- 128-bit-state integer VDF path (Paper 4, path-A rebuild)
 * Doc ID: MCL-VDF128-T4-2026-0817-001
 * ============================================================================
 * PURPOSE
 *   Replaces the two-oscillator Q30 path (mcl_q30_iterate_raw, 64-bit state)
 *   as the integer VDF substrate. That path has a MEASURED break at VDF
 *   scale: orbit closure with cycle length lambda = 1,671,196,332 (~2^30.6,
 *   rho ~2^31; independently confirmed 3x, 2026-07), and an initialization
 *   that collapses the input to s mod 2^32. This artifact fixes both:
 *
 *   (1) 128-bit reachable state: the four-oscillator integer engine
 *       mcl_q30t4_iterate_raw (keyed_q30_PQ sidecar v1.0.4, FPGA-proven,
 *       hardened) -- state (t1,t2,t3,t4), 4 x 32 bits. Random-mapping
 *       heuristic: expected rho ~ 2^64 >> any practical N (10^12 ~ 2^40).
 *
 *   (2) Real hash init: the input x (arbitrary bytes) enters through
 *       SHA-256; all 128 state bits depend cryptographically on every bit
 *       of x. No s-mod-2^32 structure, no multiply-only dispersion.
 *
 *   Output is SHA-256-finalized and bound to (x, N) -- output entropy and
 *   cross-input collision resistance rest on the hash, not the map.
 *
 * PUBLIC PARAMETERS (nothing-up-my-sleeve)
 *   The twelve integer coupling weights are derived by the sidecar's audited
 *   derivation from the PUBLIC constant key
 *       K_pub = SHA-256("MCL-VDF128-T4-v1 public parameters")
 *   with challenge 0. There is no secret: this is a public-delay primitive.
 *   The keyed variant (secret key) remains available exactly as in the
 *   sidecar; it is orthogonal to this spec.
 *
 * ADDITIVE ARTIFACT: includes mcl_core.hpp + mcl_keyed_q30.hpp read-only;
 * modifies NO existing function. Engine pins untouched.
 * ============================================================================
 */
#ifndef MCL_VDF128_T4_HPP
#define MCL_VDF128_T4_HPP

#include "../mcl_core.hpp"
#include "../keyed_q30_PQ/mcl_keyed_q30.hpp"
#include <cstring>

struct VDF128_State { uint32_t t1, t2, t3, t4; };

// Public parameter derivation (deterministic, nothing-up-my-sleeve).
inline MCL_Q30_Sextet mcl_vdf128_public_weights() {
    static const char* tag = "MCL-VDF128-T4-v1 public parameters";
    uint8_t kpub[32];
    mcl_sha256((const uint8_t*)tag, std::strlen(tag), kpub);
    return mcl_t4_q30_params_from_key(kpub, /*challenge=*/0);
}

// Hash init: x (arbitrary bytes) -> 128-bit state. h = SHA-256(x);
// t_i = LE32(h[4i..4i+3]) XOR LE32(h[16+4i..16+4i+3])  (all 256 hash bits enter).
inline VDF128_State mcl_vdf128_init(const uint8_t* x, size_t xlen) {
    uint8_t h[32];
    mcl_sha256(x, xlen, h);
    auto le32 = [&](int o) {
        return (uint32_t)h[o] | ((uint32_t)h[o+1] << 8) |
               ((uint32_t)h[o+2] << 16) | ((uint32_t)h[o+3] << 24);
    };
    VDF128_State s{ le32(0) ^ le32(16), le32(4) ^ le32(20),
                    le32(8) ^ le32(24), le32(12) ^ le32(28) };
    return s;
}

// Eval: burn-in B then N strictly sequential four-oscillator iterations.
// Returns final state; checkpoints (if wanted) are the raw 16-byte states --
// parameters are public, so raw-state disclosure is harmless here.
inline VDF128_State mcl_vdf128_eval_state(const uint8_t* x, size_t xlen,
                                          uint64_t N, uint64_t B = 10000,
                                          double K = K_DEFAULT) {
    static const MCL_Q30_Sextet W = mcl_vdf128_public_weights();
    const int64_t kp = mcl_q30_K_phase(K);
    VDF128_State s = mcl_vdf128_init(x, xlen);
    for (uint64_t i = 0; i < B + N; i++)
        mcl_q30t4_iterate_raw(s.t1, s.t2, s.t3, s.t4, W, kp);
    return s;
}

// Output finalization: y = SHA-256( state || SHA-256(x) || LE64(N) || tag ).
inline void mcl_vdf128_output(const VDF128_State& s, const uint8_t* x,
                              size_t xlen, uint64_t N, uint8_t y[32]) {
    uint8_t buf[16 + 32 + 8 + 24];
    auto put32 = [&](int o, uint32_t v) {
        buf[o]=(uint8_t)v; buf[o+1]=(uint8_t)(v>>8);
        buf[o+2]=(uint8_t)(v>>16); buf[o+3]=(uint8_t)(v>>24);
    };
    put32(0,s.t1); put32(4,s.t2); put32(8,s.t3); put32(12,s.t4);
    mcl_sha256(x, xlen, buf + 16);
    for (int i = 0; i < 8; i++) buf[48+i] = (uint8_t)(N >> (i*8));
    static const char* otag = "MCL-VDF128-T4-v1-out\0\0\0";
    std::memcpy(buf + 56, otag, 24);
    mcl_sha256(buf, sizeof(buf), y);
}

inline void mcl_vdf128_eval(const uint8_t* x, size_t xlen, uint64_t N,
                            uint8_t y[32], uint64_t B = 10000) {
    VDF128_State s = mcl_vdf128_eval_state(x, xlen, N, B);
    mcl_vdf128_output(s, x, xlen, N, y);
}

#endif // MCL_VDF128_T4_HPP
