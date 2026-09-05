/*
 * ============================================================================
 * MCL_VDF128_T4 v3 -- 128-bit-state integer VDF path, per-input weights, NEUTRAL domain strings
 * Doc ID: MCL-VDF128-T4-2026-0905-003  (additive over v1/v2 headers; engine untouched)
 * ============================================================================
 * v3 == v2 map, init and output structure. Only the byte strings that enter the
 * derivation and the finalization change, so that the public specification carries
 * no project name:  KDF label "VDF128-T4-v3-kdf" (was the sidecar's "MCL-T4-Q30-v1"),
 * output tag "VDF128-T4-v3-out" + 8 NUL (24 bytes; was "MCL-VDF128-T4-v2-out" + 4 NUL).
 * Weight derivation: range [2, 2^30), p != q pair rule, and a FULL-RANK PARITY-MATRIX re-draw that
 * excludes every translation symmetry of the map (replaces the seed-reachable-symmetry test of the sidecar).
 * ============================================================================
 */
#ifndef MCL_VDF128_T4_V3_HPP
#define MCL_VDF128_T4_V3_HPP
#include "mcl_vdf128_t4.hpp"
#define VDF128_V3_KDF_LABEL "VDF128-T4-v3-kdf"
#define VDF128_V3_OUT_TAG   "VDF128-T4-v3-out"

// Translation symmetries of the argument structure a_ij = p*t_j - q*t_i (mod 2^32): a state offset
// delta = (d1..d4) commutes with the map iff p_ij*d_j - q_ij*d_i == 0 and p_ij*d_i - q_ij*d_j == 0 (mod 2^32)
// for all six pairs. A non-zero solution exists iff the 12x4 PARITY matrix (rows q*e_i + p*e_j and
// p*e_i + q*e_j, all mod 2) is rank-deficient over GF(2): any kernel vector mod 2 lifts to 2^31*delta,
// and any kernel element mod 2^32, divided by its largest common power of two, is a kernel vector mod 2.
// This subsumes the seed-reachable global half-turn test (all p == q mod 2) and the single-word
// half-turn (all six weights touching a word even), found by the differential probe of 2026-09-05.
inline int mcl_vdf128v3_parity_rank(const int64_t w[12]) {
    static const int I[6] = {0,0,0,1,1,2}, J[6] = {1,2,3,2,3,3};
    unsigned rows[12]; int n = 0;
    for (int e = 0; e < 6; e++) {
        unsigned p = (unsigned)(w[2*e] & 1), q = (unsigned)(w[2*e+1] & 1);
        rows[n++] = (q << I[e]) | (p << J[e]);   // from a_ij = p t_j - q t_i
        rows[n++] = (p << I[e]) | (q << J[e]);   // from a_ji = p t_i - q t_j
    }
    int rank = 0;
    for (int bit = 0; bit < 4; bit++) {
        int piv = -1; for (int r = rank; r < 12; r++) if ((rows[r] >> bit) & 1u) { piv = r; break; }
        if (piv < 0) continue;
        unsigned t = rows[piv]; rows[piv] = rows[rank]; rows[rank] = t;
        for (int r = 0; r < 12; r++) if (r != rank && ((rows[r] >> bit) & 1u)) rows[r] ^= rows[rank];
        rank++;
    }
    return rank;
}
inline MCL_Q30_Sextet mcl_vdf128v3_params_from_key(const uint8_t key[32], uint64_t challenge = 0) {
    uint8_t info[8];
    for (int i = 0; i < 8; i++) info[i] = (uint8_t)(challenge >> (i * 8));
    uint8_t kd[96];
    mcl_kdf256(key, VDF128_V3_KDF_LABEL, info, sizeof(info), kd, sizeof(kd));
    constexpr int64_t W_RANGE = (int64_t)((1LL << 30) - 2);
    int64_t w[12];
    for (int lane = 0; lane < 12; lane++) {
        uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)kd[lane * 8 + i] << (i * 8);
        w[lane] = 2 + (int64_t)(v % (uint64_t)W_RANGE);
    }
    auto fix_pair = [](int64_t& p, int64_t& q) { if (p == q) q = 2 + ((q - 2 + 1) % W_RANGE); };
    for (int e = 0; e < 6; e++) fix_pair(w[2*e], w[2*e+1]);
    for (int k = 0; k < 96; k++) {
        if (mcl_vdf128v3_parity_rank(w) == 4) break;        // no translation symmetry of any form
        const int lane = 11 - (k % 12);
        w[lane] = 2 + ((w[lane] - 2 + 1) % W_RANGE);
        fix_pair(w[lane & ~1], w[lane | 1]);
    }
    return MCL_Q30_Sextet{ (uint32_t)w[0],(uint32_t)w[1],(uint32_t)w[2],(uint32_t)w[3],(uint32_t)w[4],(uint32_t)w[5],
                           (uint32_t)w[6],(uint32_t)w[7],(uint32_t)w[8],(uint32_t)w[9],(uint32_t)w[10],(uint32_t)w[11] };
}
inline MCL_Q30_Sextet mcl_vdf128v3_params_from_key_oldrule(const uint8_t key[32], uint64_t challenge = 0) {
    uint8_t info[8];
    for (int i = 0; i < 8; i++) info[i] = (uint8_t)(challenge >> (i * 8));
    uint8_t kd[96];
    mcl_kdf256(key, VDF128_V3_KDF_LABEL, info, sizeof(info), kd, sizeof(kd));
    constexpr int64_t W_RANGE = (int64_t)((1LL << 30) - 2);
    int64_t w[12];
    for (int lane = 0; lane < 12; lane++) {
        uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)kd[lane * 8 + i] << (i * 8);
        w[lane] = 2 + (int64_t)(v % (uint64_t)W_RANGE);
    }
    auto fix_pair = [](int64_t& p, int64_t& q) { if (p == q) q = 2 + ((q - 2 + 1) % W_RANGE); };
    for (int e = 0; e < 6; e++) fix_pair(w[2*e], w[2*e+1]);
    for (int k = 0; k < 96; k++) {
        MCL_Q30_Sextet probe{ (uint32_t)w[0],(uint32_t)w[1],(uint32_t)w[2],(uint32_t)w[3],(uint32_t)w[4],(uint32_t)w[5],
                              (uint32_t)w[6],(uint32_t)w[7],(uint32_t)w[8],(uint32_t)w[9],(uint32_t)w[10],(uint32_t)w[11] };
        if (!mcl_t4_q30_has_reachable_symmetry(probe)) break;
        const int lane = 11 - (k % 12);
        w[lane] = 2 + ((w[lane] - 2 + 1) % W_RANGE);
        fix_pair(w[lane & ~1], w[lane | 1]);
    }
    return MCL_Q30_Sextet{ (uint32_t)w[0],(uint32_t)w[1],(uint32_t)w[2],(uint32_t)w[3],(uint32_t)w[4],(uint32_t)w[5],
                           (uint32_t)w[6],(uint32_t)w[7],(uint32_t)w[8],(uint32_t)w[9],(uint32_t)w[10],(uint32_t)w[11] };
}
inline MCL_Q30_Sextet mcl_vdf128v3_weights(const uint8_t* x, size_t xlen) {
    uint8_t h[32]; mcl_sha256(x, xlen, h); return mcl_vdf128v3_params_from_key(h, 0);
}
inline VDF128_State mcl_vdf128v3_eval_state(const uint8_t* x, size_t xlen, uint64_t N, uint64_t B = 10000, double K = K_DEFAULT) {
    const MCL_Q30_Sextet W = mcl_vdf128v3_weights(x, xlen);
    const int64_t kp = mcl_q30_K_phase(K);
    VDF128_State s = mcl_vdf128_init(x, xlen);
    for (uint64_t i = 0; i < B + N; i++) mcl_q30t4_iterate_raw(s.t1, s.t2, s.t3, s.t4, W, kp);
    return s;
}
inline void mcl_vdf128v3_output(const VDF128_State& s, const uint8_t* x, size_t xlen, uint64_t N, uint8_t y[32]) {
    uint8_t buf[16 + 32 + 8 + 24];
    auto put32 = [&](int o, uint32_t v) { buf[o]=(uint8_t)v; buf[o+1]=(uint8_t)(v>>8); buf[o+2]=(uint8_t)(v>>16); buf[o+3]=(uint8_t)(v>>24); };
    put32(0,s.t1); put32(4,s.t2); put32(8,s.t3); put32(12,s.t4);
    mcl_sha256(x, xlen, buf + 16);
    for (int i = 0; i < 8; i++) buf[48+i] = (uint8_t)(N >> (i*8));
    static const char otag[24] = VDF128_V3_OUT_TAG;   // 16 ASCII bytes + 8 NUL
    std::memcpy(buf + 56, otag, 24);
    mcl_sha256(buf, sizeof(buf), y);
}
inline void mcl_vdf128v3_eval(const uint8_t* x, size_t xlen, uint64_t N, uint8_t y[32], uint64_t B = 10000) {
    VDF128_State s = mcl_vdf128v3_eval_state(x, xlen, N, B); mcl_vdf128v3_output(s, x, xlen, N, y);
}
#endif
