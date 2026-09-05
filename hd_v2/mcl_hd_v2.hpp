// ============================================================================
// mcl_hd_v2.hpp — Hierarchical channel-identity derivation, version 2
// PURPOSE: one-way index mixing for derive_child (Paper 5 §III), additive over
//          engine mcl_core.hpp 8.1.3 (which is NOT modified).
// Version: 1.0.0 (2026-09-05)   Doc ID: MCL-HD-V2-2026-0905-001
//
// WHY v2: in derive_child (v1) the 32 raw bytes R of the parent run are the same
// for every index i, and i enters only as a PUBLIC, INVERTIBLE mask
// (raw[0:8] ^= fmix64(i), raw[8:16] ^= fmix64(i)*0x9E37..15). Two consequences,
// both measured on 2026-09-05 (02_Engine_Code/P5_ReviewMeasurements_20260905/):
//   (a) SIBLING RECOVERY: from the p-values of three observed children the parent
//       block R_lo is recovered by enumerating 2^64/(M-2) candidates (2^34 at
//       M = 1e9: 23.8 s single-thread), after which every sibling at every index
//       is computable without the seed or the parent pair;
//   (b) PARITY LOCK: the odd multiplier preserves bit 0 and the even modulus M-2
//       preserves parity, so parity(p) XOR parity(q) is constant per parent
//       (q odd in 91.8 % of children of (3,5); 59.47 % non-coprime pre-gcd).
// v2 replaces the mask by a one-way mixing d = SHA-256("MCL-HD-v2" || R || LE64(i))
// and takes (c1, c2) from d[0:8], d[8:16]: R is hidden behind SHA-256 preimage
// resistance, the two words are independent (no parity lock), and all 32 raw
// bytes contribute. Everything else (range map, p != q, coprimality loop, the
// Step-4 resonance screen of derive_child_safe) is byte-for-byte the v1 logic.
// The Tech Guide (rev. 1.2, line 304) had recorded this fix as "recommended,
// not yet implemented".
// ============================================================================
#ifndef MCL_HD_V2_HPP
#define MCL_HD_V2_HPP
#include "mcl_core.hpp"
#include <cstring>

#define MCL_HD_V2_VERSION "1.0.0"

inline DerivedKey derive_child_v2(uint64_t seed, int64_t p_parent, int64_t q_parent,
                                  int64_t index, int64_t max_val = 1000000,
                                  double K = K_DEFAULT) {
#if !defined(MCL_UNSAFE_ALLOW_INVALID)
    assert(max_val >= 4 && "max_val must be >= 4 for distinct p,q in [2,max_val-1]");
    if (max_val < 4) {
        std::fprintf(stderr, "FATAL: derive_child_v2 max_val must be >= 4 (got %lld)\n",
            (long long)max_val);
        std::abort();
    }
#endif
    DerivedKey result;
    result.index = index;
    // Steps 1: parent engine run -> 32 raw bytes (index-independent, as in v1)
    MCL_T2 eng(seed, p_parent, q_parent, K);
    uint8_t raw[32];
    eng.gen_bytes(raw, 32);
    // Step 2 (v2): one-way index mixing. d = SHA-256("MCL-HD-v2" || raw[0:32] || LE64(index))
    uint8_t msg[9 + 32 + 8];
    std::memcpy(msg, "MCL-HD-v2", 9);
    std::memcpy(msg + 9, raw, 32);
    for (int b = 0; b < 8; b++) msg[41 + b] = (uint8_t)(((uint64_t)index) >> (8 * b));
    uint8_t d[32];
    mcl_sha256(msg, sizeof(msg), d);
    // Step 3: map d[0:8], d[8:16] (little-endian words) to coupling weights in [2, max_val-1]
    uint64_t c1 = 0, c2 = 0;
    for (int b = 0; b < 8; b++) { c1 |= ((uint64_t)d[b]) << (8 * b); c2 |= ((uint64_t)d[8 + b]) << (8 * b); }
    int64_t pc = 2 + (int64_t)(c1 % (uint64_t)(max_val - 2));
    int64_t qc = 2 + (int64_t)(c2 % (uint64_t)(max_val - 2));
    if (pc == qc) { qc = 2 + ((qc - 2 + 1) % (max_val - 2)); }
    // coprimality loop, identical to v1
    {
        int64_t a = pc > qc ? pc : qc;
        int64_t b = pc > qc ? qc : pc;
        int64_t bumps = 0;
        while (true) {
            int64_t aa = a, bb = b;
            while (bb != 0) { int64_t t = bb; bb = aa % bb; aa = t; }
            if (aa == 1) break;
            qc = 2 + ((qc - 2 + 1) % (max_val - 2));
            if (qc == pc) qc = 2 + ((qc - 2 + 1) % (max_val - 2));
            a = pc > qc ? pc : qc;
            b = pc > qc ? qc : pc;
            bumps++;
            if (bumps > max_val) { result.valid = false; secure_zero(raw, 32); secure_zero(d, 32); return result; }
        }
    }
    secure_zero(raw, 32); secure_zero(msg, sizeof(msg)); secure_zero(d, 32);
    result.p = pc;
    result.q = qc;
    result.valid = true;
    return result;
}

// derive_child_safe_v2: the v1 derive_child_safe (Step-4 resonance screen and
// index-retry policy) lifted verbatim from mcl_core.hpp 8.1.3, calling derive_child_v2.
inline DerivedKey derive_child_safe_v2(uint64_t seed, int64_t p_parent,
                                    int64_t q_parent, int64_t index,
                                    int64_t max_val = 1000000,
                                    double K = K_DEFAULT,
                                    int max_attempts = 100) {
    int64_t try_idx = index;
 // v6.0.0: 100 KB buffer moved off the stack. A stack array this large can
 // overflow a small secondary-thread stack (256 KB-1 MB on some platforms,
 // smaller on embedded/eSIM targets this code is documented to serve).
 // std::vector heap-allocates once here (outside the retry loop), so the
 // "allocated once, reused across retries" property is preserved.
 std::vector<uint8_t> test_buf_vec(100000);
 uint8_t* test_buf = test_buf_vec.data();
    for (int a = 0; a < max_attempts; a++, try_idx++) {
        DerivedKey dk = derive_child_v2(seed, p_parent, q_parent,
                                     try_idx, max_val, K);
 // K_min(p,q) safety check: skip pairs where K is below the chaos
 // threshold MCL_K_MIN_NUMERATOR/(p+q). Without this, MCL_T2 would
 // abort below. With this, the retry loop simply moves to the next idx.
        const double K_min_pq = MCL_K_MIN_NUMERATOR
                              / ((double)dk.p + (double)dk.q);
        if (K < K_min_pq) continue;
 // Verify chaoticity: generate test output and check chi-square
        MCL_T2 test_eng(seed, dk.p, dk.q, K);
        test_eng.gen_bytes(test_buf, 100000);
        double chi_val = chi_square(test_buf, 100000);
        if (chi_val < CHI2_THRESHOLD) {
            dk.index = try_idx;
            return dk;
        }
    }
 // All attempts exhausted -- return invalid
    DerivedKey fail;
    fail.p = 0; fail.q = 0; fail.valid = false; fail.index = index;
    return fail;
}

#endif // MCL_HD_V2_HPP
