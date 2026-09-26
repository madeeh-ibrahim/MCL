/*
 * ============================================================================
 * MCL Keyed Q30 Integer Engine -- mcl_keyed_q30.hpp
 * MCL (Madeeh Chaotic Lock) -- FPU-free, key-bound, post-quantum extension
 * ============================================================================
 *
 * Document ID:   MCL-KEYED-Q30-2026-0712-001
 * Version:       1.0.6  (2026-08-22: SYMMETRY REJECTION in
 *                 mcl_t4_q30_params_from_key(). The Q30 map commutes with any
 *                 state translation b that leaves every coupling argument
 *                 p*t_j - q*t_i invariant; seed offsets D reach b_i = D*omega_i
 *                 (hash_seed is the identity for seeds <= 2^52), so a weight
 *                 set admits a SEED-REACHABLE symmetry iff all twelve terms
 *                 (p*omega_j - q*omega_i), (p*omega_i - q*omega_j) are even
 *                 (then D = 2^31 works; ~2^-9 of keys). For such keys seeds s
 *                 and s+2^31 gave keystreams differing by a constant XOR 0x80
 *                 and commit32 differing in 4/256 bits (record
 *                 T4_CycleStructure/T4_CYCLE_RECORD_20260822.md sec.5a, tools
 *                 MCL-T4-CYCLE-2026-0822-003/004). v1.0.6 re-draws such weight
 *                 sets DETERMINISTICALLY (fail-closed, like the p==q fix):
 *                 perturb one lane by +1 (wrapping in [2,2^30)) and re-check.
 *                 Output changes ONLY for the ~0.2% weak weight sets; the KAT
 *                 key {0..31} has a trivial symmetry group, so the canonical
 *                 KATs are UNCHANGED (T4-Q30 commit CRC-32 0x58C99E3E, cascade
 *                 0xF7C81BC4). mcl_core.hpp NOT touched (sha 718d62658bcc...).
 *                 Prior v1.0.5 bytes archived at
 *                 _backups/mcl_keyed_q30_v1.0.5_pre_nosym_20260822.hpp.
 *                 New helper: mcl_t4_q30_has_reachable_symmetry().)
 *                 (v1.0.5: docs-only: patent list adds PCT/IB2026/058860,
 *                 filed 21 Aug 2026; prior v1.0.4 bytes archived at
 *                 _backups/mcl_keyed_q30_v1.0.4_pre_patent4num_20260821.hpp)
 *                 (v1.0.4: engine of record: mcl_core.hpp v8.1.0 -- purely
 *                 additive over v8.0.0 (sec.4b device-bound derivation; no
 *                 path this sidecar uses changed), so it stays numerically
 *                 byte-identical to the v8.0.0 / v7.x / v6.1.0 builds these
 *                 results were measured on. v1.0.1 added the C-1/C-2/C-3/N-3 hardening;
 *                 v1.0.2 was a banner/provenance metadata update ONLY.
 *                 v1.0.3 adds the OPT-IN constant-time sine
 *                 (-DMCL_Q30_CONSTANT_TIME_SIN) that closes N-1 (the
 *                 cache-timing / T-table channel) for the T4-Q30 flagship on
 *                 shared-cache SOFTWARE. It is ADDITIVE and OFF by default:
 *                 the DEFAULT build is byte-for-byte UNCHANGED -- the canonical
 *                 KAT is preserved (T4-Q30 commit CRC-32 = 0x58C99E3E), and the
 *                 constant-time build is itself byte-identical to the default
 *                 (same commit CRC 0x58C99E3E; same keystream). No KAT, CRC, or
 *                 keystream value changes in either build. mcl_core.hpp was NOT
 *                 touched by v1.0.3 -- the then-current v8.0.0 pin stayed
 *                 intact. See mcl_keyed_q30_ct_test.cpp for the byte-identity
 *                 + asm checks.
 *                 v1.0.4 is a banner/provenance metadata update ONLY: it names
 *                 the metadata-reconciled engine of record v8.1.0 (live sha
 *                 c171af4c...; the as-reviewed v8.1.0 bytes 647510e9... are
 *                 archived at ../_backup_pre_metadata_fix_20260718/) -- no
 *                 code changed; every KAT, CRC and keystream unchanged.)
 * Date:          August 22, 2026  (v1.0.5: Aug 21; v1.0.3: July 12, 2026)
 * Author:        Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:       madeeh.chaotic.lock@gmail.com
 * ORCID:         https://orcid.org/0009-0002-8562-8325
 * ============================================================================
 *
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673,
 *                 PCT/IB2026/058860 (filed 21 August 2026)
 *                 (+ planned fourth filing -- this file is its support anchor).
 * ============================================================================
 *
 * WHY THIS FILE EXISTS
 * ----------------------------------------------------------------------------
 * The v6.1.0 post-quantum keyed paths (mcl_t2_from_key / mcl_t4_from_key in
 * mcl_core.hpp) are Float64 -- they call std::sin on IEEE-754 doubles and need
 * an FPU + libm. The flagship MCL target (SIM / eSIM / iSIM secure elements,
 * ARM SecurCore SC000/SC300 = Cortex-M0/M3) has NO double-precision FPU, so the
 * only NIST PQ Category 5 path could not run on the very hardware it targets. The
 * FPU-free integer path that DID run (mcl_q30_iterate_raw) had no keyed 256-bit
 * construction (it caps p,q <= 2^30 and seeds from a single 64-bit value).
 *
 * This header closes that architectural gap with TWO FPU-free keyed engines,
 * both built only on integer arithmetic + the existing 65536-entry integer sin
 * LUT (MCL_Q30_Table) -- no float in the hot path:
 *
 *   (A) mcl_t4_q30_from_key  -- KEYED Q30 four-oscillator engine (12 integer
 *       coupling weights). Carries a full 256-bit key -> Grover 2^128 = NIST
 *       PQ Category 5 (AES-256-equivalent, highest), on FPU-less hardware. New dynamics; needs its own
 *       statistical + b_eff verification (see mcl_keyed_q30_test.cpp).
 *
 *   (B) mcl_cascade_q30      -- SECRET TEMPORAL CASCADE over the EXISTING
 *       two-oscillator Q30 integer engine (mcl_q30_iterate_raw). NOTE: that
 *       integer engine's own record is entropy 7.999796 / chi^2 282.41 /
 *       max|r| 0.002502 at 1 MB; full battery testing (BigCrush/PractRand) of
 *       the INTEGER Q30 engine is still PENDING. The published BigCrush
 *       160/160 (Paper 1, Run 2) was the Float64 two-channel LUT-sin
 *       multiplex -- a different realization -- NOT this integer engine.
 *       m epochs, each with a fresh key-derived (p,q), the
 *       carried state passing between epochs with ZERO intermediate output.
 *       The output depends jointly on every epoch's (p,q). Reuses verified
 *       dynamics -> fastest path to ship; security rests on the engine's
 *       measured backward-branching b_eff > 1 (one-wayness) per epoch.
 *
 * SECRET-ENTROPY ACCOUNTING (Grover bound; see mcl_pq_security in mcl_core.hpp)
 * ----------------------------------------------------------------------------
 *   (A) T4-Q30 : 12 weights in [2,2^30) -> 12*30 = 360-bit representation
 *                space >> 256. For any FIXED key, the probability that some
 *                OTHER key derives the same 12 weights is ~2^256/2^360 =
 *                ~2^-104 (union bound); the map is not literally injective on
 *                all 2^256 keys, but the EXPECTED key-entropy loss is
 *                ~2^-104 bits -- negligible. Brute-forceable secret = the
 *                full 256-bit key -> Grover 2^128  =>  NIST PQ Category 5.
 *                <-- structural, no protocol discipline (all 12 weights act
 *                every iter).
 *   (B) cascade : m epochs * ~59 bits/epoch (ordered coprime pair in [2,2^30])
 *                -> m=7 gives ~415-bit representation -> ~207 post-Grover under
 *                a joint search.  CAVEAT: sequential composition multiplies
 *                entropy ONLY if (i) no intermediate state is externalized
 *                (enforced here) AND (ii) the per-epoch map is non-invertible
 *                so the final output cannot be peeled back epoch-by-epoch. (ii)
 *                rests on the engine's measured b_eff>1 (mcl_extraction_security
 *                Exp7; mcl_beff_compounding). Under a hypothetical reversible
 *                claw/MITM attack the cube-root bound erodes m=5 to ~2^98, so
 *                m>=7 is mandated for margin. This is EMPIRICAL evidence, not a
 *                proof -- the cascade's "whereby joint search" is evidentiary.
 *
 * THREAT NOTE: the cascade's security is CONDITIONAL on protocol discipline
 * (no intermediate output ever leaked by any integrator). T4-Q30 is
 * misuse-resistant by construction. Prefer T4-Q30 as the flagship; the cascade
 * is the drop-in transitional path on top of the already-certified engine.
 *
 * TIMING / CONSTANT-TIME DEPLOYMENT NOTE (keyed path -- read before shipping):
 *   (N-1) The DEFAULT Q30 sine is a table lookup lut[a >> 16] whose index is
 *     derived from the SECRET coupling weights and state, so by default it is
 *     NOT constant-time -- a classic cache-timing (T-table) channel. Unlike the
 *     Float64 core (whose libm sin cannot be made CT), the integer path CAN be
 *     constant-time, and this reference NOW PROVIDES it: build the T4-Q30
 *     flagship with -DMCL_Q30_CONSTANT_TIME_SIN and the hot path routes through
 *     mcl_q30_sin_ct() -- an oblivious full-table scan that is BYTE-IDENTICAL to
 *     the fast LUT (same KATs/CRCs/keystream) but leaks no secret through the
 *     memory-access pattern (see the CONSTANT-TIME SINE block below). Cost:
 *     O(65536) reads/sine. So: on single-tenant / no-shared-cache hardware (the
 *     intended SIM/eSIM/iSIM/enclave target) the fast default LUT is already
 *     safe; for shared-cache SOFTWARE deployment, compile with the macro. (The
 *     macro covers the T4-Q30 flagship; the cascade path still uses the core
 *     fast LUT -- prefer the flagship where software CT matters.)
 *   (N-2) mcl_cascade_q30 key-setup runs a data-dependent gcd loop whose
 *     iteration count depends on the secret (p,q): a SETUP-TIME timing leak
 *     (once per key). The T4-Q30 flagship path has no gcd and is unaffected.
 *   (N-4) The cascade carries a 64-bit state (uint32 t1,t2); the T4 flagship is
 *     128-bit. The 64-bit width is cycle-safe ONLY within the cascade's short
 *     bounded run (burn-in + m*~256 iters + one SHA-256 commitment). NEVER
 *     repurpose the cascade as a long-running keystream generator -- use the
 *     128-bit T4-Q30 for keystreams; a 64-bit state risks cycling at long delays.
 *
 * BUILD (FPU-free target still builds the LUT once with std::sin at static
 * init; define MCL_Q30_USE_STATIC_LUT for a fully libm-free build):
 *   c++ -std=c++17 -O2 -I ../MCL_publish your_file.cpp
 * ============================================================================
 */

#ifndef MCL_KEYED_Q30_HPP
#define MCL_KEYED_Q30_HPP

#include "mcl_core.hpp"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <utility>

// ============================================================================
// CONSTANT-TIME SINE  -- closes N-1 (cache-timing / T-table channel) for the
// KEYED T4-Q30 flagship on shared-cache SOFTWARE targets.
// ----------------------------------------------------------------------------
// The default MCL_Q30_Table::sin_q30 evaluates lut[angle >> 16] -- a
// secret-indexed table load, i.e. the classic AES-T-table cache-timing side
// channel: on a shared cache an attacker who observes which line was touched
// recovers bits of the (secret-derived) index. On the intended FPGA / secure-
// element target this is a non-issue (single-tenant, no shared cache, and the
// RTL is timing-flat by construction -- SideChannel_Screen Task 1). It only
// bites when the keyed engine runs in shared-cache software.
//
// Define MCL_Q30_CONSTANT_TIME_SIN before including this header to route the
// T4-Q30 hot path through mcl_q30_sin_ct() instead. That evaluator returns the
// SAME int32 value as sin_q30 for every angle -- the keystream, KATs, CRCs and
// all published statistics are BYTE-IDENTICAL -- but reaches it by an oblivious
// full-table scan: every entry is read in a fixed order and the wanted one is
// selected with a branch-free mask, so the memory-access pattern and control
// flow carry no secret. Cost: O(65536) reads per sine (the price of
// obliviousness with this 16-bit LUT) -- acceptable for auth/VDF-rate use on
// the shared-cache software path; leave the macro OFF on the single-tenant
// hardware target, where the fast LUT is already safe and 65536x faster.
//
// SCOPE: the macro hardens the T4-Q30 flagship (mcl_q30t4_iterate_raw, below).
// The mcl_cascade_q30 path routes through mcl_core.hpp's mcl_q30_iterate_raw
// (the pinned engine of record) and is deliberately NOT rewired here; prefer
// the T4-Q30 flagship where constant-time software execution is required (it is
// also the misuse-resistant path -- see the THREAT NOTE above). N-2 (the
// cascade's data-dependent gcd at key-setup) is likewise a cascade-only,
// once-per-key setup leak, untouched by this timing fix.
//
// COMPILER CAVEAT: constant-time-ness of C++ is not standard-guaranteed. The
// mask-select is branchless and the `volatile` table view forces every load to
// be emitted (so the scan cannot be folded back into one indexed load), but a
// sufficiently aggressive toolchain could still reintroduce data-dependent
// behavior. For high-assurance builds, inspect the emitted asm (no indexed load
// on the secret; no conditional branch on the mask) -- see
// mcl_keyed_q30_ct_test.cpp for the byte-identity + access-pattern checks.
// ============================================================================

// Branch-free equality mask: returns 0xFFFFFFFF if x == 0 else 0x00000000,
// with no data-dependent branch and no undefined behavior (unsigned negate is
// defined mod 2^32). BearSSL-style EQ0.
inline uint32_t mcl_q30_ct_eq0_mask(uint32_t x) {
    uint32_t neg = 0u - x;                       // two's complement, mod 2^32
    return (uint32_t)0 - (uint32_t)(~(x | neg) >> 31);
}

// Constant-time sine: returns the SAME value as mcl_q30_table().sin_q30(angle),
// namely lut[angle >> 16], via an oblivious scan over the whole 65536-entry
// table. Bit-identical to sin_q30 for every angle by construction: only the
// i == idx term survives the mask, every other term contributes 0. Reads the
// table through a volatile view so all 65536 loads are actually emitted in a
// fixed order regardless of the secret index.
inline int32_t mcl_q30_sin_ct(const int32_t* lut, uint32_t angle) {
    const uint32_t idx = angle >> 16;            // the index sin_q30 would use
    const volatile int32_t* v = lut;             // force every load to be emitted
    uint32_t acc = 0;
    for (uint32_t i = 0; i < 65536u; ++i) {
        acc |= (uint32_t)v[i] & mcl_q30_ct_eq0_mask(i ^ idx);
    }
    return (int32_t)acc;
}

// Dispatch helper: the T4-Q30 hot path calls this so the fast/CT choice lives
// in exactly one place. Byte-identical output either way.
inline int32_t mcl_q30_sin_dispatch(const MCL_Q30_Table& tab, uint32_t a) {
#if defined(MCL_Q30_CONSTANT_TIME_SIN)
    return mcl_q30_sin_ct(tab.lut, a);
#else
    return tab.sin_q30(a);
#endif
}

// ============================================================================
// Q32 angular-frequency constants for the four oscillators (integer phase
// units = fraction of 2^32). omega1/2 reuse mcl_core's accessors; 3/4 added
// here from OMEGA_3 (sqrt2-1) and OMEGA_4 (e-2).
// ============================================================================
inline uint32_t mcl_q30_omega3() {
    static const uint32_t w = (uint32_t)(OMEGA_3 / MCL_TWO_PI * 4294967296.0);
    return w;
}
inline uint32_t mcl_q30_omega4() {
    static const uint32_t w = (uint32_t)(OMEGA_4 / MCL_TWO_PI * 4294967296.0);
    return w;
}

// ============================================================================
// (A) KEYED Q30 FOUR-OSCILLATOR ENGINE  -- NIST PQ Category 5, FPU-free
// ============================================================================

// Six coupling pairs (12 integer weights), each in [2, 2^30). Mirrors the
// Float64 CouplingSextet field order so the two engines stay comparable.
// Stored as uint32_t (not int64_t): the weights are < 2^30, so 32 bits hold
// them, and 32-bit storage is what makes the coupling-argument multiply a
// native 32x32->32 word multiply on an M0-class core (no __aeabi_lmul; see
// mcl_q30t4_iterate_raw and the m0_codegen_probe enablement evidence). It
// also fixes the engine working set at 72 bytes (Claim 13 / [0030], [0043]).
struct MCL_Q30_Sextet {
    uint32_t p12, q12, p13, q13, p14, q14;
    uint32_t p23, q23, p24, q24, p34, q34;
};

// One Gauss-Seidel iterate of the integer four-oscillator map. Each coupling
// term is scaled to the phase domain INDIVIDUALLY before summation (so no
// K*(sum of sines) intermediate can overflow -- the per-term-scaling property).
// All arithmetic is integer; periodicity is the natural uint32 wrap (mod 2^32).
#if defined(__clang__)
__attribute__((no_sanitize("integer")))
#endif
inline void mcl_q30t4_iterate_raw(uint32_t& t1, uint32_t& t2,
                                  uint32_t& t3, uint32_t& t4,
                                  const MCL_Q30_Sextet& w, int64_t K_phase) {
    const MCL_Q30_Table& tab = mcl_q30_table();
    // phase increment from one coupling argument (low 32 bits are what matter;
    // the int32->uint32 round-trip preserves them, as in mcl_q30_iterate_raw).
    auto inc = [&](uint32_t a) -> uint32_t {
        // Well-defined uint64 form (parity with mcl_core.hpp mcl_q30_iterate_raw,
        // hardened in core v7.0.0). Bit-identical to the former
        // (uint32_t)(int32_t)(int64_prod >> 30) in the low 32 bits for ALL inputs
        // -- the arithmetic-vs-logical shift difference lives only in bits >= 34,
        // which the uint32 truncation discards -- while avoiding the pre-C++20
        // implementation-defined negative right-shift and out-of-range int32
        // narrowing. Verified byte-identical against the KAT baseline.
        // CAVEAT (research mode only): the int64 product below can overflow if
        // K_phase is huge -- which happens only for K > 12 under
        // MCL_UNSAFE_ALLOW_INVALID (mcl_q30_K_phase's K<=12 cap is then off). In
        // every normal build K_phase is bounded (K<=12) so the product fits int64.
        // sin source is the fast LUT by default, or the oblivious constant-time
        // evaluator under -DMCL_Q30_CONSTANT_TIME_SIN (byte-identical either way;
        // see the CONSTANT-TIME SINE block above -- closes N-1 on shared cache).
        return (uint32_t)((uint64_t)((int64_t)K_phase * (int64_t)mcl_q30_sin_dispatch(tab, a)) >> 30);
    };
    auto arg = [](uint32_t p, uint32_t a, uint32_t q, uint32_t b) -> uint32_t {
        // Coupling argument, low 32 bits only (Claim 13 / [0030]): a native
        // 32x32->32 word multiply, no multi-word arithmetic. Bit-identical to
        // the former int64 form by the ring identity (P-Q) mod 2^32 ==
        // ((P mod 2^32)-(Q mod 2^32)) mod 2^32, which holds for every input
        // INCLUDING q*b > p*a (the difference's sign is irrelevant to the
        // truncation). Realizes the native-word multiply on M0 (no
        // __aeabi_lmul) -- verified by m0_codegen_probe.
        return (uint32_t)(p * a - q * b);
    };

    // Oscillator 1 <- 2,3,4
    uint32_t a12 = arg(w.p12, t2, w.q12, t1);
    uint32_t a13 = arg(w.p13, t3, w.q13, t1);
    uint32_t a14 = arg(w.p14, t4, w.q14, t1);
    t1 += mcl_q30_omega1() + inc(a12) + inc(a13) + inc(a14);

    // Oscillator 2 <- 1(updated),3,4   (Gauss-Seidel)
    uint32_t a21 = arg(w.p12, t1, w.q12, t2);
    uint32_t a23 = arg(w.p23, t3, w.q23, t2);
    uint32_t a24 = arg(w.p24, t4, w.q24, t2);
    t2 += mcl_q30_omega2() + inc(a21) + inc(a23) + inc(a24);

    // Oscillator 3 <- 1(updated),2(updated),4
    uint32_t a31 = arg(w.p13, t1, w.q13, t3);
    uint32_t a32 = arg(w.p23, t2, w.q23, t3);
    uint32_t a34 = arg(w.p34, t4, w.q34, t3);
    t3 += mcl_q30_omega3() + inc(a31) + inc(a32) + inc(a34);

    // Oscillator 4 <- 1,2,3 (all updated)
    uint32_t a41 = arg(w.p14, t1, w.q14, t4);
    uint32_t a42 = arg(w.p24, t2, w.q24, t4);
    uint32_t a43 = arg(w.p34, t3, w.q34, t4);
    t4 += mcl_q30_omega4() + inc(a41) + inc(a42) + inc(a43);
}

// Derive the 12 integer coupling weights from a 256-bit key (SHA-256 KDF).
// Each weight in [2, 2^30); each pair forced p != q by an in-range bump.
// v1.0.6 -- seed-reachable translation-symmetry test (see banner). Returns true
// iff ALL twelve oriented coupling terms (p*omega_j - q*omega_i) and
// (p*omega_i - q*omega_j) are even mod 2^32; then the seed offset D = 2^31
// maps every state t to a state t+b with F(t+b) = F(t)+b forever. The test is
// exact: any non-zero D needs every term == 0 mod 2^(32-v2(D)) >= 2.
inline bool mcl_t4_q30_has_reachable_symmetry(const MCL_Q30_Sextet& w) {
    const uint32_t om[4] = { mcl_q30_omega1(), mcl_q30_omega2(),
                             mcl_q30_omega3(), mcl_q30_omega4() };
    const uint32_t P[6] = { w.p12, w.p13, w.p14, w.p23, w.p24, w.p34 };
    const uint32_t Q[6] = { w.q12, w.q13, w.q14, w.q23, w.q24, w.q34 };
    const int I[6] = { 0, 0, 0, 1, 1, 2 }, J[6] = { 1, 2, 3, 2, 3, 3 };
    uint32_t acc = 0;
    for (int e = 0; e < 6; e++) {
        acc |= (uint32_t)(P[e] * om[J[e]] - Q[e] * om[I[e]]);   // forward argument
        acc |= (uint32_t)(P[e] * om[I[e]] - Q[e] * om[J[e]]);   // reverse argument
    }
    return (acc & 1u) == 0u;   // all twelve terms even  <=>  D = 2^31 commutes
}

inline MCL_Q30_Sextet mcl_t4_q30_params_from_key(const uint8_t key[32],
                                                 uint64_t challenge = 0) {
    uint8_t info[8];
    for (int i = 0; i < 8; i++) info[i] = (uint8_t)(challenge >> (i * 8));
    uint8_t kd[96]; // 12 weights * 8 bytes
    mcl_kdf256(key, "MCL-T4-Q30-v1", info, sizeof(info), kd, sizeof(kd));
    constexpr int64_t W_RANGE = (int64_t)((1LL << 30) - 2); // [2, 2^30)
    auto weight = [&](int lane) -> int64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)kd[lane * 8 + i] << (i * 8);
        return 2 + (int64_t)(v % (uint64_t)W_RANGE);
    };
    int64_t w[12];
    for (int i = 0; i < 12; i++) w[i] = weight(i);
    secure_zero(kd, sizeof(kd)); // erase key-derived KDF bytes (C-1)
    auto fix_pair = [](int64_t& p, int64_t& q) {
        if (p == q) q = 2 + ((q - 2 + 1) % W_RANGE);
    };
    fix_pair(w[0], w[1]);  fix_pair(w[2], w[3]);   fix_pair(w[4], w[5]);
    fix_pair(w[6], w[7]);  fix_pair(w[8], w[9]);   fix_pair(w[10], w[11]);
    // v1.0.6: fail-closed rejection of seed-reachable translation symmetries.
    // Deterministic re-draw: perturb lane (11 - k mod 12) by +1 (wrapping inside
    // [2, 2^30)), restore p != q for that pair, re-test. Terminates in a few
    // iterations (a lane change flips the parity of at least one term whenever
    // the partner omega is odd; the loop cycles through all lanes).
    for (int k = 0; k < 96; k++) {
        MCL_Q30_Sextet probe{ (uint32_t)w[0],(uint32_t)w[1], (uint32_t)w[2],(uint32_t)w[3],
                              (uint32_t)w[4],(uint32_t)w[5], (uint32_t)w[6],(uint32_t)w[7],
                              (uint32_t)w[8],(uint32_t)w[9], (uint32_t)w[10],(uint32_t)w[11] };
        if (!mcl_t4_q30_has_reachable_symmetry(probe)) break;
        const int lane = 11 - (k % 12);                  // start with q34 (partner omega3 is odd)
        w[lane] = 2 + ((w[lane] - 2 + 1) % W_RANGE);
        fix_pair(w[lane & ~1], w[lane | 1]);
    }
    // weights are in [2, 2^30) so each fits uint32_t without loss; the
    // explicit casts avoid a -Wnarrowing diagnostic on the braced init.
    MCL_Q30_Sextet result{ (uint32_t)w[0],(uint32_t)w[1], (uint32_t)w[2],(uint32_t)w[3],
                           (uint32_t)w[4],(uint32_t)w[5], (uint32_t)w[6],(uint32_t)w[7],
                           (uint32_t)w[8],(uint32_t)w[9], (uint32_t)w[10],(uint32_t)w[11] };
    secure_zero(w, sizeof(w)); // erase derived weights (copy now lives in result)
    return result;
}

// A keyed Q30 four-oscillator engine: integer-only, FPU-free, cross-platform
// bit-exact. K fixed at K_DEFAULT (capped <= 12 by mcl_q30_K_phase). The secret
// is `key`; `seed` is a PUBLIC salt for initial state (washed out by burn-in).
class MCL_T4_Q30 {
    uint32_t t1_, t2_, t3_, t4_;
    MCL_Q30_Sextet w_;
    int64_t kp_;
    // dual-zone integer extraction: fold the four phase words and read the
    // LUT-relevant HIGH 16 bits (the low 16 bits never index sin_q30, which
    // uses angle>>16, so they evolve more linearly -- excluded).
    static constexpr int Z1 = 16;
    static constexpr int Z2 = 24;
public:
    MCL_T4_Q30(const uint8_t key[32], uint64_t challenge = 0,
               uint64_t seed = DEFAULT_SEED, double K = K_DEFAULT)
        : w_(mcl_t4_q30_params_from_key(key, challenge)),
          kp_(mcl_q30_K_phase(K)) {
        // public-seed init for all four oscillators (mod 2^32, bit-exact).
        uint64_t s = hash_seed(seed);
        t1_ = (uint32_t)((s * (uint64_t)mcl_q30_omega1()) & 0xFFFFFFFFULL);
        t2_ = (uint32_t)((s * (uint64_t)mcl_q30_omega2()) & 0xFFFFFFFFULL);
        t3_ = (uint32_t)((s * (uint64_t)mcl_q30_omega3()) & 0xFFFFFFFFULL);
        t4_ = (uint32_t)((s * (uint64_t)mcl_q30_omega4()) & 0xFFFFFFFFULL);
        for (int i = 0; i < BURNIN; i++) iterate();
    }
    void iterate() { mcl_q30t4_iterate_raw(t1_, t2_, t3_, t4_, w_, kp_); }

    // Keystream byte. Passes ent + dieharder (42/1/0). NOTE: an earlier comment
    // claimed the raw keystream was "state-recoverable" from the map's weak
    // backward branching (b_eff~1); that was RETRACTED -- b_eff~1 is generic
    // arithmetic, not a demonstrated weakness, and no test fails. As ordinary
    // hygiene you may still hash a keystream that an adversary observes; a full
    // keystream-to-state recovery analysis (output-filter inversion) is not done
    // here and is not implied to be a problem.
    [[nodiscard]] uint8_t gen_byte() {
        for (int d = 0; d < DECIMATION; d++) iterate();
        uint32_t x = t1_ ^ t2_ ^ t3_ ^ t4_;
        return (uint8_t)((x >> Z1) ^ (x >> Z2));
    }
    void gen_bytes(uint8_t* buf, int64_t n) {
        if (n < 0 || (buf == nullptr && n > 0)) {
            std::fprintf(stderr, "FATAL: MCL_T4_Q30::gen_bytes bad args "
                "(buf=%p, n=%lld)\n", (void*)buf, (long long)n);
            std::abort();
        }
        for (int64_t i = 0; i < n; i++) buf[i] = gen_byte();
    }
    // 32-byte RAW state commitment (endian-independent). NOTE: this serializes
    // the integer state directly. The Q30 state-update map is only weakly
    // many-to-one (b_2D~3.25 vs the Float64 engine's ~1444; the 16-bit LUT
    // linearizes it -- mcl_keyed_q30_science2/recheck). An earlier note here
    // called raw output "NOT one-way / state-recoverable"; that was RETRACTED --
    // b_eff~1 at 8-bit is generic arithmetic (few preimages + 8-bit byte), not a
    // demonstrated keystream weakness, and ent/dieharder show none. Still, as a
    // matter of hygiene, prefer commit32_oneway() for any secret-bearing tag
    // (auth/key material) so the output reveals nothing about the state even if
    // the map is near-invertible. commit32() is fine for a public VDF-style
    // commitment.
    void commit32(uint8_t out[32]) {
        for (int b = 0; b < 4; b++) {
            iterate();
            for (int k = 0; k < 4; k++) out[b * 8 + k]     = (uint8_t)(t1_ >> (k * 8));
            for (int k = 0; k < 4; k++) out[b * 8 + 4 + k] = (uint8_t)((t2_ ^ t3_ ^ t4_) >> (k * 8));
        }
    }
    // 32-byte hashed output: the raw state commitment run through SHA-256. Use
    // this for auth tags / key material as defensive hygiene -- it reveals
    // nothing about the state regardless of map invertibility. (This was added
    // when raw output was thought state-recoverable; that claim was later
    // RETRACTED, but a hashed output is good practice anyway.) The 256-bit key
    // remains the brute-force target (Grover 2^128).
    void commit32_oneway(uint8_t out[32]) {
        uint8_t raw[32];
        commit32(raw);
        mcl_sha256(raw, 32, out);
        secure_zero(raw, sizeof(raw)); // erase raw state commitment (C-1)
    }
    // NOTE (C-1 is only PARTIAL for these): s1()..s4() and weights() return
    // COPIES of key-derived secret state into caller memory that the destructor's
    // secure_zero cannot reach. Use them for testing/measurement only; do not
    // retain the returned values in long-lived storage, and secure_zero them
    // yourself if you must.
    [[nodiscard]] uint32_t s1() const { return t1_; }
    [[nodiscard]] uint32_t s2() const { return t2_; }
    [[nodiscard]] uint32_t s3() const { return t3_; }
    [[nodiscard]] uint32_t s4() const { return t4_; }
    [[nodiscard]] MCL_Q30_Sextet weights() const { return w_; }
    // Wipe key-derived secret material (coupling weights + oscillator state) on
    // destruction. The core engine does this at 158 sites; the sidecar did not
    // (C-1). Copy stays available (trivial members) as the move fallback.
    ~MCL_T4_Q30() {
        secure_zero(&w_, sizeof(w_));
        secure_zero(&kp_, sizeof(kp_));
        secure_zero(&t1_, sizeof(t1_)); secure_zero(&t2_, sizeof(t2_));
        secure_zero(&t3_, sizeof(t3_)); secure_zero(&t4_, sizeof(t4_));
    }
};

// ============================================================================
// (B) SECRET TEMPORAL CASCADE over the EXISTING two-oscillator Q30 engine
// ============================================================================

// Default epoch schedule: the first epoch absorbs the full burn-in (to wash
// out the public seed); each later epoch is a shorter mixing run. The security
// depth of an epoch (how non-invertible one epoch is) is the b_eff-per-epoch
// quantity that must be measured (see mcl_keyed_q30_test.cpp / the existing
// mcl_beff_compounding harness) -- 256 iters is a conservative default well
// above the documented 50-iteration statistical hop warmup.
constexpr int MCL_CASCADE_FIRST_EPOCH_ITERS = BURNIN;   // 10000
constexpr int MCL_CASCADE_LATER_EPOCH_ITERS = 256;
constexpr int MCL_CASCADE_DEFAULT_EPOCHS    = 7;        // m>=7 for Grover+claw margin

// Derive m ordered coprime (p,q) pairs in [2, 2^30) from a 256-bit key.
inline std::vector<std::pair<int64_t,int64_t> >
mcl_cascade_q30_params_from_key(const uint8_t key[32], int m,
                                uint64_t challenge = 0) {
    if (m <= 0) {
        std::fprintf(stderr, "FATAL: mcl_cascade_q30_params_from_key m=%d "
            "(must be >= 1)\n", m);
        std::abort();
    }
    uint8_t info[8];
    for (int i = 0; i < 8; i++) info[i] = (uint8_t)(challenge >> (i * 8));
    std::vector<uint8_t> kd((size_t)m * 16); // 2 weights * 8 bytes per epoch
    mcl_kdf256(key, "MCL-Cascade-Q30-v1", info, sizeof(info),
               kd.data(), kd.size());
    const int64_t W_RANGE = (int64_t)((1LL << 30) - 2);
    auto weight = [&](size_t off) -> int64_t {
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= (uint64_t)kd[off + (size_t)i] << (i * 8);
        return 2 + (int64_t)(v % (uint64_t)W_RANGE);
    };
    std::vector<std::pair<int64_t,int64_t> > epochs((size_t)m);
    for (int e = 0; e < m; e++) {
        int64_t p = weight((size_t)e * 16);
        int64_t q = weight((size_t)e * 16 + 8);
        if (q == p) q = 2 + ((q - 2 + 1) % W_RANGE);
        while (gcd_compute(p, q) != 1) {
            q = 2 + ((q - 2 + 1) % W_RANGE);
            if (q == p) q = 2 + ((q - 2 + 1) % W_RANGE);
        }
        epochs[(size_t)e] = std::make_pair(p, q);
    }
    secure_zero(kd.data(), kd.size()); // erase key-derived KDF bytes (C-1)
    return epochs;
}

// Run the cascade and emit a 32-byte commitment. The secret is `key`;
// intermediate state is NEVER externalized between epochs (the precondition
// for joint-space security). `seed` is a public salt.
inline void mcl_cascade_q30(const uint8_t key[32], uint8_t out[32],
                            int m = MCL_CASCADE_DEFAULT_EPOCHS,
                            uint64_t challenge = 0, uint64_t seed = DEFAULT_SEED,
                            double K = K_DEFAULT) {
    if (m <= 0) {
        std::fprintf(stderr, "FATAL: mcl_cascade_q30 m=%d (must be >= 1)\n", m);
        std::abort();
    }
    std::vector<std::pair<int64_t,int64_t> > ep =
        mcl_cascade_q30_params_from_key(key, m, challenge);
    uint32_t t1, t2;
    mcl_q30_init_state(seed, t1, t2);
    const int64_t kp = mcl_q30_K_phase(K);
    for (int e = 0; e < m; e++) {
        const int64_t p = ep[(size_t)e].first;
        const int64_t q = ep[(size_t)e].second;
        const int iters = (e == 0) ? MCL_CASCADE_FIRST_EPOCH_ITERS
                                   : MCL_CASCADE_LATER_EPOCH_ITERS;
        for (int i = 0; i < iters; i++)
            mcl_q30_iterate_raw(t1, t2, p, q, kp);
        // NO output extracted here -- this is the joint-space precondition.
    }
    // final commitment: serialize the LAST epoch's raw (t1,t2) over 4 steps,
    // then HASH it (SHA-256) so the output is NON-INVERTIBLE. Emitting the raw
    // state directly would leak the last epoch's (p,q) to a lattice / parameter-
    // recovery attack (4 observed raw states suffice -- see "Verfications codes
    // June 2026/FINDINGS_20260615.md", 7/8 no-oracle). The 256-bit key stays safe
    // via the SHA-256 KDF either way, but raw emission needlessly leaks a derived
    // secret; hashing closes that leak (and makes the non-invertibility limitation
    // of the cascade -- PCT-04 Claim 27 -- hold in the reference code, not just on paper).
    const int64_t p = ep[(size_t)(m - 1)].first;
    const int64_t q = ep[(size_t)(m - 1)].second;
    uint8_t raw[32];
    for (int b = 0; b < 4; b++) {
        mcl_q30_iterate_raw(t1, t2, p, q, kp);
        for (int k = 0; k < 4; k++) raw[b * 8 + k]     = (uint8_t)(t1 >> (k * 8));
        for (int k = 0; k < 4; k++) raw[b * 8 + 4 + k] = (uint8_t)(t2 >> (k * 8));
    }
    mcl_sha256(raw, 32, out);
    secure_zero(raw, sizeof(raw)); // erase raw last-epoch state (C-1)
}

// ============================================================================
// PQ accounting helpers specific to the Q30 (2^30-capped) range.
// ============================================================================

// Classical secret bits of one ordered coprime (p,q) pair in [2, 2^30]
// (density 6/pi^2): log2( (6/pi^2) * (2^30 - 2)^2 ) ~= 59.28 bits.
inline double mcl_q30_pair_bits() {
    const double n = (double)((1LL << 30) - 2);
    return std::log2((6.0 / (MCL_PI * MCL_PI)) * n * n);
}

// Representation bits carried by the keyed T4-Q30 engine: 12 weights * 30 bits.
// (Key-bounded: the brute-forceable secret is min(L, this) = 256 for L=256.)
inline double mcl_t4_q30_capacity_bits() { return 12.0 * 30.0; }

// Representation bits of an m-epoch cascade: m * (ordered coprime pair bits).
inline double mcl_cascade_q30_capacity_bits(int m) {
    return (double)m * mcl_q30_pair_bits();
}

#endif // MCL_KEYED_Q30_HPP
