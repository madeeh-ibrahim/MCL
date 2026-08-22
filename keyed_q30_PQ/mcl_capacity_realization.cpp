/*
 * MCL CAPACITY REALIZATION EXPERIMENT
 * "Nominal key length is not realized security; the parameter capacity is."
 *
 * Document ID:   MCL-CAPACITY-REALIZATION-2026-0812-001
 * Version:       1.1.0 (2026-08-12; review fixes -- see CHANGELOG below)
 * Engine:        mcl_core.hpp v8.1.0 + keyed_q30_PQ/mcl_keyed_q30.hpp
 * Supports:      PCT-04 Aspect 1 — capacity relation [0019]-[0020], [0044]-[0045];
 *                inventive-step distinction over Alvarez & Li 2006 ([0010], [0053]).
 *
 * CHANGELOG
 * ---------
 *   v1.1.0 (2026-08-12): review fixes, all applied the same day.
 *     - Part 5(a) duplicate check made FAIL-CLOSED: every 64-bit digest hit
 *       is now resolved EXACTLY by re-deriving the earlier key's tuple and
 *       comparing all 48 bytes. (v1.0.0 kept only 4096 witness tuples, so a
 *       hit outside that window could not be verified -- fail-open. The
 *       archived v1.0.0 conclusion itself stands: a tuple duplicate forces a
 *       digest hit, and that run observed zero hits.)
 *     - NEW Part 5(d): independence at MINIMAL tuple distance (one weight
 *       changed by the smallest admissible step) on the four-oscillator
 *       engine; the explicit-sextet replica is first proven byte-identical
 *       to the production MCL_T4_Q30 path.
 *     - Part 4 widened from 1 to 8 sampled tuples + family chi-square gate.
 *     - Part 2 rows decorrelated: c folded into the key salt AND the KDF
 *       challenge (v1.0.0 rows reused the same KDF bytes across c).
 *     - Part 6 "key-bound" qualified per [0053]; header wording aligned.
 *     - M_PI (POSIX) -> MCL_PI (engine constant) for ISO-C++ portability.
 *   v1.0.0: initial version; measured run archived at
 *           MCL_CAPACITY_REALIZATION_20260812.txt (superseded record).
 *
 * WHY THIS EXPERIMENT EXISTS
 * --------------------------
 * The cited art (Alvarez & Li 2006) states, as an abstract REQUIREMENT, that a
 * chaotic cipher's key space must be large enough and that finite precision must
 * be considered. It does not give a sizing rule relating the number of coupled
 * variables, the number of coupling weights and the per-weight width to the key
 * length L. The examiner's expected objection is that the capacity relation is a
 * routine application of that requirement.
 *
 * This experiment measures the technical effect that the requirement alone does
 * not deliver: TWO CONFIGURATIONS THAT BOTH SATISFY THE ABSTRACT RULES -- same
 * 256-bit key, same collision-resistant derivation, same fully-chaotic operating
 * range, both producing statistically excellent output -- differ by 196 bits in
 * the key-search bound IMPOSED BY THE PARAMETER REPRESENTATION (2^60 vs 2^256).
 * Config A holds 60 bits of capacity against a 256-bit key; config B holds 360,
 * so the representation no longer reduces the key space below L -- precisely the
 * [0053] technical effect ("recoverable key-search space is not reduced below
 * the full key width by the parameter representation").
 *
 * It also measures the step that is NOT automatic and that a counting argument
 * alone cannot establish: that distinct parameter tuples actually produce
 * INDEPENDENT OUTPUT (capacity realized at the output, not merely nominal) --
 * both for KDF-random tuple pairs (Parts 5b/5c) and at the WORST CASE of
 * minimal tuple distance, a single weight changed by the smallest admissible
 * step (Part 5d).
 *
 * WHAT IS AND IS NOT CLAIMED HERE
 * -------------------------------
 *  - Parts 2/3 run at deliberately REDUCED capacity so that the birthday event is
 *    directly observable. The counting model is validated against measurement at
 *    reachable capacity and then extrapolated analytically. The full-capacity
 *    collision event (2^-360) is NOT observed and is NOT claimed to be observed.
 *  - Part 5 establishes ABSENCE of collisions over the sampled budget only.
 *  - "Key-bound" in Part 6 means exactly the [0053] effect: the parameter
 *    representation does not reduce the key-search space below L. It is NOT a
 *    claim that 2^256 is the realized security of the whole system against
 *    every other attack surface (state width, output filter, implementation
 *    channels are all out of scope here).
 *  - Nothing here is a security proof; it is a measurement of a design property.
 *
 * BUILD:
 *   c++ -std=c++17 -O3 -Wall -Wextra -Wconversion -I .. \
 *       -o mcl_capacity_realization mcl_capacity_realization.cpp && \
 *   ./mcl_capacity_realization
 */

#include "mcl_keyed_q30.hpp"

#include <cstdio>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <random>

static const char* DOC_ID      = "MCL-CAPACITY-REALIZATION-2026-0812-001";
static const char* DOC_VERSION = "1.1.0";

// ------------------------------------------------------------------ utils ---
static int g_pass = 0, g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) g_pass++; else g_fail++;
}

// Deterministic, obviously-distinct 256-bit keys (reproducible across runs).
static void make_key(uint64_t idx, uint64_t salt, uint8_t key[32]) {
    std::memset(key, 0, 32);
    for (int i = 0; i < 8; i++) key[i]      = (uint8_t)(idx  >> (i * 8));
    for (int i = 0; i < 8; i++) key[8 + i]  = (uint8_t)(salt >> (i * 8));
    key[31] = 0xA5; // fixed tag: keys differ only in idx/salt
}

// Derive n_weights coupling weights, each in [2, 2^bits), from a 256-bit key.
// Mirrors the reference derivation of [0018] (KDF -> field split -> reduce into
// range -> pairwise-distinctness bump [0023]); `bits` is the only knob, so the
// SAME code path produces both the reduced and the full-width configurations.
static void derive_tuple(const uint8_t key[32], int n_weights, int bits,
                         uint64_t challenge, std::vector<uint32_t>& out) {
    uint8_t info[8];
    for (int i = 0; i < 8; i++) info[i] = (uint8_t)(challenge >> (i * 8));
    std::vector<uint8_t> kd((size_t)n_weights * 8);
    mcl_kdf256(key, "MCL-CAPACITY-EXP-v1", info, sizeof(info), kd.data(), kd.size());

    const uint64_t range = ((uint64_t)1 << bits) - 2;   // |[2, 2^bits)|
    out.resize((size_t)n_weights);
    for (int i = 0; i < n_weights; i++) {
        uint64_t v = 0;
        for (int b = 0; b < 8; b++)
            v |= (uint64_t)kd[(size_t)i * 8 + (size_t)b] << (b * 8);
        out[(size_t)i] = (uint32_t)(2 + (v % range));
    }
    // [0023] in-range bump. Note for the Part-2 counting model: the bump
    // excludes p == q and doubles the mass of (p, p+1), scaling the birthday
    // collision rate by ~(1 + 2/R) -- a < 0.4% shift in the expected first
    // collision even at the smallest tested range (R = 254), negligible
    // against the factor-of-2 acceptance band.
    for (int i = 0; i + 1 < n_weights; i += 2)
        if (out[(size_t)i] == out[(size_t)i + 1])
            out[(size_t)i + 1] = (uint32_t)(2 + (((uint64_t)out[(size_t)i + 1] - 2 + 1) % range));
}

// Joint capacity in bits of n_weights weights each drawn from [2, 2^bits).
static double capacity_bits(int n_weights, int bits) {
    return (double)n_weights * std::log2((double)(((uint64_t)1 << bits) - 2));
}

// Expected number of draws to the first birthday collision in a space of 2^C.
static double birthday_expected(double C) {
    return std::sqrt(MCL_PI / 2.0) * std::pow(2.0, C / 2.0);
}

static uint64_t pack2(const std::vector<uint32_t>& t) {   // 2 weights -> 64 bits
    return ((uint64_t)t[0] << 32) | (uint64_t)t[1];
}

static uint64_t fnv1a64(const void* data, size_t n) {
    const uint8_t* p = (const uint8_t*)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

// The REAL two-oscillator Q30 engine under an explicit (p,q), with the same
// public-seed init / burn-in / decimation / dual-zone extraction as the shipped
// four-oscillator engine (MCL_T4_Q30), so the two configurations differ ONLY in
// the parameter representation under test.
static void run_2var_keystream(uint32_t p, uint32_t q, uint64_t seed,
                               uint8_t* buf, size_t n) {
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const uint64_t s = hash_seed(seed);
    uint32_t t1 = (uint32_t)((s * (uint64_t)mcl_q30_omega1()) & 0xFFFFFFFFULL);
    uint32_t t2 = (uint32_t)((s * (uint64_t)mcl_q30_omega2()) & 0xFFFFFFFFULL);
    for (int i = 0; i < BURNIN; i++) mcl_q30_iterate_raw(t1, t2, (int64_t)p, (int64_t)q, kp);
    for (size_t i = 0; i < n; i++) {
        for (int d = 0; d < DECIMATION; d++)
            mcl_q30_iterate_raw(t1, t2, (int64_t)p, (int64_t)q, kp);
        const uint32_t x = t1 ^ t2;
        buf[i] = (uint8_t)((x >> 16) ^ (x >> 24));
    }
}

// The production four-oscillator engine under an EXPLICIT sextet, replicating
// MCL_T4_Q30's init / burn-in / decimation / extraction exactly. Needed by
// Part 5(d) to perturb a SINGLE weight, which the key-facing class cannot
// express; proven byte-identical to the production engine there before use.
static void run_t4_keystream(const MCL_Q30_Sextet& w, uint64_t seed,
                             uint8_t* buf, size_t n) {
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const uint64_t s = hash_seed(seed);
    uint32_t t1 = (uint32_t)((s * (uint64_t)mcl_q30_omega1()) & 0xFFFFFFFFULL);
    uint32_t t2 = (uint32_t)((s * (uint64_t)mcl_q30_omega2()) & 0xFFFFFFFFULL);
    uint32_t t3 = (uint32_t)((s * (uint64_t)mcl_q30_omega3()) & 0xFFFFFFFFULL);
    uint32_t t4 = (uint32_t)((s * (uint64_t)mcl_q30_omega4()) & 0xFFFFFFFFULL);
    for (int i = 0; i < BURNIN; i++) mcl_q30t4_iterate_raw(t1, t2, t3, t4, w, kp);
    for (size_t i = 0; i < n; i++) {
        for (int d = 0; d < DECIMATION; d++)
            mcl_q30t4_iterate_raw(t1, t2, t3, t4, w, kp);
        const uint32_t x = t1 ^ t2 ^ t3 ^ t4;
        buf[i] = (uint8_t)((x >> 16) ^ (x >> 24));
    }
}

// The smallest admissible single-weight step: +1 within [2, 2^30), wrapping at
// the top -- the same in-range step the [0023] bump uses.
static uint32_t bump30(uint32_t w) {
    const uint64_t range = ((uint64_t)1 << 30) - 2;
    return (uint32_t)(2 + (((uint64_t)w - 2 + 1) % range));
}

static double shannon_entropy(const uint8_t* b, size_t n) {
    double f[256] = {0};
    for (size_t i = 0; i < n; i++) f[b[i]] += 1.0;
    double H = 0.0;
    for (int i = 0; i < 256; i++) if (f[i] > 0) {
        const double pr = f[i] / (double)n;
        H -= pr * std::log2(pr);
    }
    return H;
}

static double chi2_bytes(const uint8_t* b, size_t n) {
    double f[256] = {0};
    for (size_t i = 0; i < n; i++) f[b[i]] += 1.0;
    const double e = (double)n / 256.0;
    double c = 0.0;
    for (int i = 0; i < 256; i++) { const double d = f[i] - e; c += d * d / e; }
    return c;
}

static double hamming_pct(const uint8_t* a, const uint8_t* b, size_t n) {
    uint64_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t x = (uint8_t)(a[i] ^ b[i]);
        while (x) { diff += (x & 1u); x = (uint8_t)(x >> 1); }
    }
    return 100.0 * (double)diff / ((double)n * 8.0);
}

// ================================================================== PART 1 ===
static void part1_nominal_accounting(double& cap_2var, double& cap_4var) {
    std::printf("\n[1] NOMINAL CAPACITY ACCOUNTING (analytic, [0019]-[0020], [0044])\n");
    const int L = 256;
    cap_2var = capacity_bits(2, 30);    // 2 coupled variables -> 1 pair -> 2 weights
    cap_4var = capacity_bits(12, 30);   // 4 coupled variables -> 6 pairs -> 12 weights

    std::printf("    key length L                              = %d bits\n", L);
    std::printf("    config A: 2 variables /  2 weights [2,2^30) = %6.2f bits capacity\n", cap_2var);
    std::printf("    config B: 4 variables / 12 weights [2,2^30) = %6.2f bits capacity\n", cap_4var);
    std::printf("    N(N-1)*b rule: A -> 2*30 = 60, B -> 12*30 = 360\n");
    check(cap_2var < (double)L,
          "config A capacity < L  => a 256-bit key CANNOT be represented (the deficiency)");
    check(cap_4var >= (double)L,
          "config B capacity >= L => the capacity relation of [0019] is satisfied");
}

// ================================================================== PART 2 ===
// Validate the birthday/counting model against measurement on the REAL KDF, at
// capacities small enough for the collision to be observed directly.
static void part2_model_validation() {
    std::printf("\n[2] COUNTING-MODEL VALIDATION (measured first-collision vs analytic)\n");
    std::printf("    c(bits)   trials   measured mean   analytic sqrt(pi/2)*2^(c/2)   ratio\n");

    const int trials = 8;
    bool all_ok = true;
    for (int c : {16, 20, 24, 28}) {
        const int bits = c / 2;                 // 2 weights, c/2 bits each
        const double C = capacity_bits(2, bits);
        double sum = 0.0;
        for (int t = 0; t < trials; t++) {
            // v1.1.0: fold c into the key salt AND the KDF challenge so the
            // four c-rows draw from disjoint KDF streams. (v1.0.0 rows reused
            // the same kd bytes reduced mod different ranges -- each row
            // marginally valid, but the rows were correlated rather than
            // independent replicates.)
            const uint64_t sc = ((uint64_t)c << 32) | (uint64_t)t;
            std::unordered_map<uint64_t, uint64_t> seen;
            seen.reserve(1u << 16);
            std::vector<uint32_t> tup;
            uint64_t idx = 1;
            for (;; idx++) {
                uint8_t key[32];
                make_key(idx, sc, key);
                derive_tuple(key, 2, bits, sc, tup);
                const uint64_t packed = pack2(tup);
                auto it = seen.find(packed);
                if (it != seen.end()) break;
                seen.emplace(packed, idx);
            }
            sum += (double)idx;
        }
        const double meas = sum / (double)trials;
        const double pred = birthday_expected(C);
        const double ratio = meas / pred;
        std::printf("    %5d %8d %15.1f %28.1f %7.3f\n", c, trials, meas, pred, ratio);
        // 8 trials of a geometric-tailed statistic: accept a factor-of-2 band.
        if (!(ratio > 0.5 && ratio < 2.0)) all_ok = false;
    }
    check(all_ok, "measured first-collision counts match the 2^C counting model (within 2x)");
    std::printf("    => the model is validated on the real KDF; it is the same model that\n"
                "       gives 2^60 for config A and 2^360 for config B.\n");
}

// ================================================================== PART 3 ===
// THE CRUX: at insufficient capacity, two DISTINCT 256-bit keys collapse onto
// one parameter tuple and become cryptographically EQUIVALENT -- identical
// output. The key length is then not the security parameter; the capacity is.
static void part3_equivalent_keys() {
    std::printf("\n[3] EQUIVALENT-KEY DEMONSTRATION (capacity-bounded security, config A)\n");
    const int bits = 12;                       // 2 weights x 12 bits -> ~24-bit capacity
    const double C = capacity_bits(2, bits);
    std::printf("    reduced config: 2 weights in [2,2^%d)  => capacity %.2f bits\n", bits, C);

    std::unordered_map<uint64_t, uint64_t> seen;
    std::vector<uint32_t> tup, tupA, tupB;
    uint64_t k1 = 0, k2 = 0;
    for (uint64_t idx = 1;; idx++) {
        uint8_t key[32];
        make_key(idx, 0xEE, key);
        derive_tuple(key, 2, bits, 0xEE, tup);
        const uint64_t packed = pack2(tup);
        auto it = seen.find(packed);
        if (it != seen.end()) { k1 = it->second; k2 = idx; break; }
        seen.emplace(packed, idx);
    }

    uint8_t keyA[32], keyB[32];
    make_key(k1, 0xEE, keyA);
    make_key(k2, 0xEE, keyB);
    derive_tuple(keyA, 2, bits, 0xEE, tupA);
    derive_tuple(keyB, 2, bits, 0xEE, tupB);

    std::printf("    found after %llu derivations:\n", (unsigned long long)k2);
    std::printf("      key #%llu -> (p,q) = (%u, %u)\n", (unsigned long long)k1, tupA[0], tupA[1]);
    std::printf("      key #%llu -> (p,q) = (%u, %u)\n", (unsigned long long)k2, tupB[0], tupB[1]);
    check(std::memcmp(keyA, keyB, 32) != 0, "the two 256-bit keys are DISTINCT");
    check(tupA == tupB,                     "yet they derive the SAME parameter tuple");

    const size_t N = 4096;
    std::vector<uint8_t> sA(N), sB(N), sC(N);
    run_2var_keystream(tupA[0], tupA[1], DEFAULT_SEED, sA.data(), N);
    run_2var_keystream(tupB[0], tupB[1], DEFAULT_SEED, sB.data(), N);

    // control: a third key whose tuple differs
    std::vector<uint32_t> tupC;
    uint64_t k3 = k2;
    do { k3++; uint8_t k[32]; make_key(k3, 0xEE, k); derive_tuple(k, 2, bits, 0xEE, tupC); }
    while (tupC == tupA);
    run_2var_keystream(tupC[0], tupC[1], DEFAULT_SEED, sC.data(), N);

    const bool identical = (std::memcmp(sA.data(), sB.data(), N) == 0);
    const double hd_ab = hamming_pct(sA.data(), sB.data(), N);
    const double hd_ac = hamming_pct(sA.data(), sC.data(), N);
    std::printf("    keystream(key #%llu) vs keystream(key #%llu): Hamming = %.2f%%  (%s)\n",
                (unsigned long long)k1, (unsigned long long)k2, hd_ab,
                identical ? "BYTE-IDENTICAL" : "differs");
    std::printf("    control, distinct tuple (p,q) = (%u, %u):     Hamming = %.2f%%\n",
                tupC[0], tupC[1], hd_ac);

    check(identical,
          "distinct keys, same tuple => IDENTICAL output (keys are equivalent)");
    check(hd_ac > 45.0 && hd_ac < 55.0,
          "control: a distinct tuple gives ~50% Hamming (outputs independent)");
    std::printf("    => realized security is bounded by the PARAMETER space (%.0f bits),\n"
                "       not by the 256-bit key that was supplied.\n", C);
}

// ================================================================== PART 4 ===
// The control that matters for the prior-art argument: the SAME capacity-
// deficient configuration passes the statistical/"fully chaotic" style checks.
// v1.1.0: widened from one sampled tuple to eight (same derivation family as
// Part 3) plus a family-level chi-square consistency gate. Note the derivation
// -- mirroring the production T4 path -- enforces only pairwise distinctness
// [0023], NOT coprimality (coprimality is an Aspect-4 cascade-path
// requirement), so tuples with gcd > 1 are admissible here by design.
static void part4_statistical_control() {
    std::printf("\n[4] STATISTICAL CONTROL — the deficient configuration still looks good\n");
    const int bits = 12;
    const int T = 8;                            // sampled tuples (v1.0.0: 1)
    const size_t N = 1u << 20;                  // 1 MiB per tuple
    // chi^2 quantiles for df = 255 (computed by regularized-incomplete-gamma
    // inversion): 99% = 310.457, 99.9% = 330.520. The per-tuple gate is the
    // 99.9% quantile so the family-wise false-fail over 8 ideal-random
    // tuples stays ~0.8%; the conventional 99% value is printed as the
    // requirement-level reference. The family MEAN is additionally gated at
    // 255 +/- 4*sigma_mean, sigma_mean = sqrt(2*255/8) = 7.984.
    const double CHI99   = 310.457, CHI999 = 330.520;
    const double MEAN_LO = 255.0 - 4.0 * 7.984;   // 223.06
    const double MEAN_HI = 255.0 + 4.0 * 7.984;   // 286.94

    std::vector<uint8_t> s(N);
    double chi_sum = 0.0;
    bool all_H = true, all_chi = true;
    std::printf("    tuple     (p, q)      entropy (bits/byte)   chi^2 (df=255)\n");
    for (int t = 0; t < T; t++) {
        uint8_t key[32];
        std::vector<uint32_t> tup;
        make_key((uint64_t)t + 1, 0xEE, key);
        derive_tuple(key, 2, bits, 0xEE, tup);   // same family as Part 3
        run_2var_keystream(tup[0], tup[1], DEFAULT_SEED, s.data(), N);
        const double H  = shannon_entropy(s.data(), N);
        const double X2 = chi2_bytes(s.data(), N);
        std::printf("      #%d   (%4u, %4u)         %.6f           %7.2f\n",
                    t + 1, tup[0], tup[1], H, X2);
        if (!(H > 7.99))    all_H   = false;
        if (!(X2 < CHI999)) all_chi = false;
        chi_sum += X2;
    }
    const double chi_mean = chi_sum / (double)T;
    std::printf("    ideal entropy 8.000000; chi^2 reference: 99%% = %.3f, 99.9%% = %.3f\n",
                CHI99, CHI999);
    std::printf("    family mean chi^2 = %.2f (df expectation 255, 4-sigma band [%.2f, %.2f])\n",
                chi_mean, MEAN_LO, MEAN_HI);
    check(all_H,   "all 8 capacity-deficient tuples pass the entropy check (H > 7.99)");
    check(all_chi, "all 8 tuples pass chi-square (each below the 99.9% quantile)");
    check(chi_mean > MEAN_LO && chi_mean < MEAN_HI,
          "family mean chi-square consistent with df = 255 (within 4 sigma)");
    std::printf("    => statistical quality and a fully-chaotic range do NOT reveal the\n"
                "       capacity deficiency. Requirement-level rules cannot detect it;\n"
                "       only the sizing relation of [0019]-[0020] does.\n");
}

// ================================================================== PART 5 ===
// Capacity REALIZED at the output for the shipped four-variable configuration,
// using the production derivation (mcl_t4_q30_params_from_key) and engine.
static void part5_realized_full_config() {
    std::printf("\n[5] REALIZED CAPACITY OF THE FULL CONFIGURATION (4 vars / 12 weights)\n");

    // (a) no tuple collision over the sampled budget (predicted: ~2^-360 per
    // pair). FAIL-CLOSED (v1.1.0): the digest multimap keeps the key index of
    // EVERY digest seen (~M entries, tens of MB -- a desktop-harness cost), so
    // each digest hit is resolved EXACTLY by re-deriving every earlier holder
    // of that digest and comparing all 48 tuple bytes; a benign 64-bit digest
    // collision and a true tuple duplicate are distinguished with certainty.
    // (v1.0.0 kept only 4096 witness tuples: a true duplicate whose earlier
    // key fell outside that window would have passed check(real_dups == 0)
    // unverified -- fail-open. Its archived conclusion still stands, because
    // a tuple duplicate forces a digest hit and that run observed zero hits.)
    const uint64_t M = 1u << 20;
    std::unordered_multimap<uint64_t, uint64_t> holders;   // digest -> key idx
    holders.reserve((size_t)M);
    uint64_t hash_hits = 0, real_dups = 0, benign_hits = 0;
    for (uint64_t i = 1; i <= M; i++) {
        uint8_t key[32];
        make_key(i, 0x5A, key);
        const MCL_Q30_Sextet w = mcl_t4_q30_params_from_key(key, 0);
        const uint32_t v[12] = { w.p12, w.q12, w.p13, w.q13, w.p14, w.q14,
                                 w.p23, w.q23, w.p24, w.q24, w.p34, w.q34 };
        const uint64_t h = fnv1a64(v, sizeof(v));
        auto range = holders.equal_range(h);
        if (range.first != range.second) {
            hash_hits++;
            bool dup = false;
            for (auto it = range.first; it != range.second; ++it) {
                uint8_t k0[32];
                make_key(it->second, 0x5A, k0);
                const MCL_Q30_Sextet w0 = mcl_t4_q30_params_from_key(k0, 0);
                const uint32_t v0[12] = { w0.p12, w0.q12, w0.p13, w0.q13, w0.p14, w0.q14,
                                          w0.p23, w0.q23, w0.p24, w0.q24, w0.p34, w0.q34 };
                if (std::memcmp(v0, v, sizeof(v)) == 0) { dup = true; break; }
            }
            if (dup) real_dups++; else benign_hits++;
        }
        holders.emplace(h, i);
    }
    std::printf("    sampled %llu keys through the production derivation\n",
                (unsigned long long)M);
    std::printf("    64-bit digest hits = %llu (expected ~%.1e by birthday on the DIGEST,\n"
                "      not on the tuple); every hit resolved exactly by re-derivation:\n"
                "      true tuple duplicates = %llu, benign digest collisions = %llu\n",
                (unsigned long long)hash_hits,
                ((double)M * (double)M) / std::pow(2.0, 65.0),
                (unsigned long long)real_dups,
                (unsigned long long)benign_hits);
    check(real_dups == 0 && hash_hits == real_dups + benign_hits,
          "no parameter-tuple collision over the sampled budget (fail-closed check)");

    // (b) single-bit key avalanche
    std::mt19937_64 rng(0xC0FFEEULL);            // fixed seed: reproducible
    const size_t KS = 512;
    double av_sum = 0.0, av_min = 100.0, av_max = 0.0;
    const int TRIALS = 48;
    for (int t = 0; t < TRIALS; t++) {
        uint8_t k1[32], k2[32];
        make_key((uint64_t)t + 1, 0x77, k1);
        std::memcpy(k2, k1, 32);
        const int bit = (int)(rng() % 256);
        k2[bit >> 3] = (uint8_t)(k2[bit >> 3] ^ (1u << (bit & 7)));

        MCL_T4_Q30 e1(k1), e2(k2);
        std::vector<uint8_t> a(KS), b(KS);
        e1.gen_bytes(a.data(), (int64_t)KS);
        e2.gen_bytes(b.data(), (int64_t)KS);
        const double hd = hamming_pct(a.data(), b.data(), KS);
        av_sum += hd;
        if (hd < av_min) av_min = hd;
        if (hd > av_max) av_max = hd;
    }
    const double av = av_sum / (double)TRIALS;
    std::printf("    single-bit key avalanche over %d trials: mean %.2f%% "
                "(min %.2f%%, max %.2f%%)\n", TRIALS, av, av_min, av_max);
    check(av > 49.0 && av < 51.0,
          "one flipped key bit => ~50% output change (capacity realized at output)");

    // (c) independence between unrelated keys
    double ind_sum = 0.0;
    const int PAIRS = 24;
    for (int t = 0; t < PAIRS; t++) {
        uint8_t k1[32], k2[32];
        make_key((uint64_t)(2 * t + 1), 0x99, k1);
        make_key((uint64_t)(2 * t + 2), 0x99, k2);
        MCL_T4_Q30 e1(k1), e2(k2);
        std::vector<uint8_t> a(KS), b(KS);
        e1.gen_bytes(a.data(), (int64_t)KS);
        e2.gen_bytes(b.data(), (int64_t)KS);
        ind_sum += hamming_pct(a.data(), b.data(), KS);
    }
    const double ind = ind_sum / (double)PAIRS;
    std::printf("    unrelated-key pairs over %d pairs: mean Hamming %.2f%%\n", PAIRS, ind);
    check(ind > 49.0 && ind < 51.0,
          "distinct keys => independent output (no hidden collapse of the tuple space)");

    // (d) independence at MINIMAL tuple distance (v1.1.0). (b)/(c) exercise
    // KDF-random tuple pairs, which differ in all 12 weights; if NEARBY tuples
    // clustered (correlated output), the realized capacity would fall below
    // the counted 2^360 without any exact collision, and a random-pair test
    // could not see it. Worst case = ONE weight changed by the smallest
    // admissible step. The key-facing class cannot express a single-weight
    // change, so an explicit-sextet replica of the T4 path is used -- proven
    // byte-identical to the production engine first.
    {
        uint8_t key[32];
        make_key(1, 0x33, key);
        MCL_T4_Q30 eng(key);
        const MCL_Q30_Sextet w0 = eng.weights();
        const size_t DN = 4096;
        std::vector<uint8_t> prod(DN), base(DN), pert(DN);
        eng.gen_bytes(prod.data(), (int64_t)DN);
        run_t4_keystream(w0, DEFAULT_SEED, base.data(), DN);
        check(std::memcmp(prod.data(), base.data(), DN) == 0,
              "explicit-sextet T4 replica is byte-identical to the production engine");

        static const char* lane_name[12] = { "p12", "q12", "p13", "q13", "p14", "q14",
                                             "p23", "q23", "p24", "q24", "p34", "q34" };
        double hd[12], mn = 100.0, mx = 0.0, sum = 0.0;
        for (int lane = 0; lane < 12; lane++) {
            MCL_Q30_Sextet wp = w0;
            uint32_t* f[12] = { &wp.p12, &wp.q12, &wp.p13, &wp.q13, &wp.p14, &wp.q14,
                                &wp.p23, &wp.q23, &wp.p24, &wp.q24, &wp.p34, &wp.q34 };
            *f[lane] = bump30(*f[lane]);
            if (*f[lane] == *f[lane ^ 1])            // preserve the [0023] invariant
                *f[lane] = bump30(*f[lane]);
            run_t4_keystream(wp, DEFAULT_SEED, pert.data(), DN);
            hd[lane] = hamming_pct(base.data(), pert.data(), DN);
            sum += hd[lane];
            if (hd[lane] < mn) mn = hd[lane];
            if (hd[lane] > mx) mx = hd[lane];
        }
        std::printf("    single-weight +1 perturbation (nearest admissible tuple), %llu bytes each:\n",
                    (unsigned long long)DN);
        for (int row = 0; row < 2; row++) {
            std::printf("     ");
            for (int k = 0; k < 6; k++) {
                const int lane = row * 6 + k;
                std::printf("  %s %5.2f%%", lane_name[lane], hd[lane]);
            }
            std::printf("\n");
        }
        std::printf("    mean %.2f%%  (min %.2f%%, max %.2f%%; per-lane sigma ~0.28%%,\n"
                    "      so the (45,55) gate is ~18 sigma wide)\n", sum / 12.0, mn, mx);
        check(mn > 45.0 && mx < 55.0,
              "one weight, smallest step => ~50% change (independence at minimal distance)");
    }
}

// ================================================================== PART 6 ===
static void part6_summary(double cap_2var, double cap_4var) {
    std::printf("\n[6] SUMMARY — nominal vs realized, and the extrapolation\n");
    std::printf("    +----------------------+-----------+-----------+----------------------+\n");
    std::printf("    | configuration        | key given | capacity  | realized key search  |\n");
    std::printf("    +----------------------+-----------+-----------+----------------------+\n");
    char cellA[64], cellB[64];
    std::snprintf(cellA, sizeof(cellA), "2^%.0f (capacity-bound)", cap_2var);
    std::snprintf(cellB, sizeof(cellB), "2^256 (key-bound*)");
    std::printf("    | A: 2 vars /  2 wts   | 256 bits  | %6.1f b  | %-21s|\n", cap_2var, cellA);
    std::printf("    | B: 4 vars / 12 wts   | 256 bits  | %6.1f b  | %-21s|\n", cap_4var, cellB);
    std::printf("    +----------------------+-----------+-----------+----------------------+\n");
    std::printf("    * key-bound per [0053]: the parameter representation does not reduce\n"
                "      the recoverable key-search space below the key width L -- a measured\n"
                "      property of the REPRESENTATION, not a claim about attack surfaces\n"
                "      other than the representation (see the header disclaimer).\n");
    std::printf("    Both configurations: same key length, same derivation, same chaotic\n"
                "    range, both statistically clean (Part 4). They differ by ~%.0f bits in\n"
                "    the representation-imposed key-search bound, solely through the\n"
                "    parameter representation.\n",
                256.0 - cap_2var);
    std::printf("    Expected first collision: A ~ %.3g keys (reachable);"
                "  B ~ %.3g keys (unreachable).\n",
                birthday_expected(cap_2var), birthday_expected(cap_4var));
    std::printf("    Parts 2-3 measured the effect at reduced capacity and validated the\n"
                "    model that produces these two numbers; the 2^-360 event is not observed.\n");
    std::printf("    Part 5(d) additionally pins output independence at the minimal\n"
                "    admissible tuple distance (one weight, smallest step).\n");
}

// ===================================================================== main ==
int main() {
    std::printf("================================================================\n");
    std::printf(" MCL CAPACITY REALIZATION EXPERIMENT   %s\n", DOC_ID);
    std::printf(" version %s | engine %s\n", DOC_VERSION, MCL_VERSION_STRING);
    std::printf(" nominal key length is not realized security; capacity is\n");
    std::printf("================================================================\n");

    double cap_2var = 0.0, cap_4var = 0.0;
    part1_nominal_accounting(cap_2var, cap_4var);
    part2_model_validation();
    part3_equivalent_keys();
    part4_statistical_control();
    part5_realized_full_config();
    part6_summary(cap_2var, cap_4var);

    std::printf("\n================================================================\n");
    std::printf("  SUMMARY: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("================================================================\n");
    return g_fail == 0 ? 0 : 1;
}
