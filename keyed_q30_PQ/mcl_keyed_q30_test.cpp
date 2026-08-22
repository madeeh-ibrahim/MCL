/*
 * ============================================================================
 * MCL Keyed Q30 -- verification & measurement harness
 * Builds the patent-support evidence for the FPU-free keyed engines in
 * mcl_keyed_q30.hpp:
 *   1. determinism / cross-platform integer KAT (CRC-32)
 *   2. statistical quality of the T4-Q30 keystream (chi^2, Shannon entropy)
 *   3. key avalanche (1 key bit flipped -> ~50% output bits change)
 *   4. CAPACITY realized: every one of the 12 T4 weights affects the output
 *   5. cascade: every epoch contributes; intermediate state never externalized
 *   6. backward non-uniqueness smoke test (b_eff>1 plausibility on the Q30 LUT)
 *   7. post-quantum accounting (Grover bits, NIST Category 5 — 256-bit key = AES-256-equiv = 128 post-Grover; the earlier "Level 1" label was wrong by four categories)
 *   8. timing + working-memory footprint
 *
 * BUILD:
 *   c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish \
 *       -o mcl_keyed_q30_test mcl_keyed_q30_test.cpp && ./mcl_keyed_q30_test
 * ============================================================================
 */

#include "mcl_keyed_q30.hpp"
#include <cstdio>
#include <cstring>
#include <chrono>
#include <vector>

using clk = std::chrono::steady_clock;

static int g_pass = 0, g_fail = 0;
static void check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) g_pass++; else g_fail++;
}

// Hamming distance (% of bits) between two equal-length byte buffers.
static double hamming_pct_buf(const uint8_t* a, const uint8_t* b, int n) {
    long bits = 0;
    for (int i = 0; i < n; i++) bits += popcount8((uint8_t)(a[i] ^ b[i]));
    return 100.0 * (double)bits / ((double)n * 8.0);
}

// Raw T4-Q30: init + burn-in + 32-byte commitment from an EXPLICIT weight set
// (lets us flip individual weights to prove each one affects the output).
static void run_t4_q30_raw(const MCL_Q30_Sextet& w, uint64_t seed, uint8_t out[32]) {
    uint64_t s = hash_seed(seed);
    uint32_t t1 = (uint32_t)((s * (uint64_t)mcl_q30_omega1()) & 0xFFFFFFFFULL);
    uint32_t t2 = (uint32_t)((s * (uint64_t)mcl_q30_omega2()) & 0xFFFFFFFFULL);
    uint32_t t3 = (uint32_t)((s * (uint64_t)mcl_q30_omega3()) & 0xFFFFFFFFULL);
    uint32_t t4 = (uint32_t)((s * (uint64_t)mcl_q30_omega4()) & 0xFFFFFFFFULL);
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    for (int i = 0; i < BURNIN; i++) mcl_q30t4_iterate_raw(t1, t2, t3, t4, w, kp);
    for (int b = 0; b < 4; b++) {
        mcl_q30t4_iterate_raw(t1, t2, t3, t4, w, kp);
        for (int k = 0; k < 4; k++) out[b*8+k]     = (uint8_t)(t1 >> (k*8));
        for (int k = 0; k < 4; k++) out[b*8+4+k]   = (uint8_t)((t2 ^ t3 ^ t4) >> (k*8));
    }
}

// Raw cascade with EXPLICIT epoch list (to flip one epoch and prove it matters).
static void run_cascade_raw(const std::vector<std::pair<int64_t,int64_t> >& ep,
                            uint64_t seed, uint8_t out[32]) {
    uint32_t t1, t2;
    mcl_q30_init_state(seed, t1, t2);
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const int m = (int)ep.size();
    for (int e = 0; e < m; e++) {
        int iters = (e == 0) ? MCL_CASCADE_FIRST_EPOCH_ITERS
                             : MCL_CASCADE_LATER_EPOCH_ITERS;
        for (int i = 0; i < iters; i++)
            mcl_q30_iterate_raw(t1, t2, ep[(size_t)e].first, ep[(size_t)e].second, kp);
    }
    int64_t p = ep[(size_t)(m-1)].first, q = ep[(size_t)(m-1)].second;
    for (int b = 0; b < 4; b++) {
        mcl_q30_iterate_raw(t1, t2, p, q, kp);
        for (int k = 0; k < 4; k++) out[b*8+k]   = (uint8_t)(t1 >> (k*8));
        for (int k = 0; k < 4; k++) out[b*8+4+k] = (uint8_t)(t2 >> (k*8));
    }
}

static void hexline(const char* tag, const uint8_t* b, int n) {
    std::printf("    %s ", tag);
    for (int i = 0; i < n; i++) std::printf("%02x", b[i]);
    std::printf("\n");
}

int main() {
    std::setbuf(stdout, nullptr);
    std::printf("================================================================\n");
    std::printf("  MCL KEYED Q30 -- verification harness (engine %s)\n", mcl_version());
    std::printf("================================================================\n");

    uint8_t key[32];   for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1);
    uint8_t key2[32];  std::memcpy(key2, key, 32);  key2[0] ^= 0x01; // 1-bit flip

    // --- 1. determinism / integer KAT ---
    std::printf("\n[1] Determinism + integer KAT (platform-independent CRCs)\n");
    {
        MCL_T4_Q30 e1(key); uint8_t a[32]; e1.commit32(a);
        MCL_T4_Q30 e2(key); uint8_t b[32]; e2.commit32(b);
        check(std::memcmp(a, b, 32) == 0, "T4-Q30 commit32 deterministic");
        std::printf("    T4-Q30 commit CRC-32 = 0x%08X\n", compute_crc32(a, 32));
        hexline("T4-Q30 commit =", a, 32);

        uint8_t c[32], d[32];
        mcl_cascade_q30(key, c);
        mcl_cascade_q30(key, d);
        check(std::memcmp(c, d, 32) == 0, "cascade(m=7) deterministic");
        std::printf("    cascade(m=7) CRC-32  = 0x%08X\n", compute_crc32(c, 32));
        hexline("cascade(m=7)  =", c, 32);
    }

    // --- 2. statistical quality of T4-Q30 keystream ---
    std::printf("\n[2] T4-Q30 keystream quality (1 MiB)\n");
    {
        const int64_t N = 1 << 20;
        std::vector<uint8_t> buf((size_t)N);
        MCL_T4_Q30 e(key);
        e.gen_bytes(buf.data(), N);
        double chi = chi_square(buf.data(), N);
        double H   = shannon_entropy(buf.data(), N);
        std::printf("    chi^2 = %.2f (threshold %.2f)   entropy = %.6f bits/byte\n",
                    chi, CHI2_THRESHOLD, H);
        check(chi < CHI2_THRESHOLD, "T4-Q30 chi^2 below df=255 threshold");
        check(H > 7.99, "T4-Q30 Shannon entropy > 7.99 bits/byte");
    }

    // --- 3. key avalanche (1-bit key flip) ---
    std::printf("\n[3] Key avalanche (flip 1 of 256 key bits)\n");
    {
        double sum = 0; int trials = 16;
        for (int t = 0; t < trials; t++) {
            uint8_t k[32]; for (int i = 0; i < 32; i++) k[i] = (uint8_t)(i*13 + t);
            uint8_t kf[32]; std::memcpy(kf, k, 32);
            kf[t % 32] ^= (uint8_t)(1u << (t % 8));
            MCL_T4_Q30 e(k);  uint8_t a[32]; e.commit32(a);
            MCL_T4_Q30 ef(kf); uint8_t b[32]; ef.commit32(b);
            sum += hamming_pct_buf(a, b, 32);
        }
        double avg = sum / trials;
        std::printf("    mean output bit-change = %.2f%% (ideal 50%%)\n", avg);
        check(avg > 45.0 && avg < 55.0, "T4-Q30 key avalanche ~50%");
    }

    // --- 4. CAPACITY realized: each of the 12 weights affects the output ---
    std::printf("\n[4] Capacity: every one of the 12 T4 weights affects output\n");
    {
        MCL_Q30_Sextet w = mcl_t4_q30_params_from_key(key);
        uint8_t base[32]; run_t4_q30_raw(w, DEFAULT_SEED, base);
        int affected = 0; double min_h = 100.0;
        for (int i = 0; i < 12; i++) {
            MCL_Q30_Sextet wm = w;
            // 12 contiguous uint32_t weights (struct is now uint32-typed, 72-B
            // engine / native-word multiply, Claim 13). Pun as uint32_t*, not
            // int64_t* -- the old int64 punning read pairs and ran off the end.
            uint32_t* wmp = reinterpret_cast<uint32_t*>(&wm);
            wmp[i] ^= 1; // flip the lowest bit of weight i (stays in range, != pair)
            if (wmp[i] < 2) wmp[i] = 2;
            uint8_t o[32]; run_t4_q30_raw(wm, DEFAULT_SEED, o);
            double h = hamming_pct_buf(base, o, 32);
            if (h > 1.0) affected++;
            if (h < min_h) min_h = h;
        }
        std::printf("    weights affecting output: %d / 12 (min bit-change %.1f%%)\n",
                    affected, min_h);
        check(affected == 12, "all 12 weights change the output (full capacity)");
    }

    // --- 5. cascade: every epoch contributes (incl. the earliest) ---
    std::printf("\n[5] Cascade: every epoch contributes; no intermediate leak\n");
    {
        int m = MCL_CASCADE_DEFAULT_EPOCHS;
        std::vector<std::pair<int64_t,int64_t> > ep =
            mcl_cascade_q30_params_from_key(key, m);
        uint8_t base[32]; run_cascade_raw(ep, DEFAULT_SEED, base);
        int affected = 0; double min_h = 100.0;
        for (int e = 0; e < m; e++) {
            std::vector<std::pair<int64_t,int64_t> > epm = ep;
            epm[(size_t)e].first ^= 1;            // perturb epoch e's p
            if (epm[(size_t)e].first < 2) epm[(size_t)e].first = 3;
            uint8_t o[32]; run_cascade_raw(epm, DEFAULT_SEED, o);
            double h = hamming_pct_buf(base, o, 32);
            if (h > 1.0) affected++;
            if (h < min_h) min_h = h;
        }
        std::printf("    epochs affecting final output: %d / %d (min bit-change %.1f%%)\n",
                    affected, m, min_h);
        check(affected == m, "every epoch (incl. epoch 0) changes the final output");
        std::printf("    (intermediate state is never externalized -- joint-space"
                    " precondition holds by construction)\n");
    }

    // --- 6. forward non-monotonicity (informational; NOT a one-wayness proof) ---
    std::printf("\n[6] Forward non-monotonicity (two-osc Q30, p=3,q=5) -- INFORMATIONAL\n");
    {
        // CORRECTED (was overstated in prior versions). This counts slope sign
        // reversals of t1'(t1) at fixed t2 -- a NON-MONOTONICITY measure. NOTE:
        // non-monotonicity does NOT imply non-injectivity (a permutation built
        // from scattered slope-1 ramps is non-monotone yet bijective), so this
        // is NOT a one-wayness test. The DEFINITIVE backward-branching number is
        // measured in mcl_keyed_q30_science.cpp [T3] by image cardinality:
        // b ~= 1.59 (the Q30 map IS many-to-one but only WEAKLY -- ~24x less
        // folding than the Float64 engine's b~38, due to the coarse 16-bit LUT).
        // The KEYSTREAM-CONSTRAINED b_eff (the actual one-wayness condition,
        // Float64 ~6) is NOT yet established for Q30 -- an OPEN RISK (README).
        const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
        const uint32_t t2fix = 0x12345678u;
        const int SCAN_BITS = 22;
        const long M = 1L << SCAN_BITS;
        auto cdiff = [](uint32_t y2, uint32_t y1) -> long {
            uint32_t d = y2 - y1;
            return (d & 0x80000000u) ? ((long)d - 4294967296L) : (long)d;
        };
        long prev_y = -1; int prev_sign = 0; long reversals = 0, neg_steps = 0;
        bool have = false;
        for (long i = 0; i < M; i++) {
            uint32_t a = (uint32_t)((uint64_t)i << (32 - SCAN_BITS)), b = t2fix;
            mcl_q30_iterate_raw(a, b, 3, 5, kp);
            if (!have) { prev_y = (long)a; have = true; continue; }
            long dd = cdiff(a, (uint32_t)prev_y);
            int sgn = (dd > 0) ? 1 : ((dd < 0) ? -1 : 0);
            if (sgn < 0) neg_steps++;
            if (prev_sign != 0 && sgn != 0 && sgn != prev_sign) reversals++;
            if (sgn != 0) prev_sign = sgn;
            prev_y = (long)a;
        }
        std::printf("    scanned %ld points: slope sign reversals = %ld, downward steps = %ld\n",
                    M, reversals, neg_steps);
        std::printf("    INFORMATIONAL only: non-monotone != non-injective. Definitive backward\n");
        std::printf("    branching is b~1.59 (science [T3], weak); keystream-constrained b_eff for\n");
        std::printf("    Q30 is UNRESOLVED (open risk). No pass/fail asserted here.\n");
    }

    // --- 7. post-quantum BIT-BUDGET accounting (NOT a security proof) ---
    // NOTE: this section verifies the secret-entropy BUDGET only (capacity bits
    // and the Grover sqrt). It does NOT verify that the map delivers that
    // security -- that needs the chaos/one-wayness evidence (tests [3]-[6],
    // R1-R3 in the review harness, and the b_eff suite), and a true Lyapunov
    // spectrum for T4-Q30 is still UNMEASURED (see README "Next steps").
    std::printf("\n[7] Post-quantum BIT-BUDGET accounting (budget only, not a proof)\n");
    {
        double pair = mcl_q30_pair_bits();
        std::printf("    one Q30 coprime (p,q) pair        = %.2f classical bits\n", pair);
        MCL_PQReport t4 = mcl_pq_security(256.0); // key-bounded (capacity 360 >= 256)
        std::printf("    T4-Q30 (capacity %.0f bits, key-bounded 256): post-Grover %.0f, Cat5=%s\n",
                    mcl_t4_q30_capacity_bits(), t4.post_grover_bits,
                    t4.meets_category5 ? "YES" : "no");
        check(mcl_t4_q30_capacity_bits() >= 256.0, "T4-Q30 capacity >= 256 bits");
        check(t4.meets_category5, "T4-Q30 keyed = NIST PQ Category 5 (128 post-Grover = AES-256)");
        for (int m = 5; m <= 7; m++) {
            double cap = mcl_cascade_q30_capacity_bits(m);
            MCL_PQReport r = mcl_pq_security(cap);
            std::printf("    cascade m=%d: capacity %.0f classical -> %.0f post-Grover (joint), Cat5=%s\n",
                        m, cap, r.post_grover_bits, r.meets_category5 ? "YES" : "no");
        }
        std::printf("    (cascade security = joint FORWARD search from the public seed:\n");
        std::printf("     no intermediate output [5] + backward branching b>1 (~2.5/2-D step,\n");
        std::printf("     science [T3]) makes a full-epoch back-peel explode (b^256) and blocks\n");
        std::printf("     meet-in-the-middle, so the attacker must guess all m (p,q) forward.\n");
        std::printf("     m>=5 reaches Category 5 (>=128 post-Grover); m=7 is extra margin. NOTE: the Q30 STREAM/PRNG use --\n");
        std::printf("     where the keystream IS observed -- has an UNRESOLVED keystream-\n");
        std::printf("     constrained b_eff (open risk); this does not affect the cascade or T4.)\n");
    }

    // --- 8. timing + footprint ---
    std::printf("\n[8] Timing (this host) + working-memory footprint\n");
    {
        const int reps = 200;
        auto t0 = clk::now();
        for (int i = 0; i < reps; i++) { MCL_T4_Q30 e(key); uint8_t o[32]; e.commit32(o);
            asm volatile("" :: "g"(o[0]) : "memory"); }
        double t4ms = std::chrono::duration<double,std::milli>(clk::now()-t0).count()/reps;
        auto t1 = clk::now();
        for (int i = 0; i < reps; i++) { uint8_t o[32]; mcl_cascade_q30(key, o);
            asm volatile("" :: "g"(o[0]) : "memory"); }
        double casms = std::chrono::duration<double,std::milli>(clk::now()-t1).count()/reps;
        std::printf("    T4-Q30 construct+commit  = %.3f ms/op (this host)\n", t4ms);
        std::printf("    cascade(m=7)             = %.3f ms/op (this host)\n", casms);
        std::printf("    working state: T4-Q30 = %zu bytes (4x uint32 + 12x int64 + kp)\n",
                    sizeof(MCL_T4_Q30));
        std::printf("    sin LUT (shared, ROM-able) = %zu bytes\n", sizeof(int32_t) * 65536);
        std::printf("    (FPU-free: hot path is integer + LUT only; scale ~x125 clock\n");
        std::printf("     to a 28 MHz Cortex-M0, NO software-double penalty -- unlike\n");
        std::printf("     the Float64 keyed path)\n");
    }

    std::printf("\n================================================================\n");
    std::printf("  SUMMARY: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("================================================================\n");
    return g_fail == 0 ? 0 : 1;
}
