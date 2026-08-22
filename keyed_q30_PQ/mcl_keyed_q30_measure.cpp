/*
 * mcl_keyed_q30_measure.cpp -- measurement runner for the seven [MEASURE]
 * anchors of PCT-04 Description v4 (and the Claim-15 quarter-wave CRC proof
 * requested in the attorney notes).
 *
 * [M1] LUT geometry + CRC + quarter-wave reconstruction bit-identity   ([0027]/[0046], Claim 15)
 * [M2] Working-memory footprint (engine state, schedule, table)        ([0043], Claim 22)
 * [M3] Per-term scaling overflow bounds (analytic + empirical)         ([0031], Claim 17)
 * [M4] Latency: full auth op, cascade op, raw iterate, keystream       ([0046])
 * [M5] Cascade capacity / effective post-quantum bits                  ([0047])
 * [M6] MATRIX-KAT line for the cross-platform bit-identity matrix      ([0033], Claim 11)
 *
 * Build exactly like the harness (assert path included, as in the recorded
 * 0x58C99E3E [T4] / 0xF7C81BC4 [cascade, SHA-256-hashed since 2026-06-15] CRCs):
 *   c++ -std=c++17 -O3 -Wall -Wextra -I .. -o m mcl_keyed_q30_measure.cpp && ./m
 * Cross-ISA (Rosetta): add -arch x86_64.
 */

#include "mcl_keyed_q30.hpp"
#include <chrono>
#include <algorithm>
#include <cmath>

static const char* arch_name() {
#if defined(__aarch64__)
    return "arm64";
#elif defined(__x86_64__)
    return "x86_64";
#else
    return "unknown";
#endif
}
static const char* compiler_name() {
#if defined(__clang__)
    return "clang";
#elif defined(__GNUC__)
    return "gcc";
#else
    return "other";
#endif
}

static double now_ms() {
    using namespace std::chrono;
    return (double)duration_cast<nanoseconds>(
        steady_clock::now().time_since_epoch()).count() / 1e6;
}

int main() {
    std::setbuf(stdout, nullptr);
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + 1); // harness KAT key

    std::printf("================================================================\n");
    std::printf("  MCL KEYED Q30 -- [MEASURE] runner (engine %s)  %s/%s -O%d\n",
                mcl_version(), arch_name(), compiler_name(),
#if defined(__OPTIMIZE__)
                3
#else
                0
#endif
    );
    std::printf("================================================================\n");

    // ------------------------------------------------------------------
    // [M1] LUT geometry, CRC, quarter-wave reconstruction bit-identity
    // ------------------------------------------------------------------
    std::printf("\n[M1] Sine LUT geometry + quarter-wave compression (Claim 15)\n");
    const MCL_Q30_Table& tab = mcl_q30_table();
    {
        const uint32_t full_crc =
            compute_crc32((const uint8_t*)tab.lut, sizeof(tab.lut));
        std::printf("    full table: %d entries x %zu B = %zu B (%.1f KiB), CRC-32 = 0x%08X (expect 0xDE1340CF)\n",
                    65536, sizeof(int32_t), sizeof(tab.lut),
                    sizeof(tab.lut) / 1024.0, full_crc);

        // Stored quarter: entries 0..16384 inclusive (16385 entries).
        static int32_t quarter[16385];
        for (int i = 0; i <= 16384; i++) quarter[i] = tab.lut[i];
        const size_t qbytes = sizeof(quarter);
        const uint32_t qcrc = compute_crc32((const uint8_t*)quarter, qbytes);

        // Reconstruct the full period by index reflection + sign negation.
        static int32_t recon[65536];
        for (int i = 0; i < 65536; i++) {
            if      (i <= 16384) recon[i] =  quarter[i];
            else if (i <  32768) recon[i] =  quarter[32768 - i];
            else if (i <= 49152) recon[i] = -quarter[i - 32768];
            else                 recon[i] = -quarter[65536 - i];
        }
        long mismatches = 0; int max_abs_delta = 0;
        for (int i = 0; i < 65536; i++) {
            if (recon[i] != tab.lut[i]) {
                mismatches++;
                int d = (int)std::llabs((long long)recon[i] - (long long)tab.lut[i]);
                if (d > max_abs_delta) max_abs_delta = d;
            }
        }
        const uint32_t rcrc = compute_crc32((const uint8_t*)recon, sizeof(recon));
        std::printf("    quarter-wave: 16385 entries = %zu B (%.1f KiB), CRC-32 = 0x%08X\n",
                    qbytes, qbytes / 1024.0, qcrc);
        std::printf("    reconstructed-full CRC-32 = 0x%08X vs canonical 0x%08X -> %s\n",
                    rcrc, full_crc, (rcrc == full_crc && mismatches == 0)
                                        ? "BIT-IDENTICAL" : "MISMATCH");
        std::printf("    entry mismatches = %ld / 65536, max |delta| = %d LSB\n",
                    mismatches, max_abs_delta);
        std::printf("    compression: %zu B -> %zu B (%.2fx)\n",
                    sizeof(tab.lut), qbytes,
                    (double)sizeof(tab.lut) / (double)qbytes);
    }

    // ------------------------------------------------------------------
    // [M2] Working-memory footprint
    // ------------------------------------------------------------------
    std::printf("\n[M2] Working memory (Claim 22 / [0043])\n");
    {
        std::printf("    sizeof(MCL_T4_Q30) engine object   = %zu B "
                    "(4x uint32 state + 12x uint32 weights + int64 K_phase; "
                    "uint32 weights => native 32x32 multiply, Claim 13)\n",
                    sizeof(MCL_T4_Q30));
        const size_t casc_state = 2 * sizeof(uint32_t);
        const size_t casc_sched7 = 7 * sizeof(std::pair<int64_t,int64_t>);
        std::printf("    cascade working state              = %zu B; m=7 schedule = %zu B; total %zu B\n",
                    casc_state, casc_sched7, casc_state + casc_sched7);
        std::printf("    output buffer (commitment)         = 32 B\n");
        std::printf("    LUT (const, ROM/NVM-resident)      = %zu B full / %d B quarter-wave\n",
                    sizeof(tab.lut), 16385 * 4);
        std::printf("    all sizes fixed at compile time, independent of output length\n");
    }

    // ------------------------------------------------------------------
    // [M3] Per-term scaling overflow bounds (Claim 17 / [0031])
    // ------------------------------------------------------------------
    std::printf("\n[M3] Per-term scaling overflow analysis (Claim 17)\n");
    {
        // per-term:  |K_phase * sin_q30| <= K_phase * 2^30 must fit int64.
        // K_phase = K * 2^32 / 2pi  ->  K_max = INT64_MAX * 2pi / 2^62 = 4pi.
        const double k_max_per_term = (double)INT64_MAX * MCL_TWO_PI
                                      / std::pow(2.0, 62.0);
        const double k_max_sum3     = k_max_per_term / 3.0;
        const int64_t kp12          = mcl_q30_K_phase(12.0);
        const long double prod12    = (long double)kp12 * (long double)(1u << 30);
        // empirical max |sin_q30| over the whole table
        int32_t smax = 0;
        for (int i = 0; i < 65536; i++)
            if (std::abs(tab.lut[i]) > smax) smax = std::abs(tab.lut[i]);
        std::printf("    admissible K, per-term scaling     : K <= 4*pi = %.4f (overflow onset)\n",
                    k_max_per_term);
        std::printf("    admissible K, sum-3-then-scale     : K <= 4*pi/3 = %.4f (overflow onset)\n",
                    k_max_sum3);
        std::printf("    enforced cap K = 12.0              : margin to onset = %.2f%%\n",
                    (k_max_per_term / 12.0 - 1.0) * 100.0);
        std::printf("    max |sin_q30| entry = %d (2^30 = %d)\n", smax, 1 << 30);
        std::printf("    worst per-term product at K=12     : %.6Le of INT64_MAX %.6Le (ratio %.4Lf)\n",
                    prod12, (long double)INT64_MAX,
                    prod12 / (long double)INT64_MAX);
    }

    // ------------------------------------------------------------------
    // [M4] Latency (host measurement; target-core figure stays constructive)
    // ------------------------------------------------------------------
    std::printf("\n[M4] Latency on this host (%s, %s, -O3)\n", arch_name(), compiler_name());
    {
        const int REPS = 200;
        std::vector<double> t_auth, t_oneway, t_casc;
        uint8_t out[32];
        volatile uint8_t sink = 0;
        for (int r = 0; r < REPS; r++) {
            uint8_t k2[32]; std::memcpy(k2, key, 32); k2[31] ^= (uint8_t)r;
            double a = now_ms();
            { MCL_T4_Q30 e(k2, /*challenge=*/(uint64_t)r); e.commit32(out); }
            double b = now_ms(); t_auth.push_back(b - a);
            a = now_ms();
            { MCL_T4_Q30 e(k2, (uint64_t)r); e.commit32_oneway(out); }
            b = now_ms(); t_oneway.push_back(b - a);
            a = now_ms();
            mcl_cascade_q30(k2, out, 7, (uint64_t)r);
            b = now_ms(); t_casc.push_back(b - a);
            sink ^= out[0];
        }
        auto med = [](std::vector<double>& v) {
            std::sort(v.begin(), v.end()); return v[v.size() / 2]; };
        std::printf("    T4-Q30 full auth (KDF+derive+%d burn-in+commit32): median %.3f ms\n",
                    BURNIN, med(t_auth));
        std::printf("    T4-Q30 full auth, hashed output (commit32_oneway): median %.3f ms\n",
                    med(t_oneway));
        std::printf("    cascade m=7 full op (%d+6x%d iters+commit)       : median %.3f ms\n",
                    MCL_CASCADE_FIRST_EPOCH_ITERS, MCL_CASCADE_LATER_EPOCH_ITERS,
                    med(t_casc));

        // raw iterate cost
        {
            MCL_T4_Q30 e(key);
            const int64_t N = 10'000'000;
            double a = now_ms();
            for (int64_t i = 0; i < N; i++) e.iterate();
            double b = now_ms();
            sink ^= (uint8_t)e.s1();
            std::printf("    T4-Q30 raw iterate                : %.1f ns/iter (%.1f M iters/s)\n",
                        (b - a) * 1e6 / (double)N, (double)N / ((b - a) * 1e3));
        }
        {
            uint32_t t1, t2; mcl_q30_init_state(DEFAULT_SEED, t1, t2);
            const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
            const int64_t N = 10'000'000;
            double a = now_ms();
            for (int64_t i = 0; i < N; i++) mcl_q30_iterate_raw(t1, t2, 40009, 40013, kp);
            double b = now_ms();
            sink ^= (uint8_t)t1;
            std::printf("    2-osc Q30 raw iterate             : %.1f ns/iter (%.1f M iters/s)\n",
                        (b - a) * 1e6 / (double)N, (double)N / ((b - a) * 1e3));
        }
        {
            MCL_T4_Q30 e(key);
            const int64_t N = 1 << 20;
            std::vector<uint8_t> buf((size_t)N);
            double a = now_ms();
            e.gen_bytes(buf.data(), N);
            double b = now_ms();
            sink ^= buf[0];
            std::printf("    T4-Q30 keystream                  : %.2f MiB/s\n",
                        (double)N / 1048576.0 / ((b - a) / 1e3));
        }
        (void)sink;
    }

    // ------------------------------------------------------------------
    // [M5] Cascade capacity / effective post-quantum accounting
    // ------------------------------------------------------------------
    std::printf("\n[M5] Cascade capacity accounting ([0047])\n");
    {
        const double pair_bits = mcl_q30_pair_bits();
        std::printf("    ordered coprime (p,q) pair in [2,2^30): %.2f bits/epoch\n", pair_bits);
        for (int m : {5, 7}) {
            const double cap = mcl_cascade_q30_capacity_bits(m);
            const double secret = std::min(256.0, cap);
            std::printf("    m=%d: schedule representation %.1f bits; brute-forceable secret min(L,cap) = %.0f bits -> post-Grover %.0f (Cat-1 needs 128)\n",
                        m, cap, secret, secret / 2.0);
        }
        std::printf("    T4-Q30: 12 x 30 = %.0f-bit representation >= L=256 -> post-Grover 128 = NIST Category 1\n",
                    mcl_t4_q30_capacity_bits());
    }

    // ------------------------------------------------------------------
    // [M6] MATRIX-KAT -- one line to diff across {arch x compiler x -O}
    // ------------------------------------------------------------------
    std::printf("\n[M6] Bit-identity KATs ([0033])\n");
    {
        uint8_t a[32], ow[32], c7[32], c5[32];
        { MCL_T4_Q30 e(key); e.commit32(a); }
        { MCL_T4_Q30 e(key); e.commit32_oneway(ow); }
        mcl_cascade_q30(key, c7, 7);
        mcl_cascade_q30(key, c5, 5);
        const int64_t N = 1 << 20;
        std::vector<uint8_t> ks((size_t)N);
        { MCL_T4_Q30 e(key); e.gen_bytes(ks.data(), N); }
        const uint32_t lut_crc =
            compute_crc32((const uint8_t*)tab.lut, sizeof(tab.lut));
        std::printf("    T4-Q30 commit32 CRC = 0x%08X (recorded 0x58C99E3E)\n", compute_crc32(a, 32));
        std::printf("    cascade m=7 CRC     = 0x%08X (recorded 0xF7C81BC4, SHA-256-hashed final commitment)\n", compute_crc32(c7, 32));
        std::printf("MATRIX-KAT arch=%s cc=%s lut=0x%08X t4=0x%08X ow=0x%08X c7=0x%08X c5=0x%08X ks1MiB=0x%08X\n",
                    arch_name(), compiler_name(), lut_crc,
                    compute_crc32(a, 32), compute_crc32(ow, 32),
                    compute_crc32(c7, 32), compute_crc32(c5, 32),
                    compute_crc32(ks.data(), (size_t)N));
    }

    std::printf("\nDone.\n");
    return 0;
}
