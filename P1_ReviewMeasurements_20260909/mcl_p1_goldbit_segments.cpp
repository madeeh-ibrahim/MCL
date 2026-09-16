// mcl_p1_goldbit_segments.cpp — Doc ID MCL-P1-GOLDBIT-SEG-2026-0909-001
//
// PURPOSE (Paper 1, external review #2, item ت-37): MCL-P1-GOLDBIT-2026-0907-001
// found that emitted output bit 5 of the Goldilocks byte (Eq. 5: mantissa bit 25
// XOR mantissa bit 41) carries P(1) - 1/2 = +1.739e-04 (chi2(df=1) = 12.096) in
// seed 12345678901234 over the FIRST N = 1e8 output samples, and not in five
// other seeds. That measurement re-uses the stream start, so it cannot say
// whether the residual is a transient of that stream or a persistent property
// of the orbit. This tool answers that with PRE-SPECIFIED, NON-OVERLAPPING,
// CONSECUTIVE segments of the same stream: S = 10 segments x N = 1e8 output
// samples (10^9 samples, 2x10^9 engine iterations), reporting per segment and
// cumulatively, for every emitted bit k = 0..7, the ones count, P(1)-1/2 and
// chi2(df=1); plus the 256-bin byte-level chi2 (df=255) of the emitted byte per
// segment. It also reports the byte-level chi2 at N = 1e8 for the six seeds of
// the 2026-09-07 run, which that run did not record.
//
// Engine of record mcl_core.hpp v6.0.0 (MD5 241db79ecf8a42897eb9a8399cf37929),
// (p,q) = (3,5), K = 12, decimation D = 2, burn-in 10000 (engine default) —
// identical to mcl_p1_goldilocks_outbit.cpp.
//
// BUILD: c++ -O3 -std=c++17 -ffp-contract=off \
//            -o mcl_p1_goldbit_segments mcl_p1_goldbit_segments.cpp -lm
#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <cstring>

static double chi2_byte(const long long *bins, long long n) {
    double e = (double)n / 256.0, s = 0.0;
    for (int i = 0; i < 256; i++) { double d = (double)bins[i] - e; s += d * d / e; }
    return s;
}

int main() {
    const long long N = 100000000LL;
    const int S = 10;
    const uint64_t seeds[6] = {12345678901234ULL, 31415926535897ULL, 27182818284590ULL,
                               98765432109876ULL, 17320508075688ULL, 70466644885213ULL};
    std::printf("==============================================================\n");
    std::printf(" MCL PAPER 1 — GOLDILOCKS OUTPUT-BIT FREQUENCY ON CONSECUTIVE SEGMENTS\n");
    std::printf(" Doc ID: MCL-P1-GOLDBIT-SEG-2026-0909-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen), (p,q)=(3,5), K=12, D=2, burn-in %d\n", BURNIN);
    std::printf(" Part A: seed 12345678901234, S=%d consecutive non-overlapping segments x N=%lld\n", S, N);
    std::printf("         output bit k = mant(20+k) XOR mant(36+k); byte = sum_k bit_k << k\n");
    std::printf(" Thresholds: per-bit nominal 3.841; Bonferroni over 80 segment-bit tests = %.3f;\n",
                /* chi2_1 quantile for alpha = 0.05/80 = 6.25e-4 */ 11.703);
    std::printf("             byte-level df=255 critical 310.46 (alpha=0.01)\n");
    std::printf("==============================================================\n\n");

    // ---- Part A: segments on the flagged seed ----
    {
        MCL_T2 eng(seeds[0], 3, 5, 12.0);
        long long cum1[8] = {0};
        std::printf("Part A — seed 12345678901234\n");
        std::printf(" seg |   samples [from, to)    | bit5 ones   | bit5 p-0.5   | bit5 chi2 | worst bit (chi2) | byte chi2 | CUM bit5 p-0.5 | CUM bit5 chi2\n");
        std::printf("-----|-------------------------|-------------|--------------|-----------|------------------|-----------|----------------|--------------\n");
        for (int s = 0; s < S; s++) {
            long long ones[8] = {0};
            long long bins[256]; std::memset(bins, 0, sizeof(bins));
            for (long long i = 0; i < N; i++) {
                eng.iterate(); eng.iterate();
                uint64_t x = d2b(eng.theta1()) ^ d2b(eng.theta2());
                uint64_t xm = x & ((1ULL << 52) - 1);
                int byte = 0;
                for (int k = 0; k < 8; k++) {
                    int bit = (int)(((xm >> (20 + k)) ^ (xm >> (36 + k))) & 1);
                    ones[k] += bit; byte |= bit << k;
                }
                bins[byte]++;
            }
            double n = (double)N;
            double worst = 0; int wk = -1;
            for (int k = 0; k < 8; k++) {
                cum1[k] += ones[k];
                double d = (double)ones[k] / n - 0.5, c = n * 4.0 * d * d;
                if (c > worst) { worst = c; wk = k; }
            }
            double d5 = (double)ones[5] / n - 0.5, c5 = n * 4.0 * d5 * d5;
            double nc = n * (double)(s + 1);
            double dc = (double)cum1[5] / nc - 0.5, cc = nc * 4.0 * dc * dc;
            std::printf(" %3d | [%10lld, %10lld) | %11lld | %+12.3e | %9.3f | bit %d (%7.3f)   | %9.1f | %+14.3e | %12.3f\n",
                        s + 1, (long long)s * N, (long long)(s + 1) * N, ones[5], d5, c5, wk, worst,
                        chi2_byte(bins, N), dc, cc);
            std::fflush(stdout);
        }
        std::printf("\n Per-bit chi2 of the FULL 1e9-sample stream (cumulative):\n");
        double nc = (double)N * S;
        for (int k = 0; k < 8; k++) {
            double d = (double)cum1[k] / nc - 0.5;
            std::printf("   bit %d: ones %lld  p-0.5 %+.3e  chi2 %.3f\n", k, cum1[k], d, nc * 4.0 * d * d);
        }
        std::printf("\n");
    }

    // ---- Part B: byte-level chi2 at N=1e8 for the six seeds of the 2026-09-07 run ----
    std::printf("Part B — byte-level chi2 (df=255) of the emitted Goldilocks byte, N=%lld per seed\n", N);
    std::printf(" seed             | byte chi2 | verdict (crit 310.46) | bit5 chi2\n");
    std::printf("------------------|-----------|-----------------------|----------\n");
    for (int s = 0; s < 6; s++) {
        MCL_T2 eng(seeds[s], 3, 5, 12.0);
        long long bins[256]; std::memset(bins, 0, sizeof(bins));
        long long ones5 = 0;
        for (long long i = 0; i < N; i++) {
            eng.iterate(); eng.iterate();
            uint64_t x = d2b(eng.theta1()) ^ d2b(eng.theta2());
            uint64_t xm = x & ((1ULL << 52) - 1);
            int byte = 0;
            for (int k = 0; k < 8; k++) {
                int bit = (int)(((xm >> (20 + k)) ^ (xm >> (36 + k))) & 1);
                byte |= bit << k;
            }
            bins[byte]++; ones5 += (byte >> 5) & 1;
        }
        double c = chi2_byte(bins, N);
        double d5 = (double)ones5 / (double)N - 0.5;
        std::printf(" %-16llu | %9.1f | %-21s | %8.3f\n", (unsigned long long)seeds[s], c,
                    (c < 310.46 ? "PASS" : "FAIL"), (double)N * 4.0 * d5 * d5);
        std::fflush(stdout);
    }
    return 0;
}
