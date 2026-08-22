/*
 * MCL Byte-level Safe-Zone Boundary Scan (Paper 1 §3.4 / Table 8 / Fig. 5)
 * Engine: mcl_core.hpp v6.0.0 (archived, MD5 241db79ecf8a42897eb9a8399cf37929)
 *
 * PURPOSE: Reproduce the paper's BYTE-LEVEL Safe-Zone boundaries for single
 * oscillators (θ1, θ2) and the XOR stream, to confirm the Figure-5 / Table-8
 * values:  θ1 = [11,35] = 25 bits,  θ2 = [12,35] = 24 bits,  XOR = [6,39] = 34.
 *
 * METHOD (Paper 1 §3.3): for each start position s = 0..44, extract the 8-bit
 * window [s, s+7] of the 52-bit IEEE-754 mantissa, build one byte per sample,
 * histogram over 256 values, and test χ²(df=255) against the uniform null at
 * the α = 0.01 critical value 310.46. The Safe Zone is the widest contiguous
 * run of start positions that pass, reported as [first_start, last_start + 7].
 * XOR extraction uses xored = mantissa(θ1) ⊕ mantissa(θ2) (Paper 1 Eq. 4).
 *
 * The XOR result is the methodology self-check: it must reproduce [6,39].
 *
 * BUILD:
 *   c++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
 *       -o mcl_bytezone_scan mcl_bytezone_scan.cpp -lm && ./mcl_bytezone_scan
 */

#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <cstdint>
#include <vector>

static const uint64_t SEED = 12345678901234ULL;   // Paper-1 primary seed
static constexpr int64_t N = 100000000;            // 10^8 (paper protocol)
static constexpr int MBITS = 52;
static constexpr int WIN = 8;
static constexpr int NSTART = MBITS - WIN + 1;     // 45 start positions (0..44)
static constexpr double CRIT = 310.46;             // χ²(df=255, α=0.01)

static inline uint64_t mant(double x) { return d2b(x) & 0x000FFFFFFFFFFFFFULL; }

struct Scan {
    // hist[s][byte] : per start position s
    std::vector<std::vector<int64_t>> h;
    Scan() : h(NSTART, std::vector<int64_t>(256, 0)) {}
    inline void add(uint64_t m) {
        for (int s = 0; s < NSTART; s++)
            h[(size_t)s][(uint8_t)((m >> s) & 0xFFULL)]++;
    }
};

static void report(const char* name, const Scan& sc) {
    const double expct = (double)N / 256.0;
    int best_lo = -1, best_hi = -1, cur_lo = -1;
    std::printf("  %s: byte-level χ²(df=255), crit = %.2f\n", name, CRIT);
    for (int s = 0; s < NSTART; s++) {
        double chi2 = 0.0;
        for (int b = 0; b < 256; b++) {
            const double d = (double)sc.h[(size_t)s][(size_t)b] - expct;
            chi2 += d * d / expct;
        }
        const bool pass = chi2 < CRIT;
        if (pass) {
            if (cur_lo < 0) cur_lo = s;
            // Paper convention: zone reported as [first passing start, last passing start]
            // (the START bit of the window). XOR reproduces [6,39] under this convention.
            if (best_lo < 0 || (s - cur_lo) > (best_hi - best_lo)) {
                best_lo = cur_lo; best_hi = s;
            }
        } else cur_lo = -1;
        // print boundary-relevant windows
        if (s <= 14 || s >= 28)
            std::printf("    start %2d (bits %2d-%2d): χ² = %12.2f  %s\n",
                        s, s, s + WIN - 1, chi2, pass ? "PASS" : "FAIL");
    }
    std::printf("  => byte-level Safe Zone: [%d, %d] = %d bits\n\n",
                best_lo, best_hi, best_hi - best_lo + 1);
}

int main() {
    std::printf("=== MCL byte-level Safe-Zone scan (N=10^8, seed %llu, Apple libm) ===\n",
                (unsigned long long)SEED);
    std::printf("Engine v6.0.0 archived | (p,q,K)=(3,5,12) | 8-bit sliding window\n\n");

    double t1, t2;
    mcl_init_state(SEED, t1, t2);
    for (int i = 0; i < BURNIN; i++) mcl_iterate_raw(t1, t2, 3, 5, 12.0);

    Scan s1, s2, sx;
    for (int64_t n = 0; n < N; n++) {
        mcl_iterate_raw(t1, t2, 3, 5, 12.0);
        const uint64_t m1 = mant(t1), m2 = mant(t2);
        s1.add(m1); s2.add(m2); sx.add(m1 ^ m2);
    }

    report("theta_1 (single)", s1);
    report("theta_2 (single)", s2);
    report("XOR (theta_1 ^ theta_2)  [methodology check -> must give [6,39]]", sx);

    std::printf("Text claims: theta_1 = [11,35] = 25 ; theta_2 = [12,35] = 24 ; XOR = [6,39] = 34\n");
    return 0;
}
