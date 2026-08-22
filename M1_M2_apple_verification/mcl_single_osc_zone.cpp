/*
 * MCL Single-Oscillator Safe-Zone Boundary Measurement (Paper 1 §3.4 / Fig. 5)
 * Engine: mcl_core.hpp v6.0.0 (archived, MD5 241db79ecf8a42897eb9a8399cf37929)
 *
 * PURPOSE: Resolve the Figure-5 vs text discrepancy for the single-oscillator
 * Safe Zones. Text claims  θ1 = [11,35] = 25 bits,  θ2 = [12,35] = 24 bits.
 * Figure 5 (inherited graphic) shows θ1 = [12,35] = 24, θ2 = [12,36] = 25.
 *
 * METHOD: per-bit frequency balance χ²(df=1) over the 52-bit IEEE-754 mantissa
 * of EACH single oscillator (θ1 and θ2 separately), N = 10^8 samples, one
 * iterate() step per sample (no decimation) — the Paper-1 §3.3 per-bit protocol
 * (critical value 3.841 at α = 0.05). The contiguous run of bit positions with
 * χ² < 3.841 is the single-oscillator per-bit Safe Zone.
 *
 * BUILD:
 *   c++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
 *       -o mcl_single_osc_zone mcl_single_osc_zone.cpp -lm && ./mcl_single_osc_zone
 */

#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <cstdint>

static const uint64_t SEED = 12345678901234ULL;   // Paper-1 primary seed
static constexpr int64_t N = 100000000;           // 10^8
static constexpr int MBITS = 52;
static constexpr double CRIT = 3.841;             // χ²(df=1, α=0.05)

static inline uint64_t mantissa_of(double x) {
    return d2b(x) & 0x000FFFFFFFFFFFFFULL;
}

static void scan(const char* name, int which /*1=t1,2=t2*/) {
    double t1, t2;
    mcl_init_state(SEED, t1, t2);
    for (int i = 0; i < BURNIN; i++) mcl_iterate_raw(t1, t2, 3, 5, 12.0);

    int64_t ones[MBITS] = {0};
    for (int64_t n = 0; n < N; n++) {
        mcl_iterate_raw(t1, t2, 3, 5, 12.0);
        const uint64_t m = mantissa_of(which == 1 ? t1 : t2);
        for (int b = 0; b < MBITS; b++)
            ones[b] += (int64_t)((m >> b) & 1ULL);
    }

    // per-bit χ²(df=1) for 0/1 balance, and contiguous passing run
    int lo = -1, hi = -1, best_lo = -1, best_hi = -1, cur_lo = -1;
    std::printf("  %s per-bit χ²(df=1), crit = %.3f:\n", name, CRIT);
    for (int b = 0; b < MBITS; b++) {
        const double exp = (double)N / 2.0;
        const double o1 = (double)ones[b];
        const double o0 = (double)N - o1;
        const double chi2 = (o0 - exp) * (o0 - exp) / exp + (o1 - exp) * (o1 - exp) / exp;
        const bool pass = chi2 < CRIT;
        if (pass) {
            if (cur_lo < 0) cur_lo = b;
            lo = cur_lo; hi = b;
            if (best_lo < 0 || (hi - lo) > (best_hi - best_lo)) { best_lo = lo; best_hi = hi; }
        } else {
            cur_lo = -1;
        }
        if (b <= 15 || b >= 33)   // print the informative boundary bits
            std::printf("    bit %2d: χ² = %12.3f  %s\n", b, chi2, pass ? "PASS" : "FAIL");
    }
    std::printf("  => longest contiguous per-bit Safe Zone: [%d, %d] = %d bits\n\n",
                best_lo, best_hi, best_hi - best_lo + 1);
}

int main() {
    std::printf("=== MCL single-oscillator per-bit Safe-Zone scan (N=10^8, seed %llu) ===\n",
                (unsigned long long)SEED);
    std::printf("Engine v6.0.0 archived | (p,q,K)=(3,5,12) | Apple libm\n\n");
    scan("theta_1", 1);
    scan("theta_2", 2);
    std::printf("Text claim: theta_1 = [11,35] = 25 bits ; theta_2 = [12,35] = 24 bits\n");
    return 0;
}
