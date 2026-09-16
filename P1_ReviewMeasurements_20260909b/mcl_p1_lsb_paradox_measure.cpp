// mcl_p1_lsb_paradox_measure.cpp — Doc ID MCL-P1-LSBPARADOX-2026-0909-001
//
// PURPOSE (Paper 1, Figure 5 / §3.3 "Float64 vs Q30"): the figure inherited from
// the May 2026 draft was a synthetic rendering (its generator, make_fig4.py,
// states that the curves were "reverse-engineered" and rescaled to match three
// headline values: ~41% and ~7% avalanche, chi2 ~ 261). This tool MEASURES the
// three quantities the figure depicts, against the engine of record, under a
// stated protocol, so that the figure and the table can be regenerated from a log.
//
//  A. Float64 single-ULP avalanche per mantissa position (0..51): for M orbit
//     states (theta1, theta2) sampled every iteration after burn-in, apply ONE
//     iteration of the map (Eqs. 1-2, same arithmetic as MCL_T2::iterate) to the
//     state and to the state with theta1 replaced by nextafter(theta1, +inf);
//     report, per mantissa bit b, the fraction of trials in which bit b of the
//     resulting theta1 (and of the XOR-mixed mantissa) differs.
//  B. The same for the Q30 fixed-point path (mcl_q30_iterate_raw of the engine of
//     record): state word t1 perturbed by +1 (one Q30 phase unit), one iteration,
//     per-bit difference fraction of the resulting t1 word and of t1 XOR t2
//     (positions 0..31 of the uint32 phase word).
//  C. Q30 byte-level chi-square (256 bins, df = 255, critical 310.46 at alpha =
//     0.01) of the eight-bit window starting at position P of (t1 XOR t2), for
//     P = 0..24, N = 1e8 samples at decimation D = 2, seed 12345678901234.
//
// Engine of record mcl_core.hpp v6.0.0 (MD5 241db79ecf8a42897eb9a8399cf37929);
// (p,q) = (3,5), K = 12.0, burn-in 10000 (Float64: MCL_T2 constructor; Q30: explicit).
// BUILD: c++ -O3 -std=c++17 -ffp-contract=off \
//            -o mcl_p1_lsb_paradox_measure mcl_p1_lsb_paradox_measure.cpp -lm
#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <cstring>

static inline void step_f64(double &t1, double &t2, double p, double q, double kc) {
    double a1 = p * t2 - q * t1;
    t1 = mod2pi(t1 + OMEGA_1 + kc * std::sin(a1));
    double a2 = p * t1 - q * t2;
    t2 = mod2pi(t2 + OMEGA_2 + kc * std::sin(a2));
}

int main() {
    const uint64_t seed = 12345678901234ULL;
    const int64_t p = 3, q = 5; const double K = 12.0;
    const long long M = 1000000LL, N = 100000000LL;
    std::printf("==============================================================\n");
    std::printf(" MCL PAPER 1 — LSB PARADOX, MEASURED (Float64 vs Q30)\n");
    std::printf(" Doc ID: MCL-P1-LSBPARADOX-2026-0909-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen), (p,q)=(3,5), K=12, burn-in %d, seed %llu\n", BURNIN, (unsigned long long)seed);
    std::printf(" A/B: M = %lld orbit states, single-ULP perturbation of theta1 (Float64: nextafter; Q30: +1 phase unit), one iteration\n", M);
    std::printf(" C : Q30 byte-level chi2 (df=255, crit 310.46) of window [P, P+7] of t1 XOR t2, P = 0..24, N = %lld, D = 2\n\n", N);

    // ---------- A. Float64
    {
        MCL_T2 eng(seed, p, q, K);
        long long diff1[52] = {0}, diffx[52] = {0};
        for (long long i = 0; i < M; i++) {
            eng.iterate();
            double t1 = eng.theta1(), t2 = eng.theta2();
            double u1 = t1, u2 = t2, v1 = std::nextafter(t1, 7.0), v2 = t2;
            step_f64(u1, u2, (double)p, (double)q, K);
            step_f64(v1, v2, (double)p, (double)q, K);
            uint64_t m = (1ULL << 52) - 1;
            uint64_t du = (d2b(u1) ^ d2b(v1)) & m, dx = ((d2b(u1) ^ d2b(u2)) ^ (d2b(v1) ^ d2b(v2))) & m;
            for (int b = 0; b < 52; b++) { diff1[b] += (du >> b) & 1; diffx[b] += (dx >> b) & 1; }
        }
        std::printf("A. Float64 single-ULP avalanche per mantissa position (%% of trials in which the bit differs after one iteration)\n");
        std::printf(" bit | theta1 mantissa | XOR-mixed mantissa\n-----|-----------------|-------------------\n");
        for (int b = 0; b < 52; b++)
            std::printf(" %3d | %14.3f%% | %16.3f%%\n", b, 100.0 * diff1[b] / M, 100.0 * diffx[b] / M);
        std::printf("\n");
    }
    // ---------- B. Q30
    {
        uint32_t t1, t2; mcl_q30_init_state(seed, t1, t2);
        const int64_t kp = mcl_q30_K_phase(K);
        for (int i = 0; i < BURNIN; i++) mcl_q30_iterate_raw(t1, t2, p, q, kp);
        long long diff1[32] = {0}, diffx[32] = {0};
        for (long long i = 0; i < M; i++) {
            mcl_q30_iterate_raw(t1, t2, p, q, kp);
            uint32_t u1 = t1, u2 = t2, v1 = t1 + 1u, v2 = t2;
            mcl_q30_iterate_raw(u1, u2, p, q, kp);
            mcl_q30_iterate_raw(v1, v2, p, q, kp);
            uint32_t du = u1 ^ v1, dx = (u1 ^ u2) ^ (v1 ^ v2);
            for (int b = 0; b < 32; b++) { diff1[b] += (du >> b) & 1; diffx[b] += (dx >> b) & 1; }
        }
        std::printf("B. Q30 single-unit avalanche per phase-word bit (%% of trials in which the bit differs after one iteration)\n");
        std::printf(" bit | t1 word        | t1 XOR t2\n-----|----------------|----------------\n");
        for (int b = 0; b < 32; b++)
            std::printf(" %3d | %13.3f%% | %13.3f%%\n", b, 100.0 * diff1[b] / M, 100.0 * diffx[b] / M);
        std::printf("\n");
    }
    // ---------- C. Q30 byte-level chi2 per window start
    {
        uint32_t t1, t2; mcl_q30_init_state(seed, t1, t2);
        const int64_t kp = mcl_q30_K_phase(K);
        for (int i = 0; i < BURNIN; i++) mcl_q30_iterate_raw(t1, t2, p, q, kp);
        static long long bins[25][256]; std::memset(bins, 0, sizeof bins);
        for (long long i = 0; i < N; i++) {
            mcl_q30_iterate_raw(t1, t2, p, q, kp); mcl_q30_iterate_raw(t1, t2, p, q, kp);
            uint32_t x = t1 ^ t2;
            for (int P = 0; P < 25; P++) bins[P][(x >> P) & 0xFF]++;
        }
        std::printf("C. Q30 byte-level chi2 (df=255, crit 310.46) of window [P, P+7] of t1 XOR t2, N = %lld, D = 2\n", N);
        std::printf("  P  |     chi2     | verdict\n-----|--------------|--------\n");
        double e = (double)N / 256.0;
        for (int P = 0; P < 25; P++) {
            double s = 0; for (int k = 0; k < 256; k++) { double d = (double)bins[P][k] - e; s += d * d / e; }
            std::printf(" %3d | %12.1f | %s\n", P, s, s < 310.46 ? "PASS" : "FAIL");
        }
    }
    return 0;
}
