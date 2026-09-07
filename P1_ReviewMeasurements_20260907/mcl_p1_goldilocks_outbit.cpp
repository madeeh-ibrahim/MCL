// mcl_p1_goldilocks_outbit.cpp — Doc ID MCL-P1-GOLDBIT-2026-0907-001
//
// PURPOSE (Paper 1, review item R5): Supplementary S5 reports one nominal
// exception to the intra-mantissa independence premise of Eq. (5) — the pair
// (bit 25, bit 41) in seed 12345678901234, chi2(df=1) = 12.096,
// c = -8.695e-05 — and dismisses it as "below the single-bit detection margin
// at this sample size". That reassurance does not survive the paper's own
// thresholds: chi2 = 12.096 at df = 1 gives p = 5.05e-04, which stays below
// 0.05 after Bonferroni correction over the 24 seed-pair combinations
// (24 x 5.05e-04 = 0.0121), and 2|c| = 1.74e-04 is 3.5 standard errors of a
// single-bit frequency at N = 1e8 (SE = 5e-05).
//
// The decisive question is therefore not the source-pair covariance but
// whether the EMITTED bit is biased. Eq. (5) emits
//     output bit k = mantissa_bit(20+k) XOR mantissa_bit(36+k),
// so the (25, 41) pair is output bit k = 5 of the deployed Goldilocks byte.
// This tool measures, for each output bit k = 0..7, the 0/1 frequency of the
// emitted bit over N = 1e8 output samples, its chi2(df = 1), and — for
// cross-reference — the source-pair covariance and independence chi2 that
// S5 reports. Six seeds are used so that recurrence can be judged.
//
// Engine of record mcl_core.hpp v6.0.0 (MD5 241db79ecf8a42897eb9a8399cf37929),
// decimation D = 2 (production), burn-in 10000 — identical to
// mcl_table10_multiseed.cpp (MCL-TABLE10-MULTISEED-2026-0817-001).
//
// BUILD: c++ -O3 -std=c++17 -ffp-contract=off \
//            -o mcl_p1_goldilocks_outbit mcl_p1_goldilocks_outbit.cpp -lm
#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>

int main() {
    const long long N = 100000000LL;
    const uint64_t seeds[6] = {12345678901234ULL, 31415926535897ULL, 27182818284590ULL,
                               98765432109876ULL, 17320508075688ULL, 70466644885213ULL};
    std::printf("==============================================================\n");
    std::printf(" MCL PAPER 1 — GOLDILOCKS OUTPUT-BIT FREQUENCY (Eq. 5)\n");
    std::printf(" Doc ID: MCL-P1-GOLDBIT-2026-0907-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen), (p,q)=(3,5), K=12, D=2, burn-in %d\n", BURNIN);
    std::printf(" N = %lld output samples per seed; output bit k = mant(20+k) XOR mant(36+k)\n", N);
    std::printf(" Thresholds: nominal 3.841 (alpha=0.05, df=1);\n");
    std::printf("             Bonferroni over 48 emitted-bit tests (6 seeds x 8 bits) = 10.752\n");
    std::printf("             SE of a single-bit frequency at N=1e8 is 5.0e-05\n");
    std::printf("==============================================================\n\n");

    double worst = 0.0; int worst_s = -1, worst_k = -1;
    int k5_flag = 0;
    for (int s = 0; s < 6; s++) {
        MCL_T2 eng(seeds[s], 3, 5, 12.0);
        long long nout[8] = {0}, n1a[8] = {0}, n1b[8] = {0}, n11[8] = {0};
        for (long long i = 0; i < N; i++) {
            eng.iterate(); eng.iterate();
            uint64_t x = d2b(eng.theta1()) ^ d2b(eng.theta2());
            uint64_t xm = x & ((1ULL << 52) - 1);
            for (int k = 0; k < 8; k++) {
                int a = (int)((xm >> (20 + k)) & 1);
                int b = (int)((xm >> (36 + k)) & 1);
                nout[k] += (a ^ b);
                n1a[k] += a; n1b[k] += b; n11[k] += (a & b);
            }
        }
        std::printf("seed %llu:\n", (unsigned long long)seeds[s]);
        std::printf("  k | src bits | emitted ones |   p(1)-0.5   | chi2_out(1) |    cov     | chi2_pair(1)\n");
        std::printf(" ---|----------|--------------|--------------|-------------|------------|-------------\n");
        for (int k = 0; k < 8; k++) {
            double n = (double)N;
            double p1 = (double)nout[k] / n;
            double d = p1 - 0.5;
            double chi_out = n * (2.0 * d) * (2.0 * d);
            double pa = (double)n1a[k] / n, pb = (double)n1b[k] / n, pab = (double)n11[k] / n;
            double c = pab - pa * pb;
            double o11 = (double)n11[k], o10 = (double)(n1a[k] - n11[k]),
                   o01 = (double)(n1b[k] - n11[k]),
                   o00 = (double)(N - n1a[k] - n1b[k] + n11[k]);
            double e11 = (double)n1a[k] * (double)n1b[k] / n,
                   e10 = (double)n1a[k] * (n - (double)n1b[k]) / n,
                   e01 = (n - (double)n1a[k]) * (double)n1b[k] / n,
                   e00 = (n - (double)n1a[k]) * (n - (double)n1b[k]) / n;
            double chi_pair = (o11-e11)*(o11-e11)/e11 + (o10-e10)*(o10-e10)/e10
                            + (o01-e01)*(o01-e01)/e01 + (o00-e00)*(o00-e00)/e00;
            std::printf("  %d | (%2d,%2d)  | %12lld | %+12.3e | %11.3f | %+.3e | %11.3f%s\n",
                k, 20 + k, 36 + k, nout[k], d, chi_out, c, chi_pair,
                (chi_pair >= 3.841 ? "  <-- pair CORR" : ""));
            if (chi_out > worst) { worst = chi_out; worst_s = s; worst_k = k; }
            if (k == 5 && chi_pair >= 3.841) k5_flag++;
        }
        std::printf("\n");
    }
    std::printf("Worst emitted-bit chi2 over all 48 tests: %.3f (seed index %d, output bit %d)\n",
                worst, worst_s, worst_k);
    std::printf("Seeds in which the (25,41) source pair is nominally correlated: %d of 6\n", k5_flag);
    return 0;
}
