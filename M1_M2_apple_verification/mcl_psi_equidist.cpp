/*
 * MCL Coupling-Phase Marginal Equidistribution Verification (Paper 1, §III.B.3 / M1)
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 *
 * Document ID:   MCL-PSI-EQUIDIST-2026-0703-001
 * Engine:        mcl_core.hpp v6.0.0 (archived, MD5 241db79ecf8a42897eb9a8399cf37929)
 *
 * PURPOSE: Measure the MARGINAL distribution of the two coupling phases
 *
 *     psi_1 = p*theta_2(t)   - q*theta_1(t)      (argument of Eq. 1)
 *     psi_2 = p*theta_1(t+1) - q*theta_2(t)      (argument of Eq. 2, Gauss-Seidel)
 *
 * and the functional <ln|cos psi|> that enters the semi-analytical scaling
 * law (3b). The derivation of (3b) requires ONLY these marginals (through
 * <ln|cos psi|> = -ln 2 under equidistribution), not uniformity of the joint
 * invariant measure on T^2.
 *
 * Reported per seed and pooled:
 *   - 256-bin histogram of psi_1, psi_2 on [0, 2pi)
 *   - total-variation distance from uniform  TV = 0.5 * sum |p_hat_i - 1/256|
 *     (the L1 distance sum|.| is also printed)
 *   - chi^2 (df = 255) against the uniform null
 *   - <ln|cos psi_1|>, <ln|cos psi_2|>  vs  -ln 2 = -0.6931471805599453
 *
 * PAPER TARGETS (Paper 1 §III.B.3, measured values):
 *   TV(psi) ~ 0.005 ;  <ln|cos psi_1|> = -0.693 +/- 0.001 (within 0.1% of -ln 2)
 *   <ln|cos psi_2|> ~ -0.698 (+0.7% deviation)
 *
 * PROTOCOL: default configuration (p, q, K) = (3, 5, 12), burn-in 10,000
 * (engine BURNIN), N = 10^7 iterations, three independent seeds
 * (12345678901234, 98765432109876, 31415926535897) — the Table II protocol.
 *
 * BUILD:
 *   c++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
 *       -o mcl_psi_equidist mcl_psi_equidist.cpp -lm && ./mcl_psi_equidist
 */

#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <cstdint>
#include <vector>

static const char* DOC_VERSION = "1.0.0";
static const char* DOC_ID      = "MCL-PSI-EQUIDIST-2026-0703-001";

static constexpr int64_t  N_ITERS  = 10000000;
static constexpr int      N_BINS   = 256;
static constexpr double   LN2      = 0.6931471805599453;
static constexpr int64_t  P_DEF    = 3;
static constexpr int64_t  Q_DEF    = 5;
static constexpr double   K_DEF    = 12.0;

static const uint64_t SEEDS[3] = { 12345678901234ULL, 98765432109876ULL, 31415926535897ULL };

struct PsiStats {
    std::vector<int64_t> hist1, hist2;
    double sum_lncos1 = 0.0, sum_lncos2 = 0.0;
    int64_t n = 0;
    PsiStats() : hist1(N_BINS, 0), hist2(N_BINS, 0) {}
};

static void accumulate(uint64_t seed, PsiStats& st) {
    double t1, t2;
    mcl_init_state(seed, t1, t2);
    for (int i = 0; i < BURNIN; i++)
        mcl_iterate_raw(t1, t2, P_DEF, Q_DEF, K_DEF);

    const double bin_w = (2.0 * M_PI) / (double)N_BINS;
    for (int64_t it = 0; it < N_ITERS; it++) {
        const double t1_old = t1, t2_old = t2;
        // psi_1 uses the pre-step state (argument of Eq. 1)
        const double psi1 = mod2pi((double)P_DEF * t2_old - (double)Q_DEF * t1_old);
        mcl_iterate_raw(t1, t2, P_DEF, Q_DEF, K_DEF);
        // psi_2 uses theta_1(t+1) (Gauss-Seidel) with theta_2(t) (argument of Eq. 2)
        const double psi2 = mod2pi((double)P_DEF * t1 - (double)Q_DEF * t2_old);

        int b1 = (int)(psi1 / bin_w); if (b1 >= N_BINS) b1 = N_BINS - 1;
        int b2 = (int)(psi2 / bin_w); if (b2 >= N_BINS) b2 = N_BINS - 1;
        st.hist1[(size_t)b1]++; st.hist2[(size_t)b2]++;

        double ac1 = std::fabs(std::cos(psi1));
        double ac2 = std::fabs(std::cos(psi2));
        if (ac1 < 1e-300) ac1 = 1e-300;   // integrable singularity guard
        if (ac2 < 1e-300) ac2 = 1e-300;
        st.sum_lncos1 += std::log(ac1);
        st.sum_lncos2 += std::log(ac2);
        st.n++;
    }
}

struct MarginalReport { double tv, l1, chi2, lncos; };

static MarginalReport report_marginal(const std::vector<int64_t>& hist,
                                      double sum_lncos, int64_t n) {
    const double expct = (double)n / (double)N_BINS;
    double l1 = 0.0, chi2 = 0.0;
    for (int i = 0; i < N_BINS; i++) {
        const double d = (double)hist[(size_t)i] - expct;
        l1   += std::fabs(d) / (double)n;
        chi2 += d * d / expct;
    }
    return { 0.5 * l1, l1, chi2, sum_lncos / (double)n };
}

int main() {
    std::printf("=============================================================\n");
    std::printf(" MCL COUPLING-PHASE MARGINAL EQUIDISTRIBUTION v%s\n", DOC_VERSION);
    std::printf(" Doc ID: %s\n", DOC_ID);
    std::printf(" Engine: mcl_core.hpp v6.0.0 (archived) | (p,q,K)=(%lld,%lld,%.1f)\n",
                (long long)P_DEF, (long long)Q_DEF, K_DEF);
    std::printf(" Burn-in %d | N = %lld iterations | %d bins | 3 seeds\n",
                BURNIN, (long long)N_ITERS, N_BINS);
    std::printf(" Target: <ln|cos psi_1|> within 0.1%% of -ln2 = -%.10f\n", LN2);
    std::printf("=============================================================\n\n");

    PsiStats pooled;
    bool all_pass = true;

    for (int s = 0; s < 3; s++) {
        PsiStats st;
        accumulate(SEEDS[s], st);
        const MarginalReport r1 = report_marginal(st.hist1, st.sum_lncos1, st.n);
        const MarginalReport r2 = report_marginal(st.hist2, st.sum_lncos2, st.n);

        const double dev1 = 100.0 * (r1.lncos - (-LN2)) / LN2;
        const double dev2 = 100.0 * (r2.lncos - (-LN2)) / LN2;

        std::printf("SEED %llu\n", (unsigned long long)SEEDS[s]);
        std::printf("  psi_1: TV = %.6f (L1 = %.6f)  chi2(df=255) = %9.2f\n",
                    r1.tv, r1.l1, r1.chi2);
        std::printf("         <ln|cos psi_1|> = %+.6f   dev vs -ln2 = %+.3f%%\n",
                    r1.lncos, dev1);
        std::printf("  psi_2: TV = %.6f (L1 = %.6f)  chi2(df=255) = %9.2f\n",
                    r2.tv, r2.l1, r2.chi2);
        std::printf("         <ln|cos psi_2|> = %+.6f   dev vs -ln2 = %+.3f%%\n\n",
                    r2.lncos, dev2);

        if (std::fabs(dev1) > 0.1) all_pass = false;  // paper claim: within 0.1%

        for (int i = 0; i < N_BINS; i++) {
            pooled.hist1[(size_t)i] += st.hist1[(size_t)i];
            pooled.hist2[(size_t)i] += st.hist2[(size_t)i];
        }
        pooled.sum_lncos1 += st.sum_lncos1;
        pooled.sum_lncos2 += st.sum_lncos2;
        pooled.n += st.n;
    }

    const MarginalReport p1 = report_marginal(pooled.hist1, pooled.sum_lncos1, pooled.n);
    const MarginalReport p2 = report_marginal(pooled.hist2, pooled.sum_lncos2, pooled.n);
    std::printf("POOLED (3 x 10^7)\n");
    std::printf("  psi_1: TV = %.6f  chi2 = %.2f  <ln|cos|> = %+.6f (dev %+.3f%%)\n",
                p1.tv, p1.chi2, p1.lncos, 100.0 * (p1.lncos + LN2) / LN2);
    std::printf("  psi_2: TV = %.6f  chi2 = %.2f  <ln|cos|> = %+.6f (dev %+.3f%%)\n\n",
                p2.tv, p2.chi2, p2.lncos, 100.0 * (p2.lncos + LN2) / LN2);

    std::printf("VERDICT: %s\n", all_pass
        ? "PASS — psi_1 functional within 0.1% of -ln 2 on every seed"
        : "FAIL — psi_1 deviation exceeds 0.1% on at least one seed");
    return all_pass ? 0 : 1;
}
