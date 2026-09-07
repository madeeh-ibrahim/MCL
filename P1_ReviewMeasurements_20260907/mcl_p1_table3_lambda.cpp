// mcl_p1_table3_lambda.cpp — Doc ID MCL-P1-TABLE3-LAMBDA-2026-0907-001
//
// PURPOSE (Paper 1, review item Y4 / provenance G4): the Table 3 row
// (p,q,K) = (3,5,6) carries the measured value 4.4165, for which no runtime
// record exists in any code tree or in the public archive. That row also sets
// the "maximum error 0.50%" figure quoted in §3.2.3, §4.3, the Conclusion and
// the Highlights. This tool re-measures lambda_1 for ALL 14 Table 3
// configurations against the archived engine of record mcl_core.hpp v6.0.0
// (MD5 241db79ecf8a42897eb9a8399cf37929) under one pinned protocol, so that
// every cell of the column has a log.
//
// PROTOCOL: analytical-Jacobian sequential QR (compute_lyapunov of the engine
// of record), 1e7 iterations after the engine's 10,000-iteration burn-in,
// three independent seeds (12345678901234, 98765432109876, 31415926535897) —
// the same three seeds used for the seed-averaged rows of Table 2 — reported
// as per-seed values and their mean.
//
// Predictions compared: (3a) lambda ~ 1.96*ln(K*(p+q)) - 2.98
//                       (3b) lambda ~ 2*ln(K*p/2)
//
// BUILD: c++ -O3 -std=c++17 -ffp-contract=off -DMCL_UNSAFE_ALLOW_INVALID \
//            -o mcl_p1_table3_lambda mcl_p1_table3_lambda.cpp -lm
#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>

struct Row { int64_t p, q; double K; double published; };

int main() {
    const uint64_t seeds[3] = {12345678901234ULL, 98765432109876ULL, 31415926535897ULL};
    const int64_t ITERS = 10000000;
    const Row rows[14] = {
        {3, 5, 6.0, 4.4165}, {3, 5, 8.0, 4.9860}, {3, 5, 12.0, 5.7788}, {3, 5, 16.0, 6.3552},
        {7, 11, 6.0, 6.0879}, {7, 11, 12.0, 7.4747}, {7, 11, 18.0, 8.2855},
        {13, 19, 12.0, 8.7129}, {13, 19, 18.0, 9.5236},
        {2, 3, 12.0, 4.9702}, {5, 7, 12.0, 6.8064}, {89, 97, 12.0, 12.5616},
        {5, 3, 12.0, 6.7992}, {3, 2, 12.0, 5.7808}
    };

    std::printf("==============================================================\n");
    std::printf(" MCL PAPER 1 — TABLE 3 lambda_1 RE-MEASUREMENT (all 14 rows)\n");
    std::printf(" Doc ID: MCL-P1-TABLE3-LAMBDA-2026-0907-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen M1_M2_apple_verification copy)\n");
    std::printf(" Method: analytical-Jacobian sequential QR, %lld iterations/seed,\n",
                (long long)ITERS);
    std::printf("         burn-in %d, seeds 12345678901234 / 98765432109876 / 31415926535897\n", BURNIN);
    std::printf("==============================================================\n\n");
    std::printf("  (p,q,K)    |    seed1    seed2    seed3 |     mean |    sd   | published |  diff\n");
    std::printf("-------------|-----------------------------|----------|---------|-----------|--------\n");

    double newmax_a = 0.0, newmax_b = 0.0;
    double meas[14];
    for (int r = 0; r < 14; r++) {
        double v[3], sum = 0.0;
        for (int s = 0; s < 3; s++) {
            LyapResult lr = compute_lyapunov(seeds[s], rows[r].p, rows[r].q, rows[r].K, ITERS);
            v[s] = lr.l1; sum += lr.l1;
        }
        double mean = sum / 3.0;
        double var = 0.0;
        for (int s = 0; s < 3; s++) var += (v[s] - mean) * (v[s] - mean);
        double sd = std::sqrt(var / 2.0);
        meas[r] = mean;
        std::printf(" (%2lld,%2lld,%4.1f) | %8.4f %8.4f %8.4f | %8.4f | %7.5f | %9.4f | %+7.4f\n",
            (long long)rows[r].p, (long long)rows[r].q, rows[r].K,
            v[0], v[1], v[2], mean, sd, rows[r].published, mean - rows[r].published);
    }

    std::printf("\n  Predictions and errors against the RE-MEASURED three-seed means:\n");
    std::printf("  (p,q,K)    |  measured |     (3a) |  err %% |     (3b) |  err %%\n");
    std::printf("-------------|-----------|----------|--------|----------|--------\n");
    for (int r = 0; r < 14; r++) {
        double pa = 1.96 * std::log(rows[r].K * (double)(rows[r].p + rows[r].q)) - 2.98;
        double pb = 2.0 * std::log(rows[r].K * (double)rows[r].p / 2.0);
        double ea = 100.0 * (pa - meas[r]) / meas[r];
        double eb = 100.0 * (pb - meas[r]) / meas[r];
        if (std::fabs(ea) > newmax_a) newmax_a = std::fabs(ea);
        if (std::fabs(eb) > newmax_b) newmax_b = std::fabs(eb);
        std::printf(" (%2lld,%2lld,%4.1f) | %9.4f | %8.4f | %+6.2f | %8.4f | %+6.2f\n",
            (long long)rows[r].p, (long long)rows[r].q, rows[r].K,
            meas[r], pa, ea, pb, eb);
    }
    std::printf("\n  Maximum absolute error over the 14 re-measured rows:\n");
    std::printf("    empirical      (3a): %.2f%%\n", newmax_a);
    std::printf("    semi-analytical(3b): %.2f%%\n", newmax_b);
    std::printf("\n  Errors recomputed against the PUBLISHED column (for comparison):\n");
    double olda = 0.0, oldb = 0.0;
    for (int r = 0; r < 14; r++) {
        double pa = 1.96 * std::log(rows[r].K * (double)(rows[r].p + rows[r].q)) - 2.98;
        double pb = 2.0 * std::log(rows[r].K * (double)rows[r].p / 2.0);
        double ea = std::fabs(100.0 * (pa - rows[r].published) / rows[r].published);
        double eb = std::fabs(100.0 * (pb - rows[r].published) / rows[r].published);
        if (ea > olda) olda = ea;
        if (eb > oldb) oldb = eb;
    }
    std::printf("    (3a): %.2f%%   (3b): %.2f%%\n", olda, oldb);
    return 0;
}
