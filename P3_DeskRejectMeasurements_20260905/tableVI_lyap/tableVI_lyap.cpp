// Re-measurement of Paper 3 Table VI (lambda_1, lambda_2 vs K for topology (2,3)), 3 seeds x 1e7 QR iterations,
// with the engine's own compute_lyapunov (2026-09-06). The table had no archived raw record.
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include "../../mcl_core.hpp"
int main(int argc, char** argv) {
    int64_t n = argc > 1 ? atoll(argv[1]) : 10000000;
    const double Ks[] = {0.5, 1.0, 2.0, 5.0, 8.0, 12.0, 20.0, 50.0};
    const uint64_t seeds[] = {12345678901234ULL, 98765432109876ULL, 31415926535897ULL};
    std::printf("K,seed,lambda1,lambda2,l1_se,l2_se\n");
    for (double K : Ks) {
        double m1 = 0, m2 = 0;
        for (uint64_t s : seeds) { LyapResult L = compute_lyapunov(s, 2, 3, K, n); m1 += L.l1; m2 += L.l2; std::printf("%.1f,%llu,%.4f,%.4f,%.4f,%.4f\n", K, (unsigned long long)s, L.l1, L.l2, L.l1_stderr, L.l2_stderr); std::fflush(stdout); }
        std::fprintf(stderr, "K=%.1f mean lambda1=%.4f lambda2=%.4f sum=%.4f\n", K, m1 / 3, m2 / 3, (m1 + m2) / 3);
    }
    return 0;
}
