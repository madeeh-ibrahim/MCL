// Check the four "locked but decorrelates" cells: is the partner K+dK itself inside the window?
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include "../../mcl_core.hpp"
static void diag(int64_t p, int64_t q, double K) {
    uint64_t s = hash_seed(12345678901234ULL); double t1 = mod2pi((double)s * OMEGA_1), t2 = mod2pi((double)s * OMEGA_2);
    for (int i = 0; i < BURNIN; i++) mcl_iterate_raw(t1, t2, p, q, K);
    double s1 = t1, s2 = t2; int per = 0; double re = 0, im = 0; const long N = 100000;
    for (long i = 0; i < N; i++) { mcl_iterate_raw(t1, t2, p, q, K); double al = (double)p * t2 - (double)q * t1; re += std::cos(al); im += std::sin(al);
        if (per == 0 && i + 1 <= 256 && std::fabs(t1 - s1) < 1e-9 && std::fabs(t2 - s2) < 1e-9) per = (int)(i + 1); }
    LyapResult L = compute_lyapunov(12345678901234ULL, p, q, K, 100000);
    double Ra = std::sqrt(re * re + im * im) / N; bool lk = per > 0 || Ra > 0.9 || L.l1 <= 0.02;
    std::printf("(%lld,%lld) K=%.3f: lambda1=%+.4f R_alpha=%.3f period=%d -> %s\n", (long long)p, (long long)q, K, L.l1, Ra, per, lk ? "LOCKED" : "chaotic");
}
int main() { double cells[4][3] = {{2, 3, 0.74}, {3, 5, 0.30}, {3, 5, 0.54}, {3, 5, 0.86}};
    for (auto& c : cells) { diag((int64_t)c[0], (int64_t)c[1], c[2]); diag((int64_t)c[0], (int64_t)c[1], c[2] + 0.01); } return 0; }
