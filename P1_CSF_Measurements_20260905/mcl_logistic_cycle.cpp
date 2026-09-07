// mcl_logistic_cycle.cpp — Brent cycle detection for the binary64 logistic map
// x' = r x (1-x), initial condition x0 = 0.05 + 0.9*frac(seed*(phi-1)) (same as
// mcl_thirdmap_safezone). Reports tail length mu and cycle length lambda, capped.
// Doc ID: MCL-LOGISTIC-CYCLE-2026-0905-001
// Build: c++ -O3 -std=c++17 -o mcl_logistic_cycle mcl_logistic_cycle.cpp -lm
// Usage: mcl_logistic_cycle <r> <seed> [cap=4e9]
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
int main(int argc, char** argv) {
    double r = (argc > 1) ? std::atof(argv[1]) : 4.0;
    uint64_t seed = (argc > 2) ? std::strtoull(argv[2], nullptr, 10) : 12345678901234ULL;
    uint64_t cap = (argc > 3) ? std::strtoull(argv[3], nullptr, 10) : 4000000000ULL;
    const double OMEGA1 = 0.6180339887498949;
    double x0 = 0.05 + 0.9 * std::fmod((double)seed * OMEGA1, 1.0);
    auto f = [r](double x) { return r * x * (1.0 - x); };
    // Brent
    uint64_t power = 1, lam = 1; double tort = x0, hare = f(x0);
    while (tort != hare) {
        if (power == lam) { tort = hare; power *= 2; lam = 0; }
        hare = f(hare); lam++;
        if (power + lam > cap) { std::printf("r=%.2f seed=%llu x0=%.6f  NO CYCLE within %llu iterations\n", r, (unsigned long long)seed, x0, (unsigned long long)cap); return 0; }
    }
    uint64_t mu = 0; tort = hare = x0;
    for (uint64_t i = 0; i < lam; i++) hare = f(hare);
    while (tort != hare) { tort = f(tort); hare = f(hare); mu++; }
    std::printf("r=%.2f seed=%llu x0=%.6f  tail mu=%llu  cycle lambda=%llu  (N/lambda at N=1e8: %.2f)\n",
                r, (unsigned long long)seed, x0, (unsigned long long)mu, (unsigned long long)lam, 1e8 / (double)lam);
    return 0;
}
