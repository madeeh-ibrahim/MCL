// mcl_attractor_dump.cpp — Paper 1 (CS&F revision, 2026-09-05), item د-8:
// data for the new Figure 1 (attractor on the torus, invariant density, psi_1 marginal).
// Engine of record: mcl_core.hpp v6.0.0 (frozen M1_M2_apple_verification copy,
// MD5 241db79ecf8a42897eb9a8399cf37929), (p,q,K) = (3,5,12), engine burn-in 10,000.
//   (a) NPTS post-burn-in (theta1, theta2) samples            -> attractor_points_<seed>.csv
//   (b) 64x64 occupancy histogram of (theta1, theta2), N iters -> density64_<seed>.csv (+ TV vs uniform)
//   (c) 256-bin histogram of psi_1 = 3*theta2 - 5*theta1, N    -> psi1_hist_<seed>.csv (+ TV vs uniform)
// Doc ID: MCL-ATTRACTOR-DUMP-2026-0905-001
// Build: c++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_attractor_dump mcl_attractor_dump.cpp -lm
// Usage: mcl_attractor_dump <seed> [N=1e7] [NPTS=200000]
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>

int main(int argc, char** argv) {
    uint64_t seed = (argc > 1) ? std::strtoull(argv[1], nullptr, 10) : 12345678901234ULL;
    int64_t N = (argc > 2) ? std::strtoll(argv[2], nullptr, 10) : 10000000LL;
    int64_t NPTS = (argc > 3) ? std::strtoll(argv[3], nullptr, 10) : 200000LL;
    int G = (argc > 4) ? std::atoi(argv[4]) : 64;   // occupancy grid (audit: 32/128)
    const double TWO_PI = 6.283185307179586;
    std::printf("==============================================================\n");
    std::printf(" MCL ATTRACTOR / INVARIANT-DENSITY / PSI_1 DUMP\n");
    std::printf(" Doc ID: MCL-ATTRACTOR-DUMP-2026-0905-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen copy) | (p,q,K)=(3,5,12) | burn-in %d\n", BURNIN);
    std::printf(" Seed %llu | N = %lld | NPTS = %lld\n", (unsigned long long)seed, (long long)N, (long long)NPTS);
    std::printf("==============================================================\n");

    std::string s = std::to_string(seed);
    // (a) points
    { MCL_T2 eng(seed, 3, 5, 12.0);
      FILE* f = std::fopen(("attractor_points_" + s + ".csv").c_str(), "w");
      std::fprintf(f, "theta1,theta2\n");
      for (int64_t i = 0; i < NPTS; i++) { eng.iterate(); std::fprintf(f, "%.6f,%.6f\n", eng.theta1(), eng.theta2()); }
      std::fclose(f); }
    // (b)+(c)
    const int B = 256;
    std::vector<int64_t> dens((size_t)G * G, 0), hist((size_t)B, 0);
    double t1, t2; mcl_init_state(seed, t1, t2);
    for (int i = 0; i < BURNIN; i++) mcl_iterate_raw(t1, t2, 3, 5, 12.0);
    for (int64_t i = 0; i < N; i++) {
        double psi1 = mod2pi(3.0 * t2 - 5.0 * t1);
        int bb = (int)(psi1 / (TWO_PI / B)); if (bb >= B) bb = B - 1; hist[(size_t)bb]++;
        mcl_iterate_raw(t1, t2, 3, 5, 12.0);
        int gx = (int)(t1 / (TWO_PI / G)); if (gx >= G) gx = G - 1;
        int gy = (int)(t2 / (TWO_PI / G)); if (gy >= G) gy = G - 1;
        dens[(size_t)gy * G + (size_t)gx]++;
    }
    { FILE* f = std::fopen(("density" + std::to_string(G) + "_" + s + ".csv").c_str(), "w");
      for (int y = 0; y < G; y++) { for (int x = 0; x < G; x++) std::fprintf(f, "%lld%s", (long long)dens[(size_t)y * G + (size_t)x], x == G - 1 ? "\n" : ","); }
      std::fclose(f); }
    { FILE* f = std::fopen(("psi1_hist_" + s + ".csv").c_str(), "w");
      std::fprintf(f, "bin,count\n"); for (int k = 0; k < B; k++) std::fprintf(f, "%d,%lld\n", k, (long long)hist[(size_t)k]); std::fclose(f); }
    double tvd = 0, tvp = 0, chi2d = 0, chi2p = 0, Ed = (double)N / (G * G), Ep = (double)N / B;
    double mn = 1e300, mx = 0;
    for (auto c : dens) { double d = (double)c - Ed; tvd += std::fabs(d) / (double)N; chi2d += d * d / Ed; mn = std::fmin(mn, (double)c / Ed); mx = std::fmax(mx, (double)c / Ed); }
    for (auto c : hist) { double d = (double)c - Ep; tvp += std::fabs(d) / (double)N; chi2p += d * d / Ep; }
    std::printf("(b) %dx%d occupancy:", G, G); std::printf(" TV vs uniform = %.6f  chi2(df=4095) = %.1f  min/max cell (rel. to uniform) = %.4f / %.4f\n", 0.5 * tvd, chi2d, mn, mx);
    std::printf("(c) psi_1 256-bin:  TV vs uniform = %.6f  chi2(df=255) = %.2f\n", 0.5 * tvp, chi2p);
    std::printf("files: attractor_points_%s.csv density64_%s.csv psi1_hist_%s.csv\n", s.c_str(), s.c_str(), s.c_str());
    return 0;
}
