// Paper 3 measurement 5b' (2026-09-05): ENSEMBLE correlation versus time, r_ens(t), between two
// same-seed trajectories with parameters (p,q,K) and (p,q,K+dK).  r_ens(t) = Pearson over n seeds of
// cos theta1_A(t) against cos theta1_B(t).  In the mixing (chaotic) regime r_ens(t) decays to the
// noise floor and stays there; for a periodic locked orbit it stays at 1; for a quasi-periodic locked
// state it oscillates as cos(dOmega*t) without decaying (ergodic but not mixing).
// Grid mode: per cell, max and RMS of |r_ens(t)| over t in [T, T+W].  Trace mode: full r_ens(t) for
// selected cells.  Engine arithmetic: mcl_iterate_raw (bit-identical).
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include "../../mcl_core.hpp"
static void init_phases(uint64_t seed, double& t1, double& t2) { uint64_t s = hash_seed(seed); t1 = mod2pi((double)s * OMEGA_1); t2 = mod2pi((double)s * OMEGA_2); }
struct Acc { double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0; long n = 0; void add(double x, double y) { sx += x; sy += y; sxx += x * x; syy += y * y; sxy += x * y; n++; }
    double r() const { double mx = sx / n, my = sy / n, vx = sxx / n - mx * mx, vy = syy / n - my * my, c = sxy / n - mx * my; if (vx <= 1e-30 || vy <= 1e-30) return (vx <= 1e-30 && vy <= 1e-30) ? 1.0 : 0.0; return c / std::sqrt(vx * vy); } };
// returns r_ens(t) for t = t0+1 .. t0+W (accumulated over n seeds); also mean ln d at the end
static std::vector<double> rens(int64_t pA, int64_t qA, double KA, int64_t pB, int64_t qB, double KB, long n, int t0, int W, double& mean_ln_d_end) {
    std::vector<Acc> A(W); double slnd = 0; long cnt = 0;
    for (long i = 0; i < n; i++) {
        double a1, a2; init_phases(1000000ULL + (uint64_t)i * 7919ULL, a1, a2); double b1 = a1, b2 = a2;
        for (int t = 0; t < t0; t++) { mcl_iterate_raw(a1, a2, pA, qA, KA); mcl_iterate_raw(b1, b2, pB, qB, KB); }
        for (int w = 0; w < W; w++) { mcl_iterate_raw(a1, a2, pA, qA, KA); mcl_iterate_raw(b1, b2, pB, qB, KB); A[w].add(std::cos(a1), std::cos(b1)); }
        double d1 = std::fabs(a1 - b1); if (d1 > M_PI) d1 = 2 * M_PI - d1; double d2 = std::fabs(a2 - b2); if (d2 > M_PI) d2 = 2 * M_PI - d2; double d = std::sqrt(d1 * d1 + d2 * d2); if (d > 0) { slnd += std::log(d); cnt++; }
    }
    mean_ln_d_end = cnt ? slnd / cnt : -INFINITY; std::vector<double> r(W); for (int w = 0; w < W; w++) r[w] = A[w].r(); return r;
}
int main(int argc, char** argv) {
    if (argc < 2) { std::fprintf(stderr, "usage: %s grid n t0 W dK out.csv [Kmin Kmax step]  |  %s trace n t0 W dK out.csv p q K [p q K ...]\n", argv[0], argv[0]); return 2; }
    std::string mode = argv[1]; long n = atol(argv[2]); int t0 = atoi(argv[3]), W = atoi(argv[4]); double dK = atof(argv[5]); FILE* f = fopen(argv[6], "w");
    if (mode == "grid") {
        double Kmin = argc > 7 ? atof(argv[7]) : 0.30, Kmax = argc > 8 ? atof(argv[8]) : 1.00, st = argc > 9 ? atof(argv[9]) : 0.02;
        fprintf(f, "pair,p,q,K,KB,n,t0,W,max_abs_r_ens,rms_r_ens,r_ens_first,r_ens_last,mean_ln_d_end,floor_3sigma\n");
        const int64_t topos[2][2] = {{2, 3}, {3, 5}};
        for (int k = 0; (Kmin + k * st) <= Kmax + 1e-9; k++) { double K = Kmin + k * st;
            for (int ti = 0; ti < 3; ti++) { int64_t pA = ti < 2 ? topos[ti][0] : 2, qA = ti < 2 ? topos[ti][1] : 3, pB = ti < 2 ? pA : 3, qB = ti < 2 ? qA : 5; double KB = ti < 2 ? K + dK : K;
                double mld; std::vector<double> r = rens(pA, qA, K, pB, qB, KB, n, t0, W, mld); double mx = 0, ss = 0; for (double v : r) { mx = std::max(mx, std::fabs(v)); ss += v * v; }
                fprintf(f, "%s,%lld,%lld,%.3f,%.3f,%ld,%d,%d,%.6f,%.6f,%.6f,%.6f,%.4f,%.6f\n", ti < 2 ? "sameTopo_dK" : "crossTopo_sameK", (long long)pA, (long long)qA, K, KB, n, t0, W, mx, std::sqrt(ss / W), r[0], r[W - 1], mld, 3.0 / std::sqrt((double)n));
                std::fprintf(stderr, "%s (%lld,%lld) K=%.2f: max|r_ens|=%.4f rms=%.4f mean_ln_d=%.3f\n", ti < 2 ? "same" : "cross", (long long)pA, (long long)qA, K, mx, std::sqrt(ss / W), mld); }
            fflush(f); }
    } else {
        fprintf(f, "p,q,K,KB,t,r_ens\n");
        for (int i = 7; i + 2 < argc; i += 3) { int64_t p = atoll(argv[i]), q = atoll(argv[i + 1]); double K = atof(argv[i + 2]); double mld; std::vector<double> r = rens(p, q, K, p, q, K + dK, n, t0, W, mld);
            for (int w = 0; w < W; w++) fprintf(f, "%lld,%lld,%.3f,%.3f,%d,%.6f\n", (long long)p, (long long)q, K, K + dK, t0 + w + 1, r[w]);
            double mx = 0; for (double v : r) mx = std::max(mx, std::fabs(v)); std::fprintf(stderr, "trace (%lld,%lld) K=%.3f: max|r_ens|=%.4f last=%.4f mean_ln_d=%.3f\n", (long long)p, (long long)q, K, mx, r[W - 1], mld); }
    }
    fclose(f); return 0;
}
