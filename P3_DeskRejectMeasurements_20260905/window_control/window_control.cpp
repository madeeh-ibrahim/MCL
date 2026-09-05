// Paper 3 measurement 5b (2026-09-05): does a parameter change FAIL to decorrelate inside the
// phase-locking windows?  Same-seed pairs (p,q,K) vs (p,q,K+dK) on the Fig. 1 grid
// K = 0.30..1.00 step 0.02, plus cross-topology pairs (2,3)-vs-(3,5) at the same K.
// Per cell: ensemble same-time correlation of cos(theta1) over n seeds after T steps
// (the engine's burn-in length), single-seed time-series statistics after burn-in
// (Pearson at lag 0, max |r| over |lag|<=64, Miller-Madow mutual information and joint chi^2
// on 32x32 bins), the order parameter R_alpha and exact period (<=256) of channel A, and
// lambda1 from the engine's compute_lyapunov.  Engine arithmetic: mcl_iterate_raw (bit-identical).
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include "../../mcl_core.hpp"

static void init_phases(uint64_t seed, double& t1, double& t2) {
    uint64_t s = hash_seed(seed); t1 = mod2pi((double)s * OMEGA_1); t2 = mod2pi((double)s * OMEGA_2);
}
static double pearson_v(const std::vector<double>& x, const std::vector<double>& y, long lag) {
    long n = (long)x.size(); double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0; long m = 0;
    for (long i = 0; i < n; i++) { long j = i + lag; if (j < 0 || j >= n) continue; double a = x[i], b = y[j]; sx += a; sy += b; sxx += a * a; syy += b * b; sxy += a * b; m++; }
    double mx = sx / m, my = sy / m, vx = sxx / m - mx * mx, vy = syy / m - my * my, c = sxy / m - mx * my;
    if (vx <= 1e-30 || vy <= 1e-30) return 0.0; return c / std::sqrt(vx * vy);
}
struct MIres { double mi_mm, chi2_z; };
static MIres mi_joint(const std::vector<double>& a, const std::vector<double>& b, int B) {
    long n = (long)a.size(); std::vector<long> H(B * B, 0), Ha(B, 0), Hb(B, 0);
    for (long i = 0; i < n; i++) { int ia = std::min(B - 1, (int)(a[i] / (2 * M_PI) * B)), ib = std::min(B - 1, (int)(b[i] / (2 * M_PI) * B)); H[ia * B + ib]++; Ha[ia]++; Hb[ib]++; }
    double mi = 0, chi2 = 0; long nz = 0;
    for (int i = 0; i < B; i++) for (int j = 0; j < B; j++) { long h = H[i * B + j]; double e = (double)Ha[i] * Hb[j] / n; if (e > 0) chi2 += (h - e) * (h - e) / e; if (h > 0) { nz++; mi += (double)h / n * std::log((double)h * n / ((double)Ha[i] * Hb[j])); } }
    long ka = 0, kb = 0; for (int i = 0; i < B; i++) { if (Ha[i]) ka++; if (Hb[i]) kb++; }
    double mm = mi / std::log(2.0) - ((double)(nz - 1) - (ka - 1) - (kb - 1)) / (2.0 * n * std::log(2.0)); // Miller-Madow (bits)
    double df = (double)(ka - 1) * (kb - 1); double z = (chi2 - df) / std::sqrt(2 * df);
    return {mm, z};
}
struct Cell { double r_ens, mean_ln_d_ens, frac_gt1, r0, rlag, mi, chi2z, Ralpha, l1; int period; };

static Cell measure(int64_t pA, int64_t qA, double KA, int64_t pB, int64_t qB, double KB, long n_seeds, int T, long N) {
    Cell c{};
    // ensemble after T steps
    double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0, slnd = 0; long cnt = 0, gt1 = 0;
    for (long i = 0; i < n_seeds; i++) {
        double a1, a2; init_phases(1000000ULL + (uint64_t)i * 7919ULL, a1, a2); double b1 = a1, b2 = a2;
        for (int t = 0; t < T; t++) { mcl_iterate_raw(a1, a2, pA, qA, KA); mcl_iterate_raw(b1, b2, pB, qB, KB); }
        double d1 = std::fabs(a1 - b1); if (d1 > M_PI) d1 = 2 * M_PI - d1; double d2 = std::fabs(a2 - b2); if (d2 > M_PI) d2 = 2 * M_PI - d2; double d = std::sqrt(d1 * d1 + d2 * d2);
        if (d > 0) { slnd += std::log(d); cnt++; } if (d > 1.0) gt1++;
        double x = std::cos(a1), y = std::cos(b1); sx += x; sy += y; sxx += x * x; syy += y * y; sxy += x * y;
    }
    { double mx = sx / n_seeds, my = sy / n_seeds, vx = sxx / n_seeds - mx * mx, vy = syy / n_seeds - my * my, cv = sxy / n_seeds - mx * my;
      c.r_ens = (vx > 1e-30 && vy > 1e-30) ? cv / std::sqrt(vx * vy) : ((vx <= 1e-30 && vy <= 1e-30) ? 1.0 : 0.0); }
    c.mean_ln_d_ens = cnt ? slnd / cnt : -INFINITY; c.frac_gt1 = (double)gt1 / n_seeds;
    // single seed time series (engine seed), after BURNIN steps
    double a1, a2; init_phases(12345678901234ULL, a1, a2); double b1 = a1, b2 = a2;
    for (int t = 0; t < BURNIN; t++) { mcl_iterate_raw(a1, a2, pA, qA, KA); mcl_iterate_raw(b1, b2, pB, qB, KB); }
    std::vector<double> ca(N), cb(N), ta(N), tb(N); double ra_re = 0, ra_im = 0; double s1 = a1, s2 = a2; int per = 0;
    for (long i = 0; i < N; i++) {
        mcl_iterate_raw(a1, a2, pA, qA, KA); mcl_iterate_raw(b1, b2, pB, qB, KB);
        ta[i] = a1; tb[i] = b1; ca[i] = std::cos(a1); cb[i] = std::cos(b1);
        double al = (double)pA * a2 - (double)qA * a1; ra_re += std::cos(al); ra_im += std::sin(al);
        if (per == 0 && i + 1 <= 256 && std::fabs(a1 - s1) < 1e-9 && std::fabs(a2 - s2) < 1e-9) per = (int)(i + 1);
    }
    c.period = per; c.Ralpha = std::sqrt(ra_re * ra_re + ra_im * ra_im) / N;
    c.r0 = pearson_v(ca, cb, 0); double m = 0; for (long l = -64; l <= 64; l++) m = std::max(m, std::fabs(pearson_v(ca, cb, l))); c.rlag = m;
    MIres mr = mi_joint(ta, tb, 32); c.mi = mr.mi_mm; c.chi2z = mr.chi2_z;
    LyapResult L = compute_lyapunov(12345678901234ULL, pA, qA, KA, 100000); c.l1 = L.l1;
    return c;
}

int main(int argc, char** argv) {
    // usage: window_control <n_seeds> <T> <N> <dK> <out.csv> [Kmin Kmax step]
    if (argc < 6) { std::fprintf(stderr, "usage: %s n_seeds T N dK out.csv [Kmin Kmax step]\n", argv[0]); return 2; }
    long n = atol(argv[1]); int T = atoi(argv[2]); long N = atol(argv[3]); double dK = atof(argv[4]);
    double Kmin = argc > 6 ? atof(argv[6]) : 0.30, Kmax = argc > 7 ? atof(argv[7]) : 1.00, st = argc > 8 ? atof(argv[8]) : 0.02;
    FILE* f = fopen(argv[5], "w");
    fprintf(f, "pair,pA,qA,KA,pB,qB,KB,r_ens,mean_ln_d_ens,frac_d_gt_1,r0,rlag_max64,MI_MM_bits,chi2_z,R_alpha_A,period_A,lambda1_A\n");
    const int64_t topos[2][2] = {{2, 3}, {3, 5}};
    for (int k = 0; (Kmin + k * st) <= Kmax + 1e-9; k++) {
        double K = Kmin + k * st;
        for (int ti = 0; ti < 2; ti++) {
            Cell c = measure(topos[ti][0], topos[ti][1], K, topos[ti][0], topos[ti][1], K + dK, n, T, N);
            fprintf(f, "sameTopo_dK,%lld,%lld,%.3f,%lld,%lld,%.3f,%.6f,%.4f,%.4f,%.6f,%.6f,%.5f,%.2f,%.4f,%d,%.4f\n", (long long)topos[ti][0], (long long)topos[ti][1], K, (long long)topos[ti][0], (long long)topos[ti][1], K + dK, c.r_ens, c.mean_ln_d_ens, c.frac_gt1, c.r0, c.rlag, c.mi, c.chi2z, c.Ralpha, c.period, c.l1);
            std::fprintf(stderr, "(%lld,%lld) K=%.2f dK: r_ens=%+.4f r0=%+.4f rlag=%.4f MI=%.4f chi2z=%.1f Ra=%.3f per=%d l1=%.3f\n", (long long)topos[ti][0], (long long)topos[ti][1], K, c.r_ens, c.r0, c.rlag, c.mi, c.chi2z, c.Ralpha, c.period, c.l1);
        }
        Cell x = measure(2, 3, K, 3, 5, K, n, T, N);
        fprintf(f, "crossTopo_sameK,2,3,%.3f,3,5,%.3f,%.6f,%.4f,%.4f,%.6f,%.6f,%.5f,%.2f,%.4f,%d,%.4f\n", K, K, x.r_ens, x.mean_ln_d_ens, x.frac_gt1, x.r0, x.rlag, x.mi, x.chi2z, x.Ralpha, x.period, x.l1);
        std::fprintf(stderr, "(2,3)x(3,5) K=%.2f: r_ens=%+.4f r0=%+.4f rlag=%.4f MI=%.4f chi2z=%.1f\n", K, x.r_ens, x.r0, x.rlag, x.mi, x.chi2z);
        fflush(f);
    }
    fclose(f); return 0;
}
