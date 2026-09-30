// Paper 3, ت-309(b) (2026-09-30): does a small change of the MAP parameter fail to decorrelate inside the
// periodic windows of a coupled family (Henon a, logistic r, tent slope mu)?  Mirror of the 2026-09-05
// in-window control (MCL-P3-WINDOWCTRL-2026-0905-001): per cell c the same-seed pair (c) vs (c + delta);
// classification of each cell by lambda_1 (Benettin, 1e5 steps after the engine burn-in) and exact period
// (<= 256); ensemble r_ens(t) of x1 over n seeds for t in (T, T+W]; single-seed time series after T steps
// (N steps): Pearson at lag 0, max |r| over |lag| <= 64, Miller-Madow mutual information and joint chi^2 of
// (x1_A, x1_B) on 32 x 32 bins.  Family step = family_maps.hpp (bit-identical to the engine classes).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include "family_maps.hpp"

struct Acc { double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0; long n = 0;
    void add(double x, double y) { sx += x; sy += y; sxx += x * x; syy += y * y; sxy += x * y; n++; }
    double r() const { if (!n) return NAN; double mx = sx / n, my = sy / n, vx = sxx / n - mx * mx, vy = syy / n - my * my, c = sxy / n - mx * my;
        if (vx <= 1e-30 || vy <= 1e-30) return (vx <= 1e-30 && vy <= 1e-30) ? 1.0 : 0.0; return c / std::sqrt(vx * vy); } };
static double pearson_v(const std::vector<double>& x, const std::vector<double>& y, long lag) {
    long n = (long)x.size(); double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0; long m = 0;
    for (long i = 0; i < n; i++) { long j = i + lag; if (j < 0 || j >= n) continue; double a = x[i], b = y[j]; sx += a; sy += b; sxx += a * a; syy += b * b; sxy += a * b; m++; }
    double mx = sx / m, my = sy / m, vx = sxx / m - mx * mx, vy = syy / m - my * my, c = sxy / m - mx * my;
    if (vx <= 1e-30 || vy <= 1e-30) return (vx <= 1e-30 && vy <= 1e-30) ? 1.0 : 0.0; return c / std::sqrt(vx * vy);
}
struct MIres { double mi_mm, chi2_z; };
static MIres mi_joint(const std::vector<double>& a, const std::vector<double>& b, int Bn, double lo, double hi) {
    long n = (long)a.size(); std::vector<long> H(Bn * Bn, 0), Ha(Bn, 0), Hb(Bn, 0);
    for (long i = 0; i < n; i++) { int ia = std::min(Bn - 1, std::max(0, (int)((a[i] - lo) / (hi - lo) * Bn))), ib = std::min(Bn - 1, std::max(0, (int)((b[i] - lo) / (hi - lo) * Bn))); H[ia * Bn + ib]++; Ha[ia]++; Hb[ib]++; }
    double mi = 0, chi2 = 0; long nz = 0;
    for (int i = 0; i < Bn; i++) for (int j = 0; j < Bn; j++) { long h = H[i * Bn + j]; double e = (double)Ha[i] * Hb[j] / n; if (e > 0) chi2 += (h - e) * (h - e) / e; if (h > 0) { nz++; mi += (double)h / n * std::log((double)h * n / ((double)Ha[i] * Hb[j])); } }
    long ka = 0, kb = 0; for (int i = 0; i < Bn; i++) { if (Ha[i]) ka++; if (Hb[i]) kb++; }
    double mm = mi / std::log(2.0) - ((double)(nz - 1) - (ka - 1) - (kb - 1)) / (2.0 * n * std::log(2.0));
    double df = (double)(ka - 1) * (kb - 1); double z = df > 0 ? (chi2 - df) / std::sqrt(2 * df) : NAN;
    return {mm, z};
}
int main(int argc, char** argv) {
    // usage: family_window <family> <p> <q> <K|-> <cmin> <cmax> <step> <delta> <n_seeds> <T> <W> <N> <out.csv> [slice_k slice_m]
    if (argc < 14) { std::fprintf(stderr, "usage: %s family p q K|- cmin cmax step delta n_seeds T W N out.csv [k m]\n", argv[0]); return 2; }
    Family f = parse_family(argv[1]); int64_t p = atoll(argv[2]), q = atoll(argv[3]);
    double cmin = atof(argv[5]), cmax = atof(argv[6]), st = atof(argv[7]), delta = atof(argv[8]);
    long n = atol(argv[9]); int T = atoi(argv[10]), W = atoi(argv[11]); long N = atol(argv[12]);
    int sk = argc > 15 ? atoi(argv[14]) : 0, sm = argc > 15 ? atoi(argv[15]) : 1;
    FParams base = default_params(f, p, q); if (std::strcmp(argv[4], "-") != 0) base.K = atof(argv[4]);
    identity_check(f, p, q);
    const double lo = (f == HENON) ? -1.5 : 0.0, hi = (f == HENON) ? 1.5 : 1.0;
    FILE* fo = fopen(argv[13], "w");
    fprintf(fo, "family,p,q,K,param,paramB,lambda1_A,period_A,lambda1_B,period_B,escaped,max_abs_r_ens,rms_r_ens,r_ens_first,r_ens_last,mean_ln_d_end,frac_d_gt_scale_end,r0,rlag_max64,MI_MM_bits,chi2_z,n_seeds,T,W,N\n");
    const double scale = (f == HENON) ? 1.0 : 0.25;
    // pre-compute the seed states once (the pair splits at t = 0, as in the 09-05 protocol)
    std::vector<FState> S0(n); for (long i = 0; i < n; i++) S0[i] = init_state(1000000ULL + (uint64_t)i * 7919ULL, f);
    int M = (int)std::floor((cmax - cmin) / st + 1e-9) + 1;
    for (int ci = 0; ci < M; ci++) {
        if (ci % sm != sk) continue;
        double c = cmin + ci * st; FParams A = base, Bp = base; set_param(A, f, c); set_param(Bp, f, c + delta);
        bool eA = false, eB = false; int perA = 0, perB = 0;
        double l1A = lyap_benettin(A, f, 12345678901234ULL, BURNIN, 100000, &eA, &perA);
        double l1B = lyap_benettin(Bp, f, 12345678901234ULL, BURNIN, 100000, &eB, &perB);
        // ensemble r_ens(t), t in (T, T+W]
        std::vector<Acc> R(W); double slnd = 0; long cnt = 0, gt = 0, nesc = 0;
        for (long i = 0; i < n; i++) {
            FState a = S0[i], b = S0[i]; bool e = false;
            for (int t = 0; t < T; t++) { fstep(a, A, f); fstep(b, Bp, f); if (escaped(a) || escaped(b)) { e = true; break; } }
            if (e) { nesc++; continue; }
            for (int w = 0; w < W; w++) { fstep(a, A, f); fstep(b, Bp, f); R[w].add(a.x1, b.x1); }
            double d = fdist(a, b, f); if (d > 0) { slnd += std::log(d); cnt++; } if (d > scale) gt++;
        }
        double mx = 0, ss = 0; for (int w = 0; w < W; w++) { double v = R[w].r(); if (std::isfinite(v)) { mx = std::max(mx, std::fabs(v)); ss += v * v; } }
        // single-seed time series after T steps
        FState a = init_state(12345678901234ULL, f), b = a; bool eT = false;
        for (int t = 0; t < T; t++) { fstep(a, A, f); fstep(b, Bp, f); if (escaped(a) || escaped(b)) { eT = true; break; } }
        double r0 = NAN, rl = NAN; MIres mr{NAN, NAN};
        if (!eT) { std::vector<double> xa(N), xb(N);
            for (long i = 0; i < N; i++) { fstep(a, A, f); fstep(b, Bp, f); xa[i] = a.x1; xb[i] = b.x1; if (escaped(a) || escaped(b)) { eT = true; break; } }
            if (!eT) { r0 = pearson_v(xa, xb, 0); double m = 0; for (long l = -64; l <= 64; l++) m = std::max(m, std::fabs(pearson_v(xa, xb, l))); rl = m; mr = mi_joint(xa, xb, 32, lo, hi); } }
        int escf = (eA || eB || eT || nesc > n / 2) ? 1 : 0;
        fprintf(fo, "%s,%lld,%lld,%g,%.6f,%.6f,%.5f,%d,%.5f,%d,%d,%.6f,%.6f,%.6f,%.6f,%.4f,%.4f,%.6f,%.6f,%.5f,%.2f,%ld,%d,%d,%ld\n", FAMILY_NAME[f], (long long)p, (long long)q, base.K, c, c + delta,
                l1A, perA, l1B, perB, escf, mx, std::sqrt(ss / W), R[0].r(), R[W - 1].r(), cnt ? slnd / cnt : -INFINITY, (double)gt / std::max(1L, n - nesc), r0, rl, mr.mi_mm, mr.chi2_z, n - nesc, T, W, N);
        fflush(fo);
        std::fprintf(stderr, "%s %s=%.4f: l1A=%+.4f perA=%d | l1B=%+.4f perB=%d | max|r_ens|=%.4f rlag=%.4f MI=%.4f esc=%d\n", FAMILY_NAME[f], param_name(f), c, l1A, perA, l1B, perB, mx, rl, mr.mi_mm, escf);
    }
    fclose(fo); return 0;
}
