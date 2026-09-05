// Paper 3 measurement 5a (2026-09-05): decorrelation time of two trajectories of the
// MCL coupled-oscillator map started from the SAME initial phases under parameters that
// differ by a perturbation delta (omega_2, K, or an adjacent integer weight).
// Tests the Lyapunov prediction implicit in Paper 3 Eq. (6): t_dec ~ ln(2*pi/delta_1)/lambda_1.
//
// Engine arithmetic: the step() below reproduces mcl_iterate_raw / mcl_iterate_jacobi of
// mcl_core.hpp operation-for-operation (custom omegas only); bit-identity with the engine
// functions is asserted at startup over 10^5 steps. Lyapunov exponents come from the engine's
// own compute_lyapunov / compute_lyapunov_jacobi. Seeds -> initial phases exactly as MCL_T2's
// constructor (hash_seed, mod2pi(s*OMEGA)).
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include "../../mcl_core.hpp"

struct Params { int64_t p, q; double K, w1, w2; };
static int g_burnin = 0;

static inline void step(double& t1, double& t2, const Params& P, bool jacobi) {
    double a1 = (double)P.p * t2 - (double)P.q * t1;
    if (!jacobi) {
        t1 = mod2pi(t1 + P.w1 + P.K * std::sin(a1));
        double a2 = (double)P.p * t1 - (double)P.q * t2;
        t2 = mod2pi(t2 + P.w2 + P.K * std::sin(a2));
    } else {
        double a2 = (double)P.p * t1 - (double)P.q * t2;   // uses OLD t1
        t1 = mod2pi(t1 + P.w1 + P.K * std::sin(a1));
        t2 = mod2pi(t2 + P.w2 + P.K * std::sin(a2));
    }
}
static inline double tdist(double a1, double a2, double b1, double b2) {
    double d1 = std::fabs(a1 - b1); if (d1 > M_PI) d1 = 2 * M_PI - d1;
    double d2 = std::fabs(a2 - b2); if (d2 > M_PI) d2 = 2 * M_PI - d2;
    return std::sqrt(d1 * d1 + d2 * d2);
}
static void init_phases(uint64_t seed, double& t1, double& t2) {
    uint64_t s = hash_seed(seed);
    t1 = mod2pi((double)s * OMEGA_1);
    t2 = mod2pi((double)s * OMEGA_2);
}

struct Acc { double sx, sy, sxx, syy, sxy; long n; };
static inline void acc(Acc& a, double x, double y) { a.sx += x; a.sy += y; a.sxx += x * x; a.syy += y * y; a.sxy += x * y; a.n++; }
static inline double pearson(const Acc& a) {
    double mx = a.sx / a.n, my = a.sy / a.n;
    double vx = a.sxx / a.n - mx * mx, vy = a.syy / a.n - my * my, c = a.sxy / a.n - mx * my;
    if (vx <= 0 || vy <= 0) return (vx <= 0 && vy <= 0) ? 1.0 : 0.0;
    return c / std::sqrt(vx * vy);
}

int main(int argc, char** argv) {
    // usage: decorr_time <mode: omega|K|pq|zero> <p> <q> <K> <update: gs|jacobi> <n_seeds> <T> <out_prefix> [delta...]
    if (argc < 9) { std::fprintf(stderr, "usage: %s mode p q K gs|jacobi n_seeds T out_prefix [delta ...]\n", argv[0]); return 2; }
    std::string mode = argv[1]; int64_t p = atoll(argv[2]), q = atoll(argv[3]); double K = atof(argv[4]);
    bool jac = (std::strcmp(argv[5], "jacobi") == 0); long n = atol(argv[6]); int T = atoi(argv[7]);
    std::string out = argv[8];
    if (const char* e = getenv("DECORR_BURNIN")) g_burnin = atoi(e);
    if (g_burnin) std::fprintf(stderr, "[burn-in] %d common steps under parameter set A before the split\n", g_burnin);
    std::vector<double> deltas; for (int i = 9; i < argc; i++) deltas.push_back(atof(argv[i]));
    if (mode == "zero") deltas = {0.0};
    if (mode == "pq") deltas = {1.0, 2.0}; // 1: q -> q+1 ; 2: p -> p+1

    // --- engine-faithfulness check: step() == mcl_iterate_raw / mcl_iterate_jacobi bit-for-bit
    { double a1, a2; init_phases(12345678901234ULL, a1, a2); double b1 = a1, b2 = a2; Params P{p, q, K, OMEGA_1, OMEGA_2};
      for (int i = 0; i < 100000; i++) { step(a1, a2, P, jac); if (jac) mcl_iterate_jacobi(b1, b2, p, q, K); else mcl_iterate_raw(b1, b2, p, q, K);
        if (a1 != b1 || a2 != b2) { std::fprintf(stderr, "FATAL: step() deviates from engine at i=%d\n", i); return 3; } }
      std::fprintf(stderr, "[ok] step() bit-identical to engine %s over 1e5 steps\n", jac ? "mcl_iterate_jacobi" : "mcl_iterate_raw"); }

    // --- Lyapunov exponent of the base configuration (engine function)
    LyapResult L = jac ? compute_lyapunov_jacobi(12345678901234ULL, p, q, K, 1000000) : compute_lyapunov(12345678901234ULL, p, q, K, 1000000);
    std::fprintf(stderr, "[engine] lambda1=%.4f lambda2=%.4f (%s, p=%lld q=%lld K=%g, 1e6 iters)\n", L.l1, L.l2, jac ? "Jacobi" : "GS", (long long)p, (long long)q, K);

    FILE* fs = fopen((out + "_steps.csv").c_str(), "w");
    FILE* fsum = fopen((out + "_summary.csv").c_str(), "w");
    fprintf(fs, "mode,update,p,q,K,delta,t,mean_ln_d,frac_d_gt_1,r_cos1,r_cos2,r_sin1\n");
    fprintf(fsum, "mode,update,p,q,K,delta,ln_inv_delta,lambda1,lambda2,mean_ln_d1,t_sat,t_dec,r_floor,t_pred_1rad,t_pred_2pi,growth_slope,growth_pts,r_at_T\n");

    for (double delta : deltas) {
        Params A{p, q, K, OMEGA_1, OMEGA_2}, B = A;
        if (mode == "omega") B.w2 += delta; else if (mode == "K") B.K += delta;
        else if (mode == "pq") { if (delta == 1.0) B.q = q + 1; else B.p = p + 1; }
        std::vector<Acc> ac1(T + 1, Acc{0, 0, 0, 0, 0, 0}), ac2 = ac1, as1 = ac1;
        std::vector<double> sumlnd(T + 1, 0.0); std::vector<long> cnt(T + 1, 0), cgt1(T + 1, 0);
        for (long i = 0; i < n; i++) {
            double a1, a2; init_phases(1000000ULL + (uint64_t)i * 7919ULL, a1, a2);
            for (int t = 0; t < g_burnin; t++) step(a1, a2, A, jac);   // optional common burn-in on the attractor (2026-09-05 referee check)
            double b1 = a1, b2 = a2;
            for (int t = 1; t <= T; t++) {
                step(a1, a2, A, jac); step(b1, b2, B, jac);
                double d = tdist(a1, a2, b1, b2);
                if (d > 0) { sumlnd[t] += std::log(d); cnt[t]++; }
                if (d > 1.0) cgt1[t]++;
                acc(ac1[t], std::cos(a1), std::cos(b1)); acc(ac2[t], std::cos(a2), std::cos(b2)); acc(as1[t], std::sin(a1), std::sin(b1));
            }
        }
        double rfloor = 3.0 / std::sqrt((double)n);
        int t_dec = -1; // first t after which |r_cos1| stays below the floor for all later t
        for (int t = T; t >= 1; t--) { if (std::fabs(pearson(ac1[t])) >= rfloor) { t_dec = t + 1; break; } if (t == 1) t_dec = 1; }
        if (t_dec > T) t_dec = -1;
        int t_sat = -1; for (int t = 1; t <= T; t++) if (cnt[t] > 0 && sumlnd[t] / cnt[t] > 0.0) { t_sat = t; break; }
        double mld1 = cnt[1] > 0 ? sumlnd[1] / cnt[1] : -INFINITY;
        // growth slope: regress mean ln d on t over steps where mean ln d in (mld1+1, -2)
        double sx = 0, sy = 0, sxx = 0, sxy = 0; int m = 0;
        for (int t = 1; t <= T; t++) { if (cnt[t] == 0) continue; double y = sumlnd[t] / cnt[t]; if (y > mld1 + 1.0 && y < -2.0) { sx += t; sy += y; sxx += (double)t * t; sxy += t * y; m++; } }
        double slope = (m >= 2) ? (m * sxy - sx * sy) / (m * sxx - sx * sx) : NAN;
        double t_pred = std::isfinite(mld1) ? (std::log(2 * M_PI) - mld1) / L.l1 : NAN;
        double t_pred1 = std::isfinite(mld1) ? 1.0 + (0.0 - mld1) / L.l1 : NAN; // step at which mean ln d crosses 0 (d = 1 rad) if growth is exactly lambda1 from step 1
        for (int t = 1; t <= T; t++)
            fprintf(fs, "%s,%s,%lld,%lld,%g,%.3e,%d,%.6f,%.6f,%.6f,%.6f,%.6f\n", mode.c_str(), jac ? "jacobi" : "gs", (long long)p, (long long)q, K, delta, t,
                    cnt[t] ? sumlnd[t] / cnt[t] : NAN, (double)cgt1[t] / n, pearson(ac1[t]), pearson(ac2[t]), pearson(as1[t]));
        fprintf(fsum, "%s,%s,%lld,%lld,%g,%.3e,%.4f,%.4f,%.4f,%.4f,%d,%d,%.4f,%.3f,%.3f,%.4f,%d,%.6f\n", mode.c_str(), jac ? "jacobi" : "gs", (long long)p, (long long)q, K, delta,
                delta > 0 && mode != "pq" ? std::log(1.0 / delta) : NAN, L.l1, L.l2, mld1, t_sat, t_dec, rfloor, t_pred1, t_pred, slope, m, pearson(ac1[T]));
        std::fprintf(stderr, "  delta=%.3e  mean_ln_d(1)=%.3f  t_sat=%d  t_dec=%d  t_pred_1rad=%.2f  t_pred_2pi=%.2f  slope=%.3f (pts %d)  r(T)=%.4f\n", delta, mld1, t_sat, t_dec, t_pred1, t_pred, slope, m, pearson(ac1[T]));
    }
    fclose(fs); fclose(fsum);
    return 0;
}
