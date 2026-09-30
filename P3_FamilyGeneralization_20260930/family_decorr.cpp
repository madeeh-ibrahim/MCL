// Paper 3, ت-309(a) (2026-09-30): decorrelation time of two same-seed trajectories of a coupled family
// (Henon / logistic / tent, Sec. VII of the paper) under parameters that differ by delta in the MAP
// parameter (a, r, mu), in the coupling strength K, or by an adjacent integer weight.  Same protocol
// as the 2026-09-05 phase-oscillator measurement (MCL-P3-DECORR-2026-0905-001): n seeds, common
// burn-in B under parameter set A on the attractor (engine BURNIN by default; FAM_BURNIN=0 to split at
// the seed state), then per iteration <ln d(t)> (Euclidean distance in the full state) and the ensemble
// Pearson correlation r_ens(t) of x1 (and x2) between the two trajectories.  Family step = family_maps.hpp
// (bit-identical to the engine classes, asserted at start-up).  lambda_1 of set A by Benettin (1e6 steps).
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include "family_maps.hpp"

struct Acc { double sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0; long n = 0;
    void add(double x, double y) { sx += x; sy += y; sxx += x * x; syy += y * y; sxy += x * y; n++; }
    double r() const { double mx = sx / n, my = sy / n, vx = sxx / n - mx * mx, vy = syy / n - my * my, c = sxy / n - mx * my;
        if (vx <= 1e-30 || vy <= 1e-30) return (vx <= 1e-30 && vy <= 1e-30) ? 1.0 : 0.0; return c / std::sqrt(vx * vy); } };

int main(int argc, char** argv) {
    // usage: family_decorr <family> <mode: param|K|pq|zero> <p> <q> <base_param|-> <n_seeds> <T> <out_prefix> [delta...]
    if (argc < 9) { std::fprintf(stderr, "usage: %s family param|K|pq|zero p q base_param|- n_seeds T out_prefix [delta ...]\n", argv[0]); return 2; }
    Family f = parse_family(argv[1]); std::string mode = argv[2]; int64_t p = atoll(argv[3]), q = atoll(argv[4]);
    long n = atol(argv[6]); int T = atoi(argv[7]); std::string out = argv[8];
    FParams A = default_params(f, p, q);
    if (std::strcmp(argv[5], "-") != 0) set_param(A, f, atof(argv[5]));
    if (const char* e = getenv("FAM_K")) A.K = atof(e);
    int B = BURNIN; if (const char* e = getenv("FAM_BURNIN")) B = atoi(e);
    std::vector<double> deltas; for (int i = 9; i < argc; i++) deltas.push_back(atof(argv[i]));
    if (mode == "zero") deltas = {0.0};
    if (mode == "pq") deltas = {1.0, 2.0};      // 1: q -> q+1 ; 2: p -> p+1
    identity_check(f, p, q);
    bool esc = false; int per = 0;
    double l1 = lyap_benettin(A, f, 12345678901234ULL, BURNIN, 1000000, &esc, &per);
    std::fprintf(stderr, "[lyap] %s (%lld,%lld) K=%g %s=%.6g: lambda1=%.5f (Benettin, 1e6 steps%s), period<=256: %d, burn-in before split B=%d\n",
                 FAMILY_NAME[f], (long long)p, (long long)q, A.K, param_name(f), get_param(A, f), l1, esc ? ", ESCAPED" : "", per, B);
    // post-burn-in states of all seeds under A (shared by every delta)
    std::vector<FState> S0(n); long nesc = 0;
    for (long i = 0; i < n; i++) { FState s = init_state(1000000ULL + (uint64_t)i * 7919ULL, f); for (int t = 0; t < B; t++) fstep(s, A, f); S0[i] = s; if (escaped(s)) nesc++; }
    if (nesc) std::fprintf(stderr, "[warn] %ld of %ld seeds escaped during burn-in\n", nesc, n);
    FILE* fs = fopen((out + "_steps.csv").c_str(), "w"); FILE* fsum = fopen((out + "_summary.csv").c_str(), "w");
    fprintf(fs, "family,mode,p,q,K,param,delta,t,mean_ln_d,frac_d_gt_scale,r_x1,r_x2\n");
    fprintf(fsum, "family,mode,p,q,K,param,delta,ln_inv_delta,lambda1,mean_ln_d1,ln_d_inf,t_sat,t_dec,r_floor,growth_slope,growth_pts,r_at_T,n_seeds,burnin,n_escaped\n");
    for (double delta : deltas) {
        FParams Bp = A;
        if (mode == "param") set_param(Bp, f, get_param(A, f) - delta);       // downward, stays inside the map's domain
        else if (mode == "K") Bp.K += delta;
        else if (mode == "pq") { if (delta == 1.0) Bp.q = q + 1; else Bp.p = p + 1; }
        std::vector<Acc> ax1(T + 1), ax2(T + 1); std::vector<double> sumlnd(T + 1, 0.0); std::vector<long> cnt(T + 1, 0), cgt(T + 1, 0);
        const double scale = (f == HENON) ? 1.0 : 0.25;   // "attractor scale" reference for the fraction column only
        long nesc2 = 0;
        for (long i = 0; i < n; i++) {
            if (escaped(S0[i])) continue;
            FState a = S0[i], b = S0[i]; bool e = false;
            for (int t = 1; t <= T; t++) {
                fstep(a, A, f); fstep(b, Bp, f);
                if (escaped(a) || escaped(b)) { e = true; break; }
                double d = fdist(a, b, f);
                if (d > 0) { sumlnd[t] += std::log(d); cnt[t]++; }
                if (d > scale) cgt[t]++;
                ax1[t].add(a.x1, b.x1); ax2[t].add(a.x2, b.x2);
            }
            if (e) nesc2++;
        }
        long neff = ax1[T].n; double rfloor = 3.0 / std::sqrt((double)std::max(neff, 1L));
        int t_dec = -1; for (int t = T; t >= 1; t--) { if (std::fabs(ax1[t].r()) >= rfloor) { t_dec = t + 1; break; } if (t == 1) t_dec = 1; } if (t_dec > T) t_dec = -1;
        double mld1 = cnt[1] > 0 ? sumlnd[1] / cnt[1] : -INFINITY;
        double dinf = 0; int m2 = 0; for (int t = std::max(1, T - 49); t <= T; t++) if (cnt[t]) { dinf += sumlnd[t] / cnt[t]; m2++; } dinf = m2 ? dinf / m2 : NAN;
        int t_sat = -1; for (int t = 1; t <= T; t++) if (cnt[t] > 0 && sumlnd[t] / cnt[t] > dinf - 1.0) { t_sat = t; break; }
        double sx = 0, sy = 0, sxx = 0, sxy = 0; int m = 0;
        for (int t = 1; t <= T; t++) { if (cnt[t] == 0) continue; double y = sumlnd[t] / cnt[t]; if (y > mld1 + 1.0 && y < dinf - 2.0) { sx += t; sy += y; sxx += (double)t * t; sxy += t * y; m++; } }
        double slope = (m >= 2) ? (m * sxy - sx * sy) / (m * sxx - sx * sx) : NAN;
        for (int t = 1; t <= T; t++)
            fprintf(fs, "%s,%s,%lld,%lld,%g,%.10g,%.3e,%d,%.6f,%.6f,%.6f,%.6f\n", FAMILY_NAME[f], mode.c_str(), (long long)p, (long long)q, A.K, get_param(A, f), delta, t,
                    cnt[t] ? sumlnd[t] / cnt[t] : NAN, ax1[t].n ? (double)cgt[t] / ax1[t].n : NAN, ax1[t].r(), ax2[t].r());
        fprintf(fsum, "%s,%s,%lld,%lld,%g,%.10g,%.3e,%.4f,%.5f,%.4f,%.4f,%d,%d,%.4f,%.5f,%d,%.6f,%ld,%d,%ld\n", FAMILY_NAME[f], mode.c_str(), (long long)p, (long long)q, A.K, get_param(A, f), delta,
                (delta > 0 && mode != "pq") ? std::log(1.0 / delta) : NAN, l1, mld1, dinf, t_sat, t_dec, rfloor, slope, m, ax1[T].r(), neff, B, nesc + nesc2);
        std::fprintf(stderr, "  delta=%.3e  <ln d>(1)=%.3f  ln d_inf=%.3f  t_sat=%d  t_dec=%d  slope=%.4f (pts %d)  slope/l1=%.4f  r(T)=%.4f  esc=%ld\n",
                     delta, mld1, dinf, t_sat, t_dec, slope, m, slope / l1, ax1[T].r(), nesc + nesc2);
    }
    fclose(fs); fclose(fsum); return 0;
}
