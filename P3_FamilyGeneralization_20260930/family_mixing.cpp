// Paper 3, ت-309(b') (2026-09-30): intrinsic single-trajectory MIXING diagnostic per parameter cell, to
// classify cells independently of the two-trajectory outcome.  After the engine burn-in from the engine
// seed, the x1 series of ONE trajectory (N steps) gives the autocorrelation rho(tau), tau = 1..512.
// A mixing attractor: rho decays to the sampling floor (~3/sqrt(N)); a periodic orbit, a quasi-periodic
// state or BANDED chaos (chaotic within bands, periodic band cycle -- the reverse-bifurcation regime
// between the period-doubling accumulation point and the last band merging) keeps a persistent periodic
// component: max |rho(tau)| over tau in [65, 512] stays O(0.1-1).  Also reports lambda_1 (Benettin) and
// the exact period, as family_window does, and the positive-peak lag in [1, 64] (band period).
// 2026-09-30 (later): a FAR tail, max |rho(tau)| over tau in [4001, 4096], distinguishes a persistent periodic
// component (rigid band cycle: far tail ~ near tail) from a slowly DECAYING one near a band-merging crisis
// (far tail at the sampling floor although the near tail is still O(0.1-0.7)); N = 1e5 by default.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include "family_maps.hpp"
int main(int argc, char** argv) {
    // usage: family_mixing <family> <p> <q> <K|-> <cmin> <cmax> <step> <N> <out.csv>
    if (argc < 10) { std::fprintf(stderr, "usage: %s family p q K|- cmin cmax step N out.csv\n", argv[0]); return 2; }
    Family f = parse_family(argv[1]); int64_t p = atoll(argv[2]), q = atoll(argv[3]);
    double cmin = atof(argv[5]), cmax = atof(argv[6]), st = atof(argv[7]); long N = atol(argv[8]);
    FParams base = default_params(f, p, q); if (std::strcmp(argv[4], "-") != 0) base.K = atof(argv[4]);
    identity_check(f, p, q);
    FILE* fo = fopen(argv[9], "w");
    fprintf(fo, "family,p,q,K,param,lambda1,period,escaped,acf_max_1_64,acf_argmax_1_64,acf_pos_peak_lag,acf_tail_max_65_512,acf_tail_argmax,acf_far_max_4001_4096,acf_far_argmax,acf_decay_lag_005,acf_floor_3sigma,N\n");
    const int LMAX = 512; int M = (int)std::floor((cmax - cmin) / st + 1e-9) + 1;
    for (int ci = 0; ci < M; ci++) {
        double c = cmin + ci * st; FParams A = base; set_param(A, f, c); bool esc = false; int per = 0;
        double l1 = lyap_benettin(A, f, 12345678901234ULL, BURNIN, 100000, &esc, &per);
        FState s = init_state(12345678901234ULL, f); for (int t = 0; t < BURNIN; t++) fstep(s, A, f);
        std::vector<double> x(N); bool e2 = false;
        for (long i = 0; i < N; i++) { fstep(s, A, f); x[i] = s.x1; if (escaped(s)) { e2 = true; break; } }
        double m = 0; for (double v : x) m += v; m /= N; double v0 = 0; for (double v : x) v0 += (v - m) * (v - m);
        double mx64 = 0, tail = 0, pospk = 0, far = 0; int arg64 = 0, argt = 0, poslag = 0, argf = 0, decay = -1; std::vector<double> rhos(LMAX + 1, 0.0);
        if (!e2 && v0 > 1e-30) {
            for (int tau = 1; tau <= LMAX; tau++) { double sum = 0; for (long i = 0; i + tau < N; i++) sum += (x[i] - m) * (x[i + tau] - m); double rho = sum / v0; rhos[tau] = rho;
                if (tau <= 64) { if (std::fabs(rho) > mx64) { mx64 = std::fabs(rho); arg64 = tau; } if (rho > pospk) { pospk = rho; poslag = tau; } }
                else if (std::fabs(rho) > tail) { tail = std::fabs(rho); argt = tau; } }
            for (int tau = 1; tau + 7 <= LMAX; tau++) { bool ok = true; for (int k = 0; k < 8; k++) if (std::fabs(rhos[tau + k]) >= 0.05) { ok = false; break; } if (ok) { decay = tau; break; } }   // correlation decay lag: |rho| < 0.05 for 8 consecutive lags
            for (int tau = 4001; tau <= 4096 && tau < N / 4; tau++) { double sum = 0; for (long i = 0; i + tau < N; i++) sum += (x[i] - m) * (x[i + tau] - m); double rho = sum / v0;
                if (std::fabs(rho) > far) { far = std::fabs(rho); argf = tau; } }
        }
        fprintf(fo, "%s,%lld,%lld,%g,%.6f,%.5f,%d,%d,%.5f,%d,%d,%.5f,%d,%.5f,%d,%d,%.5f,%ld\n", FAMILY_NAME[f], (long long)p, (long long)q, base.K, c, l1, per, (esc || e2) ? 1 : 0, mx64, arg64, pospk >= 0.3 ? poslag : 0, tail, argt, far, argf, decay, 3.0 / std::sqrt((double)N), N);
        if (ci % 50 == 0) std::fprintf(stderr, "%s %s=%.4f: l1=%+.4f per=%d acf max64=%.3f@%d tail=%.3f@%d far=%.3f@%d\n", FAMILY_NAME[f], param_name(f), c, l1, per, mx64, arg64, tail, argt, far, argf);
    }
    fclose(fo); return 0;
}
