// mcl_tau_int.cpp — Integrated autocorrelation time of the QR log-stretch
// series ln|R11|, ln|R22| for the MCL Gauss-Seidel Lyapunov pipeline.
//
// Answers the 2026-07-19 deep-audit demand: the paper (§3.2.1 methodology
// note) claims "measured autocorrelation time ~= 1 step" supporting the
// 1/sqrt(N) iid standard-error model, but no archived raw measurement
// existed. This tool reproduces the engine's compute_lyapunov() QR loop
// exactly (same jacobian_gs / qr_decompose_2x2 / mcl_iterate_raw from the
// frozen v6.0.0 engine), records the per-step increments, and computes:
//   rho_k (ACF) for k=1..LAGMAX, tau_int = 1 + 2*sum rho_k with a
//   Sokal self-consistent window (M >= 5*tau_int), plus SE_eff/SE_iid.
// Validation anchor: lambda1/lambda2 at 1e6 iterations must reproduce the
// archived EXP-7 values (seed 12345678901234: 5.7778 / 1.0186).
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <vector>

static void run_seed(uint64_t seed, int64_t n_iter, int lagmax) {
    double t1, t2;
    mcl_init_state(seed, t1, t2);
    const int64_t p = 3, q = 5; const double K = 12.0;
    for (int i = 0; i < BURNIN; i++) mcl_iterate_raw(t1, t2, p, q, K);

    Mat2 Q; Q.a[0][0] = 1; Q.a[0][1] = 0; Q.a[1][0] = 0; Q.a[1][1] = 1;
    std::vector<double> s1((size_t)n_iter), s2((size_t)n_iter);
    for (int64_t n = 0; n < n_iter; n++) {
        Mat2 J = jacobian_gs(t1, t2, p, q, K);
        mcl_iterate_raw(t1, t2, p, q, K);
        Mat2 M = mat_mul(J, Q);
        double r11, r22;
        qr_decompose_2x2(M, Q, r11, r22);
        s1[(size_t)n] = std::log(std::abs(r11));
        s2[(size_t)n] = std::log(std::abs(r22));
    }

    for (int which = 0; which < 2; which++) {
        const std::vector<double>& s = which ? s2 : s1;
        double N = (double)n_iter;
        double mean = 0; for (double v : s) mean += v; mean /= N;
        double var = 0; for (double v : s) var += (v - mean) * (v - mean); var /= N;
        double se_iid = std::sqrt(var / N);

        std::vector<double> rho((size_t)lagmax + 1, 0.0);
        for (int k = 1; k <= lagmax; k++) {
            double c = 0;
            for (int64_t i = 0; i + k < n_iter; i++)
                c += (s[(size_t)i] - mean) * (s[(size_t)(i + k)] - mean);
            rho[(size_t)k] = c / ((N - k) * var);
        }
        // Sokal self-consistent window: smallest M with M >= 5*tau_int(M)
        double tau = 1.0; int M_used = lagmax;
        for (int M = 1; M <= lagmax; M++) {
            double t = 1.0; for (int k = 1; k <= M; k++) t += 2.0 * rho[(size_t)k];
            if ((double)M >= 5.0 * t) { tau = t; M_used = M; break; }
            if (M == lagmax) tau = t;
        }
        double maxabs = 0; int argmax = 1;
        for (int k = 1; k <= lagmax; k++)
            if (std::fabs(rho[(size_t)k]) > maxabs) { maxabs = std::fabs(rho[(size_t)k]); argmax = k; }

        std::printf("  seed %14llu  ln|R%d%d|: lambda=%.4f  var=%.4f  SE_iid=%.4f\n",
                    (unsigned long long)seed, which + 1, which + 1, mean, var, se_iid);
        std::printf("    rho_1=%+.5f rho_2=%+.5f rho_3=%+.5f rho_5=%+.5f rho_10=%+.5f\n",
                    rho[1], rho[2], rho[3], rho[5], rho[10]);
        std::printf("    max|rho_k| (k=1..%d) = %.5f at k=%d   (noise floor 2/sqrt(N) = %.5f)\n",
                    lagmax, maxabs, argmax, 2.0 / std::sqrt(N));
        std::printf("    tau_int (Sokal window M=%d) = %.4f   SE_eff = SE_iid*sqrt(tau) = %.4f\n\n",
                    M_used, tau, se_iid * std::sqrt(tau));
    }
}

int main() {
    std::printf("==============================================================\n");
    std::printf(" MCL QR LOG-STRETCH INTEGRATED AUTOCORRELATION TIME\n");
    std::printf(" Doc ID: MCL-TAUINT-QR-2026-0719-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen M1_M2_apple_verification copy)\n");
    std::printf(" Config: (p,q)=(3,5), K=12, burn-in 10000, 1e6 QR iterations/seed\n");
    std::printf(" Anchor: seed 12345678901234 must give lambda1=5.7778, lambda2=1.0186\n");
    std::printf("         (archived MCL-SAFEZONE-VERIFY EXP 7, 1e6 iterations)\n");
    std::printf("==============================================================\n\n");
    const int64_t N = 1000000LL;
    const int LAGMAX = 100;
    uint64_t seeds[3] = {12345678901234ULL, 98765432109876ULL, 31415926535897ULL};
    for (int i = 0; i < 3; i++) run_seed(seeds[i], N, LAGMAX);
    std::printf(" Interpretation: tau_int ~= 1 (and max|rho_k| at the noise floor)\n");
    std::printf(" validates the independent-increment 1/sqrt(N) standard-error model\n");
    std::printf(" used for the +/-0.0004 (1e7-iteration) quotes in Paper 1 Table 2.\n");
    return 0;
}
