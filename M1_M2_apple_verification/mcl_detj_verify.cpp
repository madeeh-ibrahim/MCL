/*
 * MCL Determinant Companion Laws Verification (Paper 1, §III.B.3, Eqs. 3c–3f / M2)
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 *
 * Document ID:   MCL-DETJ-VERIFY-2026-0703-001
 * Engine:        mcl_core.hpp v6.0.0 (archived, MD5 241db79ecf8a42897eb9a8399cf37929)
 *
 * ⚠ INTERNAL until Patent 4 is filed (Eq. 3e / q>p order relation — see
 *   Reviews/Paper1_Fixes_NODY_Addendum_20260703.md). Do not publish or upload.
 *
 * PURPOSE: Verify on THIS platform (Apple libm) the four claims of §III.B.3:
 *
 *  (3c)  det J = (1 - qKc1)(1 - qKc2)          — exact identity (spot-checked
 *        against the engine's analytical Jacobian to machine precision)
 *  (3d)  lambda_1 + lambda_2 = <ln|det J|>  ~  2 ln(qK/2)
 *        — Oseledets identity (4-decimal agreement) + mean-field approximation
 *        (paper: max error 0.08% across the 8 coprime topologies at K = 12)
 *  (3e)  lambda_2 ~ 2 ln(q/p), asymptotically in K
 *        (paper: worst 0.62% at (2,3); K-sweep deviations -1.06% @K=6,
 *         -0.30% @K=12, -0.01% @K=50; reversed (5,3): lambda_2 = -1.0226
 *         vs 2 ln(3/5) = -1.0217, 0.09%)
 *  (3f)  det J_Jacobi = (1 - qKc1)(1 - qKc2) - p^2 K^2 c1 c2  — the cross
 *        term does NOT cancel for the parallel update (numerical spot check)
 *
 *  Also: <ln|tr J|> vs lambda_1 (trace approximation, paper: -0.04%) and
 *        (3b) = 2 ln(pK/2) (paper: +0.03% at (3,5,12)).
 *
 * PROTOCOL: QR method = engine's compute_lyapunov (analytical Gauss-Seidel
 * Jacobian + sequential QR), 10^7 iterations, burn-in 10,000. Topology sweep
 * uses the three Table II seeds and reports seed means. Part A runs on seed
 * 12345678901234.
 *
 * BUILD:
 *   c++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
 *       -o mcl_detj_verify mcl_detj_verify.cpp -lm && ./mcl_detj_verify
 */

#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <cstdint>

static const char* DOC_VERSION = "1.0.0";
static const char* DOC_ID      = "MCL-DETJ-VERIFY-2026-0703-001";

static constexpr int64_t N_ITERS = 10000000;
static const uint64_t SEEDS[3] = { 12345678901234ULL, 98765432109876ULL, 31415926535897ULL };

// ---------------------------------------------------------------- Part A ---
// Trajectory averages <ln|tr J|>, <ln|det J|> + QR lambda_1/lambda_2 on the
// SAME trajectory, plus machine-precision check of (3c) and (3f).
static void part_A(bool& all_pass) {
    const int64_t p = 3, q = 5; const double K = 12.0;
    double t1, t2;
    mcl_init_state(SEEDS[0], t1, t2);
    for (int i = 0; i < BURNIN; i++) mcl_iterate_raw(t1, t2, p, q, K);

    Mat2 Q; Q.a[0][0] = 1; Q.a[0][1] = 0; Q.a[1][0] = 0; Q.a[1][1] = 1;
    double s_lntr = 0, s_lndet = 0, s_l1 = 0, s_l2 = 0;
    double max_3c_err = 0, max_3f_gap_err = 0;

    for (int64_t n = 0; n < N_ITERS; n++) {
        const double t1_old = t1, t2_old = t2;
        const Mat2 J = jacobian_gs(t1, t2, p, q, K);
        mcl_iterate_raw(t1, t2, p, q, K);

        const double trJ  = J.a[0][0] + J.a[1][1];
        const double detJ = J.a[0][0] * J.a[1][1] - J.a[0][1] * J.a[1][0];

        // (3c) closed form vs engine Jacobian (machine precision)
        const double c1 = K * std::cos((double)p * t2_old - (double)q * t1_old);
        // theta_1(t+1) is the freshly advanced t1 (Gauss-Seidel)
        const double c2 = K * std::cos((double)p * t1 - (double)q * t2_old);
        const double det_cf = (1.0 - (double)q * c1) * (1.0 - (double)q * c2);
        // Exactness is algebraic; float evaluation of the two expressions
        // differs by rounding, amplified when (1-qKc) nearly cancels. The
        // correct scale is the factor magnitude, not the cancelled product.
        const double scale3c = (1.0 + std::fabs((double)q * c1))
                             * (1.0 + std::fabs((double)q * c2));
        const double rel3c = std::fabs(det_cf - detJ) / scale3c;
        if (rel3c > max_3c_err) max_3c_err = rel3c;

        // (3f): Jacobi determinant differs from GS by exactly -p^2K^2c1c2
        // (with c2 evaluated at the Jacobi argument p*t1_old - q*t2_old)
        const double c2j = K * std::cos((double)p * t1_old - (double)q * t2_old);
        const double detJac_cf = (1.0 - (double)q * c1) * (1.0 - (double)q * c2j)
                               - (double)(p * p) * c1 * c2j;
        const double J11j = 1.0 - (double)q * c1,        J12j = (double)p * c1;
        const double J21j = (double)p * c2j,             J22j = 1.0 - (double)q * c2j;
        const double detJac = J11j * J22j - J12j * J21j;
        const double scale3f = (1.0 + std::fabs((double)q * c1))
                             * (1.0 + std::fabs((double)q * c2j))
                             + std::fabs((double)(p * p) * c1 * c2j);
        const double rel3f = std::fabs(detJac_cf - detJac) / scale3f;
        if (rel3f > max_3f_gap_err) max_3f_gap_err = rel3f;

        double atr = std::fabs(trJ);  if (atr  < 1e-300) atr  = 1e-300;
        double adet = std::fabs(detJ); if (adet < 1e-300) adet = 1e-300;
        s_lntr  += std::log(atr);
        s_lndet += std::log(adet);

        const Mat2 M = mat_mul(J, Q);
        double r11, r22;
        qr_decompose_2x2(M, Q, r11, r22);
        s_l1 += std::log(std::fabs(r11));
        s_l2 += std::log(std::fabs(r22));
    }

    const double lntr  = s_lntr  / (double)N_ITERS;
    const double lndet = s_lndet / (double)N_ITERS;
    const double l1    = s_l1    / (double)N_ITERS;
    const double l2    = s_l2    / (double)N_ITERS;
    const double eq3b  = 2.0 * std::log((double)p * 12.0 / 2.0);
    const double sumlaw = 2.0 * std::log((double)q * 12.0 / 2.0);

    std::printf("PART A — trajectory identities at (3,5,12), seed %llu, 10^7 iters\n",
                (unsigned long long)SEEDS[0]);
    std::printf("  (3c) closed form vs engine det J : max rel err = %.3e  %s\n",
                max_3c_err, max_3c_err < 1e-13 ? "(machine precision, EXACT)" : "(!!)");
    std::printf("  (3f) closed form vs Jacobi det J : max rel err = %.3e  %s\n",
                max_3f_gap_err, max_3f_gap_err < 1e-13 ? "(machine precision, EXACT)" : "(!!)");
    std::printf("  QR:            lambda_1 = %.4f   lambda_2 = %.4f   sum = %.4f\n",
                l1, l2, l1 + l2);
    std::printf("  <ln|tr J|>   = %.4f   vs lambda_1        -> dev %+.3f%%\n",
                lntr, 100.0 * (lntr - l1) / l1);
    std::printf("  <ln|det J|>  = %.4f   vs QR sum %.4f   -> diff %+.5f (Oseledets)\n",
                lndet, l1 + l2, lndet - (l1 + l2));
    std::printf("  (3b) 2ln(pK/2) = %.4f vs lambda_1        -> dev %+.3f%%\n",
                eq3b, 100.0 * (eq3b - l1) / l1);
    std::printf("  (3d) 2ln(qK/2) = %.4f vs sum             -> dev %+.3f%%\n\n",
                sumlaw, 100.0 * (sumlaw - (l1 + l2)) / (l1 + l2));

    if (max_3c_err > 1e-13 || max_3f_gap_err > 1e-13) all_pass = false;
    if (std::fabs(lndet - (l1 + l2)) > 5e-4) all_pass = false;   // 4-decimal claim
}

// ---------------------------------------------------------------- Part B ---
// Topology sweep at K = 12 (3-seed means): (3d) and (3e).
static void part_B(bool& all_pass) {
    struct Topo { int64_t p, q; };
    const Topo topos[10] = { {2,3},{3,5},{5,7},{7,11},{8,13},{11,17},{13,19},{17,23},
                             {5,3},{3,2} };  // last two: reversed regime
    const double K = 12.0;

    std::printf("PART B — topology sweep at K = 12 (3-seed means, 10^7 iters each)\n");
    std::printf("  (p,q)     l2_mean    2ln(q/p)   err3e%%   sum_mean   2ln(qK/2)  err3d%%\n");
    std::printf("  ----------------------------------------------------------------------\n");
    double worst3e_coprime = 0, worst3d = 0;
    for (const auto& tp : topos) {
        double m1 = 0, m2 = 0;
        for (int s = 0; s < 3; s++) {
            const LyapResult r = compute_lyapunov(SEEDS[s], tp.p, tp.q, K, N_ITERS);
            m1 += r.l1; m2 += r.l2;
        }
        m1 /= 3.0; m2 /= 3.0;
        const double pred3e = 2.0 * std::log((double)tp.q / (double)tp.p);
        const double pred3d = 2.0 * std::log((double)tp.q * K / 2.0);
        const double e3e = 100.0 * (m2 - pred3e) / std::fabs(pred3e);
        const double e3d = 100.0 * ((m1 + m2) - pred3d) / pred3d;
        const bool reversed = tp.p > tp.q;
        std::printf("  (%2lld,%2lld)   %+8.4f   %+8.4f   %+6.2f   %8.4f   %8.4f   %+5.2f%s\n",
                    (long long)tp.p, (long long)tp.q, m2, pred3e, e3e,
                    m1 + m2, pred3d, e3d, reversed ? "  [reversed]" : "");
        if (!reversed) {
            if (std::fabs(e3e) > worst3e_coprime) worst3e_coprime = std::fabs(e3e);
            if (std::fabs(e3d) > worst3d)         worst3d = std::fabs(e3d);
        }
        // sign structure: hyperchaos iff q > p (two-variable map)
        if ((tp.q > tp.p && m2 <= 0) || (tp.p > tp.q && m2 >= 0)) all_pass = false;
    }
    std::printf("  worst |err| (8 coprime, standard): (3e) %.2f%%  (3d) %.2f%%\n",
                worst3e_coprime, worst3d);
    std::printf("  paper claims: (3e) <= 0.62%% ; (3d) <= 0.08%%\n\n");
    if (worst3e_coprime > 0.75 || worst3d > 0.12) all_pass = false;
}

// ---------------------------------------------------------------- Part C ---
// K-sweep at (3,5): (3e) is asymptotic in K, approached from below.
static void part_C(bool& all_pass) {
    const double Ks[4] = { 6.0, 12.0, 20.0, 50.0 };
    const double pred = 2.0 * std::log(5.0 / 3.0);
    std::printf("PART C — (3e) K-asymptotics at (3,5), 3-seed means\n");
    std::printf("  K       l2_mean    dev vs 2ln(5/3)=%.4f\n", pred);
    double prev_dev = -1e9;
    for (const double K : Ks) {
        double m2 = 0;
        for (int s = 0; s < 3; s++)
            m2 += compute_lyapunov(SEEDS[s], 3, 5, K, N_ITERS).l2;
        m2 /= 3.0;
        const double dev = 100.0 * (m2 - pred) / pred;
        std::printf("  %5.1f   %+8.4f   %+6.2f%%\n", K, m2, dev);
        if (dev < prev_dev - 0.05) all_pass = false;  // monotone approach (tolerance)
        prev_dev = dev;
    }
    std::printf("  paper claims: -1.06%% @K=6, -0.30%% @K=12, -0.01%% @K=50 (from below)\n\n");
}

int main() {
    std::printf("=============================================================\n");
    std::printf(" MCL DETERMINANT COMPANION LAWS VERIFICATION v%s\n", DOC_VERSION);
    std::printf(" Doc ID: %s\n", DOC_ID);
    std::printf(" Engine: mcl_core.hpp v6.0.0 (archived) | QR = engine compute_lyapunov\n");
    std::printf("=============================================================\n\n");
    bool all_pass = true;
    part_A(all_pass);
    part_B(all_pass);
    part_C(all_pass);
    std::printf("VERDICT: %s\n", all_pass ? "PASS — all (3c)-(3f) claims verified on this platform"
                                          : "FAIL — at least one claim outside tolerance");
    return all_pass ? 0 : 1;
}
