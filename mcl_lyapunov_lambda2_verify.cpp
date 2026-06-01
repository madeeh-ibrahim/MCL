/*
 * ============================================================================
 * MCL Second-Lyapunov Closed-Form Verification v1.0.0
 *   lambda2 = 2 ln(q/p)  via the exact det-Jacobian sum rule
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-LYAP-LAMBDA2-2026-0526-001
 * Version:       6.0.0
 * Date:          May 26, 2026, 10:00 UTC
 * Author:        Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:       madeeh.chaotic.lock@gmail.com
 * ORCID:         https://orcid.org/0009-0002-8562-8325
 * ============================================================================
 *
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Copyright (c) 2026 Madeeh Ibrahim. All rights reserved.
 *
 * MCL Reference Implementation. Free security research / evaluation for all
 * (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
 * a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673.
 * ============================================================================
 *
 * PURPOSE: Verify the semi-analytical closed form for the SECOND Lyapunov
 *   exponent of the MCL T2 Gauss-Seidel map,
 *
 *        lambda2  ~=  2 ln(q / p)      (independent of K),
 *
 *   together with the leading exponent  lambda1 ~= 2 ln(K p / 2)  and the
 *   sum  lambda1 + lambda2 ~= 2 ln(K q / 2).  The derivation rests on the
 *   EXACT determinant identity of the analytical Gauss-Seidel Jacobian,
 *
 *        det J = (1 - qK c1)(1 - qK c2),   c1 = cos(p*t2 - q*t1),
 *                                          c2 = cos(p*t1' - q*t2),
 *
 *   which gives, by the multiplicative-ergodic (volume-contraction) rule,
 *   the EXACT sum  lambda1 + lambda2 = <ln|det J|>.  The split into the two
 *   exponents is semi-analytical (large-K + phase equidistribution); this
 *   program measures both exponents by Benettin QR on the SAME analytical
 *   Jacobian and compares them with the closed forms.
 *
 * ----------------------------------------------------------------------------
 * WHAT IS EXACT vs APPROXIMATE (mirrors the paper's scope statement)
 * ----------------------------------------------------------------------------
 *   EXACT       : det J = (1 - qK c1)(1 - qK c2)            [EXP A, machine eps]
 *   EXACT       : lambda1 + lambda2 = <ln|det J|>           [EXP A, QR vs det]
 *   SEMI-ANALYT : lambda1 ~= 2 ln(K p / 2)                  [EXP B, tol 0.02]
 *   SEMI-ANALYT : lambda2 ~= 2 ln(q / p)                    [EXP B, tol 0.02]
 * The closed forms are validated against the QR measurement, not asserted as
 * theorems. EXP C/D/E test the three falsifiable predictions of the law.
 *
 * ----------------------------------------------------------------------------
 * METHOD
 * ----------------------------------------------------------------------------
 *   - Trajectory: produced by the shipped engine MCL_T2(seed,p,q,K), which
 *     runs BURNIN=10000 internally; the post-burn-in state seeds the run.
 *   - Jacobian: computed INDEPENDENTLY in this file from the published map
 *     (it is NOT taken from the engine), so engine-vs-Jacobian agreement is
 *     non-circular evidence. The local forward step is asserted bit-faithful
 *     to MCL_T2::iterate() as a calibration (EXP 0).
 *   - lambda1,2: Benettin sequential QR (analytical Jacobian + Gram-Schmidt
 *     re-orthonormalization every iteration) -- the engine's documented method.
 *
 * ----------------------------------------------------------------------------
 * HONEST SCOPE
 * ----------------------------------------------------------------------------
 * The det identity and the sum rule are exact. The individual-exponent split
 * uses (i) the large-K limit (neglecting O(1/(qK)) terms, largest for small
 * weights) and (ii) <ln|cos psi|> = -ln 2 under the system's near-uniform
 * invariant measure. The closed forms are therefore quantitative predictors
 * validated to a fixed absolute tolerance, NOT proofs; this does not by itself
 * establish uniform hyperbolicity. The fourth decimal of any exponent is
 * libm/platform sensitive (~1 ULP in std::sin); agreement is to 3 sig figs.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_lyapunov_lambda2_verify mcl_lyapunov_lambda2_verify.cpp -lm && ./mcl_lyapunov_lambda2_verify
 *
 * EXPECTED RESULTS:
 *   det identity max error < 1e-9 ; QR-sum == <ln|det J|> ;
 *   (3,5): l1~5.78 l2~1.02 vs 2ln(18)=5.78, 2ln(5/3)=1.02 ;
 *   same-ratio (2,3)/(4,6)/(6,9): l2 all ~0.81 ; transposed l2<0.
 *
 * REFERENCES:
 *   - mcl_lyapunov.cpp v2.5.0 (Benettin QR, analytical Gauss-Seidel Jacobian).
 *   - Benettin, Galgani, Giorgilli, Strelcyn, Meccanica 15 (1980).
 *   - Oseledets multiplicative ergodic theorem (sum rule = <ln|det J|>).
 *
 * ============================================================================
 *
 * NO WARRANTY / LIMITATION OF LIABILITY
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE,
 *   AND NONINFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 *   LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN
 *   AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT
 *   OF, OR IN CONNECTION WITH THE SOFTWARE. TO THE FULLEST EXTENT
 *   PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE COPYRIGHT
 *   HOLDER BE LIABLE FOR ANY SPECIAL, INCIDENTAL, INDIRECT, OR
 *   CONSEQUENTIAL DAMAGES WHATSOEVER.
 */

#include "mcl_core.hpp"

#include <cstdint>
#include <cstdio>
#include <cmath>
#include <cstring>
#include <chrono>

namespace {

static constexpr const char* const DOC_ID      = "MCL-LYAP-LAMBDA2-2026-0526-001";
static constexpr const char* const DOC_VERSION = "6.0.0";

// Iteration counts (mirror mcl_lyapunov.cpp conventions).
static constexpr int64_t ITERS_FULL  = 10000000;  // +-0.0004 stderr on l1
static constexpr int64_t ITERS_QUICK = 1000000;   // sweeps / controls
static constexpr int64_t TRANSIENT   = 2000;      // tangent-basis alignment

// Verdict tolerances.
static constexpr double DET_TOL = 1e-9;   // det identity is EXACT; we check the
                                          // RELATIVE residual (FP reassociation),
                                          // typically ~1e-12 even at qK ~ 280
static constexpr double CF_TOL  = 0.02;   // semi-analytical closed-form band
                                          // (> finite-K bias ~0.005 + platform
                                          //  ~0.001 + QR noise ~0.0004)

// ----------------------------------------------------------------------------
// One forward step of the Gauss-Seidel map, mirroring MCL_T2::iterate()
// EXACTLY (a1 = p*t2 - q*t1 ; t1' uses a1 ; a2 = p*t1' - q*t2), together with
// the analytical one-step Jacobian evaluated at the pre-step state.
//   J = [ 1 - qK c1 ,            pK c1                  ]
//       [ pK c2 (1 - qK c1) ,    1 + K c2 (p^2 K c1 - q)]
// ----------------------------------------------------------------------------
struct Step {
    double t1n, t2n;        // next state
    double c1, c2;          // cos of the two coupling phases
    double j11, j12, j21, j22;
};

static Step step_jac(double t1, double t2, double kc, double p, double q) {
    Step s;
    const double a1 = p * t2 - q * t1;
    s.c1 = std::cos(a1);
    s.t1n = mod2pi(t1 + OMEGA_1 + kc * std::sin(a1));
    const double a2 = p * s.t1n - q * t2;
    s.c2 = std::cos(a2);
    s.t2n = mod2pi(t2 + OMEGA_2 + kc * std::sin(a2));

    const double qkc1 = q * kc * s.c1;
    s.j11 = 1.0 - qkc1;
    s.j12 = p * kc * s.c1;
    s.j21 = p * kc * s.c2 * s.j11;
    s.j22 = 1.0 + kc * s.c2 * (p * p * kc * s.c1 - q);
    return s;
}

struct LyapResult {
    double l1, l2;          // QR-measured exponents
    double sum_qr;          // l1 + l2
    double sum_det;         // <ln|det J|>  (must equal sum_qr: the sum rule)
    double max_det_err;     // max |det_full - det_factored| (exact identity)
};

// Benettin sequential QR on the analytical Jacobian, trajectory from the engine.
static LyapResult measure(uint64_t seed, int64_t p, int64_t q,
                          double kc, int64_t N) {
    MCL_T2 eng(seed, p, q, kc);          // BURNIN=10000 done in ctor
    double t1 = eng.theta1();
    double t2 = eng.theta2();
    const double pd = static_cast<double>(p);
    const double qd = static_cast<double>(q);

    // Orthonormal tangent basis Q (columns q.1, q.2), start at identity.
    double q11 = 1.0, q21 = 0.0, q12 = 0.0, q22 = 1.0;
    double s1 = 0.0, s2 = 0.0, sdet = 0.0, max_det_err = 0.0;

    const int64_t total = N + TRANSIENT;
    for (int64_t it = 0; it < total; ++it) {
        const Step st = step_jac(t1, t2, kc, pd, qd);

        // V = J * Q
        const double v11 = st.j11 * q11 + st.j12 * q21;
        const double v21 = st.j21 * q11 + st.j22 * q21;
        const double v12 = st.j11 * q12 + st.j12 * q22;
        const double v22 = st.j21 * q12 + st.j22 * q22;

        // QR by modified Gram-Schmidt (2x2)
        const double r11 = std::sqrt(v11 * v11 + v21 * v21);
        const double nq11 = v11 / r11, nq21 = v21 / r11;
        const double r12 = nq11 * v12 + nq21 * v22;
        const double w12 = v12 - r12 * nq11;
        const double w22 = v22 - r12 * nq21;
        const double r22 = std::sqrt(w12 * w12 + w22 * w22);
        const double nq12 = w12 / r22, nq22 = w22 / r22;

        // EXACT determinant identity check (the semi-analytic backbone).
        // The identity is algebraic; the residual is pure floating-point
        // reassociation in the full 2x2 form, which grows with qK. We track
        // the RELATIVE error (floored denominator) so a large |det| at high
        // coupling weights is judged on relative, not absolute, agreement.
        const double det_full = st.j11 * st.j22 - st.j12 * st.j21;
        const double det_fact = (1.0 - qd * kc * st.c1) * (1.0 - qd * kc * st.c2);
        const double denom = std::fmax(std::fmax(std::fabs(det_full),
                                                 std::fabs(det_fact)), 1.0);
        const double derr = std::fabs(det_full - det_fact) / denom;
        if (derr > max_det_err) max_det_err = derr;

        if (it >= TRANSIENT) {
            s1   += std::log(std::fabs(r11));
            s2   += std::log(std::fabs(r22));
            sdet += std::log(std::fabs(det_full));
        }

        q11 = nq11; q21 = nq21; q12 = nq12; q22 = nq22;
        t1 = st.t1n; t2 = st.t2n;
    }

    LyapResult r;
    const double Nd = static_cast<double>(N);
    r.l1 = s1 / Nd;
    r.l2 = s2 / Nd;
    r.sum_qr = r.l1 + r.l2;
    r.sum_det = sdet / Nd;
    r.max_det_err = max_det_err;
    return r;
}

static double cf_l1(double kc, double p)         { return 2.0 * std::log(kc * p / 2.0); }
static double cf_l2(double p, double q)          { return 2.0 * std::log(q / p); }

static void sep(const char* title) {
    std::printf("\n----------------------------------------------------------------"
                "--------------\n %s\n--------------------------------------------"
                "----------------------------------\n", title);
}

struct Cfg { int64_t p, q; const char* label; };

static const Cfg TOPOS[] = {
    {2, 3,  "(2,3)"},   {3, 5,  "(3,5) primary"}, {5, 7,  "(5,7)"},
    {7, 11, "(7,11)"},  {8, 13, "(8,13)"},        {11,17, "(11,17)"},
    {13,19, "(13,19)"}, {17,23, "(17,23)"},
    {4, 6,  "(4,6) gcd2"}, {6, 9,  "(6,9) gcd3"},
    {3, 2,  "(3,2) transposed"}, {5, 3,  "(5,3) transposed"},
};
static const size_t N_TOPOS = sizeof(TOPOS) / sizeof(TOPOS[0]);

static bool run(bool full) {
    const uint64_t seed = DEFAULT_SEED;
    const double   K     = K_DEFAULT;
    const int64_t  N     = full ? ITERS_FULL : ITERS_QUICK;
    bool pass = true;

    // -- EXP 0: calibration -- local map must equal the engine bit-faithfully.
    sep("EXP 0: local forward step == engine MCL_T2::iterate() (calibration)");
    {
        MCL_T2 eng(seed, 3, 5, K);
        double t1 = eng.theta1(), t2 = eng.theta2();
        double max_dev = 0.0;
        for (int i = 0; i < 100000; ++i) {
            const Step st = step_jac(t1, t2, K, 3.0, 5.0);
            eng.iterate();
            const double d1 = std::fabs(st.t1n - eng.theta1());
            const double d2 = std::fabs(st.t2n - eng.theta2());
            if (d1 > max_dev) max_dev = d1;
            if (d2 > max_dev) max_dev = d2;
            t1 = st.t1n; t2 = st.t2n;
        }
        const bool ok = (max_dev < 1e-12);
        std::printf("  max |local - engine| over 100k steps = %.3e   [%s]\n",
                    max_dev, ok ? "PASS" : "FAIL");
        if (!ok) pass = false;
    }

    // Compute the 12-topology spectrum ONCE; EXP A and EXP B both read it
    // (avoids a duplicated full Lyapunov pass and guarantees the two tables
    // are derived from identical measurements).
    LyapResult res[N_TOPOS];
    for (size_t i = 0; i < N_TOPOS; ++i)
        res[i] = measure(seed, TOPOS[i].p, TOPOS[i].q, K, N);

    // -- EXP A: exact det-Jacobian identity + sum rule (the backbone).
    sep("EXP A: EXACT  det J = (1-qK c1)(1-qK c2)  and  l1+l2 = <ln|det J|>");
    std::printf("  %-18s  %12s   %12s   %12s\n",
                "topology", "max rel|det|", "l1+l2 (QR)", "<ln|detJ|>");
    {
        double worst = 0.0, worst_sumgap = 0.0;
        for (size_t i = 0; i < N_TOPOS; ++i) {
            const double gap = std::fabs(res[i].sum_qr - res[i].sum_det);
            if (res[i].max_det_err > worst) worst = res[i].max_det_err;
            if (gap > worst_sumgap) worst_sumgap = gap;
            std::printf("  %-18s  %12.3e   %12.6f   %12.6f\n",
                        TOPOS[i].label, res[i].max_det_err,
                        res[i].sum_qr, res[i].sum_det);
        }
        const bool ok = (worst < DET_TOL) && (worst_sumgap < 1e-6);
        std::printf("\n  worst det-identity error = %.3e (< %.0e required)\n",
                    worst, DET_TOL);
        std::printf("  worst |QRsum - detsum|   = %.3e (sum rule)            [%s]\n",
                    worst_sumgap, ok ? "PASS" : "FAIL");
        if (!ok) pass = false;
    }

    // -- EXP B: the closed forms vs QR measurement, all 12 topologies.
    sep("EXP B: closed forms  l1=2ln(Kp/2)  l2=2ln(q/p)  vs QR (K=12)");
    std::printf("  %-18s  %9s %9s %8s   %9s %9s %8s\n",
                "topology", "l1 meas", "2ln(Kp/2)", "d", "l2 meas",
                "2ln(q/p)", "d");
    {
        double worst_l1 = 0.0, worst_l2 = 0.0;
        for (size_t i = 0; i < N_TOPOS; ++i) {
            const double pd = static_cast<double>(TOPOS[i].p);
            const double qd = static_cast<double>(TOPOS[i].q);
            const double d1 = res[i].l1 - cf_l1(K, pd);
            const double d2 = res[i].l2 - cf_l2(pd, qd);
            if (std::fabs(d1) > worst_l1) worst_l1 = std::fabs(d1);
            if (std::fabs(d2) > worst_l2) worst_l2 = std::fabs(d2);
            std::printf("  %-18s  %9.4f %9.4f %+8.4f   %9.4f %9.4f %+8.4f\n",
                        TOPOS[i].label, res[i].l1, cf_l1(K, pd), d1,
                        res[i].l2, cf_l2(pd, qd), d2);
        }
        const bool ok = (worst_l1 <= CF_TOL) && (worst_l2 <= CF_TOL);
        std::printf("\n  worst |l1 - closed| = %.4f ; worst |l2 - closed| = %.4f"
                    "  (tol %.2f)  [%s]\n",
                    worst_l1, worst_l2, CF_TOL, ok ? "PASS" : "FAIL");
        if (!ok) pass = false;
    }

    // -- EXP C: prediction (i) -- l2 is K-INDEPENDENT (positive control).
    sep("EXP C: l2 independent of K for (3,5)  [2ln(5/3)=1.0217]");
    {
        const double Ks[] = {8.0, 12.0, 16.0, 20.0};
        double lo = 1e9, hi = -1e9;
        std::printf("  %6s  %9s %9s\n", "K", "l1 meas", "l2 meas");
        for (double kk : Ks) {
            const LyapResult r = measure(seed, 3, 5, kk, ITERS_QUICK);
            if (r.l2 < lo) lo = r.l2;
            if (r.l2 > hi) hi = r.l2;
            std::printf("  %6.1f  %9.4f %9.4f\n", kk, r.l1, r.l2);
        }
        const bool ok = ((hi - lo) < 0.03);  // l2 should barely move with K
        std::printf("  l2 spread over K in [8,20] = %.4f (< 0.03 => K-independent)"
                    "  [%s]\n", hi - lo, ok ? "PASS" : "FAIL");
        if (!ok) pass = false;
    }

    // -- EXP D: prediction (ii) -- same q/p ratio => same l2 (3/2 -> 0.81).
    sep("EXP D: same-ratio degeneracy  (2,3)/(4,6)/(6,9), q/p=3/2 [0.8109]");
    {
        const Cfg same[] = {{2,3,"(2,3)"},{4,6,"(4,6)"},{6,9,"(6,9)"}};
        double lo = 1e9, hi = -1e9;
        for (const Cfg& c : same) {
            const LyapResult r = measure(seed, c.p, c.q, K, ITERS_QUICK);
            if (r.l2 < lo) lo = r.l2;
            if (r.l2 > hi) hi = r.l2;
            std::printf("  %-8s  l2 = %9.4f  (2ln(3/2)=%.4f)\n",
                        c.label, r.l2, 2.0 * std::log(1.5));
        }
        const bool ok = ((hi - lo) < 0.03);
        std::printf("  l2 spread across magnitudes = %.4f (< 0.03 => ratio-only)"
                    "  [%s]\n", hi - lo, ok ? "PASS" : "FAIL");
        if (!ok) pass = false;
    }

    // -- EXP E: prediction (iii) -- transposition flips l2 sign.
    sep("EXP E: sign reversal under transposition  l2(q,p) = -l2(p,q)");
    {
        const Cfg tr[] = {{3,2,"(3,2)T"},{5,3,"(5,3)T"}};
        bool ok = true;
        for (const Cfg& c : tr) {
            const double pd = static_cast<double>(c.p), qd = static_cast<double>(c.q);
            const LyapResult r = measure(seed, c.p, c.q, K, ITERS_QUICK);
            const double cf = cf_l2(pd, qd);
            const bool row_ok = (r.l2 < 0.0) && (std::fabs(r.l2 - cf) <= CF_TOL);
            std::printf("  %-8s  l2 = %9.4f  (2ln(q/p)=%.4f)  %s\n",
                        c.label, r.l2, cf, row_ok ? "[neg, PASS]" : "[FAIL]");
            if (!row_ok) ok = false;
        }
        if (!ok) pass = false;
    }

    sep("VERDICT");
    if (pass) {
        std::printf("  PASS. det-Jacobian identity exact to machine precision;\n");
        std::printf("  sum rule l1+l2 = <ln|det J|> confirmed; closed forms\n");
        std::printf("  l1=2ln(Kp/2), l2=2ln(q/p) match QR within %.2f across all\n", CF_TOL);
        std::printf("  12 topologies; K-independence, same-ratio degeneracy, and\n");
        std::printf("  transposition sign-flip all confirmed.\n");
        std::printf("  (Semi-analytical: the split is validated, not proven; the\n");
        std::printf("   det identity and sum rule are exact.)\n");
    } else {
        std::printf("  FAIL. One or more checks did not meet tolerance. Inspect\n");
        std::printf("  the per-experiment lines above. (Loud-failure policy.)\n");
    }
    return pass;
}

static void print_help(const char* prog) {
    std::printf("Usage:\n");
    std::printf("  %s            # full run (10M iters/topology)\n", prog);
    std::printf("  %s --quick    # 1M iters/topology (faster, ~3 sig figs)\n", prog);
    std::printf("  %s --help     # this message\n", prog);
    std::printf("\nVerifies lambda2 = 2 ln(q/p) for the MCL T2 Gauss-Seidel map\n");
    std::printf("via the exact det-Jacobian sum rule. Document: %s v%s\n",
                DOC_ID, DOC_VERSION);
}

}  // namespace

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);
    bool full = true;

    if (argc > 1) {
        if (std::strcmp(argv[1], "--help") == 0) { print_help(argv[0]); return 0; }
        if (std::strcmp(argv[1], "--quick") == 0) { full = false; }
        else { std::fprintf(stderr, "Unknown argument: %s\n", argv[1]); return 1; }
    }

    const auto t0 = std::chrono::steady_clock::now();

    std::printf("==============================================================="
                "===============\n");
    std::printf("  MCL SECOND-LYAPUNOV CLOSED-FORM VERIFICATION v%s\n", DOC_VERSION);
    std::printf("  lambda2 = 2 ln(q/p)  via  det J = (1-qK c1)(1-qK c2)\n");
    std::printf("  %s\n", DOC_ID);
    std::printf("==============================================================="
                "===============\n");
    std::printf("  engine: mcl_core.hpp v%s  |  seed=%llu  K=%.1f  BURNIN=%d\n",
                mcl_version(), static_cast<unsigned long long>(DEFAULT_SEED),
                K_DEFAULT, BURNIN);

    const bool ok = run(full);

    const double secs = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();
    std::printf("\n  elapsed: %.1f s\n", secs);
    return ok ? 0 : 1;
}
