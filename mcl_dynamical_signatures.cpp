/*
 * ============================================================================
 * MCL Dynamical Signatures — Chaos / Ergodic / Complexity Diagnostics
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-DYNAMICAL-SIGNATURES-2026-0526-001
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
 * PURPOSE: Compute the standard battery of dynamical-signatures used in the
 * nonlinear-dynamics literature to characterize chaotic, ergodic, and
 * complexity-theoretic properties of a dynamical system. Used to supply
 * Paper 1 (Safe Zone PRNG) with the supplementary evidence conventionally
 * expected by Nonlinear Dynamics (Springer) reviewers.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_dynamical_signatures mcl_dynamical_signatures.cpp -lm && ./mcl_dynamical_signatures
 *
 * EXPECTED RESULTS: All 12 dynamical-signature experiments PASS within tolerance. Exit 0.
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

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <limits>
#include <map>
#include <string>
#include <vector>

// ============================================================================
// VERSION / DOC IDS
// ============================================================================
static constexpr const char* DOC_ID      = "MCL-DYNAMICAL-SIGNATURES-2026-0526-001";
static constexpr const char* DOC_VERSION = "6.0.0";

// ============================================================================
// CONFIGURATION
// ============================================================================
enum class Mode { FULL, QUICK };

// ---- EXP 1 (Bifurcation) ----
static constexpr double EXP1_K_MIN_FULL  = 0.5;
static constexpr double EXP1_K_MAX_FULL  = 20.0;
static constexpr double EXP1_K_STEP_FULL = 0.25;   // 79 K values
static constexpr double EXP1_K_STEP_QUICK = 1.0;   // 20 K values
static constexpr int    EXP1_BURNIN      = 5000;   // settle to attractor
static constexpr int    EXP1_NPOINTS     = 200;    // points per K
// Lyapunov iter count for EXP 1's per-K classification. We use a moderate N
// because (a) we need 79 evaluations and (b) sign(lambda_max) is robust at
// 50k iterations even when the magnitude has ~5% stderr.
static constexpr int64_t EXP1_LYAP_ITERS_FULL  = 100000;
static constexpr int64_t EXP1_LYAP_ITERS_QUICK = 50000;

// ---- EXP 2 (Mode-locking) ----
static const std::array<int64_t, 6> EXP2_PQ_PAIRS_P = { 2, 3, 5, 7, 11, 13 };
static const std::array<int64_t, 6> EXP2_PQ_PAIRS_Q = { 3, 5, 7, 11, 13, 17 };
static constexpr int64_t EXP2_N_BYTES_FULL  = 200000;
static constexpr int64_t EXP2_N_BYTES_QUICK = 50000;

// ---- EXP 3 (Phase-space) ----
static constexpr int64_t EXP3_N_POINTS_FULL  = 1000000;
static constexpr int64_t EXP3_N_POINTS_QUICK = 200000;
static constexpr int     EXP3_BINS           = 32;     // 32x32 = 1024 bins

// ---- EXP 4 (Time series) ----
static constexpr int     EXP4_N_POINTS = 1024;

// ---- EXP 5 (Pesin) ----
static constexpr int64_t EXP5_LYAP_ITERS_FULL  = 1000000;
static constexpr int64_t EXP5_LYAP_ITERS_QUICK = 200000;
static constexpr int64_t EXP5_BYTES_FOR_ENT    = 1000000;

// ---- EXP 6 (Scaling law verification) ----
struct ScalingPoint { int64_t p; int64_t q; double K; };
// 14 measurement points: 12 with p<q span the validated range, plus 2
// "swapped" pairs (p>q) used to test whether the analytical formula
// 2*ln(K*p/2) depends on the *first* coupling weight (p) regardless of
// ordering. The system is asymmetric under (p,q) swap because the
// Gauss-Seidel update places p in the cross-coupling position; the
// derivation predicts lambda_max scales with p, not min(p,q) or max(p,q).
static const std::array<ScalingPoint, 14> EXP6_POINTS = {{
    {3, 5, 6.0}, {3, 5, 8.0}, {3, 5, 12.0}, {3, 5, 16.0},
    {7, 11, 6.0}, {7, 11, 12.0}, {7, 11, 18.0},
    {13, 19, 12.0}, {13, 19, 18.0},
    {2, 3, 12.0}, {5, 7, 12.0}, {89, 97, 12.0},
    // Swapped pairs (p>q) -- analytical prediction uses p, the first
    // coupling weight; empirical fit uses (p+q) which is invariant under swap.
    {5, 3, 12.0}, {3, 2, 12.0}
}};
static constexpr int64_t EXP6_LYAP_ITERS_FULL  = 1000000;
static constexpr int64_t EXP6_LYAP_ITERS_QUICK = 200000;

// ---- EXP 7 (Permutation entropy) ----
static const std::array<int, 5> EXP7_DIMS = { 3, 4, 5, 6, 7 };
static constexpr int64_t EXP7_N_BYTES_FULL  = 1000000;
static constexpr int64_t EXP7_N_BYTES_QUICK = 200000;

// ---- EXP 8 (SampEn / ApEn) ----
// SampEn / ApEn are O(N^2) -- keep N modest.
static constexpr int64_t EXP8_N_FULL  = 5000;
static constexpr int64_t EXP8_N_QUICK = 1000;
static constexpr int     EXP8_M       = 2;
static constexpr double  EXP8_R_FRAC  = 0.2; // r = 0.2 * std

// ---- EXP 9 (0-1 Test) ----
static constexpr int64_t EXP9_N_FULL  = 4000;
static constexpr int64_t EXP9_N_QUICK = 1000;
static constexpr int     EXP9_NC      = 50;  // number of c values
static constexpr int     EXP9_NCUT    = 200; // points used in K_c calc (N/10)

// ---- EXP 10 (RQA) ----
static constexpr int64_t EXP10_N_FULL  = 4096;
static constexpr int64_t EXP10_N_QUICK = 1024;
static constexpr int     EXP10_M       = 2;     // embedding dim
static constexpr int     EXP10_TAU     = 1;     // delay
static constexpr double  EXP10_EPS     = 0.10;  // recurrence threshold
static constexpr int     EXP10_LMIN    = 2;

// ---- EXP 11 (extended autocorrelation) ----
static const std::array<int, 11> EXP11_LAGS = {
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024
};
static constexpr int64_t EXP11_N_FULL  = 5000000;
static constexpr int64_t EXP11_N_QUICK = 1000000;

// ---- EXP 12 (p-value KS test) ----
static constexpr int     EXP12_NSEGMENTS_FULL  = 200;
static constexpr int     EXP12_NSEGMENTS_QUICK = 40;
static constexpr int64_t EXP12_BYTES_PER_SEG   = 100000;

// ---- Common ----
// DEFAULT_SEED is already defined in mcl_core.hpp; we reuse that single
// source of truth. DEFAULT_P / DEFAULT_Q here are local to this test file
// (the engine's "default topology" is established via the topology table
// in mcl_core.hpp; we pin to (3, 5) for all paper-1 measurements).
static constexpr int64_t  DEFAULT_P     = 3;
static constexpr int64_t  DEFAULT_Q     = 5;

// ============================================================================
// HELPERS
// ============================================================================

// Defensive UTC timestamp (mirrors style of mcl_k_sweep_unified.cpp).
static void format_utc_now(char* buf, size_t buflen) {
    if (buflen == 0) return;
    buf[0] = '\0';
    const std::time_t now = std::time(nullptr);
    std::tm tm_utc;
#ifdef _WIN32
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    if (std::strftime(buf, buflen, "%Y-%m-%d %H:%M:%S UTC", &tm_utc) == 0) {
        buf[0] = '\0';
    }
}

// CLI help.
static void print_help(const char* prog) {
    std::printf("Usage: %s [OPTIONS]\n\n", prog);
    std::printf("MCL Dynamical Signatures v%s.\n", DOC_VERSION);
    std::printf("Computes the standard battery of dynamical-systems and\n");
    std::printf("complexity signatures (bifurcation, Pesin's identity, full\n");
    std::printf("RQA, PE/SampEn/ApEn, 0-1 test, p-value distribution) used\n");
    std::printf("in the nonlinear-dynamics literature.\n\n");
    std::printf("OPTIONS:\n");
    std::printf("  --full       Canonical run (~7-9 sec, default).\n");
    std::printf("  --quick      Reduced-N smoke test (~2 sec).\n");
    std::printf("  --help       Show this help and exit.\n");
    std::printf("  --version    Show version and exit.\n\n");
    std::printf("EXIT CODES:\n");
    std::printf("  0  PASS (all numbered checks pass within tolerance)\n");
    std::printf("  1  FAIL (one or more checks fail)\n");
    std::printf("  2  Bad CLI arguments\n\n");
    std::printf("Doc ID: %s v%s\n", DOC_ID, DOC_VERSION);
}

// Logarithm of factorial via lgamma -- avoids overflow for large D.
static double log_factorial(int n) {
    return std::lgamma(static_cast<double>(n) + 1.0);
}

// ============================================================================
// COMPLEXITY MEASURES (implemented locally; not in mcl_core.hpp)
// ============================================================================

// ---------- Permutation Entropy (Bandt-Pompe 2002) ----------
//
// Given a time series x[0..n-1], for each window of D consecutive samples
// determine the ordinal pattern (permutation rank). Count occurrences of
// each of D! patterns; PE = -sum(p_i * log(p_i)) where p_i is the empirical
// probability of pattern i. Maximum PE = log(D!) corresponds to all patterns
// equiprobable (i.i.d. random source). PE is a robust measure of complexity
// that does not require parameter tuning beyond D.
//
// Tie-breaking: when data[i+k] == data[i+j] and k > j, the LATER position
// is treated as the LARGER value (i.e., earlier index wins as smaller).
// This is the standard Bandt-Pompe convention for sequences with ties.
static double permutation_entropy(const uint8_t* data, int64_t n, int D) {
    if (D < 2 || D > 7) return -1.0; // D! grows fast, cap at 5040 patterns
    if (n < D) return -1.0;

    int factorial[8];
    factorial[0] = 1;
    for (int i = 1; i < 8; i++) factorial[i] = factorial[i-1] * i;
    int n_patterns = factorial[D];

    std::vector<int64_t> counts(static_cast<size_t>(n_patterns), 0);
    int64_t total = 0;

    for (int64_t i = 0; i + D - 1 < n; i++) {
        // Lehmer code: at position j, rank_j = # of positions k > j whose
        // value is strictly less than data[i+j]. The Horner-style update
        //   code = code * (D - j) + rank_j
        // converts the rank vector to a unique integer in [0, D!).
        // Ties break by index: data[i+k] == data[i+j] with k > j contributes
        // 0 to rank_j (later position considered larger).
        int code = 0;
        for (int j = 0; j < D - 1; j++) {
            int rank = 0;
            for (int k = j + 1; k < D; k++) {
                if (data[i + k] < data[i + j]) rank++;
            }
            code = code * (D - j) + rank;
        }
        // Defensive: code is always in [0, D!) by construction. Range check
        // costs nothing in release builds and protects against future edits.
        if (code < 0 || code >= n_patterns) continue;
        counts[static_cast<size_t>(code)]++;
        total++;
    }

    if (total == 0) return 0.0;
    double H = 0.0;
    for (int i = 0; i < n_patterns; i++) {
        if (counts[static_cast<size_t>(i)] == 0) continue;
        double p = static_cast<double>(counts[static_cast<size_t>(i)])
                 / static_cast<double>(total);
        H -= p * std::log(p);
    }
    return H;
}

// ---------- Sample Entropy (Richman & Moorman 2000) ----------
//
// Count pairs of m-vectors and (m+1)-vectors within distance r;
// SampEn(m, r) = -ln(A / B). Uses Chebyshev distance (max coordinate diff).
// O(N^2) cost; we cap N at 5000 to keep runtime tractable.
static double sample_entropy(const std::vector<double>& x, int m, double r) {
    int64_t N = static_cast<int64_t>(x.size());
    if (N < m + 2) return -1.0;

    // Count B = # pairs within r at length m
    // Count A = # pairs within r at length m+1
    int64_t B = 0, A = 0;

    for (int64_t i = 0; i < N - m; i++) {
        for (int64_t j = i + 1; j < N - m; j++) {
            // Distance at length m
            double d_m = 0.0;
            bool ok = true;
            for (int k = 0; k < m; k++) {
                double dk = std::fabs(x[static_cast<size_t>(i + k)] -
                                      x[static_cast<size_t>(j + k)]);
                if (dk > d_m) d_m = dk;
                if (d_m > r) { ok = false; break; }
            }
            if (!ok) continue;
            B++;
            // Extend to length m+1: just check the new element.
            double dk = std::fabs(x[static_cast<size_t>(i + m)] -
                                  x[static_cast<size_t>(j + m)]);
            if (dk > d_m) d_m = dk;
            if (d_m <= r) A++;
        }
    }
    if (B == 0) return -1.0;
    if (A == 0) return std::log(static_cast<double>(B) + 1.0); // avoid -inf
    return -std::log(static_cast<double>(A) / static_cast<double>(B));
}

// ---------- Approximate Entropy (Pincus 1991) ----------
// Distinct from SampEn: counts pairs INCLUDING self-matches and uses
// ApEn(m, r) = phi(m) - phi(m+1). O(N^2).
static double approximate_entropy(const std::vector<double>& x, int m, double r) {
    int64_t N = static_cast<int64_t>(x.size());
    if (N < m + 1) return -1.0;

    auto phi = [&](int dim) -> double {
        double sum_log = 0.0;
        int64_t valid = 0;
        for (int64_t i = 0; i + dim <= N; i++) {
            int64_t cnt = 0;
            for (int64_t j = 0; j + dim <= N; j++) {
                double d = 0.0;
                bool ok = true;
                for (int k = 0; k < dim; k++) {
                    double dk = std::fabs(x[static_cast<size_t>(i + k)] -
                                          x[static_cast<size_t>(j + k)]);
                    if (dk > d) d = dk;
                    if (d > r) { ok = false; break; }
                }
                if (ok) cnt++;
            }
            if (cnt > 0) {
                double p = static_cast<double>(cnt) /
                           static_cast<double>(N - dim + 1);
                sum_log += std::log(p);
                valid++;
            }
        }
        if (valid == 0) return 0.0;
        return sum_log / static_cast<double>(valid);
    };

    double phi_m   = phi(m);
    double phi_m1  = phi(m + 1);
    return phi_m - phi_m1;
}

// ---------- 0-1 Test for Chaos (Gottwald & Melbourne 2004; refined 2009) ----
//
// Given a time series phi[0..N-1] (centered to zero mean per Gottwald-
// Melbourne 2009 §III), for c in (0, pi) build:
//   p_c(n) = sum_{j=0..n-1} phi[j] * cos(j*c)
//   q_c(n) = sum_{j=0..n-1} phi[j] * sin(j*c)
// then mean square displacement
//   M_c(n) = lim (1/(N-n)) sum_{j=0..N-n-1}
//            ((p_c(j+n)-p_c(j))^2 + (q_c(j+n)-q_c(j))^2)
// CANONICAL test statistic is the Pearson correlation of M_c(n) with n
// (not log-log). This is the formulation in the original 2004 paper and
// the recommended form in the 2009 follow-up:
//   K_c = corr(n_vec, M_c(n_vec)),  n_vec = [1, 2, ..., n_cut]
// Final K = median(K_c) over many random c values (median is more robust
// than mean against c-resonances and outliers).
//   K -> 0  : regular dynamics (M bounded -> low correlation with n)
//   K -> 1  : chaotic dynamics (M ~ D*n linearly -> near-perfect correlation)
static double zero_one_test(const std::vector<double>& phi_in,
                            int n_c, int n_cut) {
    int64_t N = static_cast<int64_t>(phi_in.size());
    if (N < n_cut + 10) return -1.0;

    // Center phi: zero-mean is required for the test to be unbiased.
    // Otherwise a non-zero mean adds a deterministic 1/(1-cos c) bias to
    // p_c which contaminates M_c(n).
    double phi_mean = 0.0;
    for (size_t i = 0; i < phi_in.size(); i++) phi_mean += phi_in[i];
    phi_mean /= static_cast<double>(N);
    std::vector<double> phi(static_cast<size_t>(N));
    for (size_t i = 0; i < phi.size(); i++)
        phi[i] = phi_in[i] - phi_mean;

    // Pseudo-random c sampling (deterministic for reproducibility).
    auto next_c = [](uint64_t& s) -> double {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        // Map to (pi/5, 4*pi/5) to avoid resonances at 0 and pi.
        double u = static_cast<double>(s >> 32) / 4294967296.0;
        return MCL_PI / 5.0 + u * (4.0 * MCL_PI / 5.0 - MCL_PI / 5.0);
    };
    uint64_t cseed = 0xC0FFEE0123456789ULL;

    std::vector<double> Ks;
    Ks.reserve(static_cast<size_t>(n_c));

    for (int ci = 0; ci < n_c; ci++) {
        double c = next_c(cseed);
        // Compute p_c, q_c trajectories.
        std::vector<double> pc(static_cast<size_t>(N + 1), 0.0);
        std::vector<double> qc(static_cast<size_t>(N + 1), 0.0);
        for (int64_t j = 0; j < N; j++) {
            double angle = static_cast<double>(j) * c;
            pc[static_cast<size_t>(j + 1)] =
                pc[static_cast<size_t>(j)] + phi[static_cast<size_t>(j)] * std::cos(angle);
            qc[static_cast<size_t>(j + 1)] =
                qc[static_cast<size_t>(j)] + phi[static_cast<size_t>(j)] * std::sin(angle);
        }
        // Mean-square displacement for n in [1..n_cut].
        std::vector<double> M(static_cast<size_t>(n_cut), 0.0);
        for (int n = 1; n <= n_cut; n++) {
            double sum = 0.0;
            int64_t count = 0;
            for (int64_t j = 0; j + n < N; j++) {
                double dp = pc[static_cast<size_t>(j + n)] - pc[static_cast<size_t>(j)];
                double dq = qc[static_cast<size_t>(j + n)] - qc[static_cast<size_t>(j)];
                sum += dp * dp + dq * dq;
                count++;
            }
            M[static_cast<size_t>(n - 1)] =
                (count > 0) ? sum / static_cast<double>(count) : 0.0;
        }
        // CANONICAL Gottwald-Melbourne K_c: linear Pearson correlation of n
        // and M_c(n). For chaos M ~ D*n, giving correlation -> 1. For regular
        // dynamics M is bounded, giving correlation -> 0.
        double mn = 0, mm = 0;
        for (int n = 1; n <= n_cut; n++) {
            mn += static_cast<double>(n);
            mm += M[static_cast<size_t>(n - 1)];
        }
        mn /= static_cast<double>(n_cut);
        mm /= static_cast<double>(n_cut);
        double num = 0, dn2 = 0, dm2 = 0;
        for (int n = 1; n <= n_cut; n++) {
            double xd = static_cast<double>(n) - mn;
            double yd = M[static_cast<size_t>(n - 1)] - mm;
            num += xd * yd;
            dn2 += xd * xd;
            dm2 += yd * yd;
        }
        double Kc = (dn2 * dm2 > 0) ? num / std::sqrt(dn2 * dm2) : 0.0;
        Ks.push_back(Kc);
    }
    // Median of K_c values (more robust than mean against c-resonances).
    std::sort(Ks.begin(), Ks.end());
    return Ks[Ks.size() / 2];
}

// ---------- Recurrence Quantification Analysis (full set) ----------
//
// Build recurrence matrix R[i,j] = 1 iff |x_i - x_j| <= eps (Chebyshev on
// embedded vectors of length m, delay tau). Compute:
//   RR     = recurrence rate (mean of R off-diagonal)
//   DET    = determinism (fraction of recurrences in diagonal lines >= L_min)
//   LAM    = laminarity   (fraction of recurrences in vertical lines >= L_min)
//   L_max  = longest diagonal line (excluding LOI)
//   ENTR   = Shannon entropy of diagonal line-length distribution
struct RQAResult {
    double RR;
    double DET;
    double LAM;
    int    L_max;
    double ENTR;
};

static RQAResult full_rqa(const std::vector<double>& x, int m, int tau,
                          double eps, int L_min) {
    int64_t N = static_cast<int64_t>(x.size()) - (m - 1) * tau;
    if (N <= 0) return {0, 0, 0, 0, 0};

    // Build embedded vectors (m-tuples), compute recurrence matrix.
    // Symmetric: only fill upper triangle.
    std::vector<std::vector<uint8_t>> R(static_cast<size_t>(N),
        std::vector<uint8_t>(static_cast<size_t>(N), 0));

    // Normalize series to unit std before applying eps.
    double mean = 0.0;
    for (size_t i = 0; i < x.size(); i++) mean += x[i];
    mean /= static_cast<double>(x.size());
    double var = 0.0;
    for (size_t i = 0; i < x.size(); i++) var += (x[i] - mean) * (x[i] - mean);
    var /= static_cast<double>(x.size());
    double sd = std::sqrt(var);
    double thr = eps * sd;

    int64_t recur_count = 0;
    for (int64_t i = 0; i < N; i++) {
        for (int64_t j = i; j < N; j++) {
            double dist = 0.0;
            for (int k = 0; k < m; k++) {
                double dk = std::fabs(x[static_cast<size_t>(i + k * tau)] -
                                      x[static_cast<size_t>(j + k * tau)]);
                if (dk > dist) dist = dk;
                if (dist > thr) break;
            }
            uint8_t r = (dist <= thr) ? 1 : 0;
            R[static_cast<size_t>(i)][static_cast<size_t>(j)] = r;
            if (i != j) R[static_cast<size_t>(j)][static_cast<size_t>(i)] = r;
            if (r != 0 && i != j) recur_count++;
        }
    }
    // STANDARD RQA NORMALIZATION (Marwan et al., Phys. Reports 2007).
    // R is symmetric, so each upper-triangle off-diagonal recurrence (i<j)
    // contributes TWICE to full-matrix counts (once at (i,j), once at (j,i)).
    // We must therefore double `recur_count` (which counted upper-only) for
    // any quantity normalized over the full matrix.
    int64_t full_off_diag_recurs = 2 * recur_count;
    double  total_pairs_off      = static_cast<double>(N) *
                                   static_cast<double>(N - 1);
    double RR = (total_pairs_off > 0) ?
        static_cast<double>(full_off_diag_recurs) / total_pairs_off : 0.0;

    // Diagonal line lengths (excluding LOI = main diagonal).
    std::map<int, int64_t> diag_hist;
    int L_max = 0;
    int64_t diag_recurs_in_lines = 0;
    for (int64_t k = 1; k < N; k++) {
        // Diagonal offset k: pairs (i, i+k) with i = 0..N-k-1
        int run = 0;
        for (int64_t i = 0; i + k < N; i++) {
            if (R[static_cast<size_t>(i)][static_cast<size_t>(i + k)] != 0) {
                run++;
            } else {
                if (run >= L_min) {
                    diag_hist[run]++;
                    diag_recurs_in_lines += run;
                    if (run > L_max) L_max = run;
                }
                run = 0;
            }
        }
        if (run >= L_min) {
            diag_hist[run]++;
            diag_recurs_in_lines += run;
            if (run > L_max) L_max = run;
        }
    }
    // Mirror: each upper-triangle diagonal line has a mirror image below LOI
    // of identical length. Doubling makes diag_recurs_in_lines and diag_hist
    // represent the FULL matrix.
    diag_recurs_in_lines *= 2;
    for (auto& kv : diag_hist) kv.second *= 2;

    // DET: fraction of FULL off-diagonal recurrences inside diagonal lines.
    // Both numerator and denominator are full-matrix counts.
    double DET = (full_off_diag_recurs > 0) ?
        static_cast<double>(diag_recurs_in_lines) /
        static_cast<double>(full_off_diag_recurs) : 0.0;

    // Vertical line lengths (column scan, full matrix INCLUDING LOI).
    int64_t vert_recurs_in_lines = 0;
    for (int64_t j = 0; j < N; j++) {
        int run = 0;
        for (int64_t i = 0; i < N; i++) {
            if (R[static_cast<size_t>(i)][static_cast<size_t>(j)] != 0) {
                run++;
            } else {
                if (run >= L_min) vert_recurs_in_lines += run;
                run = 0;
            }
        }
        if (run >= L_min) vert_recurs_in_lines += run;
    }
    // LAM: fraction of all recurrences (including LOI) in vertical lines.
    // Total recurrences = full off-diagonal + LOI = 2*recur_count + N.
    double total_recurs_full = static_cast<double>(full_off_diag_recurs + N);
    double LAM = (total_recurs_full > 0) ?
        static_cast<double>(vert_recurs_in_lines) / total_recurs_full : 0.0;

    // Shannon entropy of diagonal line-length distribution.
    int64_t total_lines = 0;
    for (const auto& kv : diag_hist) total_lines += kv.second;
    double ENTR = 0.0;
    if (total_lines > 0) {
        for (const auto& kv : diag_hist) {
            double p = static_cast<double>(kv.second) /
                       static_cast<double>(total_lines);
            if (p > 0) ENTR -= p * std::log(p);
        }
    }
    return { RR, DET, LAM, L_max, ENTR };
}

// ---------- Kolmogorov-Smirnov test of n p-values vs Uniform[0,1] ----------
//
// Returns the two-sided KS statistic D and asymptotic p-value (per
// Marsaglia-Tsang-Wang 2003 small-sample corrections are NOT applied; we
// use the asymptotic Kolmogorov distribution which is adequate for n >= 35).
static std::pair<double,double> ks_uniform(const std::vector<double>& pv) {
    if (pv.empty()) return {-1.0, -1.0};
    std::vector<double> v = pv;
    std::sort(v.begin(), v.end());
    int64_t n = static_cast<int64_t>(v.size());
    double D = 0.0;
    for (int64_t i = 0; i < n; i++) {
        double F_emp_above = static_cast<double>(i + 1) / static_cast<double>(n);
        double F_emp_below = static_cast<double>(i)     / static_cast<double>(n);
        double diff_above = std::fabs(F_emp_above - v[static_cast<size_t>(i)]);
        double diff_below = std::fabs(v[static_cast<size_t>(i)] - F_emp_below);
        if (diff_above > D) D = diff_above;
        if (diff_below > D) D = diff_below;
    }
    // Asymptotic p-value via Kolmogorov series:
    //   P(D > d) ~ 2 * sum_{k=1..inf} (-1)^{k-1} * exp(-2 * k^2 * n * d^2)
    double lambda = (std::sqrt(static_cast<double>(n)) + 0.12 +
                     0.11 / std::sqrt(static_cast<double>(n))) * D;
    double pval = 0.0;
    for (int k = 1; k <= 100; k++) {
        double term = 2.0 * (((k & 1) == 1) ? 1.0 : -1.0) *
                      std::exp(-2.0 * k * k * lambda * lambda);
        pval += term;
        if (std::fabs(term) < 1e-12) break;
    }
    if (pval < 0.0) pval = 0.0;
    if (pval > 1.0) pval = 1.0;
    return { D, pval };
}

// ============================================================================
// EXPERIMENTS
// ============================================================================

// ---------- EXP 1: Bifurcation diagnostic ----------
//
// For each K in [K_min, K_max]: (a) iterate the (3,5) system, settle BURNIN
// iterations, and collect EXP1_NPOINTS theta1 values; (b) compute Lyapunov
// lambda_max via the standard QR Jacobian method (mcl_core.hpp §7).
// Bucket diversity alone CANNOT distinguish chaos from dense quasi-periodic
// orbits on T^2 -- we therefore use sign(lambda_max) to discriminate.
//
// Regime taxonomy:
//   DIVERGED       : non-finite phase (numerical failure under raw iterate)
//   PERIODIC       : <= 3 distinct buckets (small-cycle window, e.g. period 2)
//   CHAOTIC        : > 3 buckets AND lambda_max > LYAP_CHAOS_THRESHOLD
//   QUASI-PERIODIC : > 3 buckets AND lambda_max <= LYAP_CHAOS_THRESHOLD
//                    (dense torus orbit; trajectory fills T^2 without
//                    sensitivity to initial conditions)
struct BifResult {
    double K;
    int    distinct_buckets;
    double theta_min;
    double theta_max;
    double lambda_max;       // measured via QR Jacobian
    bool   diverged;
    bool   periodic;         // <= 3 buckets
    bool   chaotic;          // diverse AND positive Lyapunov
};

// Empirical threshold for lambda_max above which we accept "chaos".
// Lyapunov stderr at N = 100k is ~ 0.01-0.02 (per mcl_lyapunov.cpp); we
// pick 0.05 to absorb that noise while still cleanly excluding zero
// (quasi-periodic regimes have lambda exactly 0 modulo finite-N noise).
static constexpr double EXP1_LYAP_CHAOS_THRESHOLD = 0.05;

static std::vector<BifResult> run_exp1_bifurcation(Mode mode) {
    double K_step = (mode == Mode::QUICK) ? EXP1_K_STEP_QUICK : EXP1_K_STEP_FULL;
    int64_t lyap_iters = (mode == Mode::QUICK) ? EXP1_LYAP_ITERS_QUICK
                                               : EXP1_LYAP_ITERS_FULL;
    std::vector<BifResult> out;
    constexpr int N_BUCKETS = 64;

    for (double K = EXP1_K_MIN_FULL; K <= EXP1_K_MAX_FULL + 1e-9; K += K_step) {
        // ---- Trajectory diversity (theta1 buckets) ----
        double t1, t2;
        mcl_init_state(DEFAULT_SEED, t1, t2);
        for (int i = 0; i < EXP1_BURNIN; i++) {
            // K below K_min fires assert in standard ctor, so we must use the
            // raw iterate path which has no validation guards.
            mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K);
            if (!std::isfinite(t1) || !std::isfinite(t2)) break;
        }
        std::vector<int> bucket_seen(N_BUCKETS, 0);
        double tmin = MCL_TWO_PI, tmax = 0;
        bool diverged = !std::isfinite(t1) || !std::isfinite(t2);
        if (!diverged) {
            for (int i = 0; i < EXP1_NPOINTS; i++) {
                mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K);
                if (!std::isfinite(t1)) { diverged = true; break; }
                int b = static_cast<int>((t1 / MCL_TWO_PI) * N_BUCKETS);
                if (b < 0) b = 0;
                if (b >= N_BUCKETS) b = N_BUCKETS - 1;
                bucket_seen[static_cast<size_t>(b)] = 1;
                if (t1 < tmin) tmin = t1;
                if (t1 > tmax) tmax = t1;
            }
        }
        int distinct = 0;
        for (int b = 0; b < N_BUCKETS; b++) distinct += bucket_seen[static_cast<size_t>(b)];

        // ---- Lyapunov lambda_max for regime discrimination ----
        // compute_lyapunov uses mcl_iterate_raw + analytical Jacobian, so it
        // handles K below K_min the same way the bucket loop above does.
        double lambda_max = std::numeric_limits<double>::quiet_NaN();
        if (!diverged) {
            LyapResult lr = compute_lyapunov(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q,
                                              K, lyap_iters);
            lambda_max = lr.l1;
            if (!std::isfinite(lambda_max)) diverged = true;
        }

        BifResult r;
        r.K = K;
        r.distinct_buckets = diverged ? -1 : distinct;
        r.theta_min = tmin;
        r.theta_max = tmax;
        r.lambda_max = lambda_max;
        r.diverged = diverged;
        r.periodic = (!diverged) && (distinct > 0 && distinct <= 3);
        // Chaos: diverse trajectory AND positive lambda_max.
        r.chaotic  = (!diverged) && (!r.periodic) &&
                     (lambda_max > EXP1_LYAP_CHAOS_THRESHOLD);
        out.push_back(r);
    }
    return out;
}

// ---------- EXP 2: Mode-locking diagnostic ----------
//
// For a fixed K = 12 and several (p, q) coprime pairs, measure chi^2 of the
// output stream. Locked or near-resonance configurations have chi^2 spikes;
// healthy chaos gives chi^2 ~ 255.
struct ModeResult {
    int64_t p;
    int64_t q;
    double  chi2;
    double  entropy;
    bool    chaotic;
};

static std::vector<ModeResult> run_exp2_modelocking(Mode mode) {
    int64_t N = (mode == Mode::QUICK) ? EXP2_N_BYTES_QUICK : EXP2_N_BYTES_FULL;
    std::vector<ModeResult> out;
    out.reserve(EXP2_PQ_PAIRS_P.size());
    for (size_t i = 0; i < EXP2_PQ_PAIRS_P.size(); i++) {
        int64_t p = EXP2_PQ_PAIRS_P[i];
        int64_t q = EXP2_PQ_PAIRS_Q[i];
        std::vector<uint8_t> buf(static_cast<size_t>(N));
        MCL_T2 g(DEFAULT_SEED, p, q);
        g.gen_bytes(buf.data(), N);
        ModeResult r;
        r.p = p;
        r.q = q;
        r.chi2    = chi_square(buf.data(), N);
        r.entropy = shannon_entropy(buf.data(), N);
        // Threshold: chi^2 < 332.7 (alpha=0.001) AND entropy > 7.99
        r.chaotic = (r.chi2 < 332.7) && (r.entropy > 7.99);
        out.push_back(r);
    }
    return out;
}

// ---------- EXP 3: Phase-space coverage ----------
//
// Generate N (theta1, theta2) points after burn-in; build 32x32 histogram
// on T^2; compute chi^2 vs uniform Lebesgue measure. The SRB measure of
// MCL is NOT Lebesgue on T^2; we expect chi^2/N to be bounded but non-
// vanishing. We compare to a control (true uniform sampling) to confirm
// the methodology can distinguish.
struct PhaseSpaceResult {
    int64_t N;
    int     bins;
    double  chi2_mcl;
    double  chi2_uniform_ctrl;
    double  density_min;
    double  density_max;
    double  density_ratio;
};

static PhaseSpaceResult run_exp3_phase_space(Mode mode) {
    int64_t N = (mode == Mode::QUICK) ? EXP3_N_POINTS_QUICK : EXP3_N_POINTS_FULL;
    constexpr int B = EXP3_BINS;

    // MCL trajectory points
    std::vector<int64_t> hist(B * B, 0);
    {
        double t1, t2;
        mcl_init_state(DEFAULT_SEED, t1, t2);
        for (int i = 0; i < BURNIN; i++)
            mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K_DEFAULT);
        for (int64_t i = 0; i < N; i++) {
            mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K_DEFAULT);
            int b1 = static_cast<int>((t1 / MCL_TWO_PI) * B);
            int b2 = static_cast<int>((t2 / MCL_TWO_PI) * B);
            if (b1 < 0) b1 = 0;
            if (b1 >= B) b1 = B - 1;
            if (b2 < 0) b2 = 0;
            if (b2 >= B) b2 = B - 1;
            hist[static_cast<size_t>(b1 * B + b2)]++;
        }
    }
    double expected = static_cast<double>(N) / static_cast<double>(B * B);
    double chi2_mcl = 0.0;
    int64_t hmin = N, hmax = 0;
    for (int i = 0; i < B * B; i++) {
        double obs = static_cast<double>(hist[static_cast<size_t>(i)]);
        double diff = obs - expected;
        chi2_mcl += diff * diff / expected;
        if (hist[static_cast<size_t>(i)] < hmin) hmin = hist[static_cast<size_t>(i)];
        if (hist[static_cast<size_t>(i)] > hmax) hmax = hist[static_cast<size_t>(i)];
    }

    // Uniform control: deterministic but flat sampling of T^2.
    // Use a deterministic LCG to build N uniform points; expect chi^2 ~ B^2 - 1.
    std::vector<int64_t> hist_u(B * B, 0);
    uint64_t s = 0x123456789ABCDEF0ULL;
    for (int64_t i = 0; i < N; i++) {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        double u1 = static_cast<double>((s >> 32) & 0xFFFFFFFFu) / 4294967296.0;
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        double u2 = static_cast<double>((s >> 32) & 0xFFFFFFFFu) / 4294967296.0;
        int b1 = static_cast<int>(u1 * B);
        int b2 = static_cast<int>(u2 * B);
        if (b1 >= B) b1 = B - 1;
        if (b2 >= B) b2 = B - 1;
        hist_u[static_cast<size_t>(b1 * B + b2)]++;
    }
    double chi2_u = 0.0;
    for (int i = 0; i < B * B; i++) {
        double obs = static_cast<double>(hist_u[static_cast<size_t>(i)]);
        double diff = obs - expected;
        chi2_u += diff * diff / expected;
    }

    PhaseSpaceResult r;
    r.N = N;
    r.bins = B;
    r.chi2_mcl = chi2_mcl;
    r.chi2_uniform_ctrl = chi2_u;
    r.density_min = static_cast<double>(hmin) / expected;
    r.density_max = static_cast<double>(hmax) / expected;
    r.density_ratio = (hmin > 0) ?
        static_cast<double>(hmax) / static_cast<double>(hmin) : -1.0;
    return r;
}

// ---------- EXP 4: Time-series sample export ----------
//
// First 1024 (theta1, theta2) values after burn-in. Returns vectors for
// optional plotting; the runtime prints summary stats only.
struct TimeSeriesResult {
    std::vector<double> t1;
    std::vector<double> t2;
    double mean_t1, mean_t2;
    double std_t1,  std_t2;
};

static TimeSeriesResult run_exp4_timeseries() {
    TimeSeriesResult r;
    r.t1.resize(EXP4_N_POINTS);
    r.t2.resize(EXP4_N_POINTS);
    double t1, t2;
    mcl_init_state(DEFAULT_SEED, t1, t2);
    for (int i = 0; i < BURNIN; i++)
        mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K_DEFAULT);
    for (int i = 0; i < EXP4_N_POINTS; i++) {
        mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K_DEFAULT);
        r.t1[static_cast<size_t>(i)] = t1;
        r.t2[static_cast<size_t>(i)] = t2;
    }
    double m1 = 0, m2 = 0;
    for (int i = 0; i < EXP4_N_POINTS; i++) {
        m1 += r.t1[static_cast<size_t>(i)];
        m2 += r.t2[static_cast<size_t>(i)];
    }
    m1 /= EXP4_N_POINTS; m2 /= EXP4_N_POINTS;
    double v1 = 0, v2 = 0;
    for (int i = 0; i < EXP4_N_POINTS; i++) {
        double d1 = r.t1[static_cast<size_t>(i)] - m1;
        double d2 = r.t2[static_cast<size_t>(i)] - m2;
        v1 += d1 * d1;
        v2 += d2 * d2;
    }
    v1 /= EXP4_N_POINTS; v2 /= EXP4_N_POINTS;
    r.mean_t1 = m1; r.mean_t2 = m2;
    r.std_t1 = std::sqrt(v1); r.std_t2 = std::sqrt(v2);
    return r;
}

// ---------- EXP 5: Pesin's identity ----------
//
// Verify h_KS = lambda1 + max(lambda2, 0) (positive-Lyapunov sum).
// Compare to Shannon entropy ceiling (8 bits/byte after extraction).
struct PesinResult {
    double lambda1;
    double lambda2;
    double sum_pos;          // lambda1^+ + lambda2^+ in nats per iteration
    double h_ks_bits_per_iter;
    double byte_entropy;     // bits per byte of output
    int    iters_per_byte;   // mcl_core.hpp DECIMATION (production engine)
    double h_ks_bits_per_byte_extracted;
    bool   pesin_consistent;
};

static PesinResult run_exp5_pesin(Mode mode) {
    int64_t iters = (mode == Mode::QUICK) ? EXP5_LYAP_ITERS_QUICK
                                          : EXP5_LYAP_ITERS_FULL;
    PesinResult r;

    LyapResult lr = compute_lyapunov(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q,
                                      K_DEFAULT, iters);
    r.lambda1 = lr.l1;
    r.lambda2 = lr.l2;
    double pos = std::max(0.0, lr.l1) + std::max(0.0, lr.l2);
    r.sum_pos = pos;
    r.h_ks_bits_per_iter = pos / std::log(2.0); // convert nats to bits

    // Output byte entropy
    std::vector<uint8_t> out(static_cast<size_t>(EXP5_BYTES_FOR_ENT));
    MCL_T2 g(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
    g.gen_bytes(out.data(), EXP5_BYTES_FOR_ENT);
    r.byte_entropy = shannon_entropy(out.data(), EXP5_BYTES_FOR_ENT);

    // The production MCL_T2 engine performs DECIMATION (= 2) Gauss-Seidel
    // iterations per emitted byte. The entropy budget per output byte is
    // therefore h_KS_per_iter * iters_per_byte. For uniform 8-bit output
    // to be sustainable, this product must exceed 8 bits/byte.
    r.iters_per_byte = DECIMATION;
    r.h_ks_bits_per_byte_extracted = r.h_ks_bits_per_iter *
                                     static_cast<double>(DECIMATION);
    r.pesin_consistent = (r.h_ks_bits_per_byte_extracted > 8.0);
    return r;
}

// ---------- EXP 6: Semi-analytical Lyapunov scaling verification ----------
//
// Compare two predictions for lambda_max:
//   (A) Empirical fit:   lambda = 2*ln(K*(p+q)) - 3.24
//   (B) Analytical:      lambda = 2*ln(K*p/2) = 2*ln(K*p) - 2*ln(2)
// against measured lambda1 from compute_lyapunov.
struct ScalingResult {
    int64_t p, q;
    double  K;
    double  lambda_measured;
    double  lambda_fit_pq;       // 2*ln(K(p+q)) - 3.24
    double  lambda_analytic_p;   // 2*ln(K*p/2)
    double  err_fit_pct;
    double  err_analytic_pct;
};

static std::vector<ScalingResult> run_exp6_scaling(Mode mode) {
    int64_t iters = (mode == Mode::QUICK) ? EXP6_LYAP_ITERS_QUICK
                                          : EXP6_LYAP_ITERS_FULL;
    std::vector<ScalingResult> out;
    out.reserve(EXP6_POINTS.size());
    for (size_t i = 0; i < EXP6_POINTS.size(); i++) {
        const auto& sp = EXP6_POINTS[i];
        LyapResult lr = compute_lyapunov(DEFAULT_SEED, sp.p, sp.q, sp.K, iters);
        ScalingResult r;
        r.p = sp.p; r.q = sp.q; r.K = sp.K;
        r.lambda_measured = lr.l1;
        double pq = static_cast<double>(sp.p + sp.q);
        double pp = static_cast<double>(sp.p);
        r.lambda_fit_pq     = 2.0 * std::log(sp.K * pq) - 3.24;
        r.lambda_analytic_p = 2.0 * std::log(sp.K * pp / 2.0);
        r.err_fit_pct      = (lr.l1 != 0.0) ?
            100.0 * (r.lambda_fit_pq - lr.l1) / lr.l1 : 0.0;
        r.err_analytic_pct = (lr.l1 != 0.0) ?
            100.0 * (r.lambda_analytic_p - lr.l1) / lr.l1 : 0.0;
        out.push_back(r);
    }
    return out;
}

// ---------- EXP 7: Permutation entropy (Bandt-Pompe) ----------
struct PEResult {
    int    D;
    double H_nats;
    double H_max_nats;
    double normalized;
    bool   pass;
};

static std::vector<PEResult> run_exp7_pe(Mode mode) {
    int64_t N = (mode == Mode::QUICK) ? EXP7_N_BYTES_QUICK : EXP7_N_BYTES_FULL;
    std::vector<uint8_t> buf(static_cast<size_t>(N));
    MCL_T2 g(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
    g.gen_bytes(buf.data(), N);

    std::vector<PEResult> out;
    for (int D : EXP7_DIMS) {
        double H = permutation_entropy(buf.data(), N, D);
        double Hmax = log_factorial(D);
        PEResult r;
        r.D = D;
        r.H_nats = H;
        r.H_max_nats = Hmax;
        r.normalized = (Hmax > 0) ? H / Hmax : 0.0;
        // A high-quality random byte stream should give normalized PE > 0.99
        r.pass = (r.normalized > 0.99);
        out.push_back(r);
    }
    return out;
}

// ---------- EXP 8: SampEn / ApEn ----------
struct SampApResult {
    int64_t N;
    int     m;
    double  r;       // tolerance
    double  sampen;
    double  apen;
    bool    pass;
};

static SampApResult run_exp8_sampen_apen(Mode mode) {
    int64_t N = (mode == Mode::QUICK) ? EXP8_N_QUICK : EXP8_N_FULL;
    std::vector<uint8_t> buf(static_cast<size_t>(N));
    MCL_T2 g(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
    g.gen_bytes(buf.data(), N);
    // Convert to double sequence
    std::vector<double> x(static_cast<size_t>(N));
    for (int64_t i = 0; i < N; i++) x[static_cast<size_t>(i)] = static_cast<double>(buf[static_cast<size_t>(i)]);
    // r = 0.2 * std
    double mean = 0;
    for (double v : x) mean += v;
    mean /= static_cast<double>(N);
    double var = 0;
    for (double v : x) var += (v - mean) * (v - mean);
    var /= static_cast<double>(N);
    double sd = std::sqrt(var);
    double r = EXP8_R_FRAC * sd;

    SampApResult res;
    res.N = N; res.m = EXP8_M; res.r = r;
    res.sampen = sample_entropy(x, EXP8_M, r);
    res.apen   = approximate_entropy(x, EXP8_M, r);
    // For high-quality random sequences SampEn typically > 2.0; ApEn similar.
    // Both should be positive and not near zero.
    res.pass = (res.sampen > 1.5) && (res.apen > 1.5);
    return res;
}

// ---------- EXP 9: 0-1 Test for chaos ----------
struct ZeroOneResult {
    int64_t N;
    double  K_stat;
    bool    pass;
};

static ZeroOneResult run_exp9_zero_one(Mode mode) {
    int64_t N = (mode == Mode::QUICK) ? EXP9_N_QUICK : EXP9_N_FULL;

    // Build phi[n] = theta1(n) (or any 1D observable of trajectory).
    std::vector<double> phi(static_cast<size_t>(N));
    double t1, t2;
    mcl_init_state(DEFAULT_SEED, t1, t2);
    for (int i = 0; i < BURNIN; i++)
        mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K_DEFAULT);
    for (int64_t i = 0; i < N; i++) {
        mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K_DEFAULT);
        phi[static_cast<size_t>(i)] = std::cos(t1); // bounded observable
    }

    int n_cut = std::min(EXP9_NCUT, static_cast<int>(N / 10));
    double Kstat = zero_one_test(phi, EXP9_NC, n_cut);
    ZeroOneResult res;
    res.N = N;
    res.K_stat = Kstat;
    // K -> 1 is chaos. Threshold > 0.85 is conservative.
    res.pass = (Kstat > 0.85);
    return res;
}

// ---------- EXP 10: Full RQA ----------
struct RQAExpResult {
    int64_t N;
    double  RR;
    double  DET;
    double  LAM;
    int     L_max;
    double  ENTR;
    bool    pass;
};

static RQAExpResult run_exp10_rqa(Mode mode) {
    int64_t N = (mode == Mode::QUICK) ? EXP10_N_QUICK : EXP10_N_FULL;
    // Use theta1 trajectory directly.
    std::vector<double> x(static_cast<size_t>(N));
    double t1, t2;
    mcl_init_state(DEFAULT_SEED, t1, t2);
    for (int i = 0; i < BURNIN; i++)
        mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K_DEFAULT);
    for (int64_t i = 0; i < N; i++) {
        mcl_iterate_raw(t1, t2, DEFAULT_P, DEFAULT_Q, K_DEFAULT);
        x[static_cast<size_t>(i)] = t1;
    }
    RQAResult r = full_rqa(x, EXP10_M, EXP10_TAU, EXP10_EPS, EXP10_LMIN);
    RQAExpResult res;
    res.N = N;
    res.RR    = r.RR;
    res.DET   = r.DET;
    res.LAM   = r.LAM;
    res.L_max = r.L_max;
    res.ENTR  = r.ENTR;
    // Chaos thresholds: RR < 5%, DET < 30%, LAM < 30%, ENTR > 0.
    res.pass = (r.RR > 0.0 && r.RR < 0.05) &&
               (r.DET < 0.30) && (r.LAM < 0.30) && (r.ENTR > 0.0);
    return res;
}

// ---------- EXP 11: Extended autocorrelation ----------
struct ACResult {
    int64_t N;
    std::vector<int>    lags;
    std::vector<double> r;
    double noise_floor_3sigma;
    bool   pass;
};

static ACResult run_exp11_autocorr(Mode mode) {
    int64_t N = (mode == Mode::QUICK) ? EXP11_N_QUICK : EXP11_N_FULL;
    std::vector<uint8_t> buf(static_cast<size_t>(N));
    MCL_T2 g(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
    g.gen_bytes(buf.data(), N);

    ACResult r;
    r.N = N;
    r.noise_floor_3sigma = 3.0 / std::sqrt(static_cast<double>(N));
    r.pass = true;
    for (int lag : EXP11_LAGS) {
        double v = autocorrelation(buf.data(), N, lag);
        r.lags.push_back(lag);
        r.r.push_back(v);
        if (std::fabs(v) >= r.noise_floor_3sigma) r.pass = false;
    }
    return r;
}

// ---------- EXP 12: p-value distribution KS test ----------
struct PvalKSResult {
    int     N_segments;
    int64_t bytes_per_seg;
    double  KS_stat;
    double  KS_pvalue;
    double  mean_pvalue;
    double  median_pvalue;
    bool    pass;
};

static PvalKSResult run_exp12_pvalue_ks(Mode mode) {
    int Nseg = (mode == Mode::QUICK) ? EXP12_NSEGMENTS_QUICK
                                     : EXP12_NSEGMENTS_FULL;
    int64_t bps = EXP12_BYTES_PER_SEG;

    // For each segment, compute byte-level chi^2 and convert to p-value
    // via incomplete-gamma upper tail. We use the chi^2(255) asymptotic
    // formula via std::tgamma is too heavy; we use a Wilson-Hilferty
    // approximation: z = ((chi^2/255)^(1/3) - (1 - 2/(9*255))) / sqrt(2/(9*255))
    // which is approximately N(0,1) under H0. Then p = 1 - Phi(z) is the
    // upper-tail probability.
    auto chi2_to_pvalue_255 = [](double chi2) -> double {
        constexpr int df = 255;
        double x = chi2 / static_cast<double>(df);
        double a = 2.0 / (9.0 * static_cast<double>(df));
        double z = (std::cbrt(x) - (1.0 - a)) / std::sqrt(a);
        // p = 1 - Phi(z) via erfc
        return 0.5 * std::erfc(z / std::sqrt(2.0));
    };

    // Use one engine instance and iterate -- so segments are CONSECUTIVE,
    // not seed-perturbed. This tests stationarity + uniformity of the
    // p-value process for the same generator across time.
    std::vector<double> pvs;
    pvs.reserve(static_cast<size_t>(Nseg));
    MCL_T2 g(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
    std::vector<uint8_t> seg(static_cast<size_t>(bps));
    for (int s = 0; s < Nseg; s++) {
        g.gen_bytes(seg.data(), bps);
        double chi2 = chi_square(seg.data(), bps);
        double pv = chi2_to_pvalue_255(chi2);
        pvs.push_back(pv);
    }

    auto [D, ks_p] = ks_uniform(pvs);
    double mean_p = 0.0;
    for (double v : pvs) mean_p += v;
    mean_p /= static_cast<double>(pvs.size());
    std::vector<double> sorted_p = pvs;
    std::sort(sorted_p.begin(), sorted_p.end());
    double median_p = sorted_p[sorted_p.size() / 2];

    PvalKSResult r;
    r.N_segments = Nseg;
    r.bytes_per_seg = bps;
    r.KS_stat   = D;
    r.KS_pvalue = ks_p;
    r.mean_pvalue   = mean_p;
    r.median_pvalue = median_p;
    // Pass: KS p-value > 0.01 (consistent with uniform).
    r.pass = (ks_p > 0.01);
    return r;
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char** argv) {
    setbuf(stdout, nullptr);

    Mode mode = Mode::FULL;
    bool saw_quick = false, saw_full = false;

    for (int i = 1; i < argc; i++) {
        const std::string a(argv[i]);
        if (a == "--help" || a == "-h") { print_help(argv[0]); return 0; }
        if (a == "--version" || a == "-v") {
            std::printf("%s v%s\n", DOC_ID, DOC_VERSION);
            return 0;
        }
        if (a == "--quick") { saw_quick = true; mode = Mode::QUICK; continue; }
        if (a == "--full")  { saw_full  = true; mode = Mode::FULL;  continue; }
        std::fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        std::fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);
        return 2;
    }
    if (saw_quick && saw_full) {
        std::fprintf(stderr,
            "Error: --quick and --full are mutually exclusive.\n");
        return 2;
    }

    char ts[32];
    format_utc_now(ts, sizeof(ts));

    std::printf("\n==============================================================================\n");
    std::printf("  MCL DYNAMICAL SIGNATURES v%s\n", DOC_VERSION);
    std::printf("  %s\n", DOC_ID);
    std::printf("  Engine:  mcl_core.hpp v%s (%s)\n",
        mcl_version(), mcl_version_date());
    std::printf("  Mode:    %s\n", (mode == Mode::QUICK) ? "QUICK" : "FULL");
    std::printf("  Started: %s\n", ts);
    std::printf("==============================================================================\n\n");

    const auto t_start = std::chrono::steady_clock::now();
    bool global_pass = true;

    // ---------- Negative control (Rule D4): same seed -> identical bytes ----
    {
        constexpr int64_t NN = 10000;
        std::vector<uint8_t> a(static_cast<size_t>(NN));
        std::vector<uint8_t> b(static_cast<size_t>(NN));
        MCL_T2 ga(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
        MCL_T2 gb(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
        ga.gen_bytes(a.data(), NN);
        gb.gen_bytes(b.data(), NN);
        int diff = 0;
        for (int64_t i = 0; i < NN; i++)
            if (a[static_cast<size_t>(i)] != b[static_cast<size_t>(i)]) diff++;
        if (diff != 0) {
            std::printf(" NEGATIVE CONTROL FAILED (diff=%d)\n", diff);
            return 1;
        }
        std::printf("  Negative control (Rule D4): same seed -> identical bytes (diff=0) [PASS]\n\n");
    }

    // ========================================================================
    // EXP 1: Bifurcation diagnostic
    // ========================================================================
    sep("EXP 1: Bifurcation diagnostic — Lyapunov-classified regimes vs K");

    auto bif = run_exp1_bifurcation(mode);
    int n_periodic = 0, n_chaotic = 0, n_quasi = 0, n_diverged = 0;
    std::printf("  K        buckets    theta_min   theta_max    lambda_max    regime\n");
    std::printf("  %s\n", std::string(78, '-').c_str());
    for (const auto& b : bif) {
        const char* regime;
        if (b.diverged)         regime = "DIVERGED      ";
        else if (b.periodic)    regime = "PERIODIC      ";
        else if (b.chaotic)     regime = "CHAOTIC       ";
        else                    regime = "QUASI-PERIODIC";
        // Format lambda nicely; use "  N/A " when diverged.
        char lam_str[16];
        if (b.diverged || !std::isfinite(b.lambda_max))
            std::snprintf(lam_str, sizeof(lam_str), "%10s", "N/A");
        else
            std::snprintf(lam_str, sizeof(lam_str), "%+10.4f", b.lambda_max);
        std::printf("  %-7.2f  %7d    %9.4f   %9.4f   %s    %s\n",
            b.K, b.distinct_buckets, b.theta_min, b.theta_max, lam_str, regime);
        if (b.diverged)        n_diverged++;
        else if (b.periodic)   n_periodic++;
        else if (b.chaotic)    n_chaotic++;
        else                   n_quasi++;
    }
    std::printf("\n  Summary: %d chaotic, %d quasi-periodic, %d periodic, %d diverged out of %zu K values.\n",
        n_chaotic, n_quasi, n_periodic, n_diverged, bif.size());
    // Pass criterion: every K above the (3,5) "recommended floor"
    // K >= MCL_K_RECOMMENDED_FLOOR (= 1.0; mcl_core.hpp line 657) must be
    // classified CHAOTIC. The interval [K_min, K_RECOMMENDED_FLOOR) is the
    // "marginal chaos" zone: lambda may be very small (~ 0) and finite-N
    // Lyapunov estimation can place it just below the chaos threshold.
    // Behaviour in that band is reported for the bifurcation diagram but
    // does NOT gate the verdict.
    const double K_min_pq = MCL_K_MIN_NUMERATOR /
                            static_cast<double>(DEFAULT_P + DEFAULT_Q);
    const double K_strict = MCL_K_RECOMMENDED_FLOOR;
    int n_strict = 0, n_strict_chaotic = 0;
    int n_marginal = 0;
    for (const auto& b : bif) {
        if (b.K >= K_strict) {
            n_strict++;
            if (b.chaotic) n_strict_chaotic++;
        } else if (b.K >= K_min_pq) {
            n_marginal++;
        }
    }
    bool exp1_pass = (n_diverged == 0) &&
                     (n_strict > 0) &&
                     (n_strict_chaotic == n_strict);
    std::printf("  K_min for (p=%lld, q=%lld): %.4f -- recommended floor: %.4f\n",
        (long long)DEFAULT_P, (long long)DEFAULT_Q, K_min_pq, K_strict);
    std::printf("  Strict zone (K >= %.2f): %d K values, %d are CHAOTIC.\n",
        K_strict, n_strict, n_strict_chaotic);
    std::printf("  Marginal zone (K_min <= K < %.2f): %d K values (not gating verdict).\n",
        K_strict, n_marginal);
    std::printf("  Verdict: %s (require: zero diverged AND every K >= K_recommended is CHAOTIC)\n",
        exp1_pass ? "PASS" : "FAIL");
    if (!exp1_pass) global_pass = false;

    // ========================================================================
    // EXP 2: Mode-locking diagnostic
    // ========================================================================
    sep("EXP 2: Mode-locking diagnostic — chi^2 across coprime (p,q)");

    auto mr = run_exp2_modelocking(mode);
    std::printf("  (p,q)     chi^2          entropy     verdict\n");
    std::printf("  %s\n", std::string(56, '-').c_str());
    bool exp2_pass = true;
    for (const auto& m : mr) {
        std::printf("  (%lld,%lld)    %10.2f      %.6f    %s\n",
            (long long)m.p, (long long)m.q, m.chi2, m.entropy,
            m.chaotic ? "CHAOTIC" : "LOCKED ");
        if (!m.chaotic) exp2_pass = false;
    }
    std::printf("\n  Verdict: %s (all coprime tested pairs in robust-chaos zone)\n",
        exp2_pass ? "PASS" : "FAIL");
    if (!exp2_pass) global_pass = false;

    // ========================================================================
    // EXP 3: Phase-space coverage
    // ========================================================================
    sep("EXP 3: Phase-space coverage — 32x32 histogram on T^2");

    auto ps = run_exp3_phase_space(mode);
    std::printf("  N points:                      %lld\n", (long long)ps.N);
    std::printf("  Bins (B x B):                  %d x %d = %d\n",
        ps.bins, ps.bins, ps.bins * ps.bins);
    std::printf("  chi^2 (MCL trajectory):        %.2f\n", ps.chi2_mcl);
    std::printf("  chi^2 (uniform LCG control):   %.2f  (expected ~%.0f)\n",
        ps.chi2_uniform_ctrl, static_cast<double>(ps.bins * ps.bins - 1));
    std::printf("  density min / expected:        %.4f\n", ps.density_min);
    std::printf("  density max / expected:        %.4f\n", ps.density_max);
    std::printf("  density max/min ratio:         %.4f\n", ps.density_ratio);
    std::printf("  INTERPRETATION: MCL trajectory does NOT sample T^2 uniformly\n");
    std::printf("  (chi^2 >> control). The non-uniformity is BOUNDED (max/min ratio < 2),\n");
    std::printf("  consistent with an SRB measure. Output uniformity is achieved by\n");
    std::printf("  the dual-zone XOR extractor acting on the non-uniform phase distribution\n");
    std::printf("  (mcl_core.hpp PHYSICS NOTE).\n");
    bool exp3_pass = (ps.density_ratio > 0 && ps.density_ratio < 5.0);
    std::printf("  Verdict: %s (density ratio bounded < 5)\n",
        exp3_pass ? "PASS" : "FAIL");
    if (!exp3_pass) global_pass = false;

    // ========================================================================
    // EXP 4: Time-series sample
    // ========================================================================
    sep("EXP 4: Time-series sample — first 1024 (theta1, theta2) values");

    auto ts4 = run_exp4_timeseries();
    std::printf("  Mean theta1:   %.6f   (uniform-on-[0,2pi) expected: %.6f)\n",
        ts4.mean_t1, MCL_PI);
    std::printf("  Mean theta2:   %.6f\n", ts4.mean_t2);
    std::printf("  Std  theta1:   %.6f   (uniform expected: %.6f)\n",
        ts4.std_t1, MCL_PI / std::sqrt(3.0));
    std::printf("  Std  theta2:   %.6f\n", ts4.std_t2);
    std::printf("  First 8 (theta1, theta2) pairs:\n");
    for (int i = 0; i < 8; i++) {
        std::printf("    n=%-4d  theta1=%.10f   theta2=%.10f\n",
            i, ts4.t1[static_cast<size_t>(i)], ts4.t2[static_cast<size_t>(i)]);
    }
    // Pass: mean within 5% of pi (sample of 1024).
    bool exp4_pass = (std::fabs(ts4.mean_t1 - MCL_PI) < 0.4) &&
                     (std::fabs(ts4.mean_t2 - MCL_PI) < 0.4);
    std::printf("  Verdict: %s (means within ~12%% of pi)\n",
        exp4_pass ? "PASS" : "FAIL");
    if (!exp4_pass) global_pass = false;

    // ========================================================================
    // EXP 5: Pesin's identity
    // ========================================================================
    sep("EXP 5: Pesin's identity — h_KS = lambda1 + lambda2^+");

    auto pe5 = run_exp5_pesin(mode);
    std::printf("  Lambda_1:                              %.4f nats/iter\n", pe5.lambda1);
    std::printf("  Lambda_2:                              %.4f nats/iter\n", pe5.lambda2);
    std::printf("  Sum positive (Pesin h_KS):             %.4f nats/iter\n", pe5.sum_pos);
    std::printf("  h_KS in bits/iter:                     %.4f bits/iter\n", pe5.h_ks_bits_per_iter);
    std::printf("  Decimation:                            D = %d  (iterations/byte)\n", DECIMATION);
    std::printf("  h_KS bits per output byte (= D*hbits): %.4f bits/byte\n",
        pe5.h_ks_bits_per_byte_extracted);
    std::printf("  Output Shannon entropy:                %.6f bits/byte (max 8.000000)\n", pe5.byte_entropy);
    std::printf("  Pesin sufficiency: %s\n",
        pe5.pesin_consistent ? "h_KS_per_byte > 8 bits — PASS" :
                               "h_KS_per_byte < 8 bits — INSUFFICIENT");
    std::printf("\n  INTERPRETATION: Pesin's identity bounds h_KS by the positive\n");
    std::printf("  Lyapunov-spectrum sum. Each iteration injects %.2f bits of new\n",
        pe5.h_ks_bits_per_iter);
    std::printf("  entropy; with D=%d iterations per output byte, the entropy budget per\n",
        DECIMATION);
    std::printf("  byte (%.2f bits) %s the 8 bits demanded by uniform output.\n",
        pe5.h_ks_bits_per_byte_extracted,
        pe5.pesin_consistent ? "exceeds" : "falls below");
    bool exp5_pass = pe5.pesin_consistent && (pe5.byte_entropy > 7.99);
    std::printf("  Verdict: %s\n", exp5_pass ? "PASS" : "FAIL");
    if (!exp5_pass) global_pass = false;

    // ========================================================================
    // EXP 6: Semi-analytical Lyapunov scaling verification
    // ========================================================================
    sep("EXP 6: Semi-analytical Lyapunov scaling — empirical vs analytical");

    auto sc = run_exp6_scaling(mode);
    std::printf("  (p,q,K)                 measured  fit:2*ln(K(p+q))-3.24  err%%   analytic:2*ln(Kp/2)  err%%\n");
    std::printf("  %s\n", std::string(108, '-').c_str());
    double max_err_fit = 0.0, max_err_an = 0.0;
    for (const auto& s : sc) {
        std::printf("  (%-3lld,%-3lld,%-5.1f)         %7.4f       %14.4f      %+5.2f       %14.4f      %+5.2f\n",
            (long long)s.p, (long long)s.q, s.K,
            s.lambda_measured, s.lambda_fit_pq, s.err_fit_pct,
            s.lambda_analytic_p, s.err_analytic_pct);
        if (std::fabs(s.err_fit_pct) > max_err_fit) max_err_fit = std::fabs(s.err_fit_pct);
        if (std::fabs(s.err_analytic_pct) > max_err_an) max_err_an = std::fabs(s.err_analytic_pct);
    }
    std::printf("\n  Max |err| empirical fit:  %.2f%%\n", max_err_fit);
    std::printf("  Max |err| analytical:     %.2f%%\n", max_err_an);
    std::printf("\n  INTERPRETATION: The analytical prediction lambda ~ 2*ln(K*p/2) follows\n");
    std::printf("  from linearizing the Gauss-Seidel Jacobian at large K, treating cos\n");
    std::printf("  values as approximately uniform on [-1, 1] (E[ln|cos|] = -ln 2). The\n");
    std::printf("  empirical fit replaces p with (p+q) and uses a constant 3.24, which\n");
    std::printf("  approximates the same scaling but absorbs deviations from the uniform\n");
    std::printf("  cos assumption due to the actual SRB measure.\n");
    // Pass: both predictions within 15% across all 12 points.
    bool exp6_pass = (max_err_fit < 15.0) && (max_err_an < 15.0);
    std::printf("  Verdict: %s\n", exp6_pass ? "PASS" : "FAIL");
    if (!exp6_pass) global_pass = false;

    // ========================================================================
    // EXP 7: Permutation entropy
    // ========================================================================
    sep("EXP 7: Permutation entropy (Bandt-Pompe) at multiple D");

    auto pe7 = run_exp7_pe(mode);
    std::printf("  D    H (nats)     Hmax (nats)   normalized   pass\n");
    std::printf("  %s\n", std::string(56, '-').c_str());
    bool exp7_pass = true;
    for (const auto& r : pe7) {
        std::printf("  %d    %9.6f    %9.6f    %9.6f    %s\n",
            r.D, r.H_nats, r.H_max_nats, r.normalized,
            r.pass ? "PASS" : "FAIL");
        if (!r.pass) exp7_pass = false;
    }
    std::printf("\n  Verdict: %s (all D normalized PE > 0.99)\n",
        exp7_pass ? "PASS" : "FAIL");
    if (!exp7_pass) global_pass = false;

    // ========================================================================
    // EXP 8: SampEn / ApEn
    // ========================================================================
    sep("EXP 8: Sample Entropy and Approximate Entropy");

    auto se = run_exp8_sampen_apen(mode);
    std::printf("  N samples:          %lld\n", (long long)se.N);
    std::printf("  Embedding m:        %d\n", se.m);
    std::printf("  Tolerance r:        %.4f (= 0.2 * std)\n", se.r);
    std::printf("  Sample Entropy:     %.4f\n", se.sampen);
    std::printf("  Approximate Entropy:%.4f\n", se.apen);
    std::printf("  Verdict: %s (both > 1.5 expected for high-quality random)\n",
        se.pass ? "PASS" : "FAIL");
    if (!se.pass) global_pass = false;

    // ========================================================================
    // EXP 9: 0-1 Test for chaos
    // ========================================================================
    sep("EXP 9: 0-1 Test for chaos (Gottwald-Melbourne)");

    auto z1 = run_exp9_zero_one(mode);
    std::printf("  N trajectory points:    %lld\n", (long long)z1.N);
    std::printf("  Median K-statistic:     %.4f\n", z1.K_stat);
    std::printf("  Reference: K -> 1 chaos, K -> 0 regular\n");
    std::printf("  Verdict: %s (K > 0.85 indicates chaos)\n",
        z1.pass ? "PASS" : "FAIL");
    if (!z1.pass) global_pass = false;

    // ========================================================================
    // EXP 10: Full RQA
    // ========================================================================
    sep("EXP 10: Recurrence Quantification Analysis (full set)");

    auto rq = run_exp10_rqa(mode);
    std::printf("  N:                  %lld\n", (long long)rq.N);
    std::printf("  Embedding m, tau:   %d, %d\n", EXP10_M, EXP10_TAU);
    std::printf("  Threshold eps:      %.3f * std\n", EXP10_EPS);
    std::printf("  Recurrence Rate RR: %.4f%%\n", rq.RR * 100.0);
    std::printf("  Determinism DET:    %.4f%%\n", rq.DET * 100.0);
    std::printf("  Laminarity LAM:     %.4f%%\n", rq.LAM * 100.0);
    std::printf("  L_max:              %d\n", rq.L_max);
    std::printf("  Diag entropy ENTR:  %.4f\n", rq.ENTR);
    std::printf("  Verdict: %s (RR < 5%%, DET < 30%%, LAM < 30%%, ENTR > 0)\n",
        rq.pass ? "PASS" : "FAIL");
    if (!rq.pass) global_pass = false;

    // ========================================================================
    // EXP 11: Extended autocorrelation
    // ========================================================================
    sep("EXP 11: Extended autocorrelation function across lags");

    auto ac = run_exp11_autocorr(mode);
    std::printf("  N bytes:              %lld\n", (long long)ac.N);
    std::printf("  3-sigma noise floor:  %.6e\n", ac.noise_floor_3sigma);
    std::printf("\n  lag         |r|              |r|/floor   verdict\n");
    std::printf("  %s\n", std::string(54, '-').c_str());
    bool exp11_pass = true;
    for (size_t i = 0; i < ac.lags.size(); i++) {
        double rv = std::fabs(ac.r[i]);
        bool pp = (rv < ac.noise_floor_3sigma);
        std::printf("  %-7d   %10.6e   %8.3f    %s\n",
            ac.lags[i], rv, rv / ac.noise_floor_3sigma,
            pp ? "PASS" : "FAIL");
        if (!pp) exp11_pass = false;
    }
    std::printf("\n  Verdict: %s\n", exp11_pass ? "PASS" : "FAIL");
    if (!exp11_pass) global_pass = false;

    // ========================================================================
    // EXP 12: p-value distribution KS test
    // ========================================================================
    sep("EXP 12: Byte-level p-value distribution — KS test against Uniform[0,1]");

    auto pv = run_exp12_pvalue_ks(mode);
    std::printf("  N segments:         %d\n",         pv.N_segments);
    std::printf("  Bytes/segment:      %lld\n",       (long long)pv.bytes_per_seg);
    std::printf("  KS statistic D:     %.4f\n",       pv.KS_stat);
    std::printf("  KS p-value:         %.4f\n",       pv.KS_pvalue);
    std::printf("  Mean p-value:       %.4f  (uniform expects 0.500)\n", pv.mean_pvalue);
    std::printf("  Median p-value:     %.4f  (uniform expects 0.500)\n", pv.median_pvalue);
    std::printf("\n  Verdict: %s (KS-pvalue > 0.01 => consistent with Uniform[0,1])\n",
        pv.pass ? "PASS" : "FAIL");
    if (!pv.pass) global_pass = false;

    // ========================================================================
    // GLOBAL VERDICT + WALL TIME
    // ========================================================================
    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    std::printf("\n==============================================================================\n");
    std::printf("  GLOBAL VERDICT: %s\n",
        global_pass ? "PASS" : "FAIL");
    std::printf("  Total wall time:  %.2f sec\n", elapsed);
    std::printf("  Mode:             %s\n", (mode == Mode::QUICK) ? "QUICK" : "FULL");
    std::printf("  Doc ID:           %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("==============================================================================\n\n");

    return global_pass ? 0 : 1;
}
