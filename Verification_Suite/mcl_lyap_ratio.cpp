/*
 * ============================================================================
 * MCL Lyapunov Ratio — GS vs Jacobi Ensemble (Benettin/QR)
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-LYAP-RATIO-2026-0526-001
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
 * PURPOSE: Produce the two central Paper 4 numbers (lambda_GS, lambda_Jacobi) and their
 *   ratio with publication-grade ensemble standard error. Paper 4 reports
 *   5.78 / 3.59 / 1.61 without uncertainty; this file supplies the SE.
 *   Methodology mirrors Paper 4 sec.VI.D: analytical Jacobian + QR every step,
 *   burn-in discarded, averaged over M random ICs; SE from across-run SD / sqrt(M).
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_lyap_ratio mcl_lyap_ratio.cpp -lm && ./mcl_lyap_ratio
 *
 * EXPECTED RESULTS: lambda_GS ≈ 5.78 ± SE, lambda_Jacobi ≈ 3.59 ± SE, ratio ≈ 1.61 ± SE.
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

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

static constexpr const char* const DOC_ID = "MCL-LYAP-RATIO-2026-0526-001";
static constexpr const char* const DOC_VERSION = "6.0.0";

static void ensemble(const char* label, bool jacobi,
                     int64_t p, int64_t q, double K,
                     int64_t iters, int M,
                     double& l1_mean, double& l1_se,
                     double& l2_mean, double& l2_se) {
    std::vector<double> L1(static_cast<size_t>(M));
    std::vector<double> L2(static_cast<size_t>(M));
    // Golden-ratio-spaced seeds give 20 distinct, well-separated initial
    // conditions on T^2 (the spacing minimizes accidental near-coincidence).
    for (int s = 0; s < M; ++s) {
        const unsigned us = static_cast<unsigned>(s);
        const uint64_t seed = 0x9E3779B97F4A7C15ULL
                            * (static_cast<uint64_t>(us) + 1ULL);
        const LyapResult r = jacobi
            ? compute_lyapunov_jacobi(seed, p, q, K, iters)
            : compute_lyapunov(seed, p, q, K, iters);
        L1[static_cast<size_t>(s)] = r.l1;
        L2[static_cast<size_t>(s)] = r.l2;
    }
    auto ms = [&](std::vector<double>& v, double& m, double& se) {
        double sum = 0.0;
        for (size_t i = 0; i < v.size(); i++) sum += v[i];
        m = sum / static_cast<double>(v.size());
        double q2 = 0.0;
        for (size_t i = 0; i < v.size(); i++) q2 += (v[i] - m) * (v[i] - m);
        const double sd = (v.size() > 1)
            ? std::sqrt(q2 / static_cast<double>(v.size() - 1))
            : 0.0;
        se = sd / std::sqrt(static_cast<double>(v.size()));
    };
    ms(L1, l1_mean, l1_se);
    ms(L2, l2_mean, l2_se);
    std::printf("  %-8s lambda1=%.4f +/- %.4f   lambda2=%.4f +/- %.4f   "
                "(M=%d, N=%lld)\n",
                label, l1_mean, l1_se, l2_mean, l2_se,
                M, static_cast<long long>(iters));
}

static void print_help(const char* prog) {
    std::printf("Usage:\n");
    std::printf("  %s            # M=20, N=2e6 (defaults)\n", prog);
    std::printf("  %s N          # custom N (iters per run)\n", prog);
    std::printf("  %s N M        # custom N and M (ensemble size)\n", prog);
    std::printf("  %s --help     # this message\n", prog);
    std::printf("\n");
    std::printf("Ensemble Benettin/QR Lyapunov for GS vs Jacobi recurrences.\n");
    std::printf("Reproduces Paper 4 numbers (5.78 / 3.59 / 1.61) with SE.\n");
    std::printf("\n");
    std::printf("Document: %s v%s\n", DOC_ID, DOC_VERSION);
}

}  // namespace

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);

    // Argument handling: --help, or 1-2 positional numeric args, else error.
    if (argc > 1 && std::strcmp(argv[1], "--help") == 0) {
        print_help(argv[0]);
        return 0;
    }
    if (argc > 3) {
        std::fprintf(stderr, "Too many arguments. Use --help.\n");
        return 1;
    }
    // Detect non-numeric stray args (unknown flag)
    for (int a = 1; a < argc; a++) {
        const char* s = argv[a];
        if (s[0] == '-') {
            std::fprintf(stderr, "Unknown argument: %s\n", s);
            return 1;
        }
    }

    const int64_t p = 3, q = 5;
    const double K = K_DEFAULT;
    int M = 20;
    int64_t N = 2000000;   // 2e6 iters per IC; paper reference uses 1e7
    if (argc > 1) N = std::atoll(argv[1]);
    if (argc > 2) M = std::atoi(argv[2]);
    if (M < 1 || N < 1) {
        std::fprintf(stderr, "M and N must be positive.\n");
        return 1;
    }

    std::printf("==========================================================="
                "=================\n");
    std::printf("  MCL ENSEMBLE LYAPUNOV v%s   (Benettin / QR)\n",
                DOC_VERSION);
    std::printf("  GS vs Jacobi at (p,q)=(%lld,%lld), K=%.1f\n",
                static_cast<long long>(p), static_cast<long long>(q), K);
    std::printf("  %s\n", DOC_ID);
    std::printf("============================================================"
                "================\n");
    std::printf("  burn-in = %d (core BURNIN), ensemble = %d ICs, N = %lld "
                "iters/run\n",
                BURNIN, M, static_cast<long long>(N));
    std::printf("------------------------------------------------------------"
                "----------------\n");

    double g1, g1e, g2, g2e, j1, j1e, j2, j2e;
    ensemble("GS",     false, p, q, K, N, M, g1, g1e, g2, g2e);
    ensemble("Jacobi", true,  p, q, K, N, M, j1, j1e, j2, j2e);

    std::printf("------------------------------------------------------------"
                "----------------\n");
    const double ratio = g1 / j1;
    // First-order error propagation:
    //   SE(r) = r * sqrt((SE_g/g)^2 + (SE_j/j)^2)
    const double rse = ratio
        * std::sqrt((g1e / g1) * (g1e / g1) + (j1e / j1) * (j1e / j1));
    std::printf("  lambda_GS     = %.4f +/- %.4f   (Paper 4 ref 5.78)\n",
                g1, g1e);
    std::printf("  lambda_Jacobi = %.4f +/- %.4f   (Paper 4 ref 3.59)\n",
                j1, j1e);
    std::printf("  ratio GS/Jac  = %.4f +/- %.4f   (Paper 4 ref 1.61)\n",
                ratio, rse);
    std::printf("  sum of exps (GS)     = %.4f   (volume contraction if <0)\n",
                g1 + g2);
    std::printf("  sum of exps (Jacobi) = %.4f\n", j1 + j2);

    std::printf("------------------------------------------------------------"
                "----------------\n");
    std::printf("  Interpretation: lambda_GS exceeds lambda_Jacobi by a ratio\n");
    std::printf("  > 1.5, so the sequential GS update is a MORE chaotic (more\n");
    std::printf("  mixing) system than its parallel Jacobi relaxation. A\n");
    std::printf("  Jacobi-based parallel approximation tracks a DIFFERENT,\n");
    std::printf("  less-divergent trajectory and cannot shortcut GS.\n");
    std::printf("  (Empirical sequentiality EVIDENCE for OP1/OP5, not a proof:\n");
    std::printf("  lambda is forward sensitivity, not a parallel-depth bound.)\n");
    std::printf("============================================================"
                "================\n\n");
    return 0;
}
