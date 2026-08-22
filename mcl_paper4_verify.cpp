/*
 * ============================================================================
 * MCL Paper 4 Verify — VDF Numerical Claims Reproduction
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-PAPER4-VERIFY-2026-0526-001
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
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673, PCT/IB2026/058860.
 * ============================================================================
 *
 * PURPOSE: Reproduce all numerical claims in Paper 4 (VDF Sequential Function)
 * §VI.B and §VI.C from the engine in mcl_core.hpp. Covers KAT test vectors,
 * Lyapunov exponent measurements, and VDF timing benchmarks.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -o mcl_paper4_verify mcl_paper4_verify.cpp -lm && ./mcl_paper4_verify
 *
 * EXPECTED RESULTS: All Paper 4 numerical claims verified. KAT vectors match. Exit 0.
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
#include <cstdio>
#include <cmath>
#include <chrono>
#include <vector>

int main() {
    const uint64_t seed = 12345678901234ULL;
    const int64_t p = 3, q = 5;
    const double K = 12.0;
    const int64_t N_LYAP = 1000000;
    
    printf("===============================================================\n");
    printf("Paper 4 - Numerical Claims Reproduction\n");
    printf("===============================================================\n");
    printf("Seed: %llu, (p,q)=(%lld,%lld), K=%.1f\n",
           (unsigned long long)seed, (long long)p, (long long)q, K);
    printf("---------------------------------------------------------------\n\n");
    
    // ===========================================================
    // Section VI.B: Empirical Sequentiality Evidence
    // ===========================================================
    printf("Section VI.B - Gauss-Seidel vs Jacobi Lyapunov:\n");
    printf("---------------------------------------------------------------\n");
    auto t0 = std::chrono::high_resolution_clock::now();
    LyapResult gs = compute_lyapunov(seed, p, q, K, N_LYAP);
    auto t1 = std::chrono::high_resolution_clock::now();
    LyapResult jc = compute_lyapunov_jacobi(seed, p, q, K, N_LYAP);
    auto t2 = std::chrono::high_resolution_clock::now();
    
    double gs_sec = std::chrono::duration<double>(t1-t0).count();
    double jc_sec = std::chrono::duration<double>(t2-t1).count();
    
    printf("                              Measured        Paper claim\n");
    printf("  lambda_1 (GS):              %.4f          5.78\n", gs.l1);
    printf("  lambda_2 (GS):              %.4f          (not stated)\n", gs.l2);
    printf("  lambda_1 (Jacobi):          %.4f          3.59\n", jc.l1);
    printf("  lambda_2 (Jacobi):          %.4f          (not stated)\n", jc.l2);
    printf("  Ratio lambda_GS/lambda_J:   %.4f          1.61\n", gs.l1/jc.l1);
    printf("  Sum lambda_1+lambda_2 GS:   %.4f          6.80\n", gs.l1+gs.l2);
    printf("  Sum lambda_1+lambda_2 J:    %.4f          6.35\n", jc.l1+jc.l2);
    printf("  (GS measurement time:       %.2fs)\n", gs_sec);
    printf("  (J  measurement time:       %.2fs)\n\n", jc_sec);
    
    // ===========================================================
    // Section VI.C: Chaos Barrier
    // ===========================================================
    printf("Section VI.C - Chaos Barrier:\n");
    printf("---------------------------------------------------------------\n");
    double lambda = gs.l1;
    double B = 10000;
    double barrier = lambda * B / std::log(10.0);
    printf("  Chaos Barrier exponent: %.2f  (Paper: ~25,102)\n\n", barrier);
    
    double eps = std::ldexp(1.0, -52);
    printf("  Error growth |error(t)| = eps * exp(lambda * t):\n");
    printf("  eps = 2^-52 = %.4e\n", eps);
    double barrier_t7 = 0.0;
    for (int t : {7, 10, 20}) {
        double err = eps * std::exp(lambda * t);
        if (t == 7) barrier_t7 = err;
        printf("  t=%-2d:  %.4e\n", t, err);
    }
    printf("  Paper claims: t=7 -> ~83 (matches actual ~82.8)\n");
    printf("                t=10 -> ~10^9\n");
    printf("                t=20 -> ~10^34\n\n");

    // ===========================================================
    // v7.0.1: ASSERT the reproduced DYNAMICAL claims, not only the KATs.
    // Before this, the values above were printed vs the paper column but
    // never checked, so the "paper claims reproduced" verdict rested on the
    // KAT CRCs alone. Tolerances bound the run-to-run Lyapunov noise (a few
    // 1e-3) with margin, while still catching any real regression.
    // ===========================================================
    printf("Dynamical-claim checks (measured vs Paper 4, with tolerance):\n");
    printf("---------------------------------------------------------------\n");
    bool dyn_pass = true;
    auto dyn_check = [&](const char* name, double got, double want, double tol) {
        bool ok = std::fabs(got - want) <= tol;
        if (!ok) dyn_pass = false;
        printf("  [%s] %-28s measured=%.4f  paper=%.4f  (tol %.3f)\n",
               ok ? "PASS" : "FAIL", name, got, want, tol);
    };
    dyn_check("lambda_1 (GS)",       gs.l1,        5.78, 0.05);
    dyn_check("lambda_1 (Jacobi)",   jc.l1,        3.59, 0.05);
    dyn_check("ratio GS/Jacobi",     gs.l1/jc.l1,  1.61, 0.03);
    dyn_check("chaos barrier t=7",   barrier_t7,   82.8, 8.0);
    printf("\n");
    
    // ===========================================================
    // KAT Verification (Test Vectors from Appendix)
    // ===========================================================
    printf("KAT Verification (Test Vectors from Appendix):\n");
    printf("---------------------------------------------------------------\n");
    bool all_pass = true;
    for (const auto& kat : mcl_kat_vectors) {
        MCL_T2 engine(kat.seed, kat.p, kat.q, K_DEFAULT);
        std::vector<uint8_t> buf(kat.n_bytes);
        engine.gen_bytes(buf.data(), static_cast<int64_t>(kat.n_bytes));
        uint32_t crc = compute_crc32(buf.data(), kat.n_bytes);
        uint32_t expected = mcl_kat_expected_crc(kat);
        const char* status = (crc == expected) ? "PASS" : "FAIL";
        if (crc != expected) all_pass = false;
        printf("  [%s] %-45s  CRC=0x%08X (expect 0x%08X)\n",
               status, kat.description, crc, expected);
    }
    printf("\n");
    printf("===============================================================\n");
    // Honest verdict: BOTH the KAT byte streams AND the reproduced dynamical
    // claims (lambda, ratio, chaos barrier) must hold.
    bool overall = all_pass && dyn_pass;
    if (overall) {
        printf("RESULT: KAT vectors PASS and dynamical claims reproduced within tolerance.\n");
    } else {
        printf("RESULT: FAILED -- %s%s%s.\n",
               all_pass ? "" : "KAT vector(s) mismatched",
               (!all_pass && !dyn_pass) ? "; " : "",
               dyn_pass ? "" : "dynamical claim(s) outside tolerance");
    }
    printf("===============================================================\n");

    return overall ? 0 : 1;
}
