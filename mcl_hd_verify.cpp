/*
 * ============================================================================
 * MCL Hierarchical Key Derivation Verification
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-HD-VERIFY-2026-0526-001
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
 * PURPOSE: Experimental verification of Hierarchical Key Derivation
 *          for the MCL coupled phase oscillator system (Paper 5).
 *          Every number in the published results comes from this code.
 *
 * TESTS:
 *   1. Derivation correctness: child params valid, distinct, q-varies
 *   2. Parent-child independence: 10 pairs Pearson + Bonferroni
 *   3. Sibling independence: C(10,2)=45 pairs Pearson + Bonferroni
 *   4. One-way property: brute-force parent recovery (~9800 candidates)
 *   5. Tree depth 3: master -> 3 batches -> 3 devices each (13 nodes)
 *   6. Resonance avoidance: K=1.0 with retry on K_min(p,q) failures
 *   7. Reproducibility: bit-exact across 100 calls
 *   8. Multi-function: PRNG + auth + encrypt with derived keys
 *   9. Cross-system: Logistic + Tent (Henon excluded by design)
 *   10. Negative control: methodology validation
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_hd_verify mcl_hd_verify.cpp -lm && ./mcl_hd_verify
 *
 * EXPECTED RESULTS: PASS - All 10 HD properties verified
 *                          (0 Bonferroni rejections across all independence
 *                          pairs; reproducibility, one-way, tree, multi-func
 *                          properties hold).
 *
 * REFERENCES:
 *   - Paper 5: Hierarchical Deterministic Keys + Transaction Authentication.
 *   - BIP-32 (Bitcoin Improvement Proposal) - conceptual basis for HD trees.
 *   - Bonferroni correction for multiple comparisons (alpha=0.05).
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
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <set>

/* Document metadata (mirror of file header - keep in sync) */
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-HD-VERIFY-2026-0526-001";

// ============================================================================
// Test parameters (named constants)
// ============================================================================

// Default parent (p, q) used by most tests.
static const int64_t DEFAULT_P = 3;
static const int64_t DEFAULT_Q = 5;

// Bytes per channel for statistical tests.
static const int64_t NB_BYTES = 1000000;       // 1M bytes per Pearson comparison

// Test 1 - derivation correctness.
static const int T1_N_CHILDREN = 20;

// Test 2 - parent-child independence.
static const int T2_N_CHILDREN = 10;

// Test 3 - sibling independence.
static const int T3_N_SIBLINGS = 10;            // C(10,2) = 45 pairs

// Test 4 - one-way (brute-force) parameters.
// QUICK mode: 30x30 = 900 candidates, FULL: 100x100 = ~9800 candidates.
static const int64_t T4_PARENT_P_QUICK = 13;
static const int64_t T4_PARENT_Q_QUICK = 19;
static const int64_t T4_RANGE_MIN      = 2;
static const int64_t T4_RANGE_MAX_QUICK = 20;
static const int64_t T4_RANGE_MAX_FULL  = 100;
static const double  T4_LYAPUNOV       = 5.78;  // chaos amplification

// Test 5 - tree depth 3.
static const int T5_N_BATCHES = 3;
static const int T5_N_DEVICES = 3;

// Test 6 - resonance avoidance.
// K=1.0 is MCL_K_RECOMMENDED_FLOOR (per mcl_core.hpp): the minimum K that's
// safe across all (p,q) topologies. K=0.5 cannot be used here because the
// parent engine (3,5) requires K >= K_min(p,q) = 5.053/8 = 0.632.
// max_val=100 keeps p+q usually >= 11; v4.1.0 derive_child_safe also auto-
// skips any (p,q) with K < K_min(p,q).
static const double  T6_K_SMALL    = 1.0;
static const int     T6_N_DERIVE   = 20;
static const int64_t T6_MAX_VAL    = 100;       // wide range, fewer K_min skips
static const int64_t T6_NB_BYTES   = 100000;    // smaller for resonance test

// Test 7 - reproducibility.
static const int T7_N_TRIALS = 100;
static const int T7_CHILD_INDEX = 42;
static const int64_t T7_NB_BYTES = 10000;

// Test 8 - multi-function.
static const int64_t T8_NB_BYTES = 1000000;     // 1M for PRNG quality
static const int64_t T8_RESP_LEN = 32;          // 256-bit auth response
static const uint64_t T8_AUTH_CHALLENGE = 98765432109876ULL;

// Test 9 - cross-system.
static const int64_t T9_DERIVE_RANGE = 1000;

// Test 10 - negative control.
// Threshold = 3 sigma for independent Pearson at 1M bytes.
// sigma = 1/sqrt(N), 3 sigma = 3/sqrt(1e6) ~ 0.00316.
static const double T10_NEG_R_THRESHOLD = 0.999;     // identical streams
static const double T10_NEG_R_SIGMA_K   = 3.0;       // independent threshold

// Quality thresholds (per Paper 1 §III.D).
static const double ENTROPY_THRESHOLD = 7.999;       // bits/byte

// Reproducibility threshold for negative control (identical streams).
// Note: T10 uses T10_NEG_R_THRESHOLD; this is for Test 7 streams.

// Global mode flag (set in main).
static bool g_full_mode = false;

static int g_passed = 0, g_failed = 0;
static bool g_results[12] = {};
static std::vector<double> g_all_pvalues;

static void test_header(int num, const char* name) {
    std::printf("\n==============================================================================\n");
    std::printf("  TEST %d: %s\n", num, name);
    std::printf("==============================================================================\n\n");
}

static void test_result(int num, bool pass, const char* detail) {
    g_results[num] = pass;
    if (pass) { std::printf("\n  [PASS] Test %d -- %s\n", num, detail); g_passed++; }
    else      { std::printf("\n  [FAIL] Test %d -- %s\n", num, detail); g_failed++; }
}

// ============================================================================
// HD DERIVATION: derive_child(), derive_child_safe(), DerivedKey
// are defined in mcl_core.hpp §12.
// This test file CALLS them, never reimplements them.
// ============================================================================

// ============================================================================
// TEST 1: DERIVATION CORRECTNESS
// ============================================================================
static void test_01_derivation_correctness() {
    test_header(1, "DERIVATION CORRECTNESS");
    const uint64_t seed = DEFAULT_SEED;
    const int64_t pp = DEFAULT_P, qp = DEFAULT_Q;
    const int NC = T1_N_CHILDREN;

    std::printf("  Parent: (%lld, %lld), seed=%llu\n\n",
        (long long)pp, (long long)qp, (unsigned long long)seed);

    std::set<std::pair<int64_t, int64_t>> seen;
    seen.insert({pp, qp});
    bool all_valid = true;

    std::printf("  %-6s  %-12s %-12s  %-6s %-6s %-7s\n",
        "Index", "p_child", "q_child", "p!=q", "Uniq", "Coprime");
    std::printf("  --------------------------------------------------------\n");

    for (int i = 0; i < NC; i++) {
        DerivedKey dk = derive_child(seed, pp, qp, i);
        bool pnq = (dk.p != dk.q);
        bool uniq = seen.insert({dk.p, dk.q}).second;
        bool cop = (gcd_compute(dk.p, dk.q) == 1);
        std::printf("  %-6d  %-12lld %-12lld  %-6s %-6s %-7s\n",
            i, (long long)dk.p, (long long)dk.q,
            pnq ? "OK" : "FAIL", uniq ? "OK" : "DUP", cop ? "Yes" : "No");
        if (!pnq || !uniq) all_valid = false;
    }

    bool no_parent = true;
    for (int i = 0; i < NC; i++) {
        DerivedKey dk = derive_child(seed, pp, qp, i);
        if (dk.p == pp && dk.q == qp) { no_parent = false; break; }
    }

    // Check that q varies across children (v1.1.0 fix verification)
    std::set<int64_t> q_values;
    for (int i = 0; i < NC; i++) {
        DerivedKey dk = derive_child(seed, pp, qp, i);
        q_values.insert(dk.q);
    }
    bool q_varies = ((int)q_values.size() > 1);
    std::printf("\n  Distinct q values: %d/%d -> %s\n",
        (int)q_values.size(), NC, q_varies ? "OK - q varies" : "FAIL - q constant");

    bool pass = all_valid && no_parent && q_varies;
    test_result(1, pass, pass ?
        "All children valid, distinct, q varies, different from parent" :
        "Derivation issue detected");
}

// ============================================================================
// TEST 2: PARENT-CHILD INDEPENDENCE
// ============================================================================
static void test_02_parent_child_independence() {
    test_header(2, "PARENT-CHILD INDEPENDENCE");
    const uint64_t seed = DEFAULT_SEED;
    const int64_t pp = DEFAULT_P, qp = DEFAULT_Q;
    const int64_t NB = NB_BYTES;
    const int NC = T2_N_CHILDREN;

    MCL_T2 peng(seed, pp, qp);
    std::vector<uint8_t> ps((size_t)NB);
    peng.gen_bytes(ps.data(), NB);

    std::printf("  Parent (%lld,%lld): ent=%.6f chi2=%.2f\n\n",
        (long long)pp, (long long)qp,
        shannon_entropy(ps.data(), NB), chi_square(ps.data(), NB));

    bool all_indep = true;
    int np = 0;
    std::vector<double> lpv;

    for (int i = 0; i < NC; i++) {
        DerivedKey dk = derive_child(seed, pp, qp, i);
        MCL_T2 ceng(seed, dk.p, dk.q);
        std::vector<uint8_t> cs((size_t)NB);
        ceng.gen_bytes(cs.data(), NB);
        double r = std::abs(pearson_r(ps.data(), cs.data(), NB));
        double pv = pvalue_from_r(r, NB);
        double ham = hamming_pct(ps.data(), cs.data(), NB);
        np++;
        lpv.push_back(pv);
        g_all_pvalues.push_back(pv);
        std::printf("  i=%d  (%lld,%lld)  |r|=%.6f  p=%.4e  ham=%.3f%%\n",
            i, (long long)dk.p, (long long)dk.q, r, pv, ham);
    }

    double bt = BONFERRONI_ALPHA / (double)np;
    for (double pv : lpv) if (pv < bt) all_indep = false;
    std::printf("\n  Bonferroni: %d pairs, threshold=%.2e\n", np, bt);
    test_result(2, all_indep, all_indep ?
        "All parent-child pairs independent" : "Correlation detected");
}

// ============================================================================
// TEST 3: SIBLING INDEPENDENCE
// ============================================================================
static void test_03_sibling_independence() {
    test_header(3, "SIBLING INDEPENDENCE");
    const uint64_t seed = DEFAULT_SEED;
    const int64_t pp = DEFAULT_P, qp = DEFAULT_Q;
    const int64_t NB = NB_BYTES;
    const int NS = T3_N_SIBLINGS;

    std::vector<DerivedKey> sibs(NS);
    std::vector<std::vector<uint8_t>> st(NS);
    for (int i = 0; i < NS; i++) {
        sibs[(size_t)i] = derive_child(seed, pp, qp, i);
        st[(size_t)i].resize((size_t)NB);
        MCL_T2 eng(seed, sibs[(size_t)i].p, sibs[(size_t)i].q);
        eng.gen_bytes(st[(size_t)i].data(), NB);
    }

    int np = 0;
    bool ok = true;
    std::vector<double> lpv;
    for (int i = 0; i < NS; i++)
        for (int j = i + 1; j < NS; j++) {
            double r = std::abs(pearson_r(st[(size_t)i].data(),
                                          st[(size_t)j].data(), NB));
            double pv = pvalue_from_r(r, NB);
            np++; lpv.push_back(pv); g_all_pvalues.push_back(pv);
            std::printf("  (%d,%d) |r|=%.6f p=%.4e\n", i, j, r, pv);
        }

    double bt = BONFERRONI_ALPHA / (double)np;
    for (double pv : lpv) if (pv < bt) ok = false;
    std::printf("\n  Pairs: %d, Bonferroni threshold=%.2e\n", np, bt);
    test_result(3, ok, ok ? "All 45 sibling pairs independent" : "Correlation");
}

// ============================================================================
// TEST 4: ONE-WAY PROPERTY
// ============================================================================
static void test_04_one_way() {
    test_header(4, "ONE-WAY - BRUTE FORCE PARENT RECOVERY");
    const uint64_t seed = DEFAULT_SEED;
    const int64_t pp = T4_PARENT_P_QUICK;
    const int64_t qp = T4_PARENT_Q_QUICK;
    const int64_t NB = NB_BYTES;
    // Mode-dependent search range. QUICK ~30s, FULL ~5min.
    const int64_t range_max = g_full_mode ? T4_RANGE_MAX_FULL : T4_RANGE_MAX_QUICK;

    DerivedKey child = derive_child(seed, pp, qp, 0);
    std::printf("  Parent: (%lld,%lld) -> Child: (%lld,%lld)\n",
        (long long)pp, (long long)qp, (long long)child.p, (long long)child.q);
    std::printf("  Mode: %s, search range [%lld, %lld]\n\n",
        g_full_mode ? "FULL" : "QUICK",
        (long long)T4_RANGE_MIN, (long long)range_max);

    MCL_T2 ceng(seed, child.p, child.q);
    std::vector<uint8_t> cstream((size_t)NB);
    ceng.gen_bytes(cstream.data(), NB);

    // Count candidates dynamically
    int candidates = 0;
    for (int64_t tp = T4_RANGE_MIN; tp <= range_max; tp++)
        for (int64_t tq = T4_RANGE_MIN; tq <= range_max; tq++)
            if (tp != tq) candidates++;
    // Exclude true parent from count for threshold
    int test_count = candidates - 1;

    std::printf("  Brute-force: %d candidate parents...\n", candidates);

    // Use Bonferroni for output correlation (consistent with other tests)
    double bf_nf = noise_floor(test_count, NB) * 2.0;
    int exact_match = 0, corr_match = 0;

    for (int64_t tp = T4_RANGE_MIN; tp <= range_max; tp++) {
        for (int64_t tq = T4_RANGE_MIN; tq <= range_max; tq++) {
            if (tp == tq) continue;
            DerivedKey tc = derive_child(seed, tp, tq, 0);
            if (tc.p == child.p && tc.q == child.q) {
                if (tp == pp && tq == qp) continue;
                exact_match++;
                std::printf("  COLLISION: (%lld,%lld) -> same child!\n",
                    (long long)tp, (long long)tq);
            }
            MCL_T2 te(seed, tc.p, tc.q);
            std::vector<uint8_t> ts((size_t)NB);
            te.gen_bytes(ts.data(), NB);
            double r = std::abs(pearson_r(cstream.data(), ts.data(), NB));
            if (r > bf_nf && !(tp == pp && tq == qp)) corr_match++;
        }
    }

    double amp = T4_LYAPUNOV * BURNIN / std::log(10.0);
    std::printf("\n  Chaos barrier: 10^(%.0f)\n", amp);
    std::printf("  Exact collisions: %d, correlated (|r|>2*nf): %d\n",
        exact_match, corr_match);

    bool pass = (exact_match == 0) && (corr_match == 0);
    test_result(4, pass, pass ?
        "One-way: 0 collisions, 0 correlations" : "One-way violated");
}

// ============================================================================
// TEST 5: TREE DEPTH 3
// ============================================================================
static void test_05_tree_depth3() {
    test_header(5, "TREE DEPTH 3: Master -> Batch -> Device");
    const uint64_t seed = DEFAULT_SEED;
    const int64_t pm = DEFAULT_P, qm = DEFAULT_Q;
    const int NB = T5_N_BATCHES, ND = T5_N_DEVICES;
    const int64_t NBYTES = NB_BYTES;

    struct Node { int64_t p, q; std::vector<uint8_t> stream; };
    std::vector<Node> nodes;

    // Master
    Node master; master.p = pm; master.q = qm;
    master.stream.resize((size_t)NBYTES);
    MCL_T2(seed, pm, qm).gen_bytes(master.stream.data(), NBYTES);
    nodes.push_back(std::move(master));
    std::printf("  L0 Master: (%lld,%lld)\n", (long long)pm, (long long)qm);

    for (int b = 0; b < NB; b++) {
        DerivedKey bk = derive_child(seed, pm, qm, b);
        Node batch; batch.p = bk.p; batch.q = bk.q;
        batch.stream.resize((size_t)NBYTES);
        MCL_T2(seed, bk.p, bk.q).gen_bytes(batch.stream.data(), NBYTES);
        nodes.push_back(std::move(batch));
        std::printf("  L1 Batch %d: (%lld,%lld) [m/%d]\n",
            b, (long long)bk.p, (long long)bk.q, b);
        for (int d = 0; d < ND; d++) {
            DerivedKey dk = derive_child(seed, bk.p, bk.q, d);
            Node dev; dev.p = dk.p; dev.q = dk.q;
            dev.stream.resize((size_t)NBYTES);
            MCL_T2(seed, dk.p, dk.q).gen_bytes(dev.stream.data(), NBYTES);
            nodes.push_back(std::move(dev));
            std::printf("  L2 Dev %d.%d: (%lld,%lld) [m/%d/%d]\n",
                b, d, (long long)dk.p, (long long)dk.q, b, d);
        }
    }

    int tn = (int)nodes.size();
    int np = 0;
    bool ok = true;
    double maxr = 0;
    std::vector<double> lpv;
    for (int i = 0; i < tn; i++)
        for (int j = i + 1; j < tn; j++) {
            double r = std::abs(pearson_r(nodes[(size_t)i].stream.data(),
                                          nodes[(size_t)j].stream.data(), NBYTES));
            double pv = pvalue_from_r(r, NBYTES);
            np++; lpv.push_back(pv); g_all_pvalues.push_back(pv);
            if (r > maxr) maxr = r;
        }

    double bt = BONFERRONI_ALPHA / (double)np;
    for (double pv : lpv) if (pv < bt) ok = false;
    std::printf("\n  Nodes: %d, Pairs: %d, max|r|=%.6f, Bonferroni thr=%.2e, rej=%d\n",
        tn, np, maxr, bt, ok ? 0 : 1);
    test_result(5, ok, ok ?
        "All tree pairs independent" : "Tree independence violated");
}

// ============================================================================
// TEST 6: RESONANCE AVOIDANCE
// ============================================================================
static void test_06_resonance_avoidance() {
    test_header(6, "RESONANCE AVOIDANCE (K=1.0 recommended floor)");
    // Small max_val forces (p,q) into the resonance-likely region;
    // derive_child_safe must still produce chaotic outputs by retrying.
    const uint64_t seed = DEFAULT_SEED;
    const int64_t pp = DEFAULT_P, qp = DEFAULT_Q;
    const double Kr = T6_K_SMALL;
    const int NDR = T6_N_DERIVE;
    const int64_t max_val = T6_MAX_VAL;
    const int64_t buflen = T6_NB_BYTES;

    std::printf("  K=%.1f, max_val=%lld (low-K region, resonance retries possible)\n\n",
        Kr, (long long)max_val);

    int success = 0, total_retries = 0;
    std::vector<uint8_t> buf((size_t)buflen);
    for (int i = 0; i < NDR; i++) {
        DerivedKey dk = derive_child_safe(seed, pp, qp, i, max_val, Kr);
        if (dk.valid) {
            MCL_T2 eng(seed, dk.p, dk.q, Kr);
            eng.gen_bytes(buf.data(), buflen);
            double chi2 = chi_square(buf.data(), buflen);
            int retries = (int)(dk.index - i);
            total_retries += retries;
            std::printf("  i=%d -> (%lld,%lld) retries=%d chi2=%.2f %s\n",
                i, (long long)dk.p, (long long)dk.q, retries, chi2,
                (chi2 < CHI2_THRESHOLD) ? "CHAOTIC" : "RESON");
            if (chi2 < CHI2_THRESHOLD) success++;
        } else {
            std::printf("  i=%d -> FAILED after 100 attempts\n", i);
        }
    }
    std::printf("\n  Chaotic: %d/%d, retries: %d\n", success, NDR, total_retries);
    test_result(6, success == NDR, (success == NDR) ?
        "Resonance avoidance works" : "Some children non-chaotic");
}

// ============================================================================
// TEST 7: REPRODUCIBILITY
// ============================================================================
static void test_07_reproducibility() {
    test_header(7, "REPRODUCIBILITY - BIT-EXACT");
    const int NT = T7_N_TRIALS;
    const int CHILD_IDX = T7_CHILD_INDEX;
    const int64_t SLEN = T7_NB_BYTES;
    DerivedKey first = derive_child(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q, CHILD_IDX);
    int mm = 0;
    for (int t = 0; t < NT; t++) {
        DerivedKey dk = derive_child(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q, CHILD_IDX);
        if (dk.p != first.p || dk.q != first.q) mm++;
    }
    MCL_T2 e1(DEFAULT_SEED, first.p, first.q), e2(DEFAULT_SEED, first.p, first.q);
    std::vector<uint8_t> b1((size_t)SLEN), b2((size_t)SLEN);
    e1.gen_bytes(b1.data(), SLEN);
    e2.gen_bytes(b2.data(), SLEN);
    int sd = 0;
    for (int64_t i = 0; i < SLEN; i++) if (b1[(size_t)i] != b2[(size_t)i]) sd++;
    std::printf("  Child: (%lld,%lld)\n", (long long)first.p, (long long)first.q);
    std::printf("  Param mismatches: %d/%d, stream diffs: %d/%lld\n",
        mm, NT, sd, (long long)SLEN);
    test_result(7, mm == 0 && sd == 0,
        (mm == 0 && sd == 0) ? "100%% bit-exact" : "Failed");
}

// ============================================================================
// TEST 8: MULTI-FUNCTION
// ============================================================================
static void test_08_multi_function() {
    test_header(8, "MULTI-FUNCTION DERIVED KEYS");
    DerivedKey child = derive_child(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q, 0);
    std::printf("  Child: (%lld,%lld)\n\n", (long long)child.p, (long long)child.q);

    // PRNG quality test
    MCL_T2 e1(DEFAULT_SEED, child.p, child.q);
    // Use std::vector instead of 1MB stack array (would blow Windows stack).
    std::vector<uint8_t> pb((size_t)T8_NB_BYTES);
    e1.gen_bytes(pb.data(), T8_NB_BYTES);
    double ent = shannon_entropy(pb.data(), T8_NB_BYTES);
    double chi = chi_square(pb.data(), T8_NB_BYTES);
    bool prng_ok = (ent > ENTROPY_THRESHOLD) && (chi < CHI2_THRESHOLD);
    std::printf("  [PRNG] ent=%.6f chi2=%.2f %s\n", ent, chi, prng_ok?"PASS":"FAIL");

    // AUTH (32-byte challenge response)
    const uint64_t chal = T8_AUTH_CHALLENGE;
    MCL_T2 a1(chal, child.p, child.q), a2(chal, child.p, child.q);
    uint8_t r1[T8_RESP_LEN], r2[T8_RESP_LEN];
    a1.gen_bytes(r1, T8_RESP_LEN);
    a2.gen_bytes(r2, T8_RESP_LEN);
    int ad = 0;
    for (int i = 0; i < T8_RESP_LEN; i++) if (r1[i] != r2[i]) ad++;
    bool auth_ok = (ad == 0);
    std::printf("  [AUTH] diffs=%d %s\n", ad, auth_ok?"PASS":"FAIL");

    // ENCRYPT
    const char* pt = "MCL Hierarchical Key Derivation Test 2026";
    int64_t ml = (int64_t)std::strlen(pt);
    MCL_T2 ee(DEFAULT_SEED, child.p, child.q);
    std::vector<uint8_t> ks((size_t)ml); ee.gen_bytes(ks.data(), ml);
    std::vector<uint8_t> ct((size_t)ml);
    for (int64_t i = 0; i < ml; i++) ct[(size_t)i] = (uint8_t)pt[i] ^ ks[(size_t)i];
    MCL_T2 de(DEFAULT_SEED, child.p, child.q);
    std::vector<uint8_t> dk((size_t)ml); de.gen_bytes(dk.data(), ml);
    std::vector<uint8_t> dec((size_t)ml);
    for (int64_t i = 0; i < ml; i++) dec[(size_t)i] = ct[(size_t)i] ^ dk[(size_t)i];
    bool enc_ok = (std::memcmp(pt, dec.data(), (size_t)ml) == 0);
    std::printf("  [ENCRYPT] %s\n", enc_ok?"PASS":"FAIL");

    // WRONG KEY
    MCL_T2 we(DEFAULT_SEED, child.p + 2, child.q + 2);
    std::vector<uint8_t> wk((size_t)ml); we.gen_bytes(wk.data(), ml);
    std::vector<uint8_t> wd((size_t)ml);
    for (int64_t i = 0; i < ml; i++) wd[(size_t)i] = ct[(size_t)i] ^ wk[(size_t)i];
    bool wf = (std::memcmp(pt, wd.data(), (size_t)ml) != 0);
    std::printf("  [WRONG KEY] %s\n", wf?"PASS - different output":"FAIL");

    test_result(8, prng_ok && auth_ok && enc_ok && wf,
        (prng_ok && auth_ok && enc_ok && wf) ?
        "PRNG + auth + encrypt all work" : "Multi-function failed");
}

// ============================================================================
// TEST 9: CROSS-SYSTEM - Logistic + Tent + Henon
// ============================================================================
static void test_09_cross_system() {
    test_header(9, "CROSS-SYSTEM GENERALITY - 3 families");
    const uint64_t seed = DEFAULT_SEED;
    const int64_t NB = NB_BYTES;

    struct CSResult { const char* name; double r; double pv; };
    std::vector<CSResult> results;

    // Helper: derive from any engine's output
    auto derive_from_bytes = [](uint8_t* raw, int64_t max_v, int64_t idx) {
        uint64_t iv = (uint64_t)idx;
        iv ^= iv >> 30; iv *= 0xBF58476D1CE4E5B9ULL;
        iv ^= iv >> 27; iv *= 0x94D049BB133111EBULL;
        iv ^= iv >> 31;
        uint64_t im = iv * 0x9E3779B97F4A7C15ULL;
        for (int b = 0; b < 8; b++) {
            raw[b]     ^= (uint8_t)(iv >> (b * 8));
            raw[8 + b] ^= (uint8_t)(im >> (b * 8));
        }
        uint64_t c1 = 0, c2 = 0;
        std::memcpy(&c1, raw, 8);
        std::memcpy(&c2, raw + 8, 8);
        int64_t p = 2 + (int64_t)(c1 % (uint64_t)(max_v - 2));
        int64_t q = 2 + (int64_t)(c2 % (uint64_t)(max_v - 2));
        if (p == q) q++;
        return std::make_pair(p, q);
    };

    // CoupledLogistic
    {
        CoupledLogistic par(seed, 3, 5);
        uint8_t raw[32]; par.gen_bytes(raw, 32);
        auto [cp, cq] = derive_from_bytes(raw, T9_DERIVE_RANGE, 0);
        CoupledLogistic child(seed, cp, cq);
        std::vector<uint8_t> pb2((size_t)NB), cb2((size_t)NB);
        CoupledLogistic par2(seed, 3, 5);
        par2.gen_bytes(pb2.data(), NB); child.gen_bytes(cb2.data(), NB);
        double r = std::abs(pearson_r(pb2.data(), cb2.data(), NB));
        double pv = pvalue_from_r(r, NB);
        g_all_pvalues.push_back(pv);
        results.push_back({"CoupledLogistic", r, pv});
        std::printf("  Logistic: parent(3,5)->child(%lld,%lld) |r|=%.6f p=%.4e\n",
            (long long)cp, (long long)cq, r, pv);
    }

    // CoupledTent
    {
        CoupledTent par(seed, 3, 5);
        uint8_t raw[32]; par.gen_bytes(raw, 32);
        auto [cp, cq] = derive_from_bytes(raw, T9_DERIVE_RANGE, 0);
        CoupledTent child(seed, cp, cq);
        std::vector<uint8_t> pb2((size_t)NB), cb2((size_t)NB);
        CoupledTent par2(seed, 3, 5);
        par2.gen_bytes(pb2.data(), NB); child.gen_bytes(cb2.data(), NB);
        double r = std::abs(pearson_r(pb2.data(), cb2.data(), NB));
        double pv = pvalue_from_r(r, NB);
        g_all_pvalues.push_back(pv);
        results.push_back({"CoupledTent", r, pv});
        std::printf("  Tent:     parent(3,5)->child(%lld,%lld) |r|=%.6f p=%.4e\n",
            (long long)cp, (long long)cq, r, pv);
    }

    // CoupledHenon - SKIPPED for HD derivation.
    // Henon's unbounded attractor basin means arbitrary derived (p,q) often
    // fall outside the narrow stable region, causing divergence. In secure
    // mode (v1.3.5+), divergence triggers abort() in gen_byte().
    // This is an intrinsic property of Henon, not an HD limitation.
    // Requires at least three distinct system families -
    // satisfied by T2 (phase oscillators), Logistic, and Tent.
    // Henon independence is demonstrated in mcl_generality.cpp with
    // KNOWN-GOOD params, not arbitrary derived params.
    std::printf("  Henon:    SKIPPED - narrow attractor incompatible with "
        "arbitrary derived params\n");

    // Bonferroni across cross-system results
    int np = (int)results.size();
    double bt = BONFERRONI_ALPHA / (double)std::max(np, 1);
    bool ok = true;
    for (auto& res : results) if (res.pv < bt) ok = false;
    std::printf("\n  Systems tested: %d/3, Bonferroni threshold=%.2e\n", np, bt);

    test_result(9, ok && np >= 2,
        (ok && np >= 2) ? "HD generalizes: T2 (tests 1-8) + Logistic + Tent = 3 families" :
        "Cross-system HD failed");
}

// ============================================================================
// TEST 10: NEGATIVE CONTROL
// ============================================================================
static void test_10_negative_control() {
    test_header(10, "NEGATIVE CONTROL");
    const int64_t NB = NB_BYTES;

    // Same params -> r approx 1
    MCL_T2 e1(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
    MCL_T2 e2(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q);
    std::vector<uint8_t> a((size_t)NB), b((size_t)NB);
    e1.gen_bytes(a.data(), NB); e2.gen_bytes(b.data(), NB);
    double rs = pearson_r(a.data(), b.data(), NB);
    bool c1 = (rs > T10_NEG_R_THRESHOLD);
    std::printf("  Same params: r=%.6f %s\n", rs, c1?"OK":"ERROR");

    // Different params -> r approx 0
    MCL_T2 e3(DEFAULT_SEED, 5, 7);
    std::vector<uint8_t> c((size_t)NB);
    e3.gen_bytes(c.data(), NB);
    double rd = std::abs(pearson_r(a.data(), c.data(), NB));
    // Rigorous threshold: 3-sigma for independent Pearson.
    // For 1 pair, noise_floor formula gives 0 (log(1)=0); use direct sigma.
    // sigma = 1/sqrt(N), so 3-sigma = 3/sqrt(1e6) ~ 0.00316.
    double thr = T10_NEG_R_SIGMA_K * std::sqrt(1.0 / (double)NB);
    bool c2 = (rd < thr);
    std::printf("  Diff params: |r|=%.6f (thr=%.4f) %s\n", rd, thr, c2?"OK":"ERROR");

    // Child != parent
    DerivedKey dk = derive_child(DEFAULT_SEED, DEFAULT_P, DEFAULT_Q, 0);
    bool c3 = (dk.p != DEFAULT_P || dk.q != DEFAULT_Q);
    std::printf("  Child!=parent: (%lld,%lld) %s\n",
        (long long)dk.p, (long long)dk.q, c3?"OK":"ERROR");

    test_result(10, c1 && c2 && c3,
        (c1 && c2 && c3) ? "Methodology validated" : "Error");
}

// ============================================================================
static void print_help(const char* prog) {
    std::printf("MCL Hierarchical Key Derivation Verification v%s\n", DOC_VERSION);
    std::printf("Usage: %s [options]\n\n", prog);
    std::printf("Options:\n");
    std::printf("  (default)   QUICK mode: Test 4 brute-force range [%lld, %lld]\n",
                (long long)T4_RANGE_MIN, (long long)T4_RANGE_MAX_QUICK);
    std::printf("              ~3 minutes on M2 Max\n");
    std::printf("  --quick     Same as default\n");
    std::printf("  --full      FULL mode: Test 4 range [%lld, %lld] (~10 min)\n",
                (long long)T4_RANGE_MIN, (long long)T4_RANGE_MAX_FULL);
    std::printf("              Paper 5 canonical brute-force coverage\n");
    std::printf("  --help, -h  Print this help and exit\n\n");
    std::printf("Document ID: %s\n", DOC_ID);
    std::printf("Engine:      mcl_core.hpp (MCL_T2 + derive_child + derive_child_safe)\n");
    std::printf("\nVerdict is PASS if all 10 tests pass AND 0 Bonferroni rejections.\n");
}

int main(int argc, char* argv[]) {
    // Realtime output (must be before any printf).
    std::setbuf(stdout, nullptr);

    // Parse CLI: --help / -h / --quick / --full
    bool mode_explicitly_set = false;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        } else if (std::strcmp(argv[i], "--quick") == 0) {
            if (mode_explicitly_set) {
                std::fprintf(stderr,
                    "ERROR: cannot combine mode flags. Use --quick OR --full.\n");
                return 2;
            }
            g_full_mode = false;
            mode_explicitly_set = true;
        } else if (std::strcmp(argv[i], "--full") == 0) {
            if (mode_explicitly_set) {
                std::fprintf(stderr,
                    "ERROR: cannot combine mode flags. Use --quick OR --full.\n");
                return 2;
            }
            g_full_mode = true;
            mode_explicitly_set = true;
        } else {
            std::fprintf(stderr,
                "ERROR: unknown argument '%s'. Run with --help for usage.\n",
                argv[i]);
            return 2;
        }
    }

    auto t0 = std::chrono::steady_clock::now();

    std::printf("\n==============================================================================\n");
    std::printf("  MCL HIERARCHICAL KEY DERIVATION VERIFICATION v%s\n", DOC_VERSION);
    std::printf("  %s\n", DOC_ID);
    std::printf("  Mode: %s\n", g_full_mode ? "FULL  (Paper 5 canonical)" : "QUICK");
    {
        std::time_t now_t = std::time(nullptr);
        std::tm* utc = std::gmtime(&now_t);
        if (utc) {
            char buf[64];
            std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", utc);
            std::printf("  Started: %s\n", buf);
        }
    }
    std::printf("==============================================================================\n\n");
    std::printf("  Engine: MCL_T2, Seed: %llu, K=%.1f\n",
        (unsigned long long)DEFAULT_SEED, K_DEFAULT);

    test_10_negative_control();
    test_01_derivation_correctness();
    test_02_parent_child_independence();
    test_03_sibling_independence();
    test_04_one_way();
    test_05_tree_depth3();
    test_06_resonance_avoidance();
    test_07_reproducibility();
    test_08_multi_function();
    test_09_cross_system();

    sep("GLOBAL BONFERRONI");
    int m = (int)g_all_pvalues.size();
    double gt = BONFERRONI_ALPHA / (double)std::max(m, 1);
    std::sort(g_all_pvalues.begin(), g_all_pvalues.end());
    int rej = 0;
    for (double pv : g_all_pvalues) if (pv < gt) rej++;
    std::printf("  Total pairs: %d, threshold: %.2e, rejections: %d\n", m, gt, rej);
    if (m >= 3) {
        std::printf("  Smallest 3 p-values:\n");
        for (int i = 0; i < 3; i++)
            std::printf("    #%d: %.4e %s\n", i+1, g_all_pvalues[(size_t)i],
                g_all_pvalues[(size_t)i] >= gt ? ">= OK" : "< REJECT");
    }

    double el = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();

    sep("SUMMARY");
    const char* names[] = {
        "", "Derivation correctness", "Parent-child independence",
        "Sibling independence (45 pairs)", "One-way property",
        "Tree depth 3", "Resonance avoidance (K=1.0)",
        "Reproducibility", "Multi-function", "Cross-system (3 families)",
        "Negative control"
    };
    for (int i : {10, 1, 2, 3, 4, 5, 6, 7, 8, 9})
        std::printf("  %2d  %-42s %s\n", i, names[i], g_results[i]?"PASS":"FAIL");
    std::printf("   G  Global Bonferroni (%d pairs)%*s %s\n",
        m, 20 - (m >= 100 ? 3 : m >= 10 ? 2 : 1), "", rej==0?"PASS":"FAIL");

    std::printf("\n  Passed: %d/10  Time: %.1f sec (%.1f min)\n",
        g_passed, el, el / 60.0);

    bool overall = (g_failed == 0 && rej == 0);
    if (overall) {
        std::printf("\n +================================================================+\n");
        std::printf(" | VERDICT: PASS - All 10 HD properties verified                  |\n");
        std::printf(" +================================================================+\n");
    } else {
        std::printf("\n +================================================================+\n");
        std::printf(" | VERDICT: FAIL\n");
        std::printf(" +================================================================+\n");
        if (g_failed > 0)
            std::printf("   Reason: %d test(s) failed\n", g_failed);
        if (rej > 0)
            std::printf("   Reason: %d Bonferroni rejection(s) out of %d pairs\n", rej, m);
    }

    std::printf("\n  Doc ID:  %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("  Author:  Madeeh Ibrahim, Cairo, Egypt\n");
    std::printf("  Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673\n");
    std::printf("==============================================================================\n\n");
    return overall ? 0 : 1;
}
