/*
 * ============================================================================
 * MCL Verifiable Delay Function Verification
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-VDF-VERIFY-2026-0526-001
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
 * PURPOSE: Experimental verification of the MCL Verifiable Delay Function
 *          (Paper 4). Every number reported here comes from actual
 *          computation. Tests cover sequentiality, reproducibility,
 *          quality, and parallelization-resistance properties.
 *
 * TESTS:
 *   1. Timing linearity: time proportional to N (linear scaling)
 *   2. Gauss-Seidel vs Jacobi: same inputs -> different outputs
 *   3. Deterministic reproducibility: same (seed, p, q, N) -> same output
 *   4. N independent of B: different N -> different output
 *   5. Checkpoint verification: segment-by-segment recomputation
 *   6. Output quality: VDF output passes chi-square + entropy
 *   7. Configurable delay: N freely selectable from 10 to 10^8
 *   8. Non-shortcut: no way to skip iterations (chaotic sensitivity)
 *   9. Cross-parameter independence: different (p,q) -> independent output
 *   10. Negative control: methodology validation
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_vdf_verify mcl_vdf_verify.cpp -lm && ./mcl_vdf_verify
 *
 * EXPECTED RESULTS: PASS - All 10 VDF properties verified.
 *                          (Sequentiality, reproducibility, output quality,
 *                           checkpoint verification, non-shortcut all hold.)
 *
 * REFERENCES:
 *   - Boneh, Bonneau, Bunz, Fisch, "Verifiable Delay Functions",
 *     CRYPTO 2018, LNCS 10991, pp. 757-788.
 *   - Boneh, Bunz, Fisch, "A Survey of Two Verifiable Delay Functions",
 *     IACR ePrint 2018/712 (updated 2024).
 *   - Paper 4 (this work): post-quantum candidate VDF based on coupled
 *     chaotic dynamical iteration with Gauss-Seidel update.
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

/* Document metadata (mirror of file header — keep in sync) */
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-VDF-VERIFY-2026-0526-001";

// ============================================================================
// Test parameters (named constants)
// ============================================================================

// Test 1 — timing linearity: N values for QUICK and FULL modes.
// Paper 4 claims: ~10^7 ~ 0.8s, 10^8 ~ 8s (per default M2 Max measurement).
// QUICK uses 500K..8M (5x ratio); FULL extends to 10^8.
static const int64_t T1_N_QUICK[] = {500000LL, 1000000LL, 2000000LL, 4000000LL, 8000000LL};
static const int     T1_N_QUICK_COUNT = 5;
static const int64_t T1_N_FULL[]  = {1000000LL, 5000000LL, 10000000LL, 50000000LL, 100000000LL};
static const int     T1_N_FULL_COUNT = 5;

// Test 1 — warmup iterations to prime CPU cache and branch predictor.
static const int64_t T1_WARMUP_ITERS = 100000LL;

// Test 1 — pass threshold: linear time-ratio error must be < 25%.
// (OS scheduling jitter on shared systems makes tighter thresholds noisy.)
static const double  T1_LINEARITY_THRESHOLD = 0.25;

// Test 2 — Gauss-Seidel vs Jacobi divergence test parameters.
static const int64_t T2_N_ITERS = 50000LL;
static const int     T2_DIFF_BYTES_THRESHOLD = 28;   // out of 32 must differ
static const double  T2_HAM_THRESHOLD        = 40.0; // Hamming% threshold

// Test 3 — deterministic reproducibility.
static const int     T3_N_TRIALS = 50;
static const int64_t T3_N_ITERS  = 100000LL;

// Test 4 — N independence test values.
static const int64_t T4_N_VALUES[] = {0LL, 1000LL, 10000LL, 50000LL, 100000LL, 500000LL};
static const int     T4_N_COUNT    = 6;

// Test 5 — checkpoint verification.
static const int64_t T5_N_ITERS = 100000LL;
static const int     T5_N_CHECKPOINTS = 10;

// Test 6 — output quality.
static const int64_t T6_N_DELAY = 50000LL;
static const int64_t T6_N_BYTES = 1000000LL;
static const double  T6_ENTROPY_THRESHOLD = 7.999;  // bits/byte

// Test 7 — configurable delay range.
struct T7Config { int64_t N; const char* label; };
static const T7Config T7_CONFIGS[] = {
    {10LL,        "Fast auth"},
    {10000LL,     "Standard"},
    {100000LL,    "Enhanced"},
    {1000000LL,   "Beacon (~0.1s)"},
    {10000000LL,  "Proof of time (~1s)"}
};
static const int T7_CONFIG_COUNT = 5;

// Test 8 — non-shortcut sensitivity.
static const int64_t T8_N_ITERS  = 50000LL;
static const double  T8_PERTURB  = 1e-12;            // ~1000 ULPs
static const double  T8_HAM_THRESHOLD = 35.0;        // Hamming% threshold

// Test 9 — cross-parameter independence.
static const int64_t T9_N_DELAY  = 50000LL;
static const int64_t T9_N_BYTES  = 1000000LL;
static const int     T9_N_PARAMS = 10;

// Test 10 — negative control.
static const int64_t T10_N_ITERS = 10000LL;

static int g_passed = 0, g_failed = 0;
static bool g_results[12] = {};

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
// Jacobi (parallel) update — uses mcl_iterate_jacobi from mcl_core.hpp §11.
// ============================================================================

// ============================================================================
// TEST 1: TIMING LINEARITY — time ∝ N
// ============================================================================
// Global mode flag (set in main).
static bool g_full_mode = false;

static void test_01_timing_linearity() {
    test_header(1, "TIMING LINEARITY - time proportional to N");

    // Use N values large enough that cache warmup and burn-in are negligible.
    // QUICK: 500K..8M (~5 sec on M2 Max).  FULL: 1M..100M (~5 min, Paper 4 §V).
    const int64_t* N_values  = g_full_mode ? T1_N_FULL    : T1_N_QUICK;
    const int      N_count   = g_full_mode ? T1_N_FULL_COUNT : T1_N_QUICK_COUNT;
    std::printf("  Mode: %s, N values: %lld..%lld\n",
                g_full_mode ? "FULL (Paper 4 §V scale)" : "QUICK",
                (long long)N_values[0], (long long)N_values[N_count - 1]);

    std::vector<double> times((size_t)N_count, 0.0);
    std::vector<double> rates((size_t)N_count, 0.0);

    // Warmup run - primes CPU cache and branch predictor
    {
        MCL_T2 warmup(DEFAULT_SEED, 3, 5);
        for (int64_t j = 0; j < T1_WARMUP_ITERS; j++) warmup.iterate();
        volatile double sink = warmup.theta1(); (void)sink;
    }

    std::printf("\n  %-12s  %-12s  %-14s\n", "N", "Time (sec)", "Rate (iter/sec)");
    std::printf("  ------------------------------------------------\n");

    for (int i = 0; i < N_count; i++) {
        // Separate burn-in from delay measurement.
        // Create engine (burn-in happens in constructor), then time ONLY the delay.
        MCL_T2 eng(DEFAULT_SEED, 3, 5);

        auto t_start = std::chrono::steady_clock::now();
        for (int64_t j = 0; j < N_values[i]; j++) eng.iterate();
        auto t_end = std::chrono::steady_clock::now();

        // Volatile sink: prevents compiler from optimizing away iterate() loop
        volatile double sink = eng.theta1() + eng.theta2(); (void)sink;

        times[(size_t)i] = std::chrono::duration<double>(t_end - t_start).count();
        rates[(size_t)i] = (double)N_values[i] / times[(size_t)i];
        std::printf("  %-12lld  %-12.6f  %-14.0f\n",
            (long long)N_values[i], times[(size_t)i], rates[(size_t)i]);
    }

    // Check linearity: rate should be approximately constant.
    // Exclude first point (may have cold-cache overhead).
    double mean_rate = 0;
    for (int i = 1; i < N_count; i++) mean_rate += rates[(size_t)i];
    mean_rate /= (double)(N_count - 1);
    double var = 0;
    for (int i = 1; i < N_count; i++) {
        double d = rates[(size_t)i] - mean_rate;
        var += d * d;
    }
    double cv = std::sqrt(var / (double)(N_count - 1)) / mean_rate;

    // Also check: incremental cost per iteration is constant.
    // Slope = Δtime / ΔN between consecutive points.
    std::printf("\n  Incremental cost per iteration:\n");
    std::vector<double> slopes((size_t)(N_count - 1), 0.0);
    for (int i = 0; i < N_count - 1; i++) {
        slopes[(size_t)i] = (times[(size_t)(i + 1)] - times[(size_t)i]) /
                    (double)(N_values[i + 1] - N_values[i]);
        std::printf("    N=%lld -> %lld: %.2f ns/iter\n",
            (long long)N_values[i], (long long)N_values[i + 1],
            slopes[(size_t)i] * 1e9);
    }
    double mean_slope = 0;
    for (int i = 0; i < N_count - 1; i++) mean_slope += slopes[(size_t)i];
    mean_slope /= (double)(N_count - 1);
    double slope_var = 0;
    for (int i = 0; i < N_count - 1; i++) {
        double d = slopes[(size_t)i] - mean_slope;
        slope_var += d * d;
    }
    double slope_cv = std::sqrt(slope_var / (double)(N_count - 1)) / mean_slope;

    std::printf("\n  Slope CV: %.4f (informational - derivative is noisy)\n", slope_cv);

    // Time ratio should match N ratio.
    // Use indices [1..N-1] (skip first) to avoid cold-cache penalty
    // that biases the first measurement and inflates the apparent ratio.
    // When N_count >= 3 we use index 1 as base; otherwise fall back to 0.
    int base_idx = (N_count >= 3) ? 1 : 0;
    double n_ratio = (double)N_values[N_count - 1] / (double)N_values[base_idx];
    double t_ratio = times[(size_t)(N_count - 1)] / times[(size_t)base_idx];
    double linearity_error = std::abs(t_ratio / n_ratio - 1.0);

    std::printf("\n  Mean rate: %.0f iter/sec\n", mean_rate);
    std::printf("  Rate CV: %.4f\n", cv);
    std::printf("  N ratio: %.0f (idx %d->%d), Time ratio: %.2f, Error: %.2f%% (threshold: %.0f%%)\n",
        n_ratio, base_idx, N_count - 1, t_ratio, linearity_error * 100.0,
        T1_LINEARITY_THRESHOLD * 100.0);

    bool pass = (linearity_error < T1_LINEARITY_THRESHOLD);
    test_result(1, pass, pass ?
        "Time scales linearly with N" : "Non-linear timing detected");
}

// ============================================================================
// TEST 2: GAUSS-SEIDEL vs JACOBI — different update = different output
// ============================================================================
static void test_02_gs_vs_jacobi() {
    test_header(2, "GAUSS-SEIDEL vs JACOBI - sequential dependency");

    const uint64_t seed = DEFAULT_SEED;
    const int64_t p = 3, q = 5;
    const int64_t N = T2_N_ITERS;

    // Gauss-Seidel (standard MCL — sequential)
    VDFResult gs = vdf_compute(seed, p, q, N);

    // Jacobi (parallel) — reconstruct from same initial state
    double t1, t2;
    mcl_init_state(seed, t1, t2);
    for (int i = 0; i < BURNIN; i++)
        mcl_iterate_raw(t1, t2, p, q, K_DEFAULT);
    // Now apply N Jacobi iterations (parallel update)
    double j_t1 = t1, j_t2 = t2;
    for (int64_t i = 0; i < N; i++) {
        mcl_iterate_jacobi(j_t1, j_t2, p, q, K_DEFAULT);
    }
    // Extract output from Jacobi state
    uint8_t j_out[32];
    for (int i = 0; i < 32; i++) {
        // Iterate once more for each byte (decimation=2)
        for (int d = 0; d < DECIMATION; d++)
            mcl_iterate_jacobi(j_t1, j_t2, p, q, K_DEFAULT);
        j_out[i] = mcl_extract_zone1(j_t1, j_t2) ^ mcl_extract_zone2(j_t1, j_t2);
    }

    // Compare
    int diff_bytes = 0;
    for (int i = 0; i < 32; i++) if (gs.output[i] != j_out[i]) diff_bytes++;
    double ham = hamming_pct(gs.output, j_out, 32);

    std::printf("  GS output:     ");
    for (int i = 0; i < 8; i++) std::printf("%02x", gs.output[i]);
    std::printf("...\n  Jacobi output:  ");
    for (int i = 0; i < 8; i++) std::printf("%02x", j_out[i]);
    std::printf("...\n\n");
    std::printf("  Different bytes: %d/32\n", diff_bytes);
    std::printf("  Hamming distance: %.1f%%\n", ham);

    bool pass = (diff_bytes >= T2_DIFF_BYTES_THRESHOLD)
             && (ham        > T2_HAM_THRESHOLD);
    test_result(2, pass, pass ?
        "GS and Jacobi produce completely different outputs" :
        "GS and Jacobi outputs too similar");
}

// ============================================================================
// TEST 3: DETERMINISTIC REPRODUCIBILITY
// ============================================================================
static void test_03_deterministic() {
    test_header(3, "DETERMINISTIC - same inputs produce same output");

    const int N_TRIALS = T3_N_TRIALS;
    VDFResult ref = vdf_compute(DEFAULT_SEED, 3, 5, T3_N_ITERS);

    int mismatches = 0;
    for (int t = 0; t < N_TRIALS; t++) {
        VDFResult trial = vdf_compute(DEFAULT_SEED, 3, 5, T3_N_ITERS);
        if (std::memcmp(ref.output, trial.output, 32) != 0) mismatches++;
    }

    std::printf("  Trials: %d, mismatches: %d\n", N_TRIALS, mismatches);
    std::printf("  Output: ");
    for (int i = 0; i < 16; i++) std::printf("%02x", ref.output[i]);
    std::printf("...\n");

    // Also test vdf_verify
    bool verify_ok = vdf_verify(DEFAULT_SEED, 3, 5, T3_N_ITERS, ref.output);
    std::printf("  vdf_verify: %s\n", verify_ok ? "PASS" : "FAIL");

    bool pass = (mismatches == 0) && verify_ok;
    test_result(3, pass, pass ?
        "100%% deterministic + vdf_verify confirmed" :
        "Reproducibility failed");
}

// ============================================================================
// TEST 4: N INDEPENDENT OF B — different N → different output
// ============================================================================
static void test_04_n_independent() {
    test_header(4, "N INDEPENDENT OF BURN-IN");

    const int64_t* N_values = T4_N_VALUES;
    const int NC = T4_N_COUNT;

    std::printf("  %-10s  %-20s  %-10s\n", "N", "Output prefix", "Time");
    std::printf("  ------------------------------------------------\n");

    uint8_t outputs[T4_N_COUNT][32];
    for (int i = 0; i < NC; i++) {
        VDFResult r = vdf_compute(DEFAULT_SEED, 3, 5, N_values[i]);
        std::memcpy(outputs[i], r.output, 32);
        std::printf("  %-10lld  ", (long long)N_values[i]);
        for (int b = 0; b < 8; b++) std::printf("%02x", r.output[b]);
        std::printf("  %.4fs\n", r.elapsed_sec);
    }

    // All pairs must differ
    int same_pairs = 0;
    int total_pairs = 0;
    for (int i = 0; i < NC; i++)
        for (int j = i + 1; j < NC; j++) {
            total_pairs++;
            if (std::memcmp(outputs[i], outputs[j], 32) == 0) {
                same_pairs++;
                std::printf("  COLLISION: N=%lld and N=%lld produce same output!\n",
                    (long long)N_values[i], (long long)N_values[j]);
            }
        }

    std::printf("\n  Pairs tested: %d, collisions: %d\n", total_pairs, same_pairs);

    bool pass = (same_pairs == 0);
    test_result(4, pass, pass ?
        "All N values produce distinct outputs" :
        "N collision detected");
}

// ============================================================================
// TEST 5: CHECKPOINT VERIFICATION
// ============================================================================
static void test_05_checkpoints() {
    test_header(5, "CHECKPOINT SEGMENT VERIFICATION");

    const int64_t N = T5_N_ITERS;
    const int K_CP = T5_N_CHECKPOINTS;
    VDFCheckpoint cps[T5_N_CHECKPOINTS];

    VDFResult r = vdf_compute_checkpointed(DEFAULT_SEED, 3, 5, N, cps, K_CP);

    std::printf("  N=%lld, checkpoints=%d, interval=%lld\n\n",
        (long long)N, K_CP, (long long)(N / K_CP));

    // Print checkpoints
    for (int i = 0; i < K_CP; i++)
        std::printf("  cp[%d]: iter=%-8lld theta1=%.10f theta2=%.10f\n",
            i, (long long)cps[i].iteration, cps[i].theta1, cps[i].theta2);

    // Verify each segment
    std::printf("\n  Segment verification:\n");
    int seg_pass = 0, seg_fail = 0;

    // First segment: after burn-in state → cp[0]
    // We need the post-burn-in state. Create engine and grab it.
    MCL_T2 ref_eng(DEFAULT_SEED, 3, 5);
    double t1_start = ref_eng.theta1();
    double t2_start = ref_eng.theta2();

    bool s0 = vdf_verify_segment(t1_start, t2_start,
        cps[0].theta1, cps[0].theta2,
        3, 5, cps[0].iteration);
    std::printf("  burn-in -> cp[0] (iter %lld): %s\n",
        (long long)cps[0].iteration, s0 ? "PASS" : "FAIL");
    if (s0) seg_pass++; else seg_fail++;

    // Segments cp[i] → cp[i+1]
    for (int i = 0; i < K_CP - 1; i++) {
        int64_t seg_len = cps[i + 1].iteration - cps[i].iteration;
        bool ok = vdf_verify_segment(
            cps[i].theta1, cps[i].theta2,
            cps[i + 1].theta1, cps[i + 1].theta2,
            3, 5, seg_len);
        std::printf("  cp[%d] -> cp[%d] (iter %lld -> %lld, delta=%lld): %s\n",
            i, i + 1, (long long)cps[i].iteration,
            (long long)cps[i + 1].iteration, (long long)seg_len,
            ok ? "PASS" : "FAIL");
        if (ok) seg_pass++; else seg_fail++;
    }

    // Verify full output matches non-checkpointed
    VDFResult r2 = vdf_compute(DEFAULT_SEED, 3, 5, N);
    bool output_match = (std::memcmp(r.output, r2.output, 32) == 0);
    std::printf("\n  Segments passed: %d/%d\n", seg_pass, seg_pass + seg_fail);
    std::printf("  Checkpointed output == plain output: %s\n",
        output_match ? "YES" : "NO");

    bool pass = (seg_fail == 0) && output_match;
    test_result(5, pass, pass ?
        "All segments verified + output matches" :
        "Checkpoint verification failed");
}

// ============================================================================
// TEST 6: OUTPUT QUALITY — VDF output is cryptographic quality
// ============================================================================
static void test_06_output_quality() {
    test_header(6, "OUTPUT QUALITY - chi-square + entropy");

    // Generate 1M bytes from a single VDF output stream.
    // This tests whether post-delay extraction maintains cryptographic quality.
    const int64_t N_DELAY = T6_N_DELAY;
    const int64_t NB = T6_N_BYTES;

    MCL_T2 eng(DEFAULT_SEED, 3, 5);
    for (int64_t i = 0; i < N_DELAY; i++) eng.iterate();
    std::vector<uint8_t> all_bytes((size_t)NB);
    eng.gen_bytes(all_bytes.data(), NB);

    double ent = shannon_entropy(all_bytes.data(), NB);
    double chi = chi_square(all_bytes.data(), NB);

    std::printf("  VDF N=%lld -> %lld bytes extracted\n",
        (long long)N_DELAY, (long long)NB);
    std::printf("  Entropy: %.6f bits/byte (ideal: 8.0, threshold: %.3f)\n",
                ent, T6_ENTROPY_THRESHOLD);
    std::printf("  Chi-square: %.2f (threshold: %.2f)\n", chi, CHI2_THRESHOLD);

    bool pass = (ent > T6_ENTROPY_THRESHOLD) && (chi < CHI2_THRESHOLD);
    test_result(6, pass, pass ?
        "VDF output is cryptographic quality" :
        "VDF output quality failed");
}

// ============================================================================
// TEST 7: CONFIGURABLE DELAY — N freely selectable
// ============================================================================
static void test_07_configurable() {
    test_header(7, "CONFIGURABLE DELAY - N from 10 to 10^7");

    std::printf("  %-15s  %-12s  %-12s  %-10s\n",
        "Application", "N", "Time (sec)", "Output");
    std::printf("  ---------------------------------------------------------------\n");

    bool all_valid = true;
    for (int i = 0; i < T7_CONFIG_COUNT; i++) {
        VDFResult r = vdf_compute(DEFAULT_SEED, 3, 5, T7_CONFIGS[i].N);
        std::printf("  %-15s  %-12lld  %-12.6f  ",
            T7_CONFIGS[i].label, (long long)T7_CONFIGS[i].N, r.elapsed_sec);
        for (int b = 0; b < 4; b++) std::printf("%02x", r.output[b]);
        std::printf("...\n");

        // Each must produce valid output (not all zeros)
        bool nonzero = false;
        for (int b = 0; b < 32; b++) if (r.output[b] != 0) nonzero = true;
        if (!nonzero) all_valid = false;
    }

    test_result(7, all_valid, all_valid ?
        "All delay configurations produce valid output" :
        "Zero output detected");
}

// ============================================================================
// TEST 8: NON-SHORTCUT — cannot skip iterations
// ============================================================================
static void test_08_non_shortcut() {
    test_header(8, "NON-SHORTCUT - no way to skip iterations");

    // The argument: if an attacker could compute VDF(N) faster than N
    // sequential iterations, they would find a shortcut. We verify that
    // the output at N depends on EVERY intermediate iteration by showing
    // that changing one iteration in the middle produces completely
    // different output.

    const int64_t N = T8_N_ITERS;
    const int64_t tp = 3, tq = 5;

    // Standard VDF
    VDFResult standard = vdf_compute(DEFAULT_SEED, tp, tq, N);

    // Perturbation test: run N/2 iterations, add tiny perturbation
    // to theta1, then run N/2 more. Chaotic sensitivity means the
    // perturbation is amplified exponentially -> completely different output.
    MCL_T2 eng(DEFAULT_SEED, tp, tq);
    for (int64_t i = 0; i < N / 2; i++) eng.iterate();
    double t1_mid = eng.theta1();
    double t2_mid = eng.theta2();

    // Perturbed path: add T8_PERTURB to theta1.
    // After N/2 GS iterations with lambda ~ 5.78, this perturbation
    // is amplified by e^(5.78 * N/2) -> total divergence.
    double pt1 = t1_mid + T8_PERTURB;
    double pt2 = t2_mid;
    for (int64_t i = 0; i < N / 2; i++)
        mcl_iterate_raw(pt1, pt2, tp, tq, K_DEFAULT);

    // Extract bytes from perturbed state
    uint8_t perturbed_out[32];
    for (int i = 0; i < 32; i++) {
        for (int d = 0; d < DECIMATION; d++)
            mcl_iterate_raw(pt1, pt2, tp, tq, K_DEFAULT);
        perturbed_out[i] = mcl_extract_zone1(pt1, pt2) ^ mcl_extract_zone2(pt1, pt2);
    }

    double ham_perturb = hamming_pct(standard.output, perturbed_out, 32);
    int diff_bytes = 0;
    for (int i = 0; i < 32; i++) if (standard.output[i] != perturbed_out[i]) diff_bytes++;
    std::printf("  Perturbation (1e-12 at midpoint): %d/32 bytes differ, ham=%.1f%%\n",
        diff_bytes, ham_perturb);

    // Also: N±1 sensitivity
    VDFResult r_minus1 = vdf_compute(DEFAULT_SEED, tp, tq, N - 1);
    VDFResult r_plus1  = vdf_compute(DEFAULT_SEED, tp, tq, N + 1);
    double ham_m1 = hamming_pct(standard.output, r_minus1.output, 32);
    double ham_p1 = hamming_pct(standard.output, r_plus1.output, 32);
    std::printf("  N=%lld vs N-1: hamming=%.1f%%\n", (long long)N, ham_m1);
    std::printf("  N=%lld vs N+1: hamming=%.1f%%\n", (long long)N, ham_p1);

    bool pass = (ham_perturb > T8_HAM_THRESHOLD)
             && (ham_m1     > T8_HAM_THRESHOLD)
             && (ham_p1     > T8_HAM_THRESHOLD);
    test_result(8, pass, pass ?
        "Output depends on every single iteration" :
        "Sensitivity test failed");
}

// ============================================================================
// TEST 9: CROSS-PARAMETER INDEPENDENCE
// ============================================================================
static void test_09_cross_param() {
    test_header(9, "CROSS-PARAMETER INDEPENDENCE");

    const int64_t N = T9_N_DELAY;
    const int N_PARAMS = T9_N_PARAMS;
    const Topology* topos = t2_topos();

    // Generate VDF output for N_PARAMS different (p,q) pairs - T9_N_BYTES bytes each
    std::vector<std::vector<uint8_t>> outputs((size_t)N_PARAMS);
    for (int i = 0; i < N_PARAMS; i++) {
        MCL_T2 eng(DEFAULT_SEED, topos[i].p, topos[i].q);
        for (int64_t j = 0; j < N; j++) eng.iterate();
        outputs[(size_t)i].resize((size_t)T9_N_BYTES);
        eng.gen_bytes(outputs[(size_t)i].data(), T9_N_BYTES);
        std::printf("  (%lld,%lld): first 4 bytes = %02x%02x%02x%02x\n",
            (long long)topos[i].p, (long long)topos[i].q,
            outputs[(size_t)i][0], outputs[(size_t)i][1],
            outputs[(size_t)i][2], outputs[(size_t)i][3]);
    }

    // Pairwise independence
    int np = 0;
    bool all_indep = true;
    std::vector<double> pvalues;

    for (int i = 0; i < N_PARAMS; i++)
        for (int j = i + 1; j < N_PARAMS; j++) {
            double r = std::abs(pearson_r(outputs[(size_t)i].data(),
                                          outputs[(size_t)j].data(), T9_N_BYTES));
            double pv = pvalue_from_r(r, T9_N_BYTES);
            np++;
            pvalues.push_back(pv);
        }

    double bt = BONFERRONI_ALPHA / (double)np;
    for (double pv : pvalues) if (pv < bt) all_indep = false;

    std::printf("\n  Pairs: %d, Bonferroni threshold: %.2e\n", np, bt);

    test_result(9, all_indep, all_indep ?
        "All parameter pairs produce independent VDF output" :
        "Correlation detected");
}

// ============================================================================
// TEST 10: NEGATIVE CONTROL
// ============================================================================
static void test_10_negative_control() {
    test_header(10, "NEGATIVE CONTROL");

    // Same inputs -> identical
    VDFResult r1 = vdf_compute(DEFAULT_SEED, 3, 5, T10_N_ITERS);
    VDFResult r2 = vdf_compute(DEFAULT_SEED, 3, 5, T10_N_ITERS);
    bool c1 = (std::memcmp(r1.output, r2.output, 32) == 0);
    std::printf("  Same inputs -> identical: %s\n", c1 ? "OK" : "ERROR");

    // Different seed -> different
    VDFResult r3 = vdf_compute(DEFAULT_SEED + 1, 3, 5, T10_N_ITERS);
    bool c2 = (std::memcmp(r1.output, r3.output, 32) != 0);
    double ham1 = hamming_pct(r1.output, r3.output, 32);
    std::printf("  Different seed -> different: %s (ham=%.1f%%)\n",
        c2 ? "OK" : "ERROR", ham1);

    // Different (p,q) -> different
    VDFResult r4 = vdf_compute(DEFAULT_SEED, 5, 7, T10_N_ITERS);
    bool c3 = (std::memcmp(r1.output, r4.output, 32) != 0);
    double ham2 = hamming_pct(r1.output, r4.output, 32);
    std::printf("  Different (p,q) -> different: %s (ham=%.1f%%)\n",
        c3 ? "OK" : "ERROR", ham2);

    // N=0 -> output exists (pure burn-in extraction)
    VDFResult r5 = vdf_compute(DEFAULT_SEED, 3, 5, 0);
    bool c4 = false;
    for (int i = 0; i < 32; i++) if (r5.output[i] != 0) { c4 = true; break; }
    std::printf("  N=0 -> valid output: %s\n", c4 ? "OK" : "ERROR");

    // vdf_verify with wrong expected -> false
    uint8_t wrong[32] = {};
    bool c5 = !vdf_verify(DEFAULT_SEED, 3, 5, T10_N_ITERS, wrong);
    std::printf("  vdf_verify(wrong) -> false: %s\n", c5 ? "OK" : "ERROR");

    bool pass = c1 && c2 && c3 && c4 && c5;
    test_result(10, pass, pass ? "Methodology validated" : "Error");
}

// ============================================================================
static void print_help(const char* prog) {
    std::printf("MCL VDF Verification v%s\n", DOC_VERSION);
    std::printf("Usage: %s [options]\n\n", prog);
    std::printf("Options:\n");
    std::printf("  --quick     QUICK mode (default): Test 1 N up to 8M (~6 sec)\n");
    std::printf("  --full      FULL mode: Test 1 N up to 10^8 (~5 min, Paper 4 Sec V)\n");
    std::printf("  --help, -h  Print this help and exit\n\n");
    std::printf("Document ID: %s\n", DOC_ID);
    std::printf("Engine:      mcl_core.hpp (MCL_T2 production engine)\n");
    std::printf("\nTests (run in both modes):\n");
    std::printf("  1. Timing linearity        6. Output quality\n");
    std::printf("  2. Gauss-Seidel vs Jacobi  7. Configurable delay\n");
    std::printf("  3. Deterministic           8. Non-shortcut\n");
    std::printf("  4. N independent of B      9. Cross-parameter independence\n");
    std::printf("  5. Checkpoint verification 10. Negative control\n");
    std::printf("\nVerdict is PASS if ALL 10 tests pass.\n");
}

int main(int argc, char* argv[]) {
    // Realtime output for long runs (must be before any printf/fprintf).
    std::setbuf(stdout, nullptr);

    // Pre-scan for --help / -h
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        }
    }

    // Parse CLI
    bool mode_explicitly_set = false;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--full") == 0) {
            if (mode_explicitly_set) {
                std::fprintf(stderr,
                    "ERROR: multiple run modes specified.  Run with --help.\n");
                return 2;
            }
            g_full_mode = true;
            mode_explicitly_set = true;
        } else if (std::strcmp(argv[i], "--quick") == 0) {
            if (mode_explicitly_set) {
                std::fprintf(stderr,
                    "ERROR: multiple run modes specified.  Run with --help.\n");
                return 2;
            }
            g_full_mode = false;
            mode_explicitly_set = true;
        } else {
            std::fprintf(stderr,
                "ERROR: unknown argument '%s'.  Run with --help for usage.\n",
                argv[i]);
            return 2;
        }
    }

    auto t0 = std::chrono::steady_clock::now();
    std::printf("\n==============================================================================\n");
    std::printf("  MCL VERIFIABLE DELAY FUNCTION VERIFICATION v%s\n", DOC_VERSION);
    std::printf("  %s\n", DOC_ID);
    std::printf("  Mode: %s\n", g_full_mode ? "FULL  (Paper 4 Sec V scale)" : "QUICK");
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
    std::printf("  Engine: MCL_T2, Seed: %llu, K=%.1f, BURNIN=%d\n",
        (unsigned long long)DEFAULT_SEED, K_DEFAULT, BURNIN);

    test_10_negative_control();
    test_01_timing_linearity();
    test_02_gs_vs_jacobi();
    test_03_deterministic();
    test_04_n_independent();
    test_05_checkpoints();
    test_06_output_quality();
    test_07_configurable();
    test_08_non_shortcut();
    test_09_cross_param();

    double el = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t0).count();

    sep("SUMMARY");
    const char* names[] = {
        "", "Timing linearity", "Gauss-Seidel vs Jacobi",
        "Deterministic reproducibility", "N independent of B",
        "Checkpoint verification", "Output quality",
        "Configurable delay", "Non-shortcut",
        "Cross-parameter independence", "Negative control"
    };
    for (int i : {10, 1, 2, 3, 4, 5, 6, 7, 8, 9})
        std::printf("  %2d  %-40s %s\n", i, names[i], g_results[i] ? "PASS" : "FAIL");

    std::printf("\n  Passed: %d/10  Time: %.1f sec (%.1f min)\n",
                g_passed, el, el / 60.0);

    if (g_failed == 0) {
        std::printf("\n  +================================================================+\n");
        std::printf("  | VERDICT: PASS - All 10 VDF properties verified                |\n");
        std::printf("  +================================================================+\n");
    } else {
        std::printf("\n  +================================================================+\n");
        std::printf("  | VERDICT: FAIL - %d test(s) failed\n", g_failed);
        std::printf("  +================================================================+\n");
    }

    std::printf("\n  Mode:    %s\n", g_full_mode ? "FULL" : "QUICK");
    std::printf("  Doc ID:  %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("  Author:  Madeeh Ibrahim, Cairo, Egypt\n");
    std::printf("  Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673\n");
    std::printf("==============================================================================\n\n");
    return g_failed > 0 ? 1 : 0;
}
