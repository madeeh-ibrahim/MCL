/*
 * ============================================================================
 * MCL Decimation Sweep — Sequential Sample Decorrelation Verification
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-DECIM-SWEEP-2026-0526-001
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
 * PURPOSE: Quantitatively justify the decimation parameter D = DECIMATION
 *          (the value defined in mcl_core.hpp) by measuring lag-k
 *          autocorrelation of the byte stream as a function of D ∈ {1, 2, 3, 4}.
 *          Two negative-control generators validate the test methodology:
 *            - WeakBiased (~10% bias toward 0): validates the chi-square
 *              uniformity check.
 *            - WeakAutocorrelated (P(b_i = b_{i-1}) = 0.5): validates the
 *              autocorrelation detection. Uniform marginal but explicit
 *              lag-1 correlation |r| ≈ 0.5.
 *
 * TESTS:
 *   - Lag-1, lag-2, lag-4, lag-8, lag-16, lag-32 byte autocorrelation per D
 *   - Bit frequency uniformity per D
 *   - Chi-square byte uniformity per D (df = 255)
 *   - Shannon entropy per D
 *   - WeakBiased control: validates the 1D uniformity detection methodology
 *   - WeakAutocorrelated control: validates the lag-1 detection methodology
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_decimation_sweep mcl_decimation_sweep.cpp -lm && ./mcl_decimation_sweep
 *
 * EXPECTED RESULTS: (default: K=12, p=3, q=5, N=10^7):
 *   D=1: lag-1 |r| < 3σ (chaos at λ₁=5.78 may already decorrelate at D=1)
 *   D=2: lag-1 |r| < 3σ (standard, all subsequent lags pass)
 *   D≥3: lag-1 |r| < 3σ (no measurable improvement vs D=2)
 *   χ² for all D: < 310.46
 *   NEG CTRL 1 (WeakBiased ~10% bias toward 0):
 *       χ² >> 310.46 (gross 1D non-uniformity, expected to dominate)
 *   NEG CTRL 2 (WeakAutocorrelated, P(repeat)=0.5):
 *       |r_lag1| ≈ 0.5 (well above 3σ noise floor)
 * REFERENCES:       (none beyond mcl_core.hpp)
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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <vector>
#include <string>
#include <cmath>

static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-DECIM-SWEEP-2026-0526-001";

static const int64_t N_DEFAULT = 10000000LL;
static const int64_t N_QUICK   = 1000000LL;

// D values to sweep
static constexpr int D_VALUES[] = {1, 2, 3, 4};
static constexpr int N_D        = (int)(sizeof(D_VALUES) / sizeof(D_VALUES[0]));

// Compile-time anchor: this sweep is designed to justify DECIMATION = 2
// specifically. The pass criteria (below) use results[1], which corresponds
// to D = D_VALUES[1] = 2. If DECIMATION is updated in mcl_core.hpp, this
// assertion forces explicit re-evaluation of the test methodology rather
// than allowing silent drift.
static_assert(DECIMATION == 2,
    "This sweep is designed to justify DECIMATION = 2. If DECIMATION "
    "changed in mcl_core.hpp, re-run the sweep around the new value "
    "and update D_VALUES + the pass-criteria index accordingly.");
static_assert(D_VALUES[1] == DECIMATION,
    "results[1] is used as the production-default row in the pass "
    "criteria. D_VALUES[1] must therefore equal DECIMATION. "
    "If you reorder D_VALUES, also update the pass-criteria index.");

// Lag values to test
static constexpr int LAG_VALUES[] = {1, 2, 4, 8, 16, 32};
static constexpr int N_LAGS       = (int)(sizeof(LAG_VALUES) / sizeof(LAG_VALUES[0]));

// ============================================================================
// WeakBiased — deliberately non-uniform generator used as 1D negative control
// (Coding Standards ECR Exception: non-MCL generators permitted in .cpp for
// negative controls only).
//
// Why not WeakRANDU here?
//   The well-known IBM RANDU generator has a documented 3D spectral failure
//   (15 hyperplanes), but its 1D byte distribution and lag-1 autocorrelation
//   pass conventional uniformity tests when extracted from the upper bits.
//   Because this test suite probes only 1D properties (byte-level chi² and
//   short-lag autocorrelation), RANDU is unsuitable as a negative control
//   here — it would falsely pass.
//
// WeakBiased instead uses a high-quality 64-bit LCG (PCG state-update) and
// then injects a ~10% probability of returning 0. This produces gross
// non-uniformity in the byte distribution that any 1D chi² test will detect,
// validating the test methodology (Rule R3).
//
// State-bit decorrelation: the bias decision and the byte output derive
// from independent state advances, eliminating the within-byte correlation
// between "is this byte forced to 0" and "what would the byte have been".
// This sharpens the ~10% nominal bias rate.
// ============================================================================
class WeakBiased {
    uint64_t state_;
    static constexpr uint64_t LCG_MULT = 6364136223846793005ULL;
    static constexpr uint64_t LCG_INC  = 1442695040888963407ULL;
public:
    explicit WeakBiased(uint64_t seed) : state_(seed | 1ULL) {}
    uint8_t gen_byte() {
        // Step 1 — advance state and extract candidate byte (high bits).
        state_ = state_ * LCG_MULT + LCG_INC;
        uint8_t b = (uint8_t)(state_ >> 56);
        // Step 2 — independent state advance for bias decision.
        // This decouples the bias decision from the byte value so that
        // the ~10% bias rate is not entangled with the underlying byte
        // distribution.
        state_ = state_ * LCG_MULT + LCG_INC;
        if ((state_ & 0x3FFULL) < 102ULL) {  // 102/1024 ≈ 9.96%
            return 0;
        }
        return b;
    }
    void gen_bytes(uint8_t* out, int64_t n) {
        for (int64_t i = 0; i < n; i++) out[i] = gen_byte();
    }
};

// ============================================================================
// WeakAutocorrelated — uniform marginal + strong lag-1 correlation
//
// MOTIVATION (Rule R3 methodology validation):
//   The WeakBiased control validates only the χ² uniformity check.
//   If the autocorrelation function were broken (always returns 0,
//   transposed args, etc.), the test would silently pass and the
//   per-D lag-1 decorrelation results would be unsupported.
//
//   WeakAutocorrelated produces a sequence with explicit P(b_i = b_{i-1})
//   = 0.5 (each byte is either fresh or a copy of the previous byte with
//   equal probability). This yields:
//     - Uniform marginal distribution → χ² should PASS
//     - lag-1 autocorrelation |r| ≈ 0.5 (large) → autocorr() must FAIL
//
//   If our test methodology can detect this generator's lag-1 correlation,
//   we have evidence that the same methodology can detect lag-1 issues
//   in the MCL output if any existed.
// ============================================================================
class WeakAutocorrelated {
    uint64_t state_;
    uint8_t  prev_;
    static constexpr uint64_t LCG_MULT = 6364136223846793005ULL;
    static constexpr uint64_t LCG_INC  = 1442695040888963407ULL;
public:
    explicit WeakAutocorrelated(uint64_t seed) : state_(seed | 1ULL), prev_(0) {
        // Generate first byte fresh (no previous to copy from).
        state_ = state_ * LCG_MULT + LCG_INC;
        prev_  = (uint8_t)(state_ >> 56);
    }
    uint8_t gen_byte() {
        state_ = state_ * LCG_MULT + LCG_INC;
        // Repeat decision: an independent bit (bit 31 of LCG state, well-
        // mixed for this LCG choice). Probability 0.5.
        bool repeat = ((state_ >> 31) & 1ULL) != 0;
        if (!repeat) {
            // Generate fresh byte from a different state slice.
            prev_ = (uint8_t)(state_ >> 56);
        }
        return prev_;
    }
    void gen_bytes(uint8_t* out, int64_t n) {
        for (int64_t i = 0; i < n; i++) out[i] = gen_byte();
    }
};

// ============================================================================
// Per-D measurement record
// ============================================================================
struct DResult {
    int    D;
    double chi2;
    double entropy;
    double bit_freq;
    double r_lag[N_LAGS];
    bool   chi2_pass;
    bool   lag1_decorrelated;
};

int main(int argc, char** argv) {
    int64_t N = N_DEFAULT;
    double  K = K_DEFAULT;
    int64_t p = 3;
    int64_t q = 5;

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--quick") == 0) {
            N = N_QUICK;
        } else if (std::strcmp(argv[i], "--N") == 0 && i + 1 < argc) {
            N = std::atoll(argv[++i]);
        } else if (std::strcmp(argv[i], "--K") == 0 && i + 1 < argc) {
            K = std::atof(argv[++i]);
        }
    }

    // Argument validation
    if (N <= 0) {
        std::fprintf(stderr,
            "FATAL: N must be a positive integer (got %lld)\n",
            (long long)N);
        return 2;
    }
    if (K <= 0.0 || !std::isfinite(K)) {
        std::fprintf(stderr,
            "FATAL: K must be a positive finite number (got %.6f)\n", K);
        return 2;
    }
    bool k_is_12 = (std::fabs(K - 12.0) < 1e-9);

    std::printf("\n");
    std::printf("******************************************************************************\n");
    std::printf("  MCL Decimation Sweep Verification\n");
    std::printf("  %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("******************************************************************************\n\n");
    std::printf("  Configuration:\n");
    std::printf("    Seed:         %llu (DEFAULT_SEED)\n",
                (unsigned long long)DEFAULT_SEED);
    std::printf("    K:            %.4f\n", K);
    std::printf("    (p, q):       (%lld, %lld)\n",
                (long long)p, (long long)q);
    std::printf("    Burn-in:      %d\n", BURNIN);
    std::printf("    Bytes per D:  %lld\n", (long long)N);
    std::printf("    D values:     {1, 2, 3, 4}\n");
    std::printf("    Lag values:   {1, 2, 4, 8, 16, 32}\n");
    std::printf("    χ² threshold: %.2f (df=255, α=0.01)\n",
                CHI2_THRESHOLD_STRICT);

    // 3σ noise floor for autocorrelation
    double noise_3sigma = 3.0 / std::sqrt((double)N);
    std::printf("    3σ noise floor for r: %.7f\n\n", noise_3sigma);

    if (!k_is_12) {
        std::printf("  Note: Default reference values apply to K=12 only.\n");
        std::printf("        Results at K=%.4f are exploratory.\n\n", K);
    }

    // ========================================================================
    // Pre-allocate stream buffer (Rule F12: no alloc in inner loops).
    // The buffer is reused across (a) each D value's MCL stream, (b)
    // WeakBiased negative control, (c) WeakAutocorrelated negative control.
    // All statistics (chi-square, autocorrelation, etc.) are computed before
    // the buffer is overwritten by the next stream — the reuse is safe.
    // ========================================================================
    std::vector<uint8_t> stream((size_t)N, 0);

    // ========================================================================
    // Sweep D values
    // ========================================================================
    std::vector<DResult> results;
    auto t_start = std::chrono::steady_clock::now();

    for (int d_idx = 0; d_idx < N_D; d_idx++) {
        int D = D_VALUES[d_idx];
        std::printf("  [D = %d] generating %lld bytes...\n", D, (long long)N);

        // Reset state via mcl_core.hpp utilities + burn-in
        double t1, t2;
        mcl_init_state(DEFAULT_SEED, t1, t2);
        for (int i = 0; i < BURNIN; i++) {
            mcl_iterate_raw(t1, t2, p, q, K);
        }

        // Generate stream with custom decimation D
        for (int64_t i = 0; i < N; i++) {
            for (int d = 0; d < D; d++) {
                mcl_iterate_raw(t1, t2, p, q, K);
            }
            uint8_t b1 = mcl_extract_zone1(t1, t2);
            uint8_t b2 = mcl_extract_zone2(t1, t2);
            stream[(size_t)i] = static_cast<uint8_t>(b1 ^ b2);
        }

        // Compute statistics using mcl_core.hpp §6 utilities
        DResult res;
        res.D        = D;
        res.chi2     = chi_square(stream.data(), N);
        res.entropy  = shannon_entropy(stream.data(), N);
        res.bit_freq = bit_frequency(stream.data(), N);
        for (int j = 0; j < N_LAGS; j++) {
            res.r_lag[j] = autocorrelation(stream.data(), N, LAG_VALUES[j]);
        }
        res.chi2_pass         = (res.chi2 < CHI2_THRESHOLD_STRICT);
        res.lag1_decorrelated = (std::fabs(res.r_lag[0]) < noise_3sigma);
        results.push_back(res);
    }

    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();
    std::printf("  All sweeps complete: %.2f sec\n\n", elapsed);

    // ========================================================================
    // Negative control 1 — WeakBiased (validates χ² methodology)
    // ========================================================================
    std::printf("  [NEG CTRL 1] generating WeakBiased stream...\n");
    WeakBiased biased(DEFAULT_SEED);
    biased.gen_bytes(stream.data(), N);

    double neg_chi2  = chi_square(stream.data(), N);
    double neg_lag1  = autocorrelation(stream.data(), N, 1);
    // NEG CTRL 1 (WeakBiased) is designed to validate the chi-square
    // uniformity methodology specifically. Its primary defect is gross
    // 1D non-uniformity. Lag-1 detection is the validation target of
    // NEG CTRL 2 (WeakAutocorrelated), not this control. We therefore
    // require chi-square detection only — using OR with lag-1 here would
    // allow accidental lag-1 noise to mask a broken chi-square check.
    bool   neg_fails = (neg_chi2 > CHI2_THRESHOLD_STRICT);

    // ========================================================================
    // Negative control 2 — WeakAutocorrelated (validates autocorr
    // methodology specifically, complementary to NEG CTRL 1)
    // ========================================================================
    std::printf("  [NEG CTRL 2] generating WeakAutocorrelated stream...\n");
    WeakAutocorrelated autocorr(DEFAULT_SEED);
    autocorr.gen_bytes(stream.data(), N);

    double ac_chi2 = chi_square(stream.data(), N);
    double ac_lag1 = autocorrelation(stream.data(), N, 1);
    // NEG CTRL 2 succeeds ONLY if lag-1 is detected — that's the whole point.
    // χ² may pass (uniform marginal) or fail (occasional copy-of-prev creates
    // some non-uniformity); the autocorrelation MUST be detected.
    // Expected |r_lag1| ≈ 0.5 for this generator, far above any reasonable
    // noise floor.
    bool ac_lag1_detected = (std::fabs(ac_lag1) > noise_3sigma);

    std::printf("\n");

    // ========================================================================
    // Print results table
    // ========================================================================
    std::printf("  Per-D Statistics (negative controls = last two rows):\n");
    std::printf("  %s\n", std::string(95, '=').c_str());
    std::printf("  | D | %10s | %8s | %8s | %9s | %9s | %9s | %9s |\n",
                "chi2", "entropy", "bit_freq",
                "r_lag1", "r_lag2", "r_lag4", "r_lag8");
    std::printf("  %s\n", std::string(95, '-').c_str());

    for (size_t i = 0; i < results.size(); i++) {
        const DResult& r = results[i];
        std::printf("  | %d | %10.2f | %8.6f | %8.6f | %+9.6f | %+9.6f | %+9.6f | %+9.6f |\n",
                    r.D, r.chi2, r.entropy, r.bit_freq,
                    r.r_lag[0], r.r_lag[1], r.r_lag[2], r.r_lag[3]);
    }
    // Negative controls — both must show their target defect.
    std::printf("  | B | %10.2e |   ----   |   ----   | %+9.6f |   ----    |   ----    |   ----    |\n",
                neg_chi2, neg_lag1);
    std::printf("  | A | %10.2f |   ----   |   ----   | %+9.6f |   ----    |   ----    |   ----    |\n",
                ac_chi2, ac_lag1);
    std::printf("  %s\n", std::string(95, '=').c_str());
    std::printf("  (B = WeakBiased: should fail χ²; A = WeakAutocorrelated: should fail lag-1)\n\n");

    // ========================================================================
    // Decorrelation analysis per D
    // ========================================================================
    std::printf("  Decorrelation Verdict per D:\n");
    std::printf("  %s\n", std::string(60, '-').c_str());
    // Note on labels: "|r| within noise floor" indicates failure to detect
    // correlation at the 3σ level — this is consistent with independence
    // but does not constitute proof. "correlation detected" indicates
    // |r| exceeds the noise floor, suggesting non-zero true correlation.
    for (size_t i = 0; i < results.size(); i++) {
        const DResult& r = results[i];
        std::printf("    D=%d: |r_lag1| = %.7f  (3σ = %.7f)  %s\n",
                    r.D, std::fabs(r.r_lag[0]), noise_3sigma,
                    r.lag1_decorrelated ?
                    "|r| within noise floor" : "correlation detected");
    }
    std::printf("\n");

    // ========================================================================
    // Pass / Fail (computed from data — Rule F1)
    // ========================================================================
    bool global_pass = true;
    int  n_failures  = 0;

    // (1) Standard D=2 must pass χ² and decorrelation tests
    if (!results[1].chi2_pass) {
        n_failures++;
        global_pass = false;
        std::printf("  [FAIL] D=2 χ² = %.2f exceeds threshold %.2f\n",
                    results[1].chi2, CHI2_THRESHOLD_STRICT);
    } else {
        std::printf("  [PASS] D=2 χ² = %.2f < %.2f (uniform)\n",
                    results[1].chi2, CHI2_THRESHOLD_STRICT);
    }

    if (!results[1].lag1_decorrelated) {
        n_failures++;
        global_pass = false;
        std::printf("  [FAIL] D=2 lag-1 |r| = %.7f exceeds 3σ = %.7f\n",
                    std::fabs(results[1].r_lag[0]), noise_3sigma);
    } else {
        std::printf("  [PASS] D=2 lag-1 |r| = %.7f < 3σ (within noise floor)\n",
                    std::fabs(results[1].r_lag[0]));
    }

    // (2) D=3, D=4 should also pass (sanity for higher decimation)
    for (size_t i = 2; i < results.size(); i++) {
        const DResult& r = results[i];
        if (!r.chi2_pass || !r.lag1_decorrelated) {
            n_failures++;
            global_pass = false;
            std::printf("  [FAIL] D=%d: χ²=%.2f (pass=%s), lag-1 |r|=%.7f (decor=%s)\n",
                        r.D, r.chi2, r.chi2_pass ? "yes" : "no",
                        std::fabs(r.r_lag[0]),
                        r.lag1_decorrelated ? "yes" : "no");
        } else {
            std::printf("  [PASS] D=%d: χ²=%.2f, lag-1 |r|=%.7f\n",
                        r.D, r.chi2, std::fabs(r.r_lag[0]));
        }
    }

    // (3a) R3: Negative control 1 (WeakBiased) must FAIL χ² uniformity
    if (!neg_fails) {
        n_failures++;
        global_pass = false;
        std::printf("  [FAIL] NEG CTRL 1: WeakBiased did NOT fail — χ² methodology broken\n");
        std::printf("           χ² = %.2e, lag-1 |r| = %.7f\n",
                    neg_chi2, std::fabs(neg_lag1));
    } else {
        std::printf("  [PASS] NEG CTRL 1: WeakBiased detected (χ²=%.2e, lag-1 |r|=%.7f)\n",
                    neg_chi2, std::fabs(neg_lag1));
    }

    // (3b) R3: Negative control 2 (WeakAutocorrelated) MUST detect
    //      a lag-1 correlation. If it does not, the autocorrelation test
    //      is broken and we cannot trust the per-D decorrelation results.
    if (!ac_lag1_detected) {
        n_failures++;
        global_pass = false;
        std::printf("  [FAIL] NEG CTRL 2: WeakAutocorrelated lag-1 NOT detected — "
                    "autocorr methodology broken\n");
        std::printf("           |r_lag1| = %.7f, 3σ = %.7f\n",
                    std::fabs(ac_lag1), noise_3sigma);
        std::printf("           Expected |r_lag1| ≈ 0.5 from this generator.\n");
    } else {
        std::printf("  [PASS] NEG CTRL 2: WeakAutocorrelated lag-1 detected "
                    "(|r|=%.4f, χ²=%.2f)\n",
                    std::fabs(ac_lag1), ac_chi2);
    }

    // ========================================================================
    // Footer
    // ========================================================================
    std::printf("\n");
    std::printf("  ============================================================================\n");
    std::printf("  GLOBAL VERDICT: %s\n", global_pass ? "PASS" : "FAIL");
    std::printf("  Failures:       %d\n", n_failures);
    std::printf("  Document:       %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("  ============================================================================\n\n");

    return global_pass ? 0 : 1;
}
