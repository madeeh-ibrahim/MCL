/*
 * ============================================================================
 * MCL Burn-In Sweep — Convergence to Chaotic Attractor Verification
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-BURNIN-SWEEP-2026-0526-001
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
 * PURPOSE: Quantitatively justify the burn-in length B = 10,000 (the value
 *          of BURNIN defined in mcl_core.hpp) by measuring two complementary
 *          convergence properties as a function of B ∈ {0, 100, 1k, 5k,
 *          10k, 50k}:
 *
 *            (a) Mean trajectory divergence under 1-ULP perturbation,
 *                averaged across N_DIV_SAMPLES = 16 independent seeds.
 *                Single-sample divergence post-saturation is uniform on
 *                [0, π] with mean = π/2, variance = π²/12, sd = π/(2√3).
 *                The standard error of the mean across N seeds is therefore
 *                SE = π / (2·√(3·N)), giving SE ≈ 0.227 for N = 16.
 *
 *            (b) Goldilocks output χ² should converge to the production
 *                value (~221.94) once the trajectory is on the attractor.
 *
 * TESTS:
 *   - Mean trajectory divergence vs B (saturation toward π/2 mean)
 *   - Goldilocks χ² vs B (convergence to uniform)
 *   - Bit frequency vs B
 *   - Demonstrates B = 10,000 is past saturation (default value justified)
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_burnin_sweep mcl_burnin_sweep.cpp -lm && ./mcl_burnin_sweep
 *
 * EXPECTED RESULTS: (default: K=12, p=3, q=5):
 *   Theory:
 *     - Per-seed divergence post-saturation: Uniform(0, π), mean = π/2
 *     - Multi-seed mean SE (N=16): π/(2·√(3·N)) ≈ 0.227
 *     - Saturation iteration: B_sat = ln(π/ulp)/λ ≈ ln(2.2e15)/5.78 ≈ 6
 *
 *   B = 0     : mean divergence ≈ 1e-16 rad (1 ULP);    χ² may pass
 *   B = 100   : mean divergence saturated (~ π/2);      χ² passes
 *   B = 1k    : mean divergence saturated;              χ² passes
 *   B = 5k    : mean divergence saturated;              χ² passes
 *   B = 10k   : mean divergence saturated; χ² well below 310.46 threshold
 *   B = 50k   : no measurable improvement vs B = 10k
 *
 *   Pass criteria (computed from data — Rule F1):
 *     (1) χ² at B=10k below threshold 310.46
 *     (2) Mean divergence at B=10k >= π/4 (lenient: well into saturation;
 *         allows ±2.4·SE deviation around the asymptotic mean π/2 ≈ 1.571)
 *     (3) NEG CTRL B=0: mean divergence < π/4 (transient state)
 * REFERENCES:
 *   - mcl_core.hpp §3 (utility functions), §4 (engines), §6 (statistics),
 *     §15 (avalanche/ULP utilities)
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
static const char* DOC_ID      = "MCL-BURNIN-SWEEP-2026-0526-001";

// Default sample size per B value
static const int64_t N_DEFAULT = 1000000LL;
static const int64_t N_QUICK   = 100000LL;

// Burn-in values to test (must include 0 baseline + standard 10000)
static const int B_VALUES[] = {0, 100, 1000, 5000, 10000, 50000};
static const int N_B        = (int)(sizeof(B_VALUES) / sizeof(B_VALUES[0]));

// Number of independent (seed, perturbation-position) samples for the
// divergence estimate. Single-sample divergence after chaotic saturation is
// a uniform random variable on [0, π] with mean = π/2, sd = π/(2√3).
// Averaging over N_DIV_SAMPLES gives a stable estimator with
// SE = π / (2·√(3·N_DIV_SAMPLES)) ≈ 0.227 for N=16.
static const int N_DIV_SAMPLES = 16;

// Saturation classification thresholds (% of π).
// Theoretical mean post-saturation = 50% of π. The classification logic
// (in the analysis loop below) uses the 95% confidence interval of the
// sample mean (point ± 2·SE) rather than the point estimate alone:
//
//   - CI fully below TRANSIENT_PCT_MAX (5%)              → "transient (1-ULP regime)"
//   - CI overlaps [GROWING_PCT_MAX, NEAR_SAT_PCT_MAX]    → "SATURATED (CI overlaps π/2)"
//     (i.e., upper bound >= 35% AND lower bound <= 65%)
//   - CI fully above NEAR_SAT_PCT_MAX (65%)              → "over-rotated tail (outlier sample)"
//   - Otherwise (CI within transient-to-growing range)   → "growing" (chaos amplifying)
//
// CI-based classification is more robust than point-estimate classification:
// at true saturation, sample-to-sample variation can place the point
// estimate temporarily outside the [35%, 65%] band even though the
// population mean remains at π/2. The CI captures this uncertainty.
//
// Note: at true saturation, the population mean concentrates at ≈50% of π.
// All B-values past the saturation iteration should therefore land in the
// SATURATED bucket once the CI is wide enough to cover π/2.
static const double TRANSIENT_PCT_MAX  =  5.0;
static const double GROWING_PCT_MAX    = 35.0;
static const double NEAR_SAT_PCT_MAX   = 65.0;

// Multi-seed pool for divergence averaging (per Coding Standards Rule E6,
// the first entry MUST be DEFAULT_SEED).
//
// constexpr (rather than `static const`) is required so the array can be
// used in static_assert below.
static constexpr uint64_t DIV_SEEDS[N_DIV_SAMPLES] = {
    12345678901234ULL, 98765432109876ULL, 31415926535897ULL,
    27182818284590ULL, 16180339887498ULL, 14142135623730ULL,
    17320508075688ULL, 22360679774997ULL, 26457513110645ULL,
    34641016151377ULL, 37416573867739ULL, 44721359549995ULL,
    52915026221291ULL, 56124843266987ULL, 64807406984078ULL,
    73484692283495ULL
};
static_assert(sizeof(DIV_SEEDS) / sizeof(DIV_SEEDS[0]) == (size_t)N_DIV_SAMPLES,
              "DIV_SEEDS array size must match N_DIV_SAMPLES");

// Compile-time enforcement that DIV_SEEDS[0] == DEFAULT_SEED.
// If DEFAULT_SEED is updated in mcl_core.hpp, this assertion forces an
// explicit decision here rather than allowing silent drift.
static_assert(DIV_SEEDS[0] == DEFAULT_SEED,
    "Rule E6 violation: DIV_SEEDS[0] must equal DEFAULT_SEED. "
    "If DEFAULT_SEED changed in mcl_core.hpp, update DIV_SEEDS[0] to match "
    "or document the deliberate override here.");

// Measurement record for one B value
struct BResult {
    int    B;
    double divergence;       // mean angular distance over N_DIV_SAMPLES seeds
    double divergence_se;    // standard error of the mean
    double chi2;             // byte-level Goldilocks χ²
    double entropy;
    double bit_freq;
    bool   chi2_pass;
};

// Wrap angular distance into [0, π] for the shorter arc.
//
// Uses std::fmod() (O(1)) rather than a `while (d > MCL_TWO_PI)` loop:
// in the standard call path (mod2pi-bounded inputs) the loop runs 0-1
// iterations, but if the engine ever produces an unbounded value (e.g.,
// via MCL_UNSAFE_ALLOW_INVALID, future regression, or an unrelated callsite
// passing raw pre-mod2pi values), the loop becomes O(d / 2π) — potentially
// millions of iterations for a degenerate input. fmod is O(1) and well-
// defined for any finite double, including denormals and large magnitudes.
static double angular_distance(double a, double b) {
    double d = std::fmod(std::fabs(a - b), MCL_TWO_PI);
    // fmod can return a negative value if its first argument is negative;
    // here std::fabs() ensures d >= 0, but we guard defensively.
    if (d < 0.0) d += MCL_TWO_PI;
    if (d > MCL_TWO_PI / 2.0) d = MCL_TWO_PI - d;
    return d;
}

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
    std::printf("  MCL Burn-In Convergence Sweep\n");
    std::printf("  %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("******************************************************************************\n\n");
    std::printf("  Configuration:\n");
    std::printf("    Seed:          %llu (DEFAULT_SEED)\n",
                (unsigned long long)DEFAULT_SEED);
    std::printf("    K:             %.4f\n", K);
    std::printf("    (p, q):        (%lld, %lld)\n",
                (long long)p, (long long)q);
    std::printf("    Decimation:    %d\n", DECIMATION);
    std::printf("    Bytes per B:   %lld\n", (long long)N);
    std::printf("    B values:      {0, 100, 1k, 5k, 10k, 50k}\n");
    std::printf("    χ² threshold:  %.2f (df=255, α=0.01)\n",
                CHI2_THRESHOLD_STRICT);
    std::printf("    Attractor:     diameter ≈ 2π ≈ %.4f rad\n\n", MCL_TWO_PI);

    if (!k_is_12) {
        std::printf("  Note: Default reference values apply to K=12 only.\n");
        std::printf("        Results at K=%.4f are exploratory.\n\n",
                    K);
    }

    // ========================================================================
    // Pre-allocate stream buffer (Rule F12)
    // ========================================================================
    std::vector<uint8_t> stream((size_t)N, 0);

    // ========================================================================
    // For each B value, measure (a) trajectory divergence and (b) χ²
    // ========================================================================
    std::vector<BResult> results;
    auto t_start = std::chrono::steady_clock::now();

    for (int b_idx = 0; b_idx < N_B; b_idx++) {
        int B = B_VALUES[b_idx];
        std::printf("  [B = %d] running...\n", B);

        // ---- (a) Trajectory divergence under 1-ULP perturbation ----
        // Average over N_DIV_SAMPLES independent seeds for a stable estimator.
        // Single-sample divergence post-saturation is uniform on [0, π], so
        // a single measurement cannot reliably distinguish saturated from
        // unsaturated states.
        double sum_div    = 0.0;
        double sum_div_sq = 0.0;

        for (int s = 0; s < N_DIV_SAMPLES; s++) {
            double t1_a, t2_a, t1_b, t2_b;
            mcl_init_state(DIV_SEEDS[s], t1_a, t2_a);
            mcl_init_state(DIV_SEEDS[s], t1_b, t2_b);

            // Perturb θ₁ by 1 ULP after init (before burn-in begins)
            // mcl_add_ulp from mcl_core.hpp §15
            t1_b = mcl_add_ulp(t1_b);

            for (int i = 0; i < B; i++) {
                mcl_iterate_raw(t1_a, t2_a, p, q, K);
                mcl_iterate_raw(t1_b, t2_b, p, q, K);
            }

            double div_s = angular_distance(t1_a, t1_b);
            sum_div    += div_s;
            sum_div_sq += div_s * div_s;
        }

        double mean_div = sum_div / (double)N_DIV_SAMPLES;

        // Unbiased sample variance (Bessel correction): divide by N-1.
        // sum((x_i - mean)^2) = sum_x_sq - N*mean^2
        double sum_sq_dev = sum_div_sq - (double)N_DIV_SAMPLES * mean_div * mean_div;
        if (sum_sq_dev < 0.0) sum_sq_dev = 0.0;       // numerical safety
        double var_div  = (N_DIV_SAMPLES > 1) ?
                          sum_sq_dev / (double)(N_DIV_SAMPLES - 1) : 0.0;
        double sd_div   = std::sqrt(var_div);
        // Standard error of the mean
        double se_div   = sd_div / std::sqrt((double)N_DIV_SAMPLES);

        // ---- (b) Goldilocks χ² after burn-in B ----
        // Use DEFAULT_SEED for χ² measurement (Rule E6)
        double t1, t2;
        mcl_init_state(DEFAULT_SEED, t1, t2);
        for (int i = 0; i < B; i++) {
            mcl_iterate_raw(t1, t2, p, q, K);
        }

        for (int64_t i = 0; i < N; i++) {
            for (int d = 0; d < DECIMATION; d++) {
                mcl_iterate_raw(t1, t2, p, q, K);
            }
            uint8_t z1 = mcl_extract_zone1(t1, t2);
            uint8_t z2 = mcl_extract_zone2(t1, t2);
            stream[(size_t)i] = static_cast<uint8_t>(z1 ^ z2);
        }

        BResult res;
        res.B             = B;
        res.divergence    = mean_div;
        res.divergence_se = se_div;
        res.chi2          = chi_square(stream.data(), N);
        res.entropy       = shannon_entropy(stream.data(), N);
        res.bit_freq      = bit_frequency(stream.data(), N);
        res.chi2_pass     = (res.chi2 < CHI2_THRESHOLD_STRICT);

        results.push_back(res);
    }

    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();
    std::printf("  All sweeps complete: %.2f sec\n\n", elapsed);

    // ========================================================================
    // Print results table
    // ========================================================================
    std::printf("  Convergence Table (divergence: mean ± SE over %d seeds):\n",
                N_DIV_SAMPLES);
    std::printf("  %s\n", std::string(95, '=').c_str());
    std::printf("  | %6s | %18s | %10s | %10s | %10s | %s |\n",
                "B", "divergence(rad)", "chi2",
                "entropy", "bit_freq", "chi2 verdict");
    std::printf("  %s\n", std::string(95, '-').c_str());

    for (size_t i = 0; i < results.size(); i++) {
        const BResult& r = results[i];
        std::printf("  | %6d | %8.4f ± %7.4f | %10.2f | %10.6f | %10.6f | %s |\n",
                    r.B, r.divergence, r.divergence_se,
                    r.chi2, r.entropy, r.bit_freq,
                    r.chi2_pass ? "PASS" : "FAIL");
    }
    std::printf("  %s\n\n", std::string(95, '=').c_str());

    // ========================================================================
    // Saturation analysis
    // ========================================================================
    double half_circle = MCL_TWO_PI / 2.0;
    std::printf("  Saturation Analysis:\n");
    std::printf("  %s\n", std::string(70, '-').c_str());
    std::printf("    Full angular range:    %.4f rad (full circle 2π)\n",
                MCL_TWO_PI);
    std::printf("    Saturation reference:  %.4f rad (half circle = max diameter)\n",
                half_circle);
    std::printf("\n");

    for (size_t i = 0; i < results.size(); i++) {
        const BResult& r = results[i];
        double pct_of_half = 100.0 * r.divergence / half_circle;
        // 95% CI bounds (point ± 2·SE) as percentages of π.
        // We classify based on the CI rather than the point estimate so that
        // borderline samples whose CI overlaps π/2 are correctly identified
        // as saturated (the population mean is plausibly in the saturated band).
        double ci_lower_pct = 100.0 * (r.divergence - 2.0 * r.divergence_se) / half_circle;
        double ci_upper_pct = 100.0 * (r.divergence + 2.0 * r.divergence_se) / half_circle;
        const char* status;
        if (ci_upper_pct < TRANSIENT_PCT_MAX) {
            status = "transient (1-ULP regime)";
        } else if (ci_lower_pct > NEAR_SAT_PCT_MAX) {
            status = "over-rotated tail (outlier sample)";
        } else if (ci_upper_pct >= GROWING_PCT_MAX &&
                   ci_lower_pct <= NEAR_SAT_PCT_MAX) {
            // CI overlaps the [35%, 65%] saturation band
            status = "SATURATED (CI overlaps π/2)";
        } else {
            status = "growing";
        }
        std::printf("    B=%-6d: mean = %.4f ± %.4f rad (%5.1f%% of π,"
                    " CI [%5.1f%%, %5.1f%%]) — %s\n",
                    r.B, r.divergence, r.divergence_se,
                    pct_of_half, ci_lower_pct, ci_upper_pct, status);
    }
    std::printf("\n");

    // ========================================================================
    // Pass / Fail (Rule F1: computed from data)
    // ========================================================================
    bool global_pass = true;
    int  n_failures  = 0;

    // Identify index of B = 10000 (the production default)
    int idx_10k = -1;
    for (size_t i = 0; i < results.size(); i++) {
        if (results[i].B == BURNIN) {
            idx_10k = (int)i;
            break;
        }
    }

    if (idx_10k < 0) {
        std::printf("  [FAIL] B=%d (production default) not in sweep — config error\n",
                    BURNIN);
        n_failures++;
        global_pass = false;
    } else {
        const BResult& r10k = results[(size_t)idx_10k];

        // (1) χ² at B = 10k must pass
        if (!r10k.chi2_pass) {
            n_failures++;
            global_pass = false;
            std::printf("  [FAIL] B=%d: χ² = %.2f exceeds threshold %.2f\n",
                        BURNIN, r10k.chi2, CHI2_THRESHOLD_STRICT);
        } else {
            std::printf("  [PASS] B=%d: χ² = %.2f < %.2f (production value uniform)\n",
                        BURNIN, r10k.chi2, CHI2_THRESHOLD_STRICT);
        }

        // (2) Mean divergence at B = 10k must reach saturation regime.
        // The system dynamics live on T² but the divergence is the angular
        // distance between θ₁(t1_a) and θ₁(t1_b) on T¹ (projection onto
        // the first oscillator). After chaotic mixing, both samples are
        // independently uniform on [0, 2π); their (folded) angular distance
        // is therefore uniform on [0, π] with mean = π/2 and sd = π/(2√3).
        // The mean estimator over N_DIV_SAMPLES seeds has SE = π/(2·√(3·N))
        // ≈ 0.227 for N = 16.
        // We require mean_div >= π/4 (lenient: well above any pre-saturation
        // value, ~2.4·SE below the asymptote π/2).
        double sat_thr = MCL_TWO_PI / 8.0;  // π/4 ≈ 0.785
        if (r10k.divergence < sat_thr) {
            n_failures++;
            global_pass = false;
            std::printf("  [FAIL] B=%d: mean divergence = %.4f ± %.4f rad < %.4f\n",
                        BURNIN, r10k.divergence, r10k.divergence_se, sat_thr);
        } else {
            std::printf("  [PASS] B=%d: mean divergence = %.4f ± %.4f rad >= %.4f (saturated)\n",
                        BURNIN, r10k.divergence, r10k.divergence_se, sat_thr);
        }
    }

    // (3) R3: Negative control — B = 0 should show small divergence
    // (1-ULP perturbation has not yet amplified). Validates the test.
    const BResult& r0 = results[0];  // B = 0 is first entry
    bool neg_ok = (r0.divergence < MCL_TWO_PI / 8.0);
    if (!neg_ok) {
        n_failures++;
        global_pass = false;
        std::printf("  [FAIL] NEG CTRL B=0: divergence = %.4f rad >= %.4f\n",
                    r0.divergence, MCL_TWO_PI / 8.0);
        std::printf("           Test methodology may be broken (1-ULP not detected as small)\n");
    } else {
        std::printf("  [PASS] NEG CTRL B=0: divergence = %.4f rad < %.4f (transient state)\n",
                    r0.divergence, MCL_TWO_PI / 8.0);
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
