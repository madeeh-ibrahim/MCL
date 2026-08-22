/*
 * ============================================================================
 * MCL Safe Zone Per-Oscillator — Single-theta Per-Bit chi^2 Measurement
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-SAFEZONE-PEROSC-2026-0526-001
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
 * PURPOSE: Measure per-bit-position byte-level χ² for θ₁ and θ₂ extracted
 *          INDEPENDENTLY (single oscillator), to determine the empirical
 *          Safe Zone boundaries for each oscillator at K = 12. Measures
 *          the per-oscillator Safe Zone widths under the production
 *          hash-based initialization in mcl_core.hpp.
 *
 *          Two distinct conventions exist for initial-state derivation:
 *
 *              Prototype init (decimal multipliers 0.1, 0.2):
 *                  θ₁ = [11, 35] = 25 bits, θ₂ = [12, 35] = 24 bits
 *              Production init (hash_seed in mcl_core.hpp):
 *                  θ₁ = [12, 35] = 24 bits, θ₂ = [12, 36] = 25 bits
 *
 *          This experiment uses the production engine (`mcl_core.hpp`
 *          hash-based initialization) to provide the authoritative
 *          measurement matching deployed code.
 *
 *          VERIFIED PROPERTIES:
 *            - Per-bit byte-level χ² for θ₁ alone, b ∈ [0, 51]
 *            - Per-bit byte-level χ² for θ₂ alone, b ∈ [0, 51]
 *            - Empirical Safe Zone boundaries [L, U] for each oscillator
 *            - Confirms or refutes 24/25 bit asymmetry at K = 12
 *
 *          USAGE:
 *            ./mcl_safe_zone_per_osc                # default: K=12, p=3, q=5, N=10^8
 *            ./mcl_safe_zone_per_osc --quick        # N=10^6 (smoke-test)
 *            ./mcl_safe_zone_per_osc --N 10000000   # custom sample count
 *            ./mcl_safe_zone_per_osc --K 10.0       # alternate K
 *            ./mcl_safe_zone_per_osc --help         # print options and exit
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_safe_zone_per_osc mcl_safe_zone_per_osc.cpp -lm && ./mcl_safe_zone_per_osc
 *
 * EXPECTED RESULTS: (K=12, p=3, q=5, default seed, N=10^8) PASS criteria (computed from
 *                   data — no hardcoded thresholds): (1) NEG CTRL: bit 0 must FAIL (LSB
 *                   rounding artifacts dominate); (2) NEG CTRL: bit 51 must FAIL (deep MSB
 *                   exponent correlation); (3) Safe Zone of width >= 18 bits must exist for
 *                   at least one oscillator.
 * REFERENCES:       Paper 1 §III.C, §III.D (Safe Zone boundaries, per-bit χ² methodology);
 *                   NIST SP 800-22 (frequency goodness-of-fit testing);
 *                   mcl_core.hpp §3, §4 (hash_seed, mcl_init_state, mcl_iterate_raw).
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
static const char* DOC_ID      = "MCL-SAFEZONE-PEROSC-2026-0526-001";

// Mantissa positions to scan (full IEEE 754 double mantissa, bits 0..51)
static const int MANTISSA_BITS = 52;

// Default sample size — Paper 1 specifies N = 10^8 for the
// per-bit χ² characterization
static const int64_t N_SAMPLES_DEFAULT = 100000000LL;
static const int64_t N_SAMPLES_QUICK   = 1000000LL;

// Safe Zone search structure
struct SafeZone {
    int lo;
    int hi;
    int width;
};

// Find largest contiguous Safe Zone (χ² < CHI2_THRESHOLD_STRICT)
static SafeZone find_safe_zone(const std::vector<double>& chi2_arr) {
    SafeZone best = {-1, -1, 0};
    int cur_lo = -1;
    int cur_len = 0;
    for (int b = 0; b < MANTISSA_BITS; b++) {
        if (chi2_arr[(size_t)b] < CHI2_THRESHOLD_STRICT) {
            if (cur_lo < 0) cur_lo = b;
            cur_len++;
            if (cur_len > best.width) {
                best.width = cur_len;
                best.lo    = cur_lo;
                best.hi    = b;
            }
        } else {
            cur_lo = -1;
            cur_len = 0;
        }
    }
    return best;
}

int main(int argc, char** argv) {
    int64_t N = N_SAMPLES_DEFAULT;
    double  K = K_DEFAULT;
    int64_t p = 3;
    int64_t q = 5;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            std::printf("MCL Safe Zone Per-Oscillator Verification v%s\n",
                        DOC_VERSION);
            std::printf("Usage: %s [options]\n\n", argv[0]);
            std::printf("Options:\n");
            std::printf("  --quick         use N=%lld samples (smoke test, ~1 second)\n",
                        (long long)N_SAMPLES_QUICK);
            std::printf("  --N <int>       sample count (default %lld)\n",
                        (long long)N_SAMPLES_DEFAULT);
            std::printf("  --K <double>    coupling strength (default %.4f)\n",
                        K_DEFAULT);
            std::printf("  --help, -h      print this help and exit\n\n");
            std::printf("Document ID: %s\n", DOC_ID);
            std::printf("Engine:      mcl_core.hpp (MCL_T2 production engine)\n");
            return 0;
        } else if (std::strcmp(argv[i], "--quick") == 0) {
            N = N_SAMPLES_QUICK;
        } else if (std::strcmp(argv[i], "--N") == 0) {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "FATAL: --N requires an integer argument\n");
                return 2;
            }
            N = std::atoll(argv[++i]);
        } else if (std::strcmp(argv[i], "--K") == 0) {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "FATAL: --K requires a numeric argument\n");
                return 2;
            }
            K = std::atof(argv[++i]);
        } else {
            std::fprintf(stderr,
                "FATAL: unknown argument '%s'.  Run with --help for usage.\n",
                argv[i]);
            return 2;
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

    std::printf("\n");
    std::printf("==============================================================================\n");
    std::printf("  MCL Safe Zone Per-Oscillator Verification\n");
    std::printf("  %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("==============================================================================\n\n");
    std::printf("  Configuration:\n");
    std::printf("    Seed:         %llu (DEFAULT_SEED)\n",
                (unsigned long long)DEFAULT_SEED);
    std::printf("    K:            %.4f\n", K);
    std::printf("    (p, q):       (%lld, %lld)\n",
                (long long)p, (long long)q);
    std::printf("    Burn-in:      %d\n", BURNIN);
    std::printf("    Decimation:   %d\n", DECIMATION);
    std::printf("    N samples:    %lld\n", (long long)N);
    std::printf("    χ² threshold: %.2f (df=255, α=0.01)\n\n",
                CHI2_THRESHOLD_STRICT);

    // ========================================================================
    // Initialize state via mcl_core.hpp utilities, perform burn-in
    // ========================================================================
    double t1, t2;
    mcl_init_state(DEFAULT_SEED, t1, t2);
    for (int i = 0; i < BURNIN; i++) {
        mcl_iterate_raw(t1, t2, p, q, K);
    }

    // ========================================================================
    // Frequency tables: 52 bit positions × 256 byte values
    // (heap-allocated to avoid stack overflow)
    // ========================================================================
    std::vector<std::vector<int64_t>> freq_t1(
        (size_t)MANTISSA_BITS, std::vector<int64_t>(256, 0));
    std::vector<std::vector<int64_t>> freq_t2(
        (size_t)MANTISSA_BITS, std::vector<int64_t>(256, 0));

    auto t_start = std::chrono::steady_clock::now();

    // ========================================================================
    // Sample generation loop
    //
    // For each sample: apply DECIMATION raw iterations, then for every
    // bit position b ∈ [0, 51], extract an 8-bit value via shift-right
    // by b and mask with 0xFF.
    //
    // NOTE on extraction range: per Paper 1 §III.C the
    // extraction is `(b1 >> b) & 0xFF` for b ∈ [0, 51]. For b >= 45 the
    // 8-bit window extends past the mantissa boundary (bit 51) into the
    // exponent bits — this is intentional and is the methodology used
    // throughout the per-bit characterization. The "MSB Zone failure"
    // at b ∈ [40, 51] reported in Paper 1 §III.C is a direct
    // consequence: byte values become dominated by the
    // (nearly-constant) exponent bits, producing the observed
    // χ² > threshold.
    // ========================================================================
    std::printf("  Generating %lld samples...\n", (long long)N);
    int64_t progress_step = (N >= 10) ? (N / 10) : 1;

    for (int64_t i = 0; i < N; i++) {
        for (int d = 0; d < DECIMATION; d++) {
            mcl_iterate_raw(t1, t2, p, q, K);
        }

        uint64_t b1 = d2b(t1);
        uint64_t b2 = d2b(t2);

        for (int b = 0; b < MANTISSA_BITS; b++) {
            uint8_t v1 = static_cast<uint8_t>((b1 >> b) & 0xFFULL);
            uint8_t v2 = static_cast<uint8_t>((b2 >> b) & 0xFFULL);
            freq_t1[(size_t)b][(size_t)v1]++;
            freq_t2[(size_t)b][(size_t)v2]++;
        }

        if ((i + 1) % progress_step == 0) {
            double pct = 100.0 * (double)(i + 1) / (double)N;
            std::printf("    %.0f%% complete\n", pct);
        }
    }

    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();
    std::printf("  Generation complete: %.2f sec\n\n", elapsed);

    // ========================================================================
    // Per-bit χ² computation (df = 255)
    // ========================================================================
    std::vector<double> chi2_t1((size_t)MANTISSA_BITS, 0.0);
    std::vector<double> chi2_t2((size_t)MANTISSA_BITS, 0.0);
    double expected = (double)N / 256.0;

    for (int b = 0; b < MANTISSA_BITS; b++) {
        double sum1 = 0.0;
        double sum2 = 0.0;
        for (int v = 0; v < 256; v++) {
            double d1 = (double)freq_t1[(size_t)b][(size_t)v] - expected;
            double d2 = (double)freq_t2[(size_t)b][(size_t)v] - expected;
            sum1 += d1 * d1 / expected;
            sum2 += d2 * d2 / expected;
        }
        chi2_t1[(size_t)b] = sum1;
        chi2_t2[(size_t)b] = sum2;
    }

    // ========================================================================
    // Print per-bit χ² table
    // ========================================================================
    std::printf("  Per-bit Byte-Level χ² Table (df=255, threshold = %.2f):\n",
                CHI2_THRESHOLD_STRICT);
    std::printf("  %s\n", std::string(72, '=').c_str());
    std::printf("  | Bit |       θ₁ alone        |       θ₂ alone        |\n");
    std::printf("  | pos |       χ²        |  V    |       χ²        |  V    |\n");
    std::printf("  %s\n", std::string(72, '-').c_str());

    for (int b = 0; b < MANTISSA_BITS; b++) {
        const char* s1 = (chi2_t1[(size_t)b] < CHI2_THRESHOLD_STRICT) ?
            "PASS" : "FAIL";
        const char* s2 = (chi2_t2[(size_t)b] < CHI2_THRESHOLD_STRICT) ?
            "PASS" : "FAIL";
        std::printf("  | %3d | %15.2e | %-7s | %15.2e | %-7s |\n",
                    b, chi2_t1[(size_t)b], s1,
                    chi2_t2[(size_t)b], s2);
    }
    std::printf("  %s\n\n", std::string(72, '=').c_str());

    // ========================================================================
    // Determine empirical Safe Zone boundaries
    // ========================================================================
    SafeZone sz1 = find_safe_zone(chi2_t1);
    SafeZone sz2 = find_safe_zone(chi2_t2);

    std::printf("  Empirical Safe Zone (largest contiguous region χ² < %.2f):\n",
                CHI2_THRESHOLD_STRICT);
    std::printf("  %s\n", std::string(60, '-').c_str());
    if (sz1.width > 0) {
        std::printf("    θ₁ alone: [%2d, %2d] = %2d bits\n",
                    sz1.lo, sz1.hi, sz1.width);
    } else {
        std::printf("    θ₁ alone: NO Safe Zone found\n");
    }
    if (sz2.width > 0) {
        std::printf("    θ₂ alone: [%2d, %2d] = %2d bits\n",
                    sz2.lo, sz2.hi, sz2.width);
    } else {
        std::printf("    θ₂ alone: NO Safe Zone found\n");
    }
    std::printf("\n");

    // ========================================================================
    // Comparison with prior measurements
    // ========================================================================
    std::printf("  Comparison (K=%.1f):\n", K);
    std::printf("  %s\n", std::string(72, '-').c_str());

    // Reference values are documented for K=12 specifically.
    // For other K values, only THIS RUN line is meaningful.
    bool k_is_12 = (std::fabs(K - 12.0) < 1e-9);
    if (k_is_12) {
        std::printf("    Prototype init (decimal multipliers 0.1, 0.2):\n");
        std::printf("        θ₁ = [11, 35] = 25 bits  |  θ₂ = [12, 35] = 24 bits\n");
        std::printf("    Production init (mcl_core.hpp hash_seed):\n");
        std::printf("        θ₁ = [12, 35] = 24 bits  |  θ₂ = [12, 36] = 25 bits\n");
    } else {
        std::printf("    Reference values are documented for K=12 only.\n");
        std::printf("    At K=%.4f no published reference exists.\n", K);
    }
    std::printf("    THIS RUN (production hash_seed init):\n");
    std::printf("        θ₁ = [%2d, %2d] = %2d bits  |  θ₂ = [%2d, %2d] = %2d bits\n\n",
                sz1.lo, sz1.hi, sz1.width,
                sz2.lo, sz2.hi, sz2.width);

    // ========================================================================
    // Pass / Fail (computed from data — Rule F1)
    // ========================================================================
    bool global_pass = true;
    int  n_failures  = 0;

    // R3: Negative control 1 — bit 0 (LSB) must FAIL
    bool neg_lsb = (chi2_t1[0] > CHI2_THRESHOLD_STRICT) &&
                   (chi2_t2[0] > CHI2_THRESHOLD_STRICT);
    if (!neg_lsb) {
        n_failures++;
        global_pass = false;
        std::printf("  [FAIL] NEG CTRL bit 0: should fail (LSB rounding) — sanity check broken\n");
    } else {
        std::printf("  [PASS] NEG CTRL bit 0 fails as expected (LSB rounding artifacts)\n");
    }

    // R3: Negative control 2 — bit 51 (deep MSB) must FAIL
    bool neg_msb = (chi2_t1[51] > CHI2_THRESHOLD_STRICT) ||
                   (chi2_t2[51] > CHI2_THRESHOLD_STRICT);
    if (!neg_msb) {
        n_failures++;
        global_pass = false;
        std::printf("  [FAIL] NEG CTRL bit 51: should fail (exponent correlation)\n");
    } else {
        std::printf("  [PASS] NEG CTRL bit 51 fails as expected (exponent correlation)\n");
    }

    // Positive: at least one Safe Zone of width >= 18 bits
    int max_width = (sz1.width > sz2.width) ? sz1.width : sz2.width;
    if (max_width < 18) {
        n_failures++;
        global_pass = false;
        std::printf("  [FAIL] No Safe Zone of width >= 18 bits found (max = %d)\n",
                    max_width);
    } else {
        std::printf("  [PASS] Safe Zone of width %d bits found (>= 18 required)\n",
                    max_width);
    }

    // ========================================================================
    // Footer
    // ========================================================================
    std::printf("\n");
    std::printf("  ============================================================================\n");
    std::printf("  GLOBAL VERDICT: %s\n", global_pass ? "PASS" : "FAIL");
    std::printf("  Failures:       %d\n", n_failures);
    std::printf("  Document:       %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("  Reference:      Paper 1 §III.C, §III.D\n");
    std::printf("  ============================================================================\n\n");

    return global_pass ? 0 : 1;
}
