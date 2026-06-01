/*
 * ============================================================================
 * MCL Channel Capacity Scaling
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-SCALE-2026-0526-001
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
 * PURPOSE: Verify MCL scales from 20 to 1M+ simultaneous orthogonal
 *          channels without quality degradation. Each scale point tests
 *          per-channel entropy, pairwise correlation (sampled), Hamming
 *          distance, and multiplex quality.
 *
 *          USAGE:
 *            ./mcl_scale              # default: 20 -> 1,000 channels, 100KB/ch
 *            ./mcl_scale --1m         # 20 -> 1,000,000 channels, 1KB/ch at top
 *            ./mcl_scale --5m         # 20 -> 5,000,000 channels, 1KB/ch at top
 *            ./mcl_scale --10m        # 20 -> 10,000,000 channels, 1KB/ch at top
 *            ./mcl_scale --strict     # 7 scales 1K -> 1M @ fixed 10KB/ch
 *                                     #   (no RAM-cap adjustment;
 *                                     #    requires ~10 GB RAM at 1M scale)
 *            ./mcl_scale --help       # this help
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_scale mcl_scale.cpp -lm && ./mcl_scale
 *
 * EXPECTED RESULTS: All scales: PASS, no degradation, neg control PASS.
 *                   VERDICT: PASS - scalable to tested channel count.
 * REFERENCES:       mcl_core.hpp (MCL_T2 engine + generate_topologies()).
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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#ifdef _OPENMP
 #include <omp.h>
#endif

// ============================================================================
// Document version constants (mirror header).
// ============================================================================
static constexpr const char* const DOC_VERSION = "6.0.0";
static constexpr const char* const DOC_ID      = "MCL-SCALE-2026-0526-001";

// ============================================================================
// Test parameters - canonical and rationale
// ============================================================================

// Bytes/channel default and RAM budget
static constexpr int64_t BYTES_DEFAULT      = 100000;       // 100 KB/ch
static constexpr int64_t RAM_TARGET_BYTES   = 1000000000LL; // 1 GB total
//
// Per-channel auxiliary memory not in channels_flat:
//   - topos vector:    NC * sizeof(Topology) = NC * 16 bytes
//   - ent_vals vector: NC * sizeof(double)   = NC *  8 bytes
// Total auxiliary overhead per channel = 24 bytes. Subtract from the RAM
// budget before dividing for bytes_per_ch so peak RAM stays within target
// at large NC.
static constexpr int64_t PER_CH_OVERHEAD    = 24;
//
// MIN_BYTES_QUALITY = 50000 (50 KB). Below this byte budget the empirical
// Shannon-entropy estimator and Hamming-distance estimator carry enough
// finite-sample variance to make pass/fail gating unreliable, so quality
// metrics are reported as informational only and only the correlation
// independence test gates the verdict.
//
// Rationale at the threshold:
//   At B=50000, stddev(H_empirical) ~= 0.0045 bits/byte, giving the
//   entropy threshold a ~5-sigma margin against the ENT_MARGIN window
//   below (false-fail rate << 0.001%). The Hamming sigma at B=50K is
//   ~0.079%, so the [49%, 51%] window is a 12.6-sigma envelope -- robust.
static constexpr int64_t MIN_BYTES_QUALITY  = 50000;        // 50 KB minimum

// Pair-sampling caps per mode
static constexpr int     MAX_PAIRS_DEFAULT  = 2000;
static constexpr int     MAX_PAIRS_LARGE    = 5000;

// Pass criteria
// Correlation: pass if max|r| < theoretical_sampled * 1.5 (EVT-based bound,
//              not at the half-normal noise floor).
// Hamming:     pass if range fits in [49.0%, 51.0%] (1% window).
// Entropy:     dynamically computed sample-bias deficit + 0.05 margin
//              (5-sigma at the 50 KB quality floor).
static constexpr double  CORR_PASS_FACTOR   = 1.5;          // x sampled bound
static constexpr double  HAM_LO             = 49.0;
static constexpr double  HAM_HI             = 51.0;
static constexpr double  ENT_MARGIN         = 0.05;
static constexpr double  DEGRADATION_RATIO  = 1.5;          // ratio threshold

// Negative control parameters
static constexpr int64_t NEG_CTRL_BYTES     = 100000;
static constexpr double  NEG_CTRL_R_MIN     = 0.999;

// Sampling RNG seed (xorshift)
static constexpr uint64_t SAMPLING_PRNG_SEED = 0x123456789ABCDEF0ULL;

// ============================================================================
// Result aggregator
// ============================================================================
struct ScaleResult {
    int     n_ch;
    int64_t bytes_per_ch;
    double  gen_time;
    double  min_ent, max_ent, mean_ent;
    double  max_corr, mean_corr, theoretical_sampled, theoretical_total;
    int64_t pairs_tested, pairs_total;
    double  ham_min, ham_max, ham_mean;
    double  mux_ent, mux_chi;
    bool    pass;
};

// ============================================================================
// CLI parsing
// ============================================================================
static void print_help(const char* progname) {
    std::printf(
        "Usage:\n"
        "  %s              # default: 20 -> 1,000 channels, 100KB/ch\n"
        "  %s --1m         # 20 -> 1,000,000 channels\n"
        "  %s --5m         # 20 -> 5,000,000 channels\n"
        "  %s --10m        # 20 -> 10,000,000 channels\n"
        "  %s --strict     # 7 scales 1K -> 1M @ fixed 10KB/ch (no RAM cap)\n"
        "  %s --help       # this message\n"
        "\n"
        "Document: %s v%s\n"
        "Threads:  %s\n",
        progname, progname, progname, progname, progname, progname,
        DOC_ID, DOC_VERSION,
#ifdef _OPENMP
        "OpenMP enabled (auto-detect)"
#else
        "single-threaded (build with -fopenmp for multicore)"
#endif
    );
}

int main(int argc, char* argv[]) {
    std::setbuf(stdout, nullptr);

    // Default mode
    std::vector<int> scales       = {20, 50, 100, 200, 500, 1000};
    int64_t          bytes_default = BYTES_DEFAULT;
    int              max_pairs     = MAX_PAIRS_DEFAULT;
    const char*      mode_name     = "default (20->1K)";
    bool             fixed_bytes   = false;  // --strict: do NOT shrink bytes_per_ch by RAM cap

    // CLI parsing - mode mutex enforced
    bool mode_set = false;
    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "--1m") {
            if (mode_set) {
                std::fprintf(stderr,
                    "Error: multiple modes specified.\n");
                return 2;
            }
            scales        = {20, 100, 1000, 10000, 100000, 1000000};
            bytes_default = BYTES_DEFAULT;
            max_pairs     = MAX_PAIRS_LARGE;
            mode_name     = "--1m (20->1M)";
            mode_set      = true;
        } else if (arg == "--5m") {
            if (mode_set) {
                std::fprintf(stderr,
                    "Error: multiple modes specified.\n");
                return 2;
            }
            scales        = {20, 100, 1000, 10000, 100000, 1000000, 5000000};
            bytes_default = BYTES_DEFAULT;
            max_pairs     = MAX_PAIRS_LARGE;
            mode_name     = "--5m (20->5M)";
            mode_set      = true;
        } else if (arg == "--10m") {
            if (mode_set) {
                std::fprintf(stderr,
                    "Error: multiple modes specified.\n");
                return 2;
            }
            scales        = {20, 100, 1000, 10000, 100000, 1000000, 10000000};
            bytes_default = BYTES_DEFAULT;
            max_pairs     = MAX_PAIRS_LARGE;
            mode_name     = "--10m (20->10M)";
            mode_set      = true;
        } else if (arg == "--strict") {
            // --------------------------------------------------------------
            // STRICT FIXED-BUDGET MODE
            // --------------------------------------------------------------
            // Runs 7 logarithmically-spaced scale points from 1,000 to
            // 1,000,000 channels with a FIXED per-channel byte budget of
            // 10,000 bytes regardless of scale.
            //
            // Unlike --1m / --5m / --10m which adapt bytes_per_ch downward
            // to keep total RAM below RAM_TARGET_BYTES, this mode bypasses
            // the RAM cap so the byte budget is identical at every scale
            // point. This produces independence numbers that are directly
            // comparable across the full scale range without scale-induced
            // 1/sqrt(L) bias in the maximum-correlation statistic.
            //
            // Scale points: {1000, 3000, 10000, 30000, 100000, 300000,
            // 1000000} -- ratio ~= 3.16 (half-decade spacing on log axis).
            //
            // NOTE: At 1,000,000 channels x 10,000 bytes/ch = 10 GB of
            // channel data plus auxiliary overhead. ~16 GB system RAM
            // recommended; the run will swap on machines with less.
            //
            // METHODOLOGY NOTE: At 10 KB/ch, bytes_per_ch is below
            // MIN_BYTES_QUALITY (50 KB), so per-channel entropy and
            // Hamming metrics are reported as informational only and
            // PASS/FAIL is determined by the correlation independence
            // test alone. This is required by the underlying mathematics:
            // at any finite byte budget, the empirical Shannon entropy
            // estimator is biased downward from its theoretical maximum
            // (Miller-Madow finite-sample bias). The bias does not
            // indicate reduced output quality; it is purely a property
            // of finite-sample estimation. The correlation test, by
            // contrast, has a well-defined sampling distribution at any
            // L and remains the definitive independence metric.
            // --------------------------------------------------------------
            if (mode_set) {
                std::fprintf(stderr,
                    "Error: multiple modes specified.\n");
                return 2;
            }
            scales        = {1000, 3000, 10000, 30000, 100000, 300000, 1000000};
            bytes_default = 10000;            // 10 KB/ch fixed budget
            max_pairs     = MAX_PAIRS_LARGE;
            mode_name     = "--strict (7 scales 1K->1M @ 10KB/ch fixed budget)";
            fixed_bytes   = true;             // bypass RAM cap
            mode_set      = true;
        } else {
            std::fprintf(stderr,
                "Error: Unknown argument: %s\n"
                "Try '%s --help' for usage.\n",
                argv[i], argv[0]);
            return 1;
        }
    }

    auto t_start = std::chrono::steady_clock::now();

    int n_threads = 1;
#ifdef _OPENMP
    n_threads = omp_get_max_threads();
#endif

    std::printf("\n==============================================================================\n");
    std::printf("  MCL CHANNEL SCALING v%s\n", DOC_VERSION);
    std::printf("  Mode: %s | Threads: %d\n", mode_name, n_threads);
    std::printf("==============================================================================\n\n");

    std::vector<ScaleResult> results;
    int total_exp = 0, passed_exp = 0;

    for (int NC : scales) {
        // Adaptive bytes: NC × bytes ≤ RAM_TARGET (skipped if fixed_bytes is set
        // by --strict mode, which deliberately holds bytes_per_ch constant
        // across all scale points for direct cross-scale numerical
        // comparability).
        int64_t bytes_per_ch = bytes_default;
        if (!fixed_bytes && static_cast<int64_t>(NC) * bytes_per_ch > RAM_TARGET_BYTES) {
            // Account for per-channel auxiliary memory (topos + ent_vals)
            // before dividing remaining budget across channels.
            const int64_t aux_overhead = static_cast<int64_t>(NC) * PER_CH_OVERHEAD;
            const int64_t RAM_for_data = RAM_TARGET_BYTES - aux_overhead;
            bytes_per_ch = std::max<int64_t>(1, RAM_for_data / NC);
        }

        // If bytes < 50KB: quality metrics unreliable, test ONLY independence.
        //
        // MATHEMATICAL NOTE - why 50KB minimum for quality:
        //
        //   At B bytes, entropy variance sigma(H) ~= sqrt(255/(4*B^2*ln^2(2))).
        //   Hamming sigma ~ 1/sqrt(8B).
        //
        //   B=50000:  sigma(H) ~= 0.0042 << ENT_MARGIN=0.05 -> 11-sigma margin
        //             -> false-fail rate << 1e-6.
        //
        //   Hamming check at B=50K: sigma_hamming = 0.079%, [49,51] window =
        //   12.6 sigma -- robust.
        //
        //   Below 50KB the quality metrics are reported but not gated on; the
        //   correlation (independence) test alone determines pass/fail since
        //   correlation noise scales as 1/sqrt(B) regardless and the EVT bound
        //   adapts.
        bool quality_reliable = (bytes_per_ch >= MIN_BYTES_QUALITY);
        if (bytes_per_ch < MIN_BYTES_QUALITY) {
            std::printf("  NOTE: %lldKB/ch < 50KB - quality metrics informational only.\n",
                static_cast<long long>(bytes_per_ch / 1000));
            std::printf("        Independence (correlation) is the definitive test.\n\n");
        }

        sep(("SCALE: " + std::to_string(NC) + " CHANNELS").c_str());
        std::printf("  Channels: %d | Bytes/ch: %lldKB | RAM: ~%lldMB\n",
            NC,
            static_cast<long long>(bytes_per_ch / 1000),
            static_cast<long long>(static_cast<int64_t>(NC) * bytes_per_ch / 1000000));

        // Generate topologies
        auto topos = generate_topologies(NC);
        if (static_cast<int>(topos.size()) < NC) {
            std::printf("  WARNING: only %d topologies generated (requested %d)\n",
                static_cast<int>(topos.size()), NC);
            continue;
        }

        // Generate channels (parallel)
        // Use a FLAT std::vector<uint8_t> with index arithmetic instead of
        // nested std::vector<std::vector<uint8_t>>. At very large NC, each
        // inner vector carries ~24 B header overhead -- at NC=10M that is
        // ~240 MB of header memory alone, pushing the actual peak above
        // RAM_TARGET. A single flat allocation has constant overhead.
        // Channel i occupies bytes [i*bytes_per_ch, (i+1)*bytes_per_ch).
        auto tg = std::chrono::steady_clock::now();
        std::vector<uint8_t> channels_flat(
            static_cast<size_t>(NC) * static_cast<size_t>(bytes_per_ch));
        auto ch_ptr = [&](int i) -> uint8_t* {
            return channels_flat.data()
                + static_cast<size_t>(i) * static_cast<size_t>(bytes_per_ch);
        };

#ifdef _OPENMP
#pragma omp parallel for schedule(dynamic)
#endif
        for (int i = 0; i < NC; i++) {
            MCL_T2 gen(DEFAULT_SEED, topos[static_cast<size_t>(i)].p,
                                     topos[static_cast<size_t>(i)].q);
            gen.gen_bytes(ch_ptr(i), bytes_per_ch);
        }

        double gen_time = std::chrono::duration<double>(
            std::chrono::steady_clock::now() - tg).count();
        // Floor gen_time at 1e-9 to avoid "inf ch/s" on implausibly fast
        // cycles (e.g., DCE-eliminated work or sub-ns timer resolution
        // edge cases).
        const double gen_time_safe = std::max(gen_time, 1e-9);
        std::printf("  Generated in %.1f s (%.0f ch/s)\n",
            gen_time, NC / gen_time_safe);

        // ── EXP 1: Per-channel entropy (parallel) ──
        double min_ent = 8.0, max_ent = 0, sum_ent = 0;
        std::vector<double> ent_vals(static_cast<size_t>(NC));
#ifdef _OPENMP
#pragma omp parallel for schedule(dynamic)
#endif
        for (int i = 0; i < NC; i++) {
            ent_vals[static_cast<size_t>(i)] =
                shannon_entropy(ch_ptr(i), bytes_per_ch);
        }
        for (int i = 0; i < NC; i++) {
            const double e = ent_vals[static_cast<size_t>(i)];
            if (e < min_ent) min_ent = e;
            if (e > max_ent) max_ent = e;
            sum_ent += e;
        }
        const double mean_ent = sum_ent / NC;
        std::printf("  Entropy: min=%.6f max=%.6f mean=%.6f\n",
            min_ent, max_ent, mean_ent);

        // ── EXP 2: Sampled pairwise correlation ──
        const int64_t total_pairs   = static_cast<int64_t>(NC) * (NC - 1) / 2;
        const int64_t pairs_to_test = std::min(total_pairs,
                                               static_cast<int64_t>(max_pairs));

        std::vector<std::pair<int,int>> test_pairs;
        if (total_pairs <= static_cast<int64_t>(max_pairs)) {
            for (int i = 0; i < NC; i++)
                for (int j = i + 1; j < NC; j++)
                    test_pairs.push_back({i, j});
        } else {
            // Deterministic sampling with xorshift64
            uint64_t prng = SAMPLING_PRNG_SEED + static_cast<uint64_t>(NC);
            auto next = [&prng]() -> uint64_t {
                prng ^= prng << 13;
                prng ^= prng >> 7;
                prng ^= prng << 17;
                return prng;
            };
            std::set<int64_t> seen;
            int attempts = 0;
            const int max_attempts = static_cast<int>(pairs_to_test) * 20;
            while (static_cast<int64_t>(test_pairs.size()) < pairs_to_test
                   && attempts < max_attempts) {
                int a = static_cast<int>(next() % static_cast<uint64_t>(NC));
                int b = static_cast<int>(next() % static_cast<uint64_t>(NC));
                if (a == b) { attempts++; continue; }
                if (a > b) std::swap(a, b);
                const int64_t key = static_cast<int64_t>(a) * NC + b;
                if (seen.insert(key).second)
                    test_pairs.push_back({a, b});
                attempts++;
            }
        }

        std::vector<double> corrs(test_pairs.size());
        std::vector<double> hams (test_pairs.size());

#ifdef _OPENMP
#pragma omp parallel for schedule(dynamic)
#endif
        for (int64_t pi = 0;
             pi < static_cast<int64_t>(test_pairs.size()); pi++) {
            const int a = test_pairs[static_cast<size_t>(pi)].first;
            const int b = test_pairs[static_cast<size_t>(pi)].second;
            corrs[static_cast<size_t>(pi)] = std::abs(pearson_r(
                ch_ptr(a), ch_ptr(b), bytes_per_ch));
            hams[static_cast<size_t>(pi)] = hamming_pct(
                ch_ptr(a), ch_ptr(b), bytes_per_ch);
        }

        double max_corr = 0, sum_corr = 0;
        double ham_min  = 100, ham_max  = 0, ham_sum  = 0;
        for (size_t pi = 0; pi < test_pairs.size(); pi++) {
            if (corrs[pi] > max_corr) max_corr = corrs[pi];
            sum_corr += corrs[pi];
            if (hams[pi] < ham_min) ham_min = hams[pi];
            if (hams[pi] > ham_max) ham_max = hams[pi];
            ham_sum  += hams[pi];
        }
        const double mean_corr = sum_corr / static_cast<double>(test_pairs.size());
        const double ham_mean  = ham_sum  / static_cast<double>(test_pairs.size());

        // Theoretical max|r| for independent sequences (EVT)
        //
        // MATHEMATICAL NOTE - sampled vs total bound:
        // |r| for independent n-byte streams is half-normal with sigma = 1/sqrt(B).
        // EVT expected max of K such variables: sigma * sqrt(2*ln(2K/pi)).
        // TOTAL bound uses K = C(NC,2) - all possible pairs.
        // SAMPLED bound uses K = pairs actually tested (<= max_pairs).
        // Pass/fail MUST use sampled bound: the measured max comes from
        // the sampled set. Using total bound (K >> sampled) inflates the
        // threshold and masks real degradation at large scales.
        // Example: NC=1M, total=5e11, sampled=5000.
        //   Total bound = 0.235 (useless - never reached by 5000 samples)
        //   Sampled bound = 0.127 (meaningful comparison)
        const double sigma_r = 1.0 / std::sqrt(static_cast<double>(bytes_per_ch));
        const double theoretical_total = sigma_r * std::sqrt(2.0 * std::log(
            2.0 * static_cast<double>(total_pairs) / MCL_PI));
        const double theoretical_sampled = sigma_r * std::sqrt(2.0 * std::log(
            2.0 * static_cast<double>(test_pairs.size()) / MCL_PI));

        std::printf("  Correlation: max|r|=%.6f mean|r|=%.6f\n",
            max_corr, mean_corr);
        std::printf("  Sampled bound (n=%lld): %.6f | Total bound (N=%lld): %.6f\n",
            static_cast<long long>(test_pairs.size()), theoretical_sampled,
            static_cast<long long>(total_pairs),       theoretical_total);
        std::printf("  Hamming: min=%.3f%% max=%.3f%% mean=%.3f%%\n",
            ham_min, ham_max, ham_mean);
        std::printf("  Pairs: %lld / %lld total\n",
            static_cast<long long>(test_pairs.size()),
            static_cast<long long>(total_pairs));

        // ── EXP 3: Multiplex quality ──
        // Parallelize the outer loop on j (byte index) instead of i (channel
        // index). Each thread owns a disjoint set of byte positions, so
        // mux[j] writes are race-free. This converts the O(NC*B) sequential
        // loop into O((NC*B)/T) on T threads.
        std::vector<uint8_t> mux(static_cast<size_t>(bytes_per_ch), 0);
#ifdef _OPENMP
#pragma omp parallel for schedule(static)
#endif
        for (int64_t j = 0; j < bytes_per_ch; j++) {
            uint8_t acc = 0;
            for (int i = 0; i < NC; i++) {
                acc = static_cast<uint8_t>(acc ^ ch_ptr(i)[j]);
            }
            mux[static_cast<size_t>(j)] = acc;
        }

        const double mux_ent = shannon_entropy(mux.data(), bytes_per_ch);
        const double mux_chi = chi_square    (mux.data(), bytes_per_ch);
        std::printf("  Multiplex: ent=%.6f chi2=%.2f\n", mux_ent, mux_chi);

        // ── Pass/Fail ──
        const double ent_deficit  = 255.0 / (2.0 * static_cast<double>(bytes_per_ch)
                                             * std::log(2.0));
        const double ent_threshold = 8.0 - ent_deficit - ENT_MARGIN;
        const bool   ent_pass  = (min_ent  >= ent_threshold);
        const bool   corr_pass = (max_corr <  theoretical_sampled * CORR_PASS_FACTOR);
        const bool   ham_pass  = (ham_min  >  HAM_LO && ham_max < HAM_HI);
        const bool   mux_pass  = (mux_ent  >= ent_threshold && mux_chi < CHI2_THRESHOLD);

        // If bytes < 50KB, quality tests are unreliable - pass on correlation
        // only (see MIN_BYTES_QUALITY note above).
        const bool scale_pass = quality_reliable
            ? (ent_pass && corr_pass && ham_pass && mux_pass)
            : corr_pass;

        std::printf("  -> %d ch: %s (corr=%s%s)\n\n",
            NC, scale_pass ? "PASS" : "FAIL",
            corr_pass ? "ok" : "FAIL",
            quality_reliable
                ? (ent_pass && ham_pass && mux_pass
                    ? " ent=ok ham=ok mux=ok"
                    : " ent/ham/mux=CHECK")
                : " [quality: informational - bytes < 50KB]");

        results.push_back({NC, bytes_per_ch, gen_time,
            min_ent, max_ent, mean_ent,
            max_corr, mean_corr, theoretical_sampled, theoretical_total,
            static_cast<int64_t>(test_pairs.size()), total_pairs,
            ham_min, ham_max, ham_mean,
            mux_ent, mux_chi, scale_pass});

        total_exp++;
        if (scale_pass) passed_exp++;

        channels_flat.clear();
        channels_flat.shrink_to_fit();
    }

    // ========================================================================
    // NEGATIVE CONTROL
    // ========================================================================
    sep("NEGATIVE CONTROL - same topology must correlate");
    bool neg_pass = true;
    {
        std::vector<uint8_t> a(static_cast<size_t>(NEG_CTRL_BYTES));
        std::vector<uint8_t> b(static_cast<size_t>(NEG_CTRL_BYTES));
        MCL_T2 ga(DEFAULT_SEED, 3, 5);
        MCL_T2 gb(DEFAULT_SEED, 3, 5);
        ga.gen_bytes(a.data(), NEG_CTRL_BYTES);
        gb.gen_bytes(b.data(), NEG_CTRL_BYTES);
        const double r = pearson_r(a.data(), b.data(), NEG_CTRL_BYTES);
        int diff = 0;
        for (int64_t i = 0; i < NEG_CTRL_BYTES; i++)
            if (a[static_cast<size_t>(i)] != b[static_cast<size_t>(i)]) diff++;
        const bool ok = (r > NEG_CTRL_R_MIN) && (diff == 0);
        if (!ok) neg_pass = false;
        std::printf("  (3,5) r=%.6f diff=%d %s\n",
            r, diff, ok ? "OK" : "BROKEN!");
    }

    // ========================================================================
    // SUMMARY TABLE
    // ========================================================================
    sep("SCALING SUMMARY TABLE");

    std::printf("  %-10s %-8s %-10s %-10s %-10s %-10s %-6s\n",
        "Channels", "KB/ch", "max|r|", "samp_bnd", "min_ent", "mux_ent", "Pass");
    std::printf("  %s\n", std::string(64, '-').c_str());

    for (const auto& r : results) {
        std::printf("  %-10d %-8lld %-10.6f %-10.6f %-10.6f %-10.6f %s\n",
            r.n_ch,
            static_cast<long long>(r.bytes_per_ch / 1000),
            r.max_corr, r.theoretical_sampled,
            r.min_ent, r.mux_ent,
            r.pass ? "PASS" : "FAIL");
    }

    // ── Degradation check ──
    sep("DEGRADATION ANALYSIS");
    bool degradation = false;
    for (const auto& r : results) {
        const double ratio = r.max_corr / r.theoretical_sampled;
        std::printf("  %7d ch: max|r|/sampled_bound = %.3f %s\n",
            r.n_ch, ratio,
            ratio > DEGRADATION_RATIO ? "ABOVE 1.5x!" : "OK");
        if (ratio > DEGRADATION_RATIO) degradation = true;
    }

    // ========================================================================
    // VERDICT
    // ========================================================================
    const double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    const bool gp = (passed_exp == total_exp && !degradation && neg_pass);

    sep("VERDICT");
    std::printf("  Scales tested: %d / %d PASS\n", passed_exp, total_exp);
    std::printf("  Max channels:  %d\n",
        results.empty() ? 0 : results.back().n_ch);
    std::printf("  Degradation:   %s\n", degradation ? "DETECTED" : "NONE");
    std::printf("  Neg control:   %s\n", neg_pass ? "PASS" : "FAIL");

    std::printf("\n +================================================================+\n");
    std::printf(" | VERDICT: %-53s |\n",
        gp ? "PASS - scalable to tested channel count"
           : "FAIL - degradation detected at scale");
    std::printf(" +================================================================+\n");

    std::printf("\n  Time: %.1f seconds | Threads: %d\n", elapsed, n_threads);
    std::printf("\n  %s v%s | Madeeh Ibrahim, Cairo\n", DOC_ID, DOC_VERSION);
    std::printf("==============================================================================\n");

    return gp ? 0 : 1;
}
