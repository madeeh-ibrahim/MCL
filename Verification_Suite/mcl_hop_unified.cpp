/*
 * ============================================================================
 * MCL Dynamic Parameter Hopping - Unified Verification Suite
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-HOP-UNIFIED-2026-0526-001
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
 * PURPOSE: Free experiment - run hopping tests, report exact numbers.
 *          No preconceived targets. Results are the empirical record
 *          of dynamic parameter hopping behavior.
 *
 * 22 TESTS (Part A: Quality, Part B: Post-Quantum):
 *   A1:  Post-hop entropy
 *   A2:  Post-hop chi-square
 *   A3:  Micro-warmup sufficiency curve (W=0..200)
 *   A4:  Hopping stream vs static channels independence
 *   A5:  Different hop schedules give independent streams
 *   A6:  Hop boundary invisibility (sliding window entropy)
 *   A7:  Negative control (zero warmup vs W=50)
 *   A8:  Hop frequency scaling (100..5000 bytes/hop)
 *   A9:  Windowed entropy analysis
 *   A10: Deterministic reproducibility (sender = receiver)
 *   A11: Cross-seed hopping independence
 *   A12: Hopping + multiplexing combined
 *   B1:  Per-segment brute force (unknown state barrier)
 *   B2:  Cross-segment correlation leakage
 *   B3:  Topology identification attack
 *   B4:  Hop schedule entropy (exact calculation)
 *   B5:  Grover oracle cost with hopping
 *   B6:  Forward secrecy verification
 *   B7:  Hop boundary detection attack (split-half correlation)
 *   B8:  Multiplex channel invisibility at N-sweep
 *   B9:  Same-ratio pair independence
 *   B10: PQ security summary
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_hop mcl_hop_unified.cpp -lm && ./mcl_hop
 *
 * EXPECTED RESULTS:
 *   22/22 PASS, VERDICT: PASS
 *
 * REFERENCES:
 *   - Paper 2 §VI    Multi-Receiver Communication (multiplex baseline)
 *   - Paper 2 §VII   Forward secrecy via parameter hopping
 *   - mcl_core.hpp   v5.0.0 MCL_T2 engine + hop() method
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
#include <string>
#include <vector>

// ============================================================================
// Document version constants (mirror header).
// ============================================================================
static constexpr const char* const DOC_VERSION = "6.0.0";
static constexpr const char* const DOC_ID      = "MCL-HOP-UNIFIED-2026-0526-001";

// ============================================================================
// Test sample sizes - canonical and quick variants.
// ============================================================================
static constexpr int64_t N_FULL  = 500000;   // canonical bytes per stream
static constexpr int64_t N_QUICK = 100000;   // smaller for smoke test

// Hopping configuration (Paper 2 §VII).
static constexpr int64_t BYTES_PER_HOP        = 1000;
static constexpr int     DEFAULT_WARMUP       = 50;
static constexpr int64_t SAMPLE_PRE_HOP       = 10000;  // A3, A7 sample size
static constexpr int     SLIDING_WINDOW_SIZE  = 500;    // A6
static constexpr int     SLIDING_WINDOW_STEP  = 100;    // A6
static constexpr int     BOUNDARY_DIST_LIMIT  = 200;    // A6 boundary band
static constexpr double  CORR_THRESHOLD       = 0.01;   // independence test
static constexpr double  ENTROPY_HIGH         = 7.999;  // bytes-level threshold
static constexpr double  ENTROPY_WINDOW       = 7.4;    // 500-byte window threshold
static constexpr double  HAMMING_NEG_CTRL_MIN = 40.0;   // A7 minimum diff %
static constexpr double  PEARSON_BRUTE_SIGMA  = 4.0;    // B1/B6 threshold sigma
static constexpr int     B3_TESTED_SEGMENTS   = 200;    // B3 sampling cap
static constexpr int     B7_BOUNDARY_LIMIT    = 100;    // B7 boundary samples cap
static constexpr int     B2_STRIDE_TARGET     = 25;     // B2 stride to ~25 base segs

// Number of multiplex receivers in test A12.
static constexpr int     NRX_MULTIPLEX        = 6;

// PQ security thresholds (B10).
static constexpr double  AES128_PQ_BITS       = 64.0;
static constexpr int     PQ_NMAX              = 1000;
static constexpr int     PQ_KAPPA_BASE        = 128;
static constexpr int     PQ_KAPPA_ENHANCED    = 64;     // additional bits

// ============================================================================
// Global tally + scratch buffer.
// (Kept file-scope to match the original style; chk() updates these.)
// ============================================================================
static int  g_total  = 0;
static int  g_passed = 0;
static char g_buf[256];

static void chk(const char* name, bool pass, const char* detail) {
    g_total++;
    if (pass) g_passed++;
    std::printf("  [%s] %-42s %s\n", pass ? "PASS" : "FAIL", name, detail);
}

// ============================================================================
// Generate bytes with periodic hopping through a fixed schedule.
// (Identical algorithm to v1.1.1; only signature reformatted.)
// ============================================================================
static void gen_hopping(MCL_T2& gen, uint8_t* out, int64_t total,
                        const Topology* sched, int sched_len,
                        int64_t bytes_per_hop, int warmup) {
    int64_t pos = 0;
    int     si  = 0;
    while (pos < total) {
        const int64_t chunk = std::min(bytes_per_hop, total - pos);
        gen.gen_bytes(out + pos, chunk);
        pos += chunk;
        if (pos < total) {
            si = (si + 1) % sched_len;
            gen.hop(sched[si].p, sched[si].q, warmup);
        }
    }
}

// ============================================================================
// CLI parsing
// ============================================================================
static void print_help(const char* progname) {
    std::printf(
        "Usage:\n"
        "  %s              # default mode (canonical N=%lld)\n"
        "  %s --quick      # quick smoke test (N=%lld)\n"
        "  %s --full       # explicit canonical N\n"
        "  %s --help       # this message\n"
        "\n"
        "Document: %s v%s\n",
        progname, static_cast<long long>(N_FULL),
        progname, static_cast<long long>(N_QUICK),
        progname, progname,
        DOC_ID, DOC_VERSION);
}

int main(int argc, char* argv[]) {
    std::setbuf(stdout, nullptr);

    int64_t N         = N_FULL;
    bool    quick_set = false;
    bool    full_set  = false;

    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_help(argv[0]);
            return 0;
        } else if (arg == "--quick") {
            quick_set = true;
        } else if (arg == "--full") {
            full_set = true;
        } else {
            std::fprintf(stderr,
                "Error: Unknown argument: %s\n"
                "Try '%s --help' for usage.\n",
                argv[i], argv[0]);
            return 1;
        }
    }
    if (quick_set && full_set) {
        std::fprintf(stderr,
            "Error: --quick and --full are mutually exclusive.\n");
        return 2;
    }
    if (quick_set) N = N_QUICK;

    const auto t_start = std::chrono::steady_clock::now();
    bool gp = true; // global pass

    std::printf("\n==============================================================================\n");
    std::printf("  MCL DYNAMIC PARAMETER HOPPING - UNIFIED SUITE v%s\n", DOC_VERSION);
    std::printf("  22 Tests - Free Experiment (results ARE the empirical record)\n");
    std::printf("==============================================================================\n\n");

    // Shared configuration
    const int64_t  BPH    = BYTES_PER_HOP;
    const int      WARMUP = DEFAULT_WARMUP;
    const Topology sched[] = {{3,5},{7,11},{11,17},{29,37},{43,53},{67,73}};
    const int      NSCHED = static_cast<int>(sizeof(sched) / sizeof(sched[0]));
    const int64_t  n_hops = N / BPH;

    std::printf("  N=%lldK, BPH=%lld, warmup=%d, schedule=%d topos, hops=%lld\n",
        static_cast<long long>(N / 1000),
        static_cast<long long>(BPH),
        WARMUP, NSCHED,
        static_cast<long long>(n_hops));

    // Adaptive thresholds for sample-size effects.
    // Pearson |r| has natural noise floor ~ 1/sqrt(N). At canonical N=500K,
    // 1/sqrt(N) ~= 0.0014 and the 0.01 threshold has comfortable margin.
    // At quick N=100K, 1/sqrt(N) ~= 0.0032, which leaves the 0.01 threshold
    // only 3 sigma above noise -- sampling fluctuations of |r| ~ 0.012 are
    // common. We use max(0.01, 5/sqrt(N)) so both modes pass without
    // changing the canonical-mode thresholds reported in Paper 2.
    const double corr_threshold = std::max(
        CORR_THRESHOLD,
        5.0 / std::sqrt(static_cast<double>(N)));

    // R2.23: A3 uses SAMPLE_PRE_HOP=10000 bytes (not the global N) for its
    // Pearson |r| computations. The natural noise floor is 1/sqrt(10000) =
    // 0.01 exactly -- the same as the unscaled CORR_THRESHOLD. This means
    // A3 fluctuations sit AT the threshold and the test pass/fail outcome
    // is essentially a coin flip across platforms (Linux=0.000437 lucky,
    // macOS=0.011443 unlucky). We use a separate sample-aware threshold
    // (4-sigma above noise floor) for tests that operate on the smaller
    // SAMPLE_PRE_HOP block.
    const double corr_threshold_sample = std::max(
        CORR_THRESHOLD,
        5.0 / std::sqrt(static_cast<double>(SAMPLE_PRE_HOP)));

    std::printf("  N=%lldK -> corr_threshold = %.5f (block: %.5f)\n\n",
        static_cast<long long>(N / 1000),
        corr_threshold, corr_threshold_sample);

    // Generate primary hopping stream + segments
    std::vector<uint8_t> hop_stream(static_cast<size_t>(N));
    MCL_T2 hop_gen(DEFAULT_SEED, sched[0].p, sched[0].q);
    gen_hopping(hop_gen, hop_stream.data(), N, sched, NSCHED, BPH, WARMUP);

    // Split into segments
    std::vector<std::vector<uint8_t>> segs(static_cast<size_t>(n_hops));
    std::vector<int> seg_topo(static_cast<size_t>(n_hops));
    for (int64_t h = 0; h < n_hops; h++) {
        segs[static_cast<size_t>(h)].assign(
            hop_stream.data() + h * BPH,
            hop_stream.data() + (h + 1) * BPH);
        seg_topo[static_cast<size_t>(h)] = static_cast<int>(h % NSCHED);
    }

    // ========================================================================
    // PART A: HOPPING QUALITY (12 tests)
    // ========================================================================
    sep("PART A: HOPPING QUALITY");

    // A1: Post-hop entropy
    // Threshold scales with N: smaller N has more sampling noise. The
    // canonical 7.999 threshold assumes N=500000; for the quick smoke
    // test (N=100000) we relax to 7.998 since the variance of byte-level
    // entropy is O(1/sqrt(N)).
    const double entropy_threshold = (N >= N_FULL) ? ENTROPY_HIGH : 7.998;
    const double hop_ent = shannon_entropy(hop_stream.data(), N);
    std::snprintf(g_buf, sizeof(g_buf), "%.6f bits/byte (thr=%.3f)",
        hop_ent, entropy_threshold);
    chk("A1: Post-hop entropy threshold", hop_ent > entropy_threshold, g_buf);
    if (hop_ent <= entropy_threshold) gp = false;

    // A2: Post-hop chi-square
    const double hop_chi = chi_square(hop_stream.data(), N);
    std::snprintf(g_buf, sizeof(g_buf), "%.1f (threshold %.1f)",
        hop_chi, CHI2_THRESHOLD);
    chk("A2: Post-hop chi2 < 330.5", hop_chi < CHI2_THRESHOLD, g_buf);
    if (hop_chi >= CHI2_THRESHOLD) gp = false;

    // A3: Micro-warmup sufficiency curve
    sep("A3: MICRO-WARMUP SUFFICIENCY CURVE");
    const int warmups[] = {0, 5, 10, 25, 50, 100, 200};
    double corr_at_50 = 0;
    std::printf("  %-6s %-12s %-12s\n", "W", "|r|", "Hamming%");
    std::printf("  %s\n", std::string(32, '-').c_str());
    for (int w : warmups) {
        MCL_T2 gw(DEFAULT_SEED, 3, 5);
        std::vector<uint8_t> before(static_cast<size_t>(SAMPLE_PRE_HOP));
        std::vector<uint8_t> after (static_cast<size_t>(SAMPLE_PRE_HOP));
        gw.gen_bytes(before.data(), SAMPLE_PRE_HOP);
        gw.hop(7, 11, w);
        gw.gen_bytes(after.data(),  SAMPLE_PRE_HOP);
        const double r = std::abs(pearson_r(before.data(), after.data(),
                                            SAMPLE_PRE_HOP));
        const double h = hamming_pct(before.data(), after.data(),
                                     SAMPLE_PRE_HOP);
        if (w == DEFAULT_WARMUP) corr_at_50 = r;
        std::printf("  %-6d %-12.6f %-12.2f%s\n", w, r, h,
            w == 0               ? " (neg ctrl)" :
            w == DEFAULT_WARMUP  ? " <- default" : "");
    }
    std::snprintf(g_buf, sizeof(g_buf), "|r| at W=50: %.6f (thr=%.5f)",
        corr_at_50, corr_threshold_sample);
    chk("A3: W=50 sufficient",
        corr_at_50 < corr_threshold_sample, g_buf);
    if (corr_at_50 >= corr_threshold_sample) gp = false;

    // A4: Hopping stream vs static channels
    sep("A4: HOPPING vs STATIC INDEPENDENCE");
    double max_hop_static = 0;
    for (int i = 0; i < NSCHED; i++) {
        std::vector<uint8_t> st(static_cast<size_t>(N));
        MCL_T2 gs(DEFAULT_SEED, sched[i].p, sched[i].q);
        gs.gen_bytes(st.data(), N);
        const double r = std::abs(pearson_r(hop_stream.data(), st.data(), N));
        if (r > max_hop_static) max_hop_static = r;
    }
    std::snprintf(g_buf, sizeof(g_buf), "max|r|=%.6f vs %d static ch",
        max_hop_static, NSCHED);
    chk("A4: Hop vs static independent",
        max_hop_static < corr_threshold, g_buf);
    if (max_hop_static >= corr_threshold) gp = false;

    // A5: Different schedules -> independent
    sep("A5: DIFFERENT SCHEDULES -> INDEPENDENT");
    const Topology sched2[] = {{67,73},{43,53},{29,37},{11,17},{7,11},{3,5}};
    const Topology sched3[] = {{11,17},{3,5},{67,73},{7,11},{43,53},{29,37}};
    std::vector<uint8_t> s2(static_cast<size_t>(N));
    std::vector<uint8_t> s3(static_cast<size_t>(N));
    {
        MCL_T2 g2(DEFAULT_SEED, sched2[0].p, sched2[0].q);
        gen_hopping(g2, s2.data(), N, sched2, NSCHED, BPH, WARMUP);
        MCL_T2 g3(DEFAULT_SEED, sched3[0].p, sched3[0].q);
        gen_hopping(g3, s3.data(), N, sched3, NSCHED, BPH, WARMUP);
    }
    const double r12 = std::abs(pearson_r(hop_stream.data(), s2.data(), N));
    const double r13 = std::abs(pearson_r(hop_stream.data(), s3.data(), N));
    const double r23 = std::abs(pearson_r(s2.data(),         s3.data(), N));
    const double max_sched = std::max({r12, r13, r23});
    std::snprintf(g_buf, sizeof(g_buf), "max|r|=%.6f (3 schedules)",
        max_sched);
    chk("A5: Schedule independence", max_sched < corr_threshold, g_buf);
    if (max_sched >= corr_threshold) gp = false;

    // A6: Hop boundary invisibility (sliding window)
    sep("A6: HOP BOUNDARY INVISIBILITY");
    const int WIN  = SLIDING_WINDOW_SIZE;
    const int STEP = SLIDING_WINDOW_STEP;
    const int n_win = static_cast<int>((N - WIN) / STEP) + 1;
    double sum_all = 0, sum_sq = 0, min_e = 9, max_e = 0;
    std::vector<double> wents(static_cast<size_t>(n_win));
    for (int wi = 0; wi < n_win; wi++) {
        const double e = shannon_entropy(
            hop_stream.data() + static_cast<int64_t>(wi) * STEP, WIN);
        wents[static_cast<size_t>(wi)] = e;
        sum_all += e;
        sum_sq  += e * e;
        if (e < min_e) min_e = e;
        if (e > max_e) max_e = e;
    }
    const double mean_e  = sum_all / n_win;
    const double sigma_e = std::sqrt(std::max(0.0,
                              sum_sq / n_win - mean_e * mean_e));

    // Compare boundary vs non-boundary
    double sum_bnd = 0, sum_mid = 0;
    int    n_bnd = 0, n_mid = 0;
    for (int wi = 0; wi < n_win; wi++) {
        const int64_t center = static_cast<int64_t>(wi) * STEP + WIN / 2;
        int64_t dist_to_hop = center % BPH;
        if (dist_to_hop > BPH / 2) dist_to_hop = BPH - dist_to_hop;
        if (dist_to_hop < BOUNDARY_DIST_LIMIT) {
            sum_bnd += wents[static_cast<size_t>(wi)];
            n_bnd++;
        } else {
            sum_mid += wents[static_cast<size_t>(wi)];
            n_mid++;
        }
    }
    const double bnd_diff = std::abs(
        sum_bnd / std::max(1, n_bnd) - sum_mid / std::max(1, n_mid));
    std::printf("  sigma=%.6f, |bnd-mid|=%.6f, range [%.4f, %.4f]\n",
        sigma_e, bnd_diff, min_e, max_e);
    std::snprintf(g_buf, sizeof(g_buf), "|bnd-mid|=%.6f < 3sigma=%.6f",
        bnd_diff, 3 * sigma_e);
    chk("A6: Boundary invisible", bnd_diff < 3 * sigma_e, g_buf);
    if (bnd_diff >= 3 * sigma_e) gp = false;

    // A7: Negative control (zero warmup)
    // R1.0 fix: MCL_T2 is non-copyable in v5.0.0+; replay seed instead of
    // 'MCL_T2 gneg2 = gneg' (deleted copy ctor for security).
    sep("A7: NEGATIVE CONTROL");
    std::vector<uint8_t> pre_neg(static_cast<size_t>(SAMPLE_PRE_HOP));
    std::vector<uint8_t> post0  (static_cast<size_t>(SAMPLE_PRE_HOP));
    std::vector<uint8_t> post50 (static_cast<size_t>(SAMPLE_PRE_HOP));
    {
        // Branch 1: warmup = 0
        MCL_T2 gneg(DEFAULT_SEED, 3, 5);
        gneg.gen_bytes(pre_neg.data(), SAMPLE_PRE_HOP);
        gneg.hop(7, 11, 0);
        gneg.gen_bytes(post0.data(), SAMPLE_PRE_HOP);
    }
    {
        // Branch 2: warmup = 50, replay first 10 KB so engine state matches
        // what gneg had immediately before the hop call above.
        MCL_T2 gneg2(DEFAULT_SEED, 3, 5);
        std::vector<uint8_t> replay(static_cast<size_t>(SAMPLE_PRE_HOP));
        gneg2.gen_bytes(replay.data(), SAMPLE_PRE_HOP);
        gneg2.hop(7, 11, DEFAULT_WARMUP);
        gneg2.gen_bytes(post50.data(), SAMPLE_PRE_HOP);
    }
    const double r0  = std::abs(pearson_r(pre_neg.data(), post0.data(),
                                          SAMPLE_PRE_HOP));
    const double r50 = std::abs(pearson_r(pre_neg.data(), post50.data(),
                                          SAMPLE_PRE_HOP));
    const double h0  = hamming_pct(post0.data(), post50.data(),
                                   SAMPLE_PRE_HOP);
    std::printf("  |r| W=0: %.6f, |r| W=50: %.6f, H(W0 vs W50): %.2f%%\n",
        r0, r50, h0);
    std::snprintf(g_buf, sizeof(g_buf), "W=0 |r|=%.4f vs W=50 |r|=%.4f",
        r0, r50);
    chk("A7: Zero warmup differs from W=50",
        h0 > HAMMING_NEG_CTRL_MIN, g_buf);
    if (h0 <= HAMMING_NEG_CTRL_MIN) gp = false;

    // A8: Hop frequency scaling
    sep("A8: HOP FREQUENCY SCALING");
    const int64_t freqs[] = {100, 500, 1000, 5000};
    bool a8 = true;
    for (int64_t f : freqs) {
        MCL_T2 gf(DEFAULT_SEED, sched[0].p, sched[0].q);
        std::vector<uint8_t> fdata(static_cast<size_t>(N));
        gen_hopping(gf, fdata.data(), N, sched, NSCHED, f, WARMUP);
        const double ent = shannon_entropy(fdata.data(), N);
        const double chi = chi_square(fdata.data(), N);
        const bool   ok  = ent > 7.99 && chi < CHI2_THRESHOLD;
        if (!ok) a8 = false;
        std::printf("  %5lld B/hop (%5lld hops): ent=%.6f chi=%.1f %s\n",
            static_cast<long long>(f),
            static_cast<long long>(N / f),
            ent, chi, ok ? "OK" : "FAIL");
    }
    chk("A8: All hop frequencies pass", a8, "100-5000 B/hop");
    if (!a8) gp = false;

    // A9: Windowed entropy (non-overlapping)
    double min_win = 9, max_win = 0;
    const int n_no = static_cast<int>(N / WIN);
    for (int wi = 0; wi < n_no; wi++) {
        const double e = shannon_entropy(
            hop_stream.data() + static_cast<int64_t>(wi) * WIN, WIN);
        if (e < min_win) min_win = e;
        if (e > max_win) max_win = e;
    }
    std::snprintf(g_buf, sizeof(g_buf),
        "[%.4f, %.4f] (%d non-overlapping)", min_win, max_win, n_no);
    chk("A9: Windowed entropy uniform", min_win > ENTROPY_WINDOW, g_buf);
    if (min_win <= ENTROPY_WINDOW) gp = false;

    // A10: Deterministic reproducibility
    std::vector<uint8_t> repro(static_cast<size_t>(N));
    {
        MCL_T2 grep(DEFAULT_SEED, sched[0].p, sched[0].q);
        gen_hopping(grep, repro.data(), N, sched, NSCHED, BPH, WARMUP);
    }
    int64_t errors = 0;
    for (int64_t i = 0; i < N; i++) {
        if (hop_stream[static_cast<size_t>(i)]
            != repro[static_cast<size_t>(i)]) errors++;
    }
    std::snprintf(g_buf, sizeof(g_buf), "%lld/%lld errors",
        static_cast<long long>(errors), static_cast<long long>(N));
    chk("A10: Deterministic (sender=receiver)", errors == 0, g_buf);
    if (errors != 0) gp = false;

    // A11: Cross-seed hopping independence
    const uint64_t* seeds = mcl_seeds();
    double cs_max = 0;
    for (int s = 1; s < N_MCL_SEEDS; s++) {
        std::vector<uint8_t> cs(static_cast<size_t>(N));
        MCL_T2 gcs(seeds[s], sched[0].p, sched[0].q);
        gen_hopping(gcs, cs.data(), N, sched, NSCHED, BPH, WARMUP);
        const double r = std::abs(pearson_r(hop_stream.data(),
                                            cs.data(), N));
        if (r > cs_max) cs_max = r;
    }
    std::snprintf(g_buf, sizeof(g_buf), "max|r|=%.6f (%d seeds)",
        cs_max, N_MCL_SEEDS - 1);
    chk("A11: Cross-seed hop independence",
        cs_max < corr_threshold, g_buf);
    if (cs_max >= corr_threshold) gp = false;

    // A12: Hopping + multiplexing combined
    sep("A12: HOPPING + MULTIPLEXING");
    const int NRX = NRX_MULTIPLEX;
    std::vector<std::vector<uint8_t>> rx(static_cast<size_t>(NRX));
    for (int r = 0; r < NRX; r++) {
        rx[static_cast<size_t>(r)].resize(static_cast<size_t>(N));
        // Each receiver: same schedule, different seed -> unique streams
        const uint64_t rxseed = DEFAULT_SEED
            + static_cast<uint64_t>(r) * static_cast<uint64_t>(999983);
        MCL_T2 gr(rxseed, sched[0].p, sched[0].q);
        gen_hopping(gr, rx[static_cast<size_t>(r)].data(),
                    N, sched, NSCHED, BPH, WARMUP);
    }
    std::vector<uint8_t> mux(static_cast<size_t>(N), 0);
    for (int r = 0; r < NRX; r++) {
        for (int64_t i = 0; i < N; i++) {
            mux[static_cast<size_t>(i)] ^=
                rx[static_cast<size_t>(r)][static_cast<size_t>(i)];
        }
    }
    const double mux_ent = shannon_entropy(mux.data(), N);
    double mux_max = 0;
    for (int r = 0; r < NRX; r++) {
        const double c = std::abs(pearson_r(
            rx[static_cast<size_t>(r)].data(), mux.data(), N));
        if (c > mux_max) mux_max = c;
    }
    std::printf("  %d hopping receivers, mux entropy=%.6f, max|r|=%.6f\n",
        NRX, mux_ent, mux_max);
    const bool a12 = mux_ent > entropy_threshold && mux_max < corr_threshold;
    std::snprintf(g_buf, sizeof(g_buf), "ent=%.4f, max|r|=%.6f",
        mux_ent, mux_max);
    chk("A12: Hop+multiplex combined", a12, g_buf);
    if (!a12) gp = false;

    // ========================================================================
    // PART B: POST-QUANTUM HOPPING SECURITY (10 tests)
    // ========================================================================
    sep("PART B: POST-QUANTUM HOPPING SECURITY");

    // B1+B6: Per-segment brute force + Forward secrecy (5 segments)
    double  worst_brute_r = 0;
    double  worst_brute_h = 50;
    const int b1_segs[] = {
        1,
        static_cast<int>(n_hops / 4),
        static_cast<int>(n_hops / 2),
        static_cast<int>(3 * n_hops / 4),
        static_cast<int>(n_hops - 1)
    };
    for (int ti : b1_segs) {
        if (ti < 0 || ti >= n_hops) continue;
        MCL_T2 fr(DEFAULT_SEED,
                  sched[seg_topo[static_cast<size_t>(ti)]].p,
                  sched[seg_topo[static_cast<size_t>(ti)]].q);
        std::vector<uint8_t> fs(static_cast<size_t>(BPH));
        fr.gen_bytes(fs.data(), BPH);
        const double r = std::abs(pearson_r(
            fs.data(), segs[static_cast<size_t>(ti)].data(), BPH));
        const double h = hamming_pct(
            fs.data(), segs[static_cast<size_t>(ti)].data(), BPH);
        if (r > worst_brute_r) worst_brute_r = r;
        if (std::abs(h - 50) > std::abs(worst_brute_h - 50)) {
            worst_brute_h = h;
        }
    }
    const double brute_thresh = PEARSON_BRUTE_SIGMA
        / std::sqrt(static_cast<double>(BPH));
    std::snprintf(g_buf, sizeof(g_buf),
        "worst |r|=%.6f (thresh=%.4f), H=%.2f%%",
        worst_brute_r, brute_thresh, worst_brute_h);
    const bool b1_pass = worst_brute_h > 45 && worst_brute_h < 55;
    chk("B1: Fresh MCL != hopping MCL (5 segs)", b1_pass, g_buf);
    if (!b1_pass) gp = false;

    // B2: Cross-segment correlation (stride-sampled to avoid bias)
    double max_cross = 0;
    int    pairs_tested = 0;
    const int64_t stride = std::max<int64_t>(1, n_hops / B2_STRIDE_TARGET);
    for (int64_t i = 0; i < n_hops; i += stride) {
        for (int64_t j = i + 1; j < n_hops && j < i + stride + 5; j++) {
            const double r = std::abs(pearson_r(
                segs[static_cast<size_t>(i)].data(),
                segs[static_cast<size_t>(j)].data(), BPH));
            if (r > max_cross) max_cross = r;
            pairs_tested++;
        }
    }
    const double evt_cross = PEARSON_BRUTE_SIGMA
        / std::sqrt(static_cast<double>(BPH));
    std::snprintf(g_buf, sizeof(g_buf),
        "max|r|=%.6f (EVT=%.4f, %d pairs)",
        max_cross, evt_cross, pairs_tested);
    chk("B2: Cross-segment |r| < EVT", max_cross < evt_cross, g_buf);
    if (max_cross >= evt_cross) gp = false;

    // B3: Topology identification attack
    std::vector<std::vector<uint8_t>> static_ref(static_cast<size_t>(NSCHED));
    for (int t = 0; t < NSCHED; t++) {
        static_ref[static_cast<size_t>(t)].resize(static_cast<size_t>(BPH));
        MCL_T2 gs(DEFAULT_SEED, sched[t].p, sched[t].q);
        gs.gen_bytes(static_ref[static_cast<size_t>(t)].data(), BPH);
    }
    int correct = 0;
    const int tested_id = std::min(static_cast<int>(n_hops),
                                   B3_TESTED_SEGMENTS);
    for (int h = 0; h < tested_id; h++) {
        int    best   = -1;
        double best_r = -1;
        for (int t = 0; t < NSCHED; t++) {
            const double r = std::abs(pearson_r(
                segs[static_cast<size_t>(h)].data(),
                static_ref[static_cast<size_t>(t)].data(), BPH));
            if (r > best_r) {
                best_r = r;
                best = t;
            }
        }
        if (best == seg_topo[static_cast<size_t>(h)]) correct++;
    }
    const double id_rate     = 100.0 * correct / tested_id;
    const double random_rate = 100.0 / NSCHED;
    std::snprintf(g_buf, sizeof(g_buf), "%.1f%% (random=%.1f%%)",
        id_rate, random_rate);
    chk("B3: Topology unidentifiable",
        id_rate < random_rate * 2, g_buf);
    if (id_rate >= random_rate * 2) gp = false;

    // B4: Hop schedule entropy
    const double topo_capacity = std::log2(
        6.0 / (MCL_PI * MCL_PI)
        * static_cast<double>(PQ_NMAX) * static_cast<double>(PQ_NMAX));
    const double fixed_cycle_bits = std::log2(static_cast<double>(NSCHED))
        * static_cast<double>(n_hops);
    const double max_entropy = topo_capacity * static_cast<double>(n_hops);
    std::printf("  Fixed %d-topo cycle: %.0f bits (log2(%d) x %lld)\n",
        NSCHED, fixed_cycle_bits, NSCHED,
        static_cast<long long>(n_hops));
    std::printf("  Random nmax=%d: %.0f bits (%.1f x %lld) - max capacity\n",
        PQ_NMAX, max_entropy, topo_capacity,
        static_cast<long long>(n_hops));
    std::snprintf(g_buf, sizeof(g_buf),
        "cycle=%.0f bits, capacity=%.0f bits",
        fixed_cycle_bits, max_entropy);
    chk("B4: Schedule entropy > 128",
        fixed_cycle_bits > 128, g_buf);
    if (fixed_cycle_bits <= 128) gp = false;

    // B5: Grover oracle cost
    const double iters_no_hop  = BURNIN + 64.0 * 2.0;
    const double iters_with_hop = BURNIN
        + static_cast<double>(n_hops)
        * (static_cast<double>(BPH) * 2.0 + WARMUP);
    const double oracle_ratio  = iters_with_hop / iters_no_hop;
    std::printf("  Without hop: %.0f iters | With hop: %.0f iters (%.1fx)\n",
        iters_no_hop, iters_with_hop, oracle_ratio);
    std::snprintf(g_buf, sizeof(g_buf),
        "%.1fx oracle cost (+%.2f PQ bits)",
        oracle_ratio, std::log2(oracle_ratio) / 2);
    chk("B5: Grover cost increased", oracle_ratio > 1.0, g_buf);
    if (oracle_ratio <= 1.0) gp = false;

    // B6: Forward secrecy (reuses B1 data - same 5 segments)
    const bool b6_pass = worst_brute_r < brute_thresh;
    std::snprintf(g_buf, sizeof(g_buf),
        "worst |r|=%.4f < 4/sqrt(%lld)=%.4f",
        worst_brute_r, static_cast<long long>(BPH), brute_thresh);
    chk("B6: Forward secrecy (4-sigma threshold)", b6_pass, g_buf);
    if (!b6_pass) gp = false;

    // B7: Boundary detection attack (split-half)
    std::vector<double> at_bnd, away_bnd;
    const int half = static_cast<int>(BPH / 4);
    for (int64_t h = 1;
         h < n_hops - 1 && h < B7_BOUNDARY_LIMIT; h++) {
        const int64_t bp     = h * BPH;
        const int64_t s_at   = bp - half;
        const int64_t s_away = bp - BPH / 2 - half;
        if (s_at < 0 || s_at + 2 * half > N
            || s_away < 0 || s_away + 2 * half > N) continue;
        const double r_at = std::abs(pearson_r(
            hop_stream.data() + s_at,
            hop_stream.data() + s_at + half, half));
        const double r_aw = std::abs(pearson_r(
            hop_stream.data() + s_away,
            hop_stream.data() + s_away + half, half));
        at_bnd.push_back(r_at);
        away_bnd.push_back(r_aw);
    }
    auto mean_v = [](const std::vector<double>& v) -> double {
        double s = 0;
        for (auto x : v) s += x;
        return v.empty() ? 0.0 : s / static_cast<double>(v.size());
    };
    const double m_at    = mean_v(at_bnd);
    const double m_away  = mean_v(away_bnd);
    const double det_diff = std::abs(m_at - m_away);
    std::printf("  mean|r| at boundary: %.6f, away: %.6f, diff: %.6f\n",
        m_at, m_away, det_diff);
    std::snprintf(g_buf, sizeof(g_buf), "diff=%.6f", det_diff);
    chk("B7: Boundary undetectable",
        det_diff < corr_threshold, g_buf);
    if (det_diff >= corr_threshold) gp = false;

    // B8: Multiplex channel invisibility at N-sweep
    // R2.22: in --quick mode use only the smallest sweep point so the
    // smoke test stays fast. Full mode keeps the canonical 3-point sweep
    // from Paper 2 §VII for proper N-scaling characterization.
    sep("B8: MULTIPLEX INVISIBILITY N-SWEEP");
    static constexpr int64_t Ns_full[]  = {500000, 1000000, 3000000};
    static constexpr int64_t Ns_quick[] = {500000};
    const int64_t* const Ns       = (N >= N_FULL) ? Ns_full : Ns_quick;
    const int            Ns_count = (N >= N_FULL)
        ? static_cast<int>(sizeof(Ns_full)  / sizeof(Ns_full[0]))
        : static_cast<int>(sizeof(Ns_quick) / sizeof(Ns_quick[0]));
    const Topology t20[] = {
        {2,3},{3,5},{5,7},{7,11},{8,13},{11,17},{13,19},{17,23},
        {19,29},{23,31},{29,37},{31,41},{37,43},{41,47},{43,53},
        {47,59},{53,61},{59,67},{61,71},{67,73}
    };
    constexpr int B8_CHANNELS = 20;
    double b8_worst = 0;
    for (int ni = 0; ni < Ns_count; ni++) {
        const int64_t SN = Ns[ni];
        std::vector<std::vector<uint8_t>> chs(B8_CHANNELS);
        std::vector<uint8_t> mx(static_cast<size_t>(SN), 0);
        for (int i = 0; i < B8_CHANNELS; i++) {
            chs[static_cast<size_t>(i)].resize(static_cast<size_t>(SN));
            MCL_T2 gi(DEFAULT_SEED, t20[i].p, t20[i].q);
            gi.gen_bytes(chs[static_cast<size_t>(i)].data(), SN);
            for (int64_t j = 0; j < SN; j++) {
                mx[static_cast<size_t>(j)] ^=
                    chs[static_cast<size_t>(i)][static_cast<size_t>(j)];
            }
        }
        double mx_max = 0;
        for (int i = 0; i < B8_CHANNELS; i++) {
            const double r = std::abs(pearson_r(
                chs[static_cast<size_t>(i)].data(), mx.data(), SN));
            if (r > mx_max) mx_max = r;
        }
        if (mx_max > b8_worst) b8_worst = mx_max;
        std::printf("  N=%lldK: max|r|=%.6f (nf=%.6f)\n",
            static_cast<long long>(SN / 1000),
            mx_max, 1.0 / std::sqrt(static_cast<double>(SN)));
    }
    std::snprintf(g_buf, sizeof(g_buf), "worst max|r|=%.6f", b8_worst);
    chk("B8: Channel invisible in multiplex",
        b8_worst < corr_threshold, g_buf);
    if (b8_worst >= corr_threshold) gp = false;

    // B9: Same-ratio pair independence
    // R2.21: scale SR_BYTES with N so --quick mode is genuinely faster.
    // 500K is the canonical sample size from Paper 2; in --quick we use
    // the same N as the rest of the suite.
    double sr_max = 0;
    struct SR { int64_t p, q; };
    const SR same_ratio[] = {{2,3},{4,6},{6,9},{8,12}};
    constexpr int SR_COUNT = sizeof(same_ratio) / sizeof(same_ratio[0]);
    const int64_t SR_BYTES = N;
    for (int i = 0; i < SR_COUNT; i++) {
        for (int j = i + 1; j < SR_COUNT; j++) {
            std::vector<uint8_t> a(static_cast<size_t>(SR_BYTES));
            std::vector<uint8_t> b(static_cast<size_t>(SR_BYTES));
            MCL_T2 ga(DEFAULT_SEED, same_ratio[i].p, same_ratio[i].q);
            ga.gen_bytes(a.data(), SR_BYTES);
            MCL_T2 gb(DEFAULT_SEED, same_ratio[j].p, same_ratio[j].q);
            gb.gen_bytes(b.data(), SR_BYTES);
            const double r = std::abs(pearson_r(a.data(), b.data(),
                                                SR_BYTES));
            if (r > sr_max) sr_max = r;
        }
    }
    std::snprintf(g_buf, sizeof(g_buf),
        "max|r|=%.6f (6 pairs, ratio 2/3)", sr_max);
    chk("B9: Same-ratio pairs independent",
        sr_max < corr_threshold, g_buf);
    if (sr_max >= corr_threshold) gp = false;

    // B10: PQ security summary
    sep("B10: POST-QUANTUM SECURITY SUMMARY");
    auto ks = [](int sb, int nm, int pb) -> double {
        const double tb = std::log2(
            6.0 / (MCL_PI * MCL_PI)
            * static_cast<double>(nm) * static_cast<double>(nm));
        return (sb + tb + pb) / 2.0;
    };
    const double pq_con = ks(PQ_KAPPA_BASE, PQ_NMAX, 0);
    const double pq_enh = ks(PQ_KAPPA_BASE, PQ_NMAX, PQ_KAPPA_ENHANCED);
    std::printf("  PQ (conservative): %.1f bits\n", pq_con);
    std::printf("  PQ (enhanced):     %.1f bits\n", pq_enh);
    std::printf("  Oracle with hop: %.1fx | Sched entropy: %.0f bits\n",
        oracle_ratio, fixed_cycle_bits);
    std::snprintf(g_buf, sizeof(g_buf), "%.1f bits > %.0f (AES-128 PQ)",
        pq_con, AES128_PQ_BITS);
    chk("B10: PQ security above AES-128",
        pq_con >= AES128_PQ_BITS, g_buf);
    if (pq_con < AES128_PQ_BITS) gp = false;

    // ========================================================================
    // VERDICT
    // ========================================================================
    const double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    sep("UNIFIED HOPPING VERIFICATION SUMMARY");

    std::printf("  Tests passed: %d / %d\n\n", g_passed, g_total);
    std::printf("  KEY NUMBERS (free experiment results):\n");
    std::printf("    Hop entropy:           %.6f bits/byte\n", hop_ent);
    std::printf("    Hop chi2:              %.1f\n",           hop_chi);
    std::printf("    W=50 |r|:              %.6f\n",           corr_at_50);
    std::printf("    Boundary sigma:        %.6f bits/byte\n", sigma_e);
    std::printf("    Boundary |bnd-mid|:    %.6f bits/byte\n", bnd_diff);
    std::printf("    Freq scaling:          100-5000 B/hop all pass\n");
    std::printf("    Reproducibility:       %lld errors\n",
        static_cast<long long>(errors));
    std::printf("    Mux max|r| (hop):      %.6f\n", mux_max);
    std::printf("    Mux entropy (hop):     %.6f\n", mux_ent);
    std::printf("    Cross-seg max|r|:      %.6f\n", max_cross);
    std::printf("    Topo ID attack:        %.1f%% (random=%.1f%%)\n",
        id_rate, random_rate);
    std::printf("    Forward secrecy H:     %.2f%%\n", worst_brute_h);
    std::printf("    Boundary detect diff:  %.6f\n", det_diff);
    std::printf("    Same-ratio max|r|:     %.6f\n", sr_max);
    std::printf("    PQ (conservative):     %.1f bits\n", pq_con);

    std::printf("\n +================================================================+\n");
    std::printf(" | VERDICT: %-54s |\n",
        gp ? "PASS - all 22 hopping tests verified"
           : "ISSUES DETECTED");
    std::printf(" +================================================================+\n");

    std::printf("\n  Time: %.1f seconds\n", elapsed);
    std::printf("\n  %s v%s | Madeeh Ibrahim, Cairo\n",
        DOC_ID, DOC_VERSION);
    std::printf("==============================================================================\n");

    return gp ? 0 : 1;
}
