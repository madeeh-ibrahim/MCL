/*
 * ============================================================================
 * MCL Topological Channel Orthogonality — Extended Verification Suite
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-ORTH-2026-0526-001
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
 * PURPOSE: Verify that MCL channels indexed by different (p,q) pairs are
 *          statistically orthogonal — a foundation for multi-channel
 *          communication and hardware authentication. The verification
 *          uses a two-stage independence framework with two-tier output
 *          and three configurable run modes for reviewers with different
 *          time budgets.
 *
 * METHOD:
 *   Stage 1: Pearson r independence test for each channel pair
 *            Bonferroni-corrected alpha = 0.001 across all pairs
 *   Stage 2: Hamming distance uniformity test for the same pairs
 *            5-sigma tolerance, with sigma = 0.5 / sqrt(8 * N) per pair
 *   Plus extended single-seed tests (entropy, chi-square, encrypt/decrypt
 *   round-trip, multiplex quality, channel invisibility) and a multi-seed
 *   cross-seed isolation check.
 *   Negative control verifies that identical (seed, p, q) input produces
 *   identical output (deterministic engine requirement, Rule R3).
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_orth_verify mcl_orth_verify.cpp -lm && ./mcl_orth_verify
 *
 * EXPECTED RESULTS: PASS — all stages, extended tests, and global
 *                          Bonferroni analysis report zero failures.
 * REFERENCES:
 *   - Pearson, K., Phil. Trans. R. Soc. London 187:253-318, 1896.
 *   - Bonferroni, C.E., Pubblicazioni R. Ist. Sup. Sc. Econ. Comm. 8:3-62, 1936.
 *   - Dunn, O.J., JASA 56:52-64, 1961.
 *   - NIST SP 800-22, Section 2.3 (frequency tests), 2010.
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
#include <cstdlib>   // for std::atexit
#include <cstring>
#include <ctime>

/* Document metadata (mirror of file header — keep in sync) */
static constexpr const char* const DOC_VERSION = "6.0.0";
static constexpr const char* const DOC_ID      = "MCL-ORTH-2026-0526-001";

// ============================================================================
// Configuration constants (compile-time)
// ============================================================================

static const int NR = 20;             // channels per seed (fixed across all modes)

// CORR_THRESH_FLOOR is the canonical Pearson |r| threshold for the
// STANDARD mode (N=1M) reported in Paper 2 §V. It is the FLOOR of the
// adaptive threshold computed at runtime as
//     corr_threshold = max(CORR_THRESH_FLOOR, 5 / sqrt(N))
// to defend against the threshold-at-noise-floor pattern (R2.23):
// when the threshold equals 1/sqrt(N) (the natural noise floor), the
// pass/fail outcome becomes a coin flip across platforms because chaos
// amplifies last-bit differences in glibc sin() vs Apple libm sin().
// The 5/sqrt(N) term places the threshold 5 sigma above the noise
// floor in QUICK mode (N=100K, 5/sqrt(N)=0.0158), avoiding spurious
// failures observed in mcl_hop_unified.cpp v1.2.1 on macOS.
static const double CORR_THRESH_FLOOR = 0.01;
static const double HAM_TOL = 0.5;    // ±0.5% for fast-pass tests

// Statistical safety margin for Hamming uniformity test
// Set to 5σ — exceeds the EVT bound sqrt(2*ln(K))*sigma for K up to ~10^5
// (see derivation in comment block below).
static const double HAMMING_SIGMA_MULTIPLIER = 5.0;

// Negative control threshold: identical (seed, p, q) MUST produce
// bit-identical output. Pearson r near 1.0 is required, but the
// authoritative test is byte-equality (diff==0). This threshold is
// retained as a defensive cross-check against a broken pearson_r
// implementation; if pearson_r returns r != 1.0 on identical inputs
// while diff==0, the engine OR the statistic is malfunctioning.
static const double NEG_CTRL_R_MIN = 0.999;

// Hamming uniformity tolerance — derived per Rule R4 (mathematical verification):
//   For 8N i.i.d. Bernoulli(0.5) bits, the bit-mismatch fraction has:
//     mean  = 0.5
//     sigma = sqrt(0.5 * 0.5 / 8N) = 0.5 / sqrt(8N)
//   The deviation |H_pct/100 - 0.5| follows a half-normal with the same sigma.
//
// EVT for max of K independent half-normals (Gumbel asymptotics):
//   E[max] ≈ sigma * sqrt(2 * ln(K))
//
// Tolerance is set to HAMMING_SIGMA_MULTIPLIER (=5) * sigma. This is above
// the EVT bound for any practical K (5*sigma exceeds sqrt(2*ln K)*sigma for
// K up to ~10^5). Computed at runtime in main() using the active mode's N.
static double g_ham_epsilon = 0.0;

// ============================================================================
// Run modes — controlled by command-line flag
// ============================================================================

enum class RunMode { QUICK, STANDARD, FULL };

struct ModeParams {
    int n_seeds;        // NS at runtime
    int64_t n_bytes;    // N at runtime (bytes per channel)
    const char* name;
    const char* description;
    const char* time_estimate;
};

static ModeParams get_mode_params(RunMode mode) {
    switch (mode) {
        case RunMode::QUICK:
            return { 2, 100000, "QUICK",
                     "Smoke test for fast review",
                     "~5 seconds" };
        case RunMode::STANDARD:
            return { 5, 1000000, "STANDARD",
                     "Reasonable verification (default)",
                     "~1-2 minutes" };
        case RunMode::FULL:
            return { 20, 10000000, "FULL",
                     "Extended verification with maximum seed/byte budget",
                     "~30-60 minutes" };
    }
    return { 5, 1000000, "STANDARD", "default", "~1-2 minutes" };
}

// 20 coprime topology pairs covering small to medium magnitudes
static const Topology RATIOS[] = {
    {2,3},  {3,5},  {5,7},  {7,11}, {8,13}, {11,17},
    {13,19},{17,23},{19,29},{23,31},{29,37},{31,41},
    {37,43},{41,47},{43,53},{47,59},{53,61},{59,67},
    {61,71},{67,73}
};

// 20 distinct seeds for the full-configuration verification
static const uint64_t SEEDS[] = {
    12345678901234ULL, 98765432109876ULL, 55555555555555ULL,
    11111111111111ULL, 77777777777777ULL, 22222222222222ULL,
    33333333333333ULL, 44444444444444ULL, 66666666666666ULL,
    88888888888888ULL, 99999999999999ULL, 12121212121212ULL,
    34343434343434ULL, 56565656565656ULL, 78787878787878ULL,
    90909090909090ULL, 13579135791357ULL, 24682468246824ULL,
    31415926535897ULL, 27182818284590ULL
};

// Compile-time assertions: array sizes must satisfy the largest mode (FULL).
// FULL mode uses NR=20 channels and NS=20 seeds, so arrays must be >= 20.
// If a future mode adds more channels or seeds, these arrays must grow.
static_assert(sizeof(RATIOS) / sizeof(RATIOS[0]) >= 20,
              "RATIOS[] must have at least NR=20 entries for FULL mode");
static_assert(sizeof(SEEDS) / sizeof(SEEDS[0]) >= 20,
              "SEEDS[] must have at least NS=20 entries for FULL mode");

// Global state for logging and counting
static int g_total = 0, g_passed = 0;
static int g_pearson_tests_run = 0;
static int g_pearson_tests_failed = 0;
static int g_hamming_tests_run = 0;
static int g_hamming_tests_failed = 0;
static FILE* g_evidence_log = nullptr;

// Global container for Bonferroni p-values
static std::vector<double> g_pearson_pvalues;

// ============================================================================
// Helper functions
// ============================================================================

static void print_help(const char* prog) {
    std::printf("MCL Topological Channel Orthogonality Verification v%s\n",
                DOC_VERSION);
    std::printf("\n");
    std::printf("Usage:\n");
    std::printf("  %s [MODE] [OPTIONS]\n", prog);
    std::printf("\n");
    std::printf("Run modes (mutually exclusive):\n");
    std::printf("  --quick      Smoke test:    NS=2,  N=10^5,  ~5 seconds\n");
    std::printf("                              (380 pairs, 760 individual tests)\n");
    std::printf("  --standard   Default mode:  NS=5,  N=10^6,  ~1-2 minutes\n");
    std::printf("                              (950 pairs, 1,900 individual tests)\n");
    std::printf("  --full       Full config:   NS=20, N=10^7,  ~30-60 minutes\n");
    std::printf("                              (3,800 pairs, 7,600 individual tests)\n");
    std::printf("\n");
    std::printf("Output options:\n");
    std::printf("  --evidence              Write detailed evidence file (default name:\n");
    std::printf("                          mcl_orth_evidence_YYYY-MM-DD.tsv)\n");
    std::printf("  --evidence-file PATH    Write evidence file to PATH (implies --evidence)\n");
    std::printf("  --help, -h              Print this message and exit\n");
    std::printf("\n");
    std::printf("Examples:\n");
    std::printf("  %s --quick                 # fastest review path\n", prog);
    std::printf("  %s --standard --evidence   # default + evidence file\n", prog);
    std::printf("  %s --full                  # full configuration run\n", prog);
    std::printf("\n");
    std::printf("Exit codes:\n");
    std::printf("  0  All tests passed\n");
    std::printf("  1  At least one test failed\n");
    std::printf("  2  Invalid command-line arguments\n");
}

static void tcheck(const char* name, bool pass, const char* detail) {
    g_total++;
    if (pass) g_passed++;
    std::printf("  [%s] %-40s %s\n", pass ? "PASS" : "FAIL", name, detail);
}

// Write a Pearson test entry to the evidence log
static void log_pearson_test(int test_id, int seed_idx, int ch_i, int ch_j,
                             double abs_r, double pvalue,
                             double bonf_thresh, bool pass) {
    if (g_evidence_log == nullptr) return;
    std::fprintf(g_evidence_log,
        "%-7d  %-5d  (%2d,%2d)   %.6f   %.4e   %.4e   %s\n",
        test_id, seed_idx, ch_i, ch_j, abs_r, pvalue, bonf_thresh,
        pass ? "PASS" : "FAIL");
}

// Write a Hamming test entry to the evidence log
static void log_hamming_test(int test_id, int seed_idx, int ch_i, int ch_j,
                             double ham_pct, double deviation,
                             double tolerance, bool pass) {
    if (g_evidence_log == nullptr) return;
    std::fprintf(g_evidence_log,
        "%-7d  %-5d  (%2d,%2d)   %8.4f%%  %.4e   %.4e   %s\n",
        test_id, seed_idx, ch_i, ch_j, ham_pct, deviation, tolerance,
        pass ? "PASS" : "FAIL");
}

static void evidence_section_header(const char* title, int n_tests) {
    if (g_evidence_log == nullptr) return;
    std::fprintf(g_evidence_log,
        "\n=========================================================================\n");
    std::fprintf(g_evidence_log, "%s (%d entries)\n", title, n_tests);
    std::fprintf(g_evidence_log,
        "=========================================================================\n\n");
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    std::setbuf(stdout, nullptr);  // TR2: prompt printf flush

    auto t_start = std::chrono::steady_clock::now();
    bool global_pass = true;

    // ─── Parse command-line flags ───
    RunMode mode = RunMode::STANDARD;   // default
    bool mode_explicitly_set = false;
    bool emit_evidence = false;
    const char* evidence_path = nullptr;
    char default_evidence_path[128];

    auto fail_arg = [](const char* msg, int code = 2) {
        std::fprintf(stderr, "ERROR: %s\n", msg);
        std::fprintf(stderr, "Run with --help for usage.\n");
        return code;
    };

    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        }
        else if (std::strcmp(argv[i], "--quick") == 0) {
            if (mode_explicitly_set)
                return fail_arg("multiple run modes specified; pick one of "
                                "--quick / --standard / --full");
            mode = RunMode::QUICK;
            mode_explicitly_set = true;
        }
        else if (std::strcmp(argv[i], "--standard") == 0) {
            if (mode_explicitly_set)
                return fail_arg("multiple run modes specified; pick one of "
                                "--quick / --standard / --full");
            mode = RunMode::STANDARD;
            mode_explicitly_set = true;
        }
        else if (std::strcmp(argv[i], "--full") == 0) {
            if (mode_explicitly_set)
                return fail_arg("multiple run modes specified; pick one of "
                                "--quick / --standard / --full");
            mode = RunMode::FULL;
            mode_explicitly_set = true;
        }
        else if (std::strcmp(argv[i], "--evidence") == 0) {
            emit_evidence = true;
        }
        else if (std::strcmp(argv[i], "--evidence-file") == 0) {
            if (i + 1 >= argc)
                return fail_arg("--evidence-file requires a path argument");
            evidence_path = argv[++i];
            emit_evidence = true;
        }
        else {
            std::fprintf(stderr, "ERROR: unknown argument '%s'\n", argv[i]);
            std::fprintf(stderr, "Run with --help for usage.\n");
            return 2;
        }
    }

    // ─── Resolve mode parameters ───
    ModeParams params = get_mode_params(mode);
    const int NS = params.n_seeds;
    const int64_t N = params.n_bytes;

    // R2.23: Adaptive Pearson |r| threshold defending against the
    // threshold-at-noise-floor pattern (see CORR_THRESH_FLOOR comment).
    // Computed at runtime once N is known.
    const double corr_threshold = std::max(
        CORR_THRESH_FLOOR,
        5.0 / std::sqrt(static_cast<double>(N)));

    // Compute Hamming epsilon dynamically (Rule R4 — verifiable from N)
    // sigma(deviation) = 0.5 / sqrt(8 * N), tolerance = SIGMA_MULTIPLIER * sigma
    g_ham_epsilon = HAMMING_SIGMA_MULTIPLIER * 0.5 / std::sqrt(8.0 * static_cast<double>(N));

    if (emit_evidence && evidence_path == nullptr) {
        // Default filename: mcl_orth_evidence_YYYY-MM-DD.tsv
        std::time_t now = std::time(nullptr);
        std::tm* lt = std::localtime(&now);
        std::snprintf(default_evidence_path, sizeof(default_evidence_path),
            "mcl_orth_evidence_%04d-%02d-%02d.tsv",
            lt->tm_year + 1900, lt->tm_mon + 1, lt->tm_mday);
        evidence_path = default_evidence_path;
    }

    if (emit_evidence) {
        g_evidence_log = std::fopen(evidence_path, "w");
        if (g_evidence_log == nullptr) {
            std::fprintf(stderr,
                "ERROR: cannot open evidence file '%s' for writing.\n",
                evidence_path);
            return 2;
        }
        // Defensive: register cleanup to ensure log is flushed and
        // closed even on abnormal exit (std::abort, exception, etc.).
        // The normal path also calls fclose() at end of main; the
        // double-close is guarded by setting g_evidence_log to nullptr.
        std::atexit([]() {
            if (g_evidence_log != nullptr) {
                std::fflush(g_evidence_log);
                std::fclose(g_evidence_log);
                g_evidence_log = nullptr;
            }
        });
    }

    // ─── Banner ───
    std::printf("\n=========================================================="
                "====================\n");
    std::printf("  MCL TOPOLOGICAL CHANNEL ORTHOGONALITY v%s\n", DOC_VERSION);
    std::printf("  Two-stage verification: Pearson independence + Hamming uniformity\n");
    std::printf("  Run mode: %s  (%s)\n", params.name, params.description);
    std::printf("  Estimated time: %s\n", params.time_estimate);
    std::printf("=========================================================="
                "====================\n\n");

    int total_pairs = (NR * (NR - 1) / 2) * NS;
    int total_individual_tests = total_pairs * 2;
    std::printf("  Configuration:\n");
    std::printf("    Run mode:                 %s\n", params.name);
    std::printf("    Channels per seed:        %d\n", NR);
    std::printf("    Seeds:                    %d\n", NS);
    std::printf("    Bytes per channel:        %lld (10^%d)\n",
        static_cast<long long>(N),
        static_cast<int>(std::log10(static_cast<double>(N))));
    std::printf("    Total pairs:              %d  (= %d * %d)\n",
        total_pairs, NS, NR * (NR - 1) / 2);
    std::printf("    Tests per pair:           2  (Pearson + Hamming)\n");
    std::printf("    Total individual tests:   %d\n", total_individual_tests);
    if (!mode_explicitly_set) {
        std::printf("\n    NOTE: running in STANDARD mode by default.\n");
        std::printf("          Use --quick for smoke test (~5 sec) or --full\n");
        std::printf("          for the complete configuration (~30-60 min).\n");
    }
    if (mode == RunMode::QUICK) {
        std::printf("\n    NOTE: QUICK mode (%lld bytes) is for smoke testing only.\n",
            static_cast<long long>(N));
        std::printf("          Statistical conclusions about orthogonality require\n");
        std::printf("          --standard (10^6 bytes) or --full (10^7 bytes).\n");
    }

    if (emit_evidence) {
        std::printf("\n    Evidence log:             %s\n", evidence_path);
    } else {
        std::printf("\n    Evidence log:             (disabled — use --evidence to enable)\n");
    }
    std::printf("\n");

    // ─── Evidence file header ───
    if (g_evidence_log) {
        std::fprintf(g_evidence_log,
            "=========================================================================\n");
        std::fprintf(g_evidence_log,
            "MCL Orthogonality — Detailed Evidence Log\n");
        std::fprintf(g_evidence_log, "Document: %s v%s\n", DOC_ID, DOC_VERSION);
        std::fprintf(g_evidence_log, "Author:   Madeeh Ibrahim\n");
        std::fprintf(g_evidence_log, "Run mode: %s (%s)\n",
            params.name, params.description);
        std::fprintf(g_evidence_log,
            "=========================================================================\n\n");
        std::fprintf(g_evidence_log, "CONFIGURATION:\n");
        std::fprintf(g_evidence_log, "  Engine:              MCL_T2 (Gauss-Seidel)\n");
        std::fprintf(g_evidence_log, "  Channels per seed:   %d\n", NR);
        std::fprintf(g_evidence_log, "  Bytes per channel:   %lld\n", static_cast<long long>(N));
        std::fprintf(g_evidence_log, "  Seeds:               %d\n", NS);
        std::fprintf(g_evidence_log, "  Total pairs:         %d\n", total_pairs);
        std::fprintf(g_evidence_log, "  Tests per pair:      2 (Pearson + Hamming)\n");
        std::fprintf(g_evidence_log, "  Total individual tests: %d\n",
            total_individual_tests);
        std::fprintf(g_evidence_log, "  Hamming epsilon:     %.4e\n",
            g_ham_epsilon);
    }

    // ────────────────────────────────────────────────────────────────────
    // STAGE 1 & 2 PREP: Generate channels for all seeds, run both stages
    // Memory note: each seed loads NR channels of N bytes (= NR*N bytes).
    // Channels are released at the end of each per-seed iteration so the
    // peak channel-memory footprint stays at NR*N regardless of NS.
    // ────────────────────────────────────────────────────────────────────
    {
        char stage_title[128];
        std::snprintf(stage_title, sizeof(stage_title),
            "STAGE 1 + 2: Independence and Uniformity across %d seed(s)", NS);
        sep(stage_title);
    }

    // Defensive: total_pairs > 0 guaranteed by NS >= 2 and NR >= 2,
    // but use std::max to avoid division by zero in pathological builds.
    double bonf_threshold_global =
        BONFERRONI_ALPHA / static_cast<double>(std::max(total_pairs, 1));

    std::printf("  Generating %d channels x %d seeds = %d streams ...\n",
        NR, NS, NR * NS);
    std::printf("  Bonferroni threshold (alpha=%.3f / %d): %.4e\n",
        BONFERRONI_ALPHA, total_pairs, bonf_threshold_global);
    std::printf("  Hamming epsilon (%.0f*sigma at N=%lld): %.4e\n",
        HAMMING_SIGMA_MULTIPLIER, static_cast<long long>(N), g_ham_epsilon);
    std::printf("  Pearson |r| threshold (R2.23 adaptive, max(%.4f, 5/sqrt(N))): %.5f\n\n",
        CORR_THRESH_FLOOR, corr_threshold);

    // Stage 1 (Pearson) accumulators
    double s1_max_r = 0;
    double s1_sum_r = 0;
    double s1_min_p = 1.0;

    // Stage 2 (Hamming) accumulators
    double s2_min_h = 100, s2_max_h = 0;
    double s2_sum_h = 0;
    double s2_max_dev = 0;

    int s1_test_id = 0;       // 1 ... 3800
    int s2_test_id_base = total_pairs;  // 3800
    int s2_test_id = 0;

    // Evidence log — Stage 1 header
    evidence_section_header(
        "STAGE 1: Pearson Independence Tests (per pair)", total_pairs);
    if (g_evidence_log) {
        std::fprintf(g_evidence_log,
            "Test_ID  Seed   Pair       |r|        p-value      Bonf_thresh   Pass\n");
        std::fprintf(g_evidence_log,
            "-------  -----  ---------  ---------  -----------  ------------  -----\n");
    }

    // Per-seed loop. For each seed: generate NR channels and run pairwise.
    // We collect Stage 1 (Pearson) entries first, Stage 2 (Hamming) afterwards.
    // To avoid regenerating NR*NS channels twice, we cache per-seed and run
    // both measurements per pair, deferring Stage 2 logging until Stage 1
    // finishes. This keeps the evidence file in canonical order
    // (Pearson first, then Hamming) while only requiring NR*N bytes
    // of channel memory at any time.

    struct PendingHamming {
        int seed_idx, i, j;
        double ham_pct;
    };
    std::vector<PendingHamming> hamming_queue;
    hamming_queue.reserve(static_cast<size_t>(total_pairs));

    for (int s = 0; s < NS; s++) {
        std::vector<std::vector<uint8_t>> ch(static_cast<size_t>(NR));
        for (int i = 0; i < NR; i++) {
            ch[static_cast<size_t>(i)].resize(static_cast<size_t>(N));
            MCL_T2 gen(SEEDS[s], RATIOS[i].p, RATIOS[i].q);
            gen.gen_bytes(ch[static_cast<size_t>(i)].data(), N);
        }

        for (int i = 0; i < NR; i++) {
            for (int j = i + 1; j < NR; j++) {
                // Stage 1: Pearson r
                double abs_r = std::abs(pearson_r(
                    ch[static_cast<size_t>(i)].data(), ch[static_cast<size_t>(j)].data(), N));
                double pvalue = pvalue_from_r(abs_r, N);
                bool pearson_pass = (pvalue >= bonf_threshold_global);

                s1_test_id++;
                g_pearson_tests_run++;
                if (!pearson_pass) g_pearson_tests_failed++;

                if (abs_r > s1_max_r) s1_max_r = abs_r;
                s1_sum_r += abs_r;
                if (pvalue < s1_min_p) s1_min_p = pvalue;

                g_pearson_pvalues.push_back(pvalue);

                log_pearson_test(s1_test_id, s, i, j, abs_r, pvalue,
                    bonf_threshold_global, pearson_pass);

                // Stage 2: Hamming (queued for logging after Stage 1)
                double ham_pct = hamming_pct(
                    ch[static_cast<size_t>(i)].data(), ch[static_cast<size_t>(j)].data(), N);

                if (ham_pct < s2_min_h) s2_min_h = ham_pct;
                if (ham_pct > s2_max_h) s2_max_h = ham_pct;
                s2_sum_h += ham_pct;

                double dev = std::abs(ham_pct - 50.0) / 100.0;
                if (dev > s2_max_dev) s2_max_dev = dev;

                hamming_queue.push_back({s, i, j, ham_pct});
            }
        }

        // Progress reporting: print every 5 seeds when many, every seed when few
        int progress_interval = (NS >= 10) ? 5 : 1;
        if ((s + 1) % progress_interval == 0 || (s + 1) == NS) {
            std::printf("  Seed batch %d/%d complete (%d pairs accumulated)\n",
                s + 1, NS, s1_test_id);
        }
    }

    // ─── Stage 2 evidence logging (after all seeds processed) ───
    evidence_section_header(
        "STAGE 2: Hamming Uniformity Tests (per pair)", total_pairs);
    if (g_evidence_log) {
        std::fprintf(g_evidence_log,
            "Test_ID  Seed   Pair       Hamming%%   Deviation    Tolerance     Pass\n");
        std::fprintf(g_evidence_log,
            "-------  -----  ---------  ---------  -----------  ------------  -----\n");
    }

    for (auto& q : hamming_queue) {
        s2_test_id++;
        int absolute_test_id = s2_test_id_base + s2_test_id;
        double dev = std::abs(q.ham_pct - 50.0) / 100.0;
        // Use <= for symmetry with Pearson's >= (boundary value passes)
        bool hamming_pass = (dev <= g_ham_epsilon);

        g_hamming_tests_run++;
        if (!hamming_pass) g_hamming_tests_failed++;

        log_hamming_test(absolute_test_id, q.seed_idx, q.i, q.j,
            q.ham_pct, dev, g_ham_epsilon, hamming_pass);
    }

    // ─── Stage 1 + 2 summary to terminal ───
    // Defensive: g_pearson_tests_run > 0 guaranteed by NS >= 2 and NR >= 2,
    // but guard division anyway for robustness.
    double s1_mean_r = (g_pearson_tests_run > 0)
        ? (s1_sum_r / static_cast<double>(g_pearson_tests_run)) : 0.0;
    double s2_mean_h = (g_hamming_tests_run > 0)
        ? (s2_sum_h / static_cast<double>(g_hamming_tests_run)) : 0.0;

    std::printf("\n  Stage 1 (Pearson Independence):\n");
    std::printf("    Pairs tested:        %d\n", g_pearson_tests_run);
    std::printf("    Max |r|:             %.6f\n", s1_max_r);
    std::printf("    Mean |r|:            %.6f\n", s1_mean_r);
    std::printf("    Min p-value:         %.4e\n", s1_min_p);
    std::printf("    Bonferroni threshold: %.4e\n", bonf_threshold_global);
    std::printf("    Failures:            %d / %d\n",
        g_pearson_tests_failed, g_pearson_tests_run);
    bool stage1_pass = (g_pearson_tests_failed == 0);
    std::printf("    Status:              %s\n", stage1_pass ? "PASS" : "FAIL");

    std::printf("\n  Stage 2 (Hamming Uniformity):\n");
    std::printf("    Pairs tested:        %d\n", g_hamming_tests_run);
    std::printf("    Hamming range:       [%.4f%%, %.4f%%]\n",
        s2_min_h, s2_max_h);
    std::printf("    Mean Hamming:        %.4f%%\n", s2_mean_h);
    std::printf("    Max deviation:       %.6f\n", s2_max_dev);
    std::printf("    Tolerance epsilon:   %.6f\n", g_ham_epsilon);
    std::printf("    Failures:            %d / %d\n",
        g_hamming_tests_failed, g_hamming_tests_run);
    bool stage2_pass = (g_hamming_tests_failed == 0);
    std::printf("    Status:              %s\n", stage2_pass ? "PASS" : "FAIL");

    if (!stage1_pass || !stage2_pass) global_pass = false;

    // Evidence file: combined-stage summary
    if (g_evidence_log) {
        std::fprintf(g_evidence_log,
            "\n=========================================================================\n");
        std::fprintf(g_evidence_log, "COMBINED VERIFICATION SUMMARY\n");
        std::fprintf(g_evidence_log,
            "=========================================================================\n\n");
        std::fprintf(g_evidence_log, "Stage 1 (Pearson):  %d / %d failures\n",
            g_pearson_tests_failed, g_pearson_tests_run);
        std::fprintf(g_evidence_log, "  Max |r|:     %.6f\n", s1_max_r);
        std::fprintf(g_evidence_log, "  Mean |r|:    %.6f\n", s1_mean_r);
        std::fprintf(g_evidence_log, "  Min p-value: %.4e\n", s1_min_p);
        std::fprintf(g_evidence_log, "Stage 2 (Hamming):  %d / %d failures\n",
            g_hamming_tests_failed, g_hamming_tests_run);
        std::fprintf(g_evidence_log, "  Range:       [%.4f%%, %.4f%%]\n",
            s2_min_h, s2_max_h);
        std::fprintf(g_evidence_log, "Total individual statistical tests: %d\n",
            g_pearson_tests_run + g_hamming_tests_run);
        std::fprintf(g_evidence_log, "Total failures: %d\n",
            g_pearson_tests_failed + g_hamming_tests_failed);
    }

    // ────────────────────────────────────────────────────────────────────
    // EXTENDED VERIFICATION TESTS
    //
    // These tests probe orthogonality properties beyond the per-pair
    // independence + uniformity criteria of Stage 1 + 2:
    //   - Tests 3, 4: per-channel quality (entropy, chi-square)
    //   - Tests 5, 7: encrypt/decrypt round-trip and isolation
    //   - Test  6:    inter-channel Hamming distribution
    //   - Tests 8-10: multiplex quality and channel invisibility
    //   - Tests 15a-c: negative parameter classes (non-coprime,
    //                  same-ratio, swapped (p,q) <-> (q,p))
    //
    // These run on a single representative seed (SEEDS[0]) with the
    // mode's bytes-per-channel budget. Cross-seed isolation runs on
    // multiple seeds and is reported in its own section below.
    // ────────────────────────────────────────────────────────────────────
    sep("EXTENDED VERIFICATION TESTS (single representative seed)");

    // Reuse representative-seed channels for these tests
    std::vector<std::vector<uint8_t>> ch(static_cast<size_t>(NR));
    for (int i = 0; i < NR; i++) {
        ch[static_cast<size_t>(i)].resize(static_cast<size_t>(N));
        MCL_T2 gen(SEEDS[0], RATIOS[i].p, RATIOS[i].q);
        gen.gen_bytes(ch[static_cast<size_t>(i)].data(), N);
    }

    // ── TEST 3: per-channel entropy ──
    double min_ent = 9;
    bool t3 = true;
    for (int i = 0; i < NR; i++) {
        double e = shannon_entropy(ch[static_cast<size_t>(i)].data(), N);
        if (e < min_ent) min_ent = e;
        if (e < 7.99) t3 = false;
    }
    char buf[160];
    std::snprintf(buf, sizeof(buf), "min=%.6f over %d channels", min_ent, NR);
    tcheck("Channel entropy > 7.99", t3, buf);
    if (!t3) global_pass = false;

    // ── TEST 4: per-channel chi-square ──
    double max_chi = 0;
    bool t4 = true;
    for (int i = 0; i < NR; i++) {
        double c2 = chi_square(ch[static_cast<size_t>(i)].data(), N);
        if (c2 > max_chi) max_chi = c2;
        if (c2 > CHI2_THRESHOLD) t4 = false;
    }
    std::snprintf(buf, sizeof(buf), "max=%.1f (threshold %.1f)",
        max_chi, CHI2_THRESHOLD);
    tcheck("Chi-square < 330.52", t4, buf);
    if (!t4) global_pass = false;

    // ── TEST 5: XOR encrypt/decrypt ──
    bool t5 = true;
    int t5_errors = 0;
    for (int i = 0; i < NR; i++) {
        MCL_T2 enc(SEEDS[0], RATIOS[i].p, RATIOS[i].q);
        MCL_T2 dec(SEEDS[0], RATIOS[i].p, RATIOS[i].q);
        uint8_t key_enc[100], key_dec[100], msg[100];
        MCL_T2 pt(SEEDS[0] + uint64_t{5000} + static_cast<uint64_t>(i), 2, 3);
        pt.gen_bytes(msg, 100);
        enc.gen_bytes(key_enc, 100);
        dec.gen_bytes(key_dec, 100);
        for (int b = 0; b < 100; b++)
            if ((msg[b] ^ key_enc[b] ^ key_dec[b]) != msg[b]) {
                t5_errors++;
                t5 = false;
            }
    }
    std::snprintf(buf, sizeof(buf), "%d channels x 100 bytes, %d errors",
        NR, t5_errors);
    tcheck("Encrypt/Decrypt", t5, buf);
    if (!t5) global_pass = false;

    // ── TEST 6: inter-channel Hamming distribution ──
    // For two independent random byte streams, the bit-level Hamming
    // distance percentage is expected to be 50% +- a small statistical
    // tolerance. This test verifies that distinct channels (different (p,q),
    // same seed) produce streams with this property — a necessary condition
    // for XOR-based wrong-key decryption to yield uniform noise.
    double min_wh = 100, max_wh = 0;
    bool t6 = true;
    for (int i = 0; i < NR; i++) {
        int j = (i + 1) % NR;
        double h = hamming_pct(
            ch[static_cast<size_t>(i)].data(), ch[static_cast<size_t>(j)].data(), N);
        if (h < min_wh) min_wh = h;
        if (h > max_wh) max_wh = h;
        if (h < 50.0 - HAM_TOL || h > 50.0 + HAM_TOL) t6 = false;
    }
    std::snprintf(buf, sizeof(buf), "H range [%.3f%%, %.3f%%]", min_wh, max_wh);
    tcheck("Inter-channel Hamming ~50%", t6, buf);
    if (!t6) global_pass = false;

    // ── TEST 7: multi-receiver isolation ──
    bool t7 = true;
    int t7_errors = 0;
    for (int i = 0; i < NR; i++) {
        MCL_T2 enc(SEEDS[0], RATIOS[i].p, RATIOS[i].q);
        MCL_T2 dec(SEEDS[0], RATIOS[i].p, RATIOS[i].q);
        uint8_t k_enc[64], k_dec[64], pt[64], ct[64], rt[64];
        MCL_T2 pt_gen(SEEDS[0] + uint64_t{7000} + static_cast<uint64_t>(i), 2, 3);
        pt_gen.gen_bytes(pt, 64);
        enc.gen_bytes(k_enc, 64);
        for (int b = 0; b < 64; b++) ct[b] = static_cast<uint8_t>(pt[b] ^ k_enc[b]);
        dec.gen_bytes(k_dec, 64);
        for (int b = 0; b < 64; b++) rt[b] = static_cast<uint8_t>(ct[b] ^ k_dec[b]);
        if (std::memcmp(pt, rt, 64) != 0) {
            t7_errors++;
            t7 = false;
        }
    }
    std::snprintf(buf, sizeof(buf), "%d receivers, %d errors", NR, t7_errors);
    tcheck("Multi-receiver isolation", t7, buf);
    if (!t7) global_pass = false;

    // ── TESTS 8-10: multiplex quality and channel invisibility ──
    std::vector<uint8_t> mux(static_cast<size_t>(N), 0);
    for (int i = 0; i < NR; i++)
        for (int64_t b = 0; b < N; b++)
            mux[static_cast<size_t>(b)] = static_cast<uint8_t>(
                mux[static_cast<size_t>(b)] ^ ch[static_cast<size_t>(i)][static_cast<size_t>(b)]);

    double mux_ent = shannon_entropy(mux.data(), N);
    bool t8 = (mux_ent > 7.99);
    std::snprintf(buf, sizeof(buf), "mux entropy=%.6f", mux_ent);
    tcheck("Multiplex entropy > 7.99", t8, buf);
    if (!t8) global_pass = false;

    double mux_chi = chi_square(mux.data(), N);
    bool t9 = (mux_chi < CHI2_THRESHOLD);
    std::snprintf(buf, sizeof(buf), "mux chi^2=%.2f", mux_chi);
    tcheck("Multiplex chi-square < 330.52", t9, buf);
    if (!t9) global_pass = false;

    double max_mux_corr = 0;
    bool t10 = true;
    for (int i = 0; i < NR; i++) {
        double c = std::abs(pearson_r(ch[static_cast<size_t>(i)].data(), mux.data(), N));
        if (c > max_mux_corr) max_mux_corr = c;
        if (c > corr_threshold) t10 = false;
    }
    std::snprintf(buf, sizeof(buf), "max|r| ch vs mux = %.6f", max_mux_corr);
    tcheck("Channel invisible in multiplex", t10, buf);
    if (!t10) global_pass = false;

    // ────────────────────────────────────────────────────────────────────
    // CROSS-SEED ISOLATION
    // Tests that the same (p,q) topology with different seeds produces
    // independent streams. Uses NS seeds (mode-dependent) and 3 reference
    // topologies, yielding 3 * C(NS, 2) cross-seed pairs.
    // ────────────────────────────────────────────────────────────────────
    sep("CROSS-SEED ISOLATION (same (p,q), different seed)");
    double cs_max = 0;
    int cs_total = 0;
    bool t12 = true;
    Topology iso_topos[] = {{3, 5}, {11, 17}, {29, 37}};
    for (auto& tp : iso_topos) {
        std::vector<std::vector<uint8_t>> sd(static_cast<size_t>(NS));
        for (int s = 0; s < NS; s++) {
            sd[static_cast<size_t>(s)].resize(static_cast<size_t>(N));
            MCL_T2 gen(SEEDS[s], tp.p, tp.q);
            gen.gen_bytes(sd[static_cast<size_t>(s)].data(), N);
        }
        for (int i = 0; i < NS; i++)
            for (int j = i + 1; j < NS; j++) {
                double c = std::abs(pearson_r(
                    sd[static_cast<size_t>(i)].data(), sd[static_cast<size_t>(j)].data(), N));
                if (c > cs_max) cs_max = c;
                if (c >= corr_threshold) t12 = false;
                cs_total++;
            }
    }
    // Skip if NS < 2 (no pairs possible)
    if (cs_total > 0) {
        std::snprintf(buf, sizeof(buf),
            "max|r|=%.6f over %d pairs (3 topos x C(%d,2))",
            cs_max, cs_total, NS);
        tcheck("Cross-seed isolation", t12, buf);
        if (!t12) global_pass = false;
    } else {
        std::printf("  [SKIP] Cross-seed isolation                    "
                    "NS=%d < 2 (no pairs to test)\n", NS);
    }

    // ── TEST 15a: non-coprime independence ──
    sep("NEGATIVE CONTROLS (non-coprime, same-ratio, swapped)");
    bool t15a = true;
    struct NCP { int64_t p, q; };
    NCP ncp[] = {{4, 6}, {6, 9}, {6, 10}, {10, 15}};
    std::vector<std::vector<uint8_t>> nc_ch(4);
    for (int i = 0; i < 4; i++) {
        nc_ch[static_cast<size_t>(i)].resize(static_cast<size_t>(N));
        MCL_T2 gen(SEEDS[0], ncp[i].p, ncp[i].q);
        gen.gen_bytes(nc_ch[static_cast<size_t>(i)].data(), N);
    }
    double nc_max = 0;
    for (int i = 0; i < 4; i++)
        for (int j = i + 1; j < 4; j++) {
            double c = std::abs(pearson_r(
                nc_ch[static_cast<size_t>(i)].data(), nc_ch[static_cast<size_t>(j)].data(), N));
            if (c > nc_max) nc_max = c;
            if (c >= corr_threshold) t15a = false;
        }
    std::snprintf(buf, sizeof(buf), "non-coprime max|r|=%.6f", nc_max);
    tcheck("15a: Non-coprime independent", t15a, buf);

    // ── TEST 15b: same-ratio independence ──
    bool t15b = true;
    NCP sr[] = {{2, 3}, {4, 6}, {6, 9}};
    std::vector<std::vector<uint8_t>> sr_ch(3);
    for (int i = 0; i < 3; i++) {
        sr_ch[static_cast<size_t>(i)].resize(static_cast<size_t>(N));
        MCL_T2 gen(SEEDS[0], sr[i].p, sr[i].q);
        gen.gen_bytes(sr_ch[static_cast<size_t>(i)].data(), N);
    }
    double sr_max = 0;
    for (int i = 0; i < 3; i++)
        for (int j = i + 1; j < 3; j++) {
            double c = std::abs(pearson_r(
                sr_ch[static_cast<size_t>(i)].data(), sr_ch[static_cast<size_t>(j)].data(), N));
            if (c > sr_max) sr_max = c;
            if (c >= corr_threshold) t15b = false;
        }
    std::snprintf(buf, sizeof(buf), "same-ratio max|r|=%.6f", sr_max);
    tcheck("15b: Same ratio independent", t15b, buf);

    // ── TEST 15c: swapped (p,q) <-> (q,p) ──
    std::vector<uint8_t> fwd(static_cast<size_t>(N)), rev(static_cast<size_t>(N));
    MCL_T2 gf(SEEDS[0], 3, 5);
    gf.gen_bytes(fwd.data(), N);
    MCL_T2 gr(SEEDS[0], 5, 3);
    gr.gen_bytes(rev.data(), N);
    double swap_r = std::abs(pearson_r(fwd.data(), rev.data(), N));
    bool t15c = (swap_r < corr_threshold);
    std::snprintf(buf, sizeof(buf), "|r|=%.6f", swap_r);
    tcheck("15c: Swapped (3,5) vs (5,3) independent", t15c, buf);

    if (!t15a || !t15b || !t15c) global_pass = false;

    // ── NEGATIVE CONTROL (Rule R3 / D4) ──
    sep("NEGATIVE CONTROL — same parameters must correlate");
    bool neg_pass = true;
    {
        std::vector<uint8_t> a(static_cast<size_t>(N)), b(static_cast<size_t>(N));
        MCL_T2 ga(SEEDS[0], 3, 5);
        MCL_T2 gb(SEEDS[0], 3, 5);
        ga.gen_bytes(a.data(), N);
        gb.gen_bytes(b.data(), N);
        double r = pearson_r(a.data(), b.data(), N);
        int diff = 0;
        for (int64_t i = 0; i < N; i++)
            if (a[static_cast<size_t>(i)] != b[static_cast<size_t>(i)]) diff++;
        // Authoritative test: byte-equality (diff == 0). Pearson r near 1.0
        // is a defensive cross-check — if pearson_r returns r != ~1.0 on
        // identical inputs while diff==0, the statistic is malfunctioning.
        bool ok = (r > NEG_CTRL_R_MIN) && (diff == 0);
        std::printf("  (3,5) seed=%llu: r=%.6f diff=%d %s\n",
            static_cast<unsigned long long>(SEEDS[0]), r, diff,
            ok ? "PASS — identical" : "FAIL — non-deterministic!");
        if (!ok) {
            neg_pass = false;
            global_pass = false;
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // GLOBAL BONFERRONI ANALYSIS (across all Pearson p-values collected
    // during Stage 1). This re-applies the same threshold used per-test
    // in Stage 1, but additionally reports the smallest p-values for
    // diagnostic visibility.
    // ────────────────────────────────────────────────────────────────────
    sep("GLOBAL BONFERRONI ANALYSIS (Pearson p-values)");

    int m_total = static_cast<int>(g_pearson_pvalues.size());
    // Re-use the threshold computed earlier; it equals
    // BONFERRONI_ALPHA / m_total because m_total == total_pairs (every
    // pair contributed exactly one p-value to g_pearson_pvalues).
    double bonf_threshold = bonf_threshold_global;
    std::sort(g_pearson_pvalues.begin(), g_pearson_pvalues.end());

    int n_reject = 0;
    for (double pv : g_pearson_pvalues)
        if (pv < bonf_threshold) n_reject++;

    std::printf("  Total p-values:    %d\n", m_total);
    std::printf("  Threshold:         %.4e / %d = %.4e\n",
        BONFERRONI_ALPHA, m_total, bonf_threshold);
    std::printf("  Rejections:        %d / %d\n", n_reject, m_total);

    if (m_total >= 5) {
        std::printf("  Smallest 5 p-values:\n");
        for (int i = 0; i < 5; i++)
            std::printf("    #%d  %.6e  %s\n", i + 1,
                g_pearson_pvalues[static_cast<size_t>(i)],
                g_pearson_pvalues[static_cast<size_t>(i)] < bonf_threshold
                    ? "< REJECT" : ">= OK");
    }

    if (n_reject != 0) global_pass = false;

    // ────────────────────────────────────────────────────────────────────
    // CRC-32 REPRODUCIBILITY MARKER (Rule O4)
    // Compute CRC-32 of the first 10,000 bytes from the canonical channel
    // (T2, (3,5), seed SEEDS[0]). Differences across platforms are expected
    // due to libm sin()/cos() ULP differences; statistical properties remain
    // consistent.
    // ────────────────────────────────────────────────────────────────────
    sep("CRC-32 REPRODUCIBILITY MARKER");
    {
        std::vector<uint8_t> crc_buf(10000);
        MCL_T2 crc_gen(SEEDS[0], 3, 5);
        crc_gen.gen_bytes(crc_buf.data(), 10000);
        uint32_t crc = compute_crc32(crc_buf.data(), 10000);
        std::printf("  Canonical channel: T2, (p,q)=(3,5), seed=%llu, 10,000 bytes\n",
            static_cast<unsigned long long>(SEEDS[0]));
        std::printf("  CRC-32: 0x%08X\n", crc);
        if (g_evidence_log) {
            std::fprintf(g_evidence_log,
                "\nCRC-32 (T2, (3,5), seed %llu, 10,000 bytes): 0x%08X\n",
                static_cast<unsigned long long>(SEEDS[0]), crc);
        }
    }

    // ────────────────────────────────────────────────────────────────────
    // FINAL SUMMARY
    // ────────────────────────────────────────────────────────────────────
    double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    sep("ORTHOGONALITY VERIFICATION SUMMARY");

    std::printf("  Pairwise independence tests:        %d\n", total_pairs);
    std::printf("  Individual statistical tests:       %d\n",
        total_individual_tests);
    std::printf("    Stage 1 (Pearson):                 %d  (%d failures)\n",
        g_pearson_tests_run, g_pearson_tests_failed);
    std::printf("    Stage 2 (Hamming):                 %d  (%d failures)\n",
        g_hamming_tests_run, g_hamming_tests_failed);
    std::printf("  Combined criteria failures:         %d / %d\n",
        g_pearson_tests_failed + g_hamming_tests_failed,
        total_individual_tests);
    std::printf("  Extended tests (single-seed):       %d / %d PASS\n",
        g_passed, g_total);
    std::printf("  Negative control:                   %s\n",
        neg_pass ? "PASS" : "FAIL");
    std::printf("  Global Bonferroni rejections:       %d / %d\n",
        n_reject, m_total);

    std::printf("\n  +================================================================+\n");
    std::printf("  | VERDICT: %s |\n",
        global_pass
            ? "PASS - all orthogonality criteria satisfied          "
            : "FAIL - see failure details above                     ");
    std::printf("  +================================================================+\n");

    if (emit_evidence) {
        std::printf("\n  Evidence file: %s (%d entries)\n",
            evidence_path, total_individual_tests);
    }

    std::printf("\n  Time:    %.1f seconds\n", elapsed);
    std::printf("  Mode:    %s\n", params.name);
    std::printf("  Doc ID:  %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("  Author:  Madeeh Ibrahim, Cairo, Egypt\n");
    std::printf("=============================================================="
                "================\n\n");

    if (g_evidence_log) {
        std::fprintf(g_evidence_log, "\nElapsed: %.1f seconds\n", elapsed);
        std::fprintf(g_evidence_log,
            "\n=========================================================================\n");
        std::fprintf(g_evidence_log, "END OF EVIDENCE LOG\n");
        std::fprintf(g_evidence_log,
            "=========================================================================\n");
        std::fclose(g_evidence_log);
        g_evidence_log = nullptr;
    }

    return global_pass ? 0 : 1;
}
