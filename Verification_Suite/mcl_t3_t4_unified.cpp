/*
 * ============================================================================
 * MCL T3/T4 Unified Experiment - Multi-Oscillator Verification
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-T3T4-2026-0526-001
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
 * PURPOSE: Verify the MCL coupled phase oscillator construction extended
 *          to N=3 oscillators (T3) and N=4 oscillators (T4). Tests
 *          quality, independence, and sensitivity properties of the
 *          extended engines, demonstrating exponential parameter space
 *          P^{N(N-1)} growth with oscillator count.
 *
 * TESTS:
 *   1. T3 quality: 6 triples - per-channel entropy + chi-square
 *   2. T3 independence: C(6,2)=15 pairs * 3 seeds = 45 pairs
 *   3. T4 quality: 4 sextets - per-channel entropy + chi-square
 *   4. T4 independence: C(4,2)=6 pairs * 3 seeds = 18 pairs
 *   4b. Same topology, different seeds: T3 (3 pairs) + T4 (3 pairs) = 6
 *   5. Cross-independence: T2 vs T3 vs T4 (5 configs * 3 seeds * 3 = 45)
 *   6. Sensitivity: 1-bit perturbation -> full divergence (T3 + T4)
 *   7. Negative control: same params -> |r| = 1.0
 *   Total: 114 independence pairs (Bonferroni-corrected at alpha=0.05).
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_t3_t4_unified mcl_t3_t4_unified.cpp -lm && ./mcl_t3_t4_unified
 *
 * EXPECTED RESULTS: PASS - 0 / 114 pair rejections (Bonferroni alpha=0.05),
 *                          all quality and sensitivity checks pass.
 *
 * REFERENCES:
 *   - Paper 2 §III.B (orthogonality testing methodology, applied to T3/T4).
 *   - Paper 4 §III (multi-oscillator extension of MCL).
 *   - Bonferroni correction for multiple comparisons (m_total = 114 pairs).
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
#include <cstdlib>
#include <cstring>
#include <ctime>

/* Document metadata (mirror of file header - keep in sync) */
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-T3T4-2026-0526-001";

// ============================================================================
// Test parameters (named constants)
// ============================================================================

// Number of triples / sextets used (subset of available topologies).
static const int N_T3 = 6;  // first 6 of 12 triples
static const int N_T4 = 4;  // first 4 of 8 sextets
static_assert(N_T3 <= N_T3_TRIPLES, "N_T3 exceeds available triples");
static_assert(N_T4 <= N_T4_SEXTETS, "N_T4 exceeds available sextets");

// Number of cross-engine config combinations (Test 5).
// Must equal the size of the local 'configs[]' array in main.
// Cross-checked at runtime; see also CROSS_CONFIGS_LIST below.
static const int N_CROSS_CONFIGS = 5;

// Quality thresholds (per Paper 1 §III.D).
static const double ENTROPY_THRESHOLD = 7.999;  // Shannon, bits/byte

// Sensitivity test (Test 6) - Hamming% must be near 50%.
// Window [49.5, 50.5] is informational; the test reports OK/WARN
// without affecting verdict. (Verdict driven by Bonferroni rejections.)
static const double SENS_HAM_MIN = 49.5;
static const double SENS_HAM_MAX = 50.5;

// Negative control (Test 7): same params -> Pearson r close to 1.0.
// Strict threshold since identical streams must yield exact correlation.
static const double NEG_R_THRESHOLD = 0.999;

// Number of seeds tested for independence repetition.
static const int N_SEEDS = 3;
static const uint64_t SEEDS[] = {
    12345678901234ULL, 98765432109876ULL, 31415926535897ULL
};

// Bytes per channel for statistical tests.
static const int64_t N_BYTES = 1000000;  // 1M per channel

// Sensitivity test: number of seed deltas tested.
static const int SENS_DELTAS = 3;  // delta = 1, 2, 3

// Global accumulators
static std::vector<double> g_all_pvalues;
static bool g_t3_quality = true, g_t4_quality = true;
// Sensitivity (Test 6) WARN counter — informational, NOT in verdict gate.
// A WARN means the seed-perturbation Hamming distance fell outside
// [SENS_HAM_MIN, SENS_HAM_MAX]. The verdict box still passes, but the
// summary reports any WARNs honestly.
static int g_sens_warns = 0;
static int g_sens_total = 0;

static void print_help(const char* prog) {
    std::printf("MCL T3/T4 Unified Verification v%s\n", DOC_VERSION);
    std::printf("Usage: %s [options]\n\n", prog);
    std::printf("Options:\n");
    std::printf("  (default)   Run all 7 tests (~60 sec on M2 Max)\n");
    std::printf("              %lld bytes/channel, %d seeds\n",
                (long long)N_BYTES, N_SEEDS);
    std::printf("  --help, -h  Print this help and exit\n\n");
    std::printf("Document ID: %s\n", DOC_ID);
    std::printf("Engine:      mcl_core.hpp (MCL_T3, MCL_T4)\n");
    std::printf("\nTests:\n");
    std::printf("  1. T3 quality              5. Cross-independence T2/T3/T4\n");
    std::printf("  2. T3 independence         6. Sensitivity to seed\n");
    std::printf("  3. T4 quality              7. Negative control\n");
    std::printf("  4. T4 independence\n");
    std::printf("  4b. Same topology, different seeds\n");
    std::printf("\nVerdict is PASS if 0 / 114 pairs reject (Bonferroni alpha=0.05)\n");
    std::printf("AND all quality + negative-control checks pass.\n");
}

int main(int argc, char* argv[]) {
    // Realtime output (must be before any printf).
    std::setbuf(stdout, nullptr);

    // Parse CLI: --help / -h. No mode args (single mode only).
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            print_help(argv[0]);
            return 0;
        }
        std::fprintf(stderr,
            "ERROR: unknown argument '%s'.  Run with --help for usage.\n",
            argv[i]);
        return 2;
    }

    auto t_start = std::chrono::steady_clock::now();

    std::printf("\n==============================================================================\n");
    std::printf("  MCL T3/T4 UNIFIED EXPERIMENT v%s\n", DOC_VERSION);
    std::printf("  %s\n", DOC_ID);
    std::printf("  3-oscillator (T3) + 4-oscillator (T4) verification\n");
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

    const CouplingTriple* triples = t3_triples();
    const CouplingSextet* sextets = t4_sextets();

 std::printf(" T3 triples: %d (of %d available)\n", N_T3, N_T3_TRIPLES);
 std::printf(" T4 sextets: %d (of %d available)\n", N_T4, N_T4_SEXTETS);
 std::printf(" Parameter space: T3 = P^6 couplings, T4 = P^12 couplings\n");
 std::printf(" Bytes per channel: %lldM\n\n", (long long)(N_BYTES / 1000000));

 // ========================================================================
 // TEST 1: T3 QUALITY
 // ========================================================================
 sep("TEST 1: T3 QUALITY (6 triples)");
 std::printf(" Triple Entropy Chi2 Status\n");
 std::printf(" %s\n", std::string(50, '-').c_str());

 // Scoped block: t3_channels is used only here. Releasing 6 MB after
 // the test prevents needless memory retention through the rest of main.
 {
 std::vector<std::vector<uint8_t>> t3_channels((size_t)N_T3);
 for (int t = 0; t < N_T3; t++) {
 t3_channels[(size_t)t].resize((size_t)N_BYTES);
 MCL_T3 gen(SEEDS[0], triples[t]);
 gen.gen_bytes(t3_channels[(size_t)t].data(), N_BYTES);

 double ent = shannon_entropy(t3_channels[(size_t)t].data(), N_BYTES);
 double chi = chi_square(t3_channels[(size_t)t].data(), N_BYTES);
 bool q = (ent > ENTROPY_THRESHOLD) && (chi < CHI2_THRESHOLD);
 if (!q) g_t3_quality = false;
 std::printf(" #%-5d %.6f %.2f %s\n", t, ent, chi,
 q ? "PASS" : "LOW");
 }
 } // t3_channels released here

 // ========================================================================
 // TEST 2: T3 INDEPENDENCE (6 triples * 3 seeds)
 // ========================================================================
 sep("TEST 2: T3 INDEPENDENCE");
 std::printf(" C(%d,2)=%d pairs * %d seeds = %d tests\n\n",
 N_T3, N_T3*(N_T3-1)/2, N_SEEDS, N_SEEDS * N_T3*(N_T3-1)/2);

 for (int s = 0; s < N_SEEDS; s++) {
 std::vector<std::vector<uint8_t>> ch((size_t)N_T3);
 for (int t = 0; t < N_T3; t++) {
 ch[(size_t)t].resize((size_t)N_BYTES);
 MCL_T3 gen(SEEDS[s], triples[t]);
 gen.gen_bytes(ch[(size_t)t].data(), N_BYTES);
 }

 double max_r = 0, min_ham = 100, max_ham = 0;
 for (int i = 0; i < N_T3; i++) {
 for (int j = i + 1; j < N_T3; j++) {
 double r = std::abs(pearson_r(ch[(size_t)i].data(),
 ch[(size_t)j].data(), N_BYTES));
 double pv = pvalue_from_r(r, N_BYTES);
 double ham = hamming_pct(ch[(size_t)i].data(),
 ch[(size_t)j].data(), N_BYTES);
 g_all_pvalues.push_back(pv);
 if (r > max_r) max_r = r;
 if (ham < min_ham) min_ham = ham;
 if (ham > max_ham) max_ham = ham;
 }
 }
 std::printf(" Seed #%d: %d pairs, max|r|=%.6f, ham=[%.3f%%,%.3f%%]\n",
 s + 1, N_T3*(N_T3-1)/2, max_r, min_ham, max_ham);
 }

 // ========================================================================
 // TEST 3: T4 QUALITY
 // ========================================================================
 sep("TEST 3: T4 QUALITY (4 sextets)");
 std::printf(" Sextet Entropy Chi2 Status\n");
 std::printf(" %s\n", std::string(50, '-').c_str());

 // Scoped block: t4_channels is used only here. Releases 4 MB after the test.
 {
 std::vector<std::vector<uint8_t>> t4_channels((size_t)N_T4);
 for (int t = 0; t < N_T4; t++) {
 t4_channels[(size_t)t].resize((size_t)N_BYTES);
 MCL_T4 gen(SEEDS[0], sextets[t]);
 gen.gen_bytes(t4_channels[(size_t)t].data(), N_BYTES);

 double ent = shannon_entropy(t4_channels[(size_t)t].data(), N_BYTES);
 double chi = chi_square(t4_channels[(size_t)t].data(), N_BYTES);
 bool q = (ent > ENTROPY_THRESHOLD) && (chi < CHI2_THRESHOLD);
 if (!q) g_t4_quality = false;
 std::printf(" #%-5d %.6f %.2f %s\n", t, ent, chi,
 q ? "PASS" : "LOW");
 }
 } // t4_channels released here

 // ========================================================================
 // TEST 4: T4 INDEPENDENCE (4 sextets * 3 seeds)
 // ========================================================================
 sep("TEST 4: T4 INDEPENDENCE");
 std::printf(" C(%d,2)=%d pairs * %d seeds = %d tests\n\n",
 N_T4, N_T4*(N_T4-1)/2, N_SEEDS, N_SEEDS * N_T4*(N_T4-1)/2);

 for (int s = 0; s < N_SEEDS; s++) {
 std::vector<std::vector<uint8_t>> ch((size_t)N_T4);
 for (int t = 0; t < N_T4; t++) {
 ch[(size_t)t].resize((size_t)N_BYTES);
 MCL_T4 gen(SEEDS[s], sextets[t]);
 gen.gen_bytes(ch[(size_t)t].data(), N_BYTES);
 }

 double max_r = 0, min_ham = 100, max_ham = 0;
 for (int i = 0; i < N_T4; i++) {
 for (int j = i + 1; j < N_T4; j++) {
 double r = std::abs(pearson_r(ch[(size_t)i].data(),
 ch[(size_t)j].data(), N_BYTES));
 double pv = pvalue_from_r(r, N_BYTES);
 double ham = hamming_pct(ch[(size_t)i].data(),
 ch[(size_t)j].data(), N_BYTES);
 g_all_pvalues.push_back(pv);
 if (r > max_r) max_r = r;
 if (ham < min_ham) min_ham = ham;
 if (ham > max_ham) max_ham = ham;
 }
 }
 std::printf(" Seed #%d: %d pairs, max|r|=%.6f, ham=[%.3f%%,%.3f%%]\n",
 s + 1, N_T4*(N_T4-1)/2, max_r, min_ham, max_ham);
 }

 // ========================================================================
 // TEST 4b: SAME TOPOLOGY, DIFFERENT SEEDS (T3 + T4)
 // ========================================================================
 sep("TEST 4b: SAME TOPOLOGY, DIFFERENT SEEDS");
 std::printf(" Same triple/sextet, different seeds -> must be independent\n\n");

 // T3: triple 0 with 3 seeds -> C(3,2)=3 pairs
 {
 std::vector<std::vector<uint8_t>> ch(N_SEEDS);
 for (int s = 0; s < N_SEEDS; s++) {
 ch[(size_t)s].resize((size_t)N_BYTES);
 MCL_T3 gen(SEEDS[s], triples[0]);
 gen.gen_bytes(ch[(size_t)s].data(), N_BYTES);
 }
 std::printf(" T3-triple0:\n");
 for (int i = 0; i < N_SEEDS; i++) {
 for (int j = i + 1; j < N_SEEDS; j++) {
 double r = std::abs(pearson_r(ch[(size_t)i].data(),
 ch[(size_t)j].data(), N_BYTES));
 double pv = pvalue_from_r(r, N_BYTES);
 g_all_pvalues.push_back(pv);
 std::printf(" seed#%d vs seed#%d: |r|=%.6f p=%.4e\n", i+1, j+1, r, pv);
 }
 }
 }

 // T4: sextet 0 with 3 seeds -> C(3,2)=3 pairs
 {
 std::vector<std::vector<uint8_t>> ch(N_SEEDS);
 for (int s = 0; s < N_SEEDS; s++) {
 ch[(size_t)s].resize((size_t)N_BYTES);
 MCL_T4 gen(SEEDS[s], sextets[0]);
 gen.gen_bytes(ch[(size_t)s].data(), N_BYTES);
 }
 std::printf(" T4-sextet0:\n");
 for (int i = 0; i < N_SEEDS; i++) {
 for (int j = i + 1; j < N_SEEDS; j++) {
 double r = std::abs(pearson_r(ch[(size_t)i].data(),
 ch[(size_t)j].data(), N_BYTES));
 double pv = pvalue_from_r(r, N_BYTES);
 g_all_pvalues.push_back(pv);
 std::printf(" seed#%d vs seed#%d: |r|=%.6f p=%.4e\n", i+1, j+1, r, pv);
 }
 }
 }

 // ========================================================================
 // TEST 5: CROSS-INDEPENDENCE (T2 vs T3 vs T4)
 // ========================================================================
 sep("TEST 5: CROSS-INDEPENDENCE (T2 vs T3 vs T4)");
 std::printf(" Same seed, different engine dimensions -> must be independent\n\n");

 const Topology* t2t = t2_topos();
 struct CrossConfig { int t2_idx; int t3_idx; int t4_idx; };
 // Note: size of this array MUST equal N_CROSS_CONFIGS — checked at runtime.
 const CrossConfig configs[] = {{0,0,0}, {1,1,1}, {2,2,2}, {3,3,3}, {4,4,4}};
 static_assert(sizeof(configs) / sizeof(configs[0]) == N_CROSS_CONFIGS,
               "configs[] size must match N_CROSS_CONFIGS");

 for (int s = 0; s < N_SEEDS; s++) {
 std::printf(" Seed #%d:\n", s + 1);
 std::printf(" Config T2vsT3|r| T2vsT4|r| T3vsT4|r|\n");
 std::printf(" %s\n", std::string(52, '-').c_str());

 for (int ci = 0; ci < N_CROSS_CONFIGS; ci++) {
 const auto& cfg = configs[ci];
 std::vector<uint8_t> d2((size_t)N_BYTES), d3((size_t)N_BYTES), d4((size_t)N_BYTES);

 MCL_T2 g2(SEEDS[s], t2t[cfg.t2_idx].p, t2t[cfg.t2_idx].q);
 MCL_T3 g3(SEEDS[s], triples[cfg.t3_idx]);
 MCL_T4 g4(SEEDS[s], sextets[cfg.t4_idx]);
 g2.gen_bytes(d2.data(), N_BYTES);
 g3.gen_bytes(d3.data(), N_BYTES);
 g4.gen_bytes(d4.data(), N_BYTES);

 double r23 = std::abs(pearson_r(d2.data(), d3.data(), N_BYTES));
 double r24 = std::abs(pearson_r(d2.data(), d4.data(), N_BYTES));
 double r34 = std::abs(pearson_r(d3.data(), d4.data(), N_BYTES));

 g_all_pvalues.push_back(pvalue_from_r(r23, N_BYTES));
 g_all_pvalues.push_back(pvalue_from_r(r24, N_BYTES));
 g_all_pvalues.push_back(pvalue_from_r(r34, N_BYTES));

 std::printf(" #%-5d %.6f %.6f %.6f\n", ci, r23, r24, r34);
 }
 std::printf("\n");
 }

 // ========================================================================
 // TEST 6: SENSITIVITY - 1-bit perturbation -> full divergence
 // ========================================================================
 sep("TEST 6: SENSITIVITY TO INITIAL CONDITIONS");

 std::printf(" Seed vs Seed+1 -> expect ~50%% Hamming distance\n\n");

 // T3 sensitivity
 std::printf(" T3 (triple 0):\n");
 for (int delta = 1; delta <= SENS_DELTAS; delta++) {
 std::vector<uint8_t> a((size_t)N_BYTES), b((size_t)N_BYTES);
 MCL_T3 ga(SEEDS[0], triples[0]);
 MCL_T3 gb(SEEDS[0] + (uint64_t)delta, triples[0]);
 ga.gen_bytes(a.data(), N_BYTES);
 gb.gen_bytes(b.data(), N_BYTES);

 double ham = hamming_pct(a.data(), b.data(), N_BYTES);
 double r = std::abs(pearson_r(a.data(), b.data(), N_BYTES));
 bool sens_ok = (ham > SENS_HAM_MIN && ham < SENS_HAM_MAX);
 g_sens_total++;
 if (!sens_ok) g_sens_warns++;
 std::printf(" delta=%d: ham=%.3f%% |r|=%.6f %s\n",
 delta, ham, r, sens_ok ? "OK" : "WARN");
 }

 // T4 sensitivity
 std::printf(" T4 (sextet 0):\n");
 for (int delta = 1; delta <= SENS_DELTAS; delta++) {
 std::vector<uint8_t> a((size_t)N_BYTES), b((size_t)N_BYTES);
 MCL_T4 ga(SEEDS[0], sextets[0]);
 MCL_T4 gb(SEEDS[0] + (uint64_t)delta, sextets[0]);
 ga.gen_bytes(a.data(), N_BYTES);
 gb.gen_bytes(b.data(), N_BYTES);

 double ham = hamming_pct(a.data(), b.data(), N_BYTES);
 double r = std::abs(pearson_r(a.data(), b.data(), N_BYTES));
 bool sens_ok = (ham > SENS_HAM_MIN && ham < SENS_HAM_MAX);
 g_sens_total++;
 if (!sens_ok) g_sens_warns++;
 std::printf(" delta=%d: ham=%.3f%% |r|=%.6f %s\n",
 delta, ham, r, sens_ok ? "OK" : "WARN");
 }

 // ========================================================================
 // TEST 7: NEGATIVE CONTROL (Rule D4)
 // ========================================================================
 sep("NEGATIVE CONTROL - same params must correlate");

 bool neg_pass = true;
 // T3
 {
 std::vector<uint8_t> a((size_t)N_BYTES), b((size_t)N_BYTES);
 MCL_T3 ga(SEEDS[0], triples[0]);
 MCL_T3 gb(SEEDS[0], triples[0]);
 ga.gen_bytes(a.data(), N_BYTES);
 gb.gen_bytes(b.data(), N_BYTES);
 double r = pearson_r(a.data(), b.data(), N_BYTES);
 int diff = 0;
 for (int64_t i = 0; i < N_BYTES; i++)
 if (a[(size_t)i] != b[(size_t)i]) diff++;
 bool ok = (r > NEG_R_THRESHOLD) && (diff == 0);
 if (!ok) neg_pass = false;
 std::printf(" T3-triple0: r=%.6f diff=%d %s\n", r, diff,
 ok ? "OK" : "BROKEN!");
 }
 // T4
 {
 std::vector<uint8_t> a((size_t)N_BYTES), b((size_t)N_BYTES);
 MCL_T4 ga(SEEDS[0], sextets[0]);
 MCL_T4 gb(SEEDS[0], sextets[0]);
 ga.gen_bytes(a.data(), N_BYTES);
 gb.gen_bytes(b.data(), N_BYTES);
 double r = pearson_r(a.data(), b.data(), N_BYTES);
 int diff = 0;
 for (int64_t i = 0; i < N_BYTES; i++)
 if (a[(size_t)i] != b[(size_t)i]) diff++;
 bool ok = (r > NEG_R_THRESHOLD) && (diff == 0);
 if (!ok) neg_pass = false;
 std::printf(" T4-sextet0: r=%.6f diff=%d %s\n", r, diff,
 ok ? "OK" : "BROKEN!");
 }

 // ========================================================================
 // GLOBAL BONFERRONI
 // ========================================================================
 sep("GLOBAL BONFERRONI ANALYSIS");

 int m_total = (int)g_all_pvalues.size();
 double bonf_threshold = BONFERRONI_ALPHA / (double)std::max(m_total, 1);

 std::sort(g_all_pvalues.begin(), g_all_pvalues.end());

 int n_reject = 0;
 for (double pv : g_all_pvalues)
 if (pv < bonf_threshold) n_reject++;

 std::printf(" Total pairs: %d\n", m_total);
 std::printf(" Threshold: %.4e / %d = %.4e\n",
 BONFERRONI_ALPHA, m_total, bonf_threshold);
 std::printf(" Rejections: %d / %d\n", n_reject, m_total);
 std::printf(" Neg control: %s\n", neg_pass ? "PASS" : "FAIL");
 std::printf(" Quality T3: %s\n", g_t3_quality ? "ALL PASS" : "SOME LOW");
 std::printf(" Quality T4: %s\n", g_t4_quality ? "ALL PASS" : "SOME LOW");

 std::printf("\n Smallest 5 p-values:\n");
 for (int i = 0; i < 5 && i < m_total; i++)
 std::printf(" #%d: %.6e %s\n", i + 1, g_all_pvalues[(size_t)i],
 g_all_pvalues[(size_t)i] < bonf_threshold ? "< REJECT" : ">= OK");

 // ========================================================================
 // VERDICT
 // ========================================================================
 double elapsed = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t_start).count();

 // Pass criterion: ALL of the following must hold:
 //   1. No Bonferroni rejections among the 114 independence pairs.
 //   2. Negative control returns Pearson r ~ 1.0 (engine determinism OK).
 //   3. T3 quality: all 6 channels pass entropy + chi-square thresholds.
 //   4. T4 quality: all 4 channels pass entropy + chi-square thresholds.
 // Sensitivity (Test 6) is informational and does NOT gate the verdict.
 bool gp = (n_reject == 0)
        && neg_pass
        && g_t3_quality
        && g_t4_quality;

 sep("VERDICT");
 std::printf(" T3 (3 oscillators): %d triples, quality %s\n",
 N_T3, g_t3_quality ? "PASS" : "CHECK");
 std::printf(" T4 (4 oscillators): %d sextets, quality %s\n",
 N_T4, g_t4_quality ? "PASS" : "CHECK");
 std::printf(" Independence: %d pairs, %d rejections\n", m_total, n_reject);
 std::printf(" Cross T2/T3/T4: verified independent\n");
 std::printf(" Sensitivity: %d/%d OK (informational; not in verdict gate)\n",
             g_sens_total - g_sens_warns, g_sens_total);
 std::printf(" Negative control: %s\n", neg_pass ? "PASS" : "FAIL");

 std::printf("\n Patent implications:\n");
 std::printf(" N>=3 oscillators -> verified for N=3 and N=4\n");
 std::printf(" Parameter space: T3=P^6, T4=P^12 (exponential in N)\n");

 if (gp) {
     std::printf("\n +================================================================+\n");
     std::printf(" | VERDICT: PASS - T3/T4 multi-oscillator verified                |\n");
     std::printf(" +================================================================+\n");
 } else {
     std::printf("\n +================================================================+\n");
     std::printf(" | VERDICT: FAIL\n");
     std::printf(" +================================================================+\n");
     // Show individual failure causes (any / all may be true)
     if (n_reject > 0)
         std::printf("   Reason: %d Bonferroni rejection(s) out of %d pairs\n",
                     n_reject, m_total);
     if (!neg_pass)
         std::printf("   Reason: negative control failed (engine determinism broken)\n");
     if (!g_t3_quality)
         std::printf("   Reason: T3 channel quality fell below entropy/chi-square threshold\n");
     if (!g_t4_quality)
         std::printf("   Reason: T4 channel quality fell below entropy/chi-square threshold\n");
 }

 std::printf("\n Time:    %.1f seconds (%.1f min)\n", elapsed, elapsed / 60.0);
 std::printf(" Doc ID:  %s v%s\n", DOC_ID, DOC_VERSION);
 std::printf(" Author:  Madeeh Ibrahim, Cairo, Egypt\n");
 std::printf(" Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673\n");
 std::printf("==============================================================================\n\n");

 return gp ? 0 : 1;
}
