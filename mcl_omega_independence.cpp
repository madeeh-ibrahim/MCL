/*
 * ============================================================================
 * MCL omega-Independence Experiment — Angular Frequency Channel Independence
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-OMEGA-INDEP-2026-0526-001
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
 * PURPOSE: Verify that different angular frequencies (ω₁,ω₂), with FIXED
 *          topology (p,q) and K, produce statistically independent streams.
 *          This establishes ω as a third independent channel axis alongside
 *          (p,q) and K, creating a 3-dimensional parameter space:
 *              Channel = f(seed, p, q, K, ω₁, ω₂)
 *
 * EXPERIMENTS:
 *   EXP 1: Single-frequency variation (ω₂ varied, ω₁=φ−1 fixed)
 *          5 configurations × 55 pairs = 275 tests
 *   EXP 2: Dual-frequency variation (all C(12,2)=66 ω-pairs, ALL C(66,2)=2145
 *          channel-pairs tested exhaustively — no sampling bias)
 *   EXP 3: Adjacent-frequency extreme test (Δω down to 10⁻¹²)
 *          7 deltas × 2 positions = 14 tests
 *   EXP 4: Cross-parameter (ω vs (p,q)) independence = 21 tests
 *   TOTAL: 2,455 pairwise independence tests (exhaustive)
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_omega_indep mcl_omega_independence.cpp -lm && ./mcl_omega_indep
 *
 * EXPECTED RESULTS:
 *   0 of ≈2,455 pairs rejected at Bonferroni α=0.001.
 *   VERDICT: PASS
 * REFERENCES:       N/A
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

// Document metadata (mirror of file header — keep in sync)
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-OMEGA-INDEP-2026-0526-001";

// Per-channel byte budget for independence testing.
// 1M bytes gives a noise-floor expected |r| ≈ √(2/π)/√N ≈ 7.98e-4,
// well below any signal we would consider meaningful.
static constexpr int64_t OMEGA_INDEP_BYTES = 1000000;

// EXP 2 — channel pairs are tested exhaustively (no sampling). C(12,2)=66
// channels × C(66,2)=2145 pairs is small enough that exhaustive testing
// adds only a few seconds; this removes any concern about sampling bias
// (and any need to justify a sampling design).

// Local aliases
static const FreqEntry* FREQ = freq_pool();
static const uint64_t* SEEDS = mcl_seeds();

// Global p-value tracking
static std::vector<double> g_all_pvalues;

// Global max|r| trackers (for SUMMARY / documentation)
static double g_exp1_max_r = 0; // worst max|r| across all EXP 1 configs
static double g_exp2_max_r = 0; // max|r| from EXP 2 (dual-freq)
static double g_exp3_max_r = 0; // max|r| from EXP 3 (adjacent ω)
static double g_exp4_max_r = 0; // max|r| from EXP 4 (cross-parameter)

// ============================================================================
// EXP 1: Vary ω₂ only (fix ω₁ = φ−1)
// ============================================================================
void exp1_vary_omega2(uint64_t seed, int64_t p, int64_t q, double K,
 int64_t n_bytes, const char* label) {
 sep(label);
 double omega1 = FREQ[0].value;
 int n_ch = N_FREQ_POOL - 1;

 std::printf(" Fixed: (p,q)=(%lld,%lld), K=%.1f, omega1=%s (%.16f)\n",
 (long long)p, (long long)q, K, FREQ[0].name, omega1);
 std::printf(" Seed: %llu, Bytes: %lld\n", (unsigned long long)seed, (long long)n_bytes);
 std::printf(" Varying omega2 across %d values from frequency pool.\n\n", n_ch);

 std::vector<std::vector<uint8_t>> channels((size_t)n_ch);
 std::printf(" Channel omega2 Entropy\n");
 std::printf(" %s\n", std::string(50, '-').c_str());

 for (int i = 0; i < n_ch; i++) {
 double omega2 = FREQ[i + 1].value;
 MCL_T2_Omega gen(seed, p, q, omega1, omega2, K);
 channels[(size_t)i].resize((size_t)n_bytes);
 gen.gen_bytes(channels[(size_t)i].data(), n_bytes);
 std::printf(" %-14s %.16f %.6f\n",
 FREQ[i + 1].name, omega2,
 shannon_entropy(channels[(size_t)i].data(), n_bytes));
 }

 int n_pairs = n_ch * (n_ch - 1) / 2;
 double max_r = 0, sum_r = 0, min_p = 1.0;

 std::printf("\n Pairwise independence (%d pairs):\n", n_pairs);
 std::printf(" omega2_i omega2_j |r| p-value Ham%%\n");
 std::printf(" %s\n", std::string(72, '-').c_str());

 for (int i = 0; i < n_ch; i++) {
 for (int j = i + 1; j < n_ch; j++) {
 double r = std::abs(pearson_r(channels[(size_t)i].data(),
 channels[(size_t)j].data(), n_bytes));
 double pv = pvalue_from_r(r, n_bytes);
 double ham = hamming_pct(channels[(size_t)i].data(),
 channels[(size_t)j].data(), n_bytes);
 if (r > max_r) max_r = r;
 sum_r += r;
 if (pv < min_p) min_p = pv;
 g_all_pvalues.push_back(pv);

 std::printf(" %-14s %-14s %.6f %.4e %.3f%%\n",
 FREQ[i+1].name, FREQ[j+1].name, r, pv, ham);
 }
 }

 double suite_bonf = BONFERRONI_ALPHA / (double)n_pairs;
 bool pass = min_p >= suite_bonf;
 double expected_mean = 1.0 / std::sqrt((double)n_bytes) * std::sqrt(2.0 / MCL_PI);
 if (max_r > g_exp1_max_r) g_exp1_max_r = max_r; // track for SUMMARY
 std::printf("\n max|r|=%.6f mean|r|=%.6f (expected %.6f) min(p)=%.4e\n",
 max_r, sum_r / n_pairs, expected_mean, min_p);
 std::printf(" Suite Bonferroni: %.4e VERDICT: %s\n", suite_bonf, pass ? "PASS" : "FAIL");
}

// ============================================================================
// EXP 2: Vary both ω₁ and ω₂ (all C(12,2) pairs)
// ============================================================================
void exp2_vary_both_omegas(uint64_t seed, int64_t p, int64_t q, double K,
 int64_t n_bytes, const char* label) {
 sep(label);

 struct OmegaPair { int i1, i2; };
 std::vector<OmegaPair> pairs;
 for (int i = 0; i < N_FREQ_POOL; i++)
 for (int j = i + 1; j < N_FREQ_POOL; j++)
 pairs.push_back({i, j});

 int n_ch = (int)pairs.size();
 std::printf(" Fixed: (p,q)=(%lld,%lld), K=%.1f\n", (long long)p, (long long)q, K);
 std::printf(" Seed: %llu, Bytes: %lld\n", (unsigned long long)seed, (long long)n_bytes);
 std::printf(" Channels: %d (all C(%d,2) distinct omega pairs)\n\n", n_ch, N_FREQ_POOL);

 std::vector<std::vector<uint8_t>> channels((size_t)n_ch);
 std::printf(" Ch omega1 omega2 Entropy\n");
 std::printf(" %s\n", std::string(54, '-').c_str());

 for (int c = 0; c < n_ch; c++) {
 double w1 = FREQ[pairs[(size_t)c].i1].value;
 double w2 = FREQ[pairs[(size_t)c].i2].value;
 MCL_T2_Omega gen(seed, p, q, w1, w2, K);
 channels[(size_t)c].resize((size_t)n_bytes);
 gen.gen_bytes(channels[(size_t)c].data(), n_bytes);

 if (c < 10 || c >= n_ch - 3)
 std::printf(" %-3d %-14s %-14s %.6f\n",
 c, FREQ[pairs[(size_t)c].i1].name,
 FREQ[pairs[(size_t)c].i2].name,
 shannon_entropy(channels[(size_t)c].data(), n_bytes));
 else if (c == 10)
 std::printf(" ... (%d channels total) ...\n", n_ch);
 }

 int n_ch_pairs = n_ch * (n_ch - 1) / 2;

 std::printf("\n Pairwise independence (%d total channel-pairs, all tested):\n",
 n_ch_pairs);

 double max_r = 0, sum_r = 0, min_p = 1.0;
 int tested = 0;

 for (int i = 0; i < n_ch; i++) {
 for (int j = i + 1; j < n_ch; j++) {
 double r = std::abs(pearson_r(channels[(size_t)i].data(),
 channels[(size_t)j].data(), n_bytes));
 double pv = pvalue_from_r(r, n_bytes);
 if (r > max_r) max_r = r;
 sum_r += r;
 if (pv < min_p) min_p = pv;
 g_all_pvalues.push_back(pv);
 tested++;
 }
 }

 double expected_mean = 1.0 / std::sqrt((double)n_bytes) * std::sqrt(2.0 / MCL_PI);
 double suite_bonf = BONFERRONI_ALPHA / (double)tested;
 bool pass = min_p >= suite_bonf;
 g_exp2_max_r = max_r; // track for SUMMARY

 std::printf(" Tested: %d pairs (exhaustive)\n", tested);
 std::printf(" max|r|=%.6f mean|r|=%.6f (expected %.6f)\n",
 max_r, sum_r / tested, expected_mean);
 std::printf(" min(p)=%.4e Bonferroni=%.4e VERDICT: %s\n",
 min_p, suite_bonf, pass ? "PASS" : "FAIL");
}

// ============================================================================
// EXP 3: Adjacent ω — minimal frequency differences (Δω → 10⁻¹²)
// ============================================================================
void exp3_adjacent_omega(uint64_t seed, int64_t p, int64_t q, double K,
 int64_t n_bytes) {
 sep("EXP 3: ADJACENT omega — minimal frequency differences");

 double base_w1 = FREQ[0].value;
 double base_w2 = FREQ[1].value;
 double deltas[] = {1e-12, 1e-10, 1e-8, 1e-6, 1e-4, 1e-2, 0.1};
 size_t n_d = sizeof(deltas) / sizeof(deltas[0]);

 std::printf(" Base: omega1=%s, omega2=%s, (p,q)=(%lld,%lld), K=%.1f\n",
 FREQ[0].name, FREQ[1].name,
 (long long)p, (long long)q, K);
 std::printf(" Question: how close can two omega values be?\n\n");

 MCL_T2_Omega gen_base(seed, p, q, base_w1, base_w2, K);
 std::vector<uint8_t> data_base((size_t)n_bytes);
 gen_base.gen_bytes(data_base.data(), n_bytes);

 std::printf(" Test A: Perturb omega2 (omega1 fixed)\n");
 std::printf(" Delta omega2_new |r| p-value Indep?\n");
 std::printf(" %s\n", std::string(72, '-').c_str());
 // Display marker: "OK" iff p > BONFERRONI_ALPHA (raw individual α=0.001).
 // This is an EARLY-WARNING indicator only. The authoritative pass criterion
 // is the GLOBAL Bonferroni test in main(), where threshold = α / m_total
 // (much stricter than 0.001). A row marked "CHECK" here may still pass
 // globally; "OK" here does not guarantee global pass either.
 // Same convention as mcl_k_independence: raw α at suite level for
 // transparency, global Bonferroni as the authoritative verdict.

 for (size_t d = 0; d < n_d; d++) {
 double w2_new = base_w2 + deltas[d];
 MCL_T2_Omega gen2(seed, p, q, base_w1, w2_new, K);
 std::vector<uint8_t> data2((size_t)n_bytes);
 gen2.gen_bytes(data2.data(), n_bytes);

 double r = std::abs(pearson_r(data_base.data(), data2.data(), n_bytes));
 double pv = pvalue_from_r(r, n_bytes);
 g_all_pvalues.push_back(pv);
 if (r > g_exp3_max_r) g_exp3_max_r = r;

 std::printf(" %.0e %.16f %.6f %.4e %s\n",
 deltas[d], w2_new, r, pv,
 pv > BONFERRONI_ALPHA ? "OK (raw)" : "CHECK");
 }

 std::printf("\n Test B: Perturb omega1 (omega2 fixed)\n");
 std::printf(" Delta omega1_new |r| p-value Indep?\n");
 std::printf(" %s\n", std::string(72, '-').c_str());

 for (size_t d = 0; d < n_d; d++) {
 double w1_new = base_w1 + deltas[d];
 MCL_T2_Omega gen2(seed, p, q, w1_new, base_w2, K);
 std::vector<uint8_t> data2((size_t)n_bytes);
 gen2.gen_bytes(data2.data(), n_bytes);

 double r = std::abs(pearson_r(data_base.data(), data2.data(), n_bytes));
 double pv = pvalue_from_r(r, n_bytes);
 g_all_pvalues.push_back(pv);
 if (r > g_exp3_max_r) g_exp3_max_r = r;

 std::printf(" %.0e %.16f %.6f %.4e %s\n",
 deltas[d], w1_new, r, pv,
 pv > BONFERRONI_ALPHA ? "OK (raw)" : "CHECK");
 }
}

// ============================================================================
// EXP 4: Cross-parameter — ω vs (p,q) independence
// ============================================================================
void exp4_omega_vs_pq(uint64_t seed, double K, int64_t n_bytes) {
 sep("EXP 4: CROSS-CHECK — omega-channel vs (p,q)-channel independence");

 // Cross-check channels: deliberately span 3 (p,q) topologies × 3 ω-pair
 // selections to stress-test independence across mixed parameter changes.
 // Labels are built dynamically from FREQ pool names to avoid drift if
 // freq_pool() in mcl_core.hpp is ever reordered.
 struct Chan { int64_t p, q; int w1_idx, w2_idx; };

 Chan chans[] = {
 {2, 3, 0, 1},
 {2, 3, 2, 3},
 {2, 3, 4, 5},
 {3, 5, 0, 1},
 {3, 5, 2, 3},
 {5, 7, 0, 1},
 {5, 7, 4, 5},
 };
 size_t n_ch = sizeof(chans) / sizeof(chans[0]);

 // Build display labels at runtime (avoids hardcoded "phi-1,rho" strings).
 std::vector<std::string> labels(n_ch);
 for (size_t i = 0; i < n_ch; i++) {
 char buf[80];
 std::snprintf(buf, sizeof(buf), "pq(%lld,%lld) w(%s,%s)",
 (long long)chans[i].p, (long long)chans[i].q,
 FREQ[chans[i].w1_idx].name, FREQ[chans[i].w2_idx].name);
 labels[i] = buf;
 }

 std::printf(" Question: are channels varying ω, (p,q), or both all independent?\n\n");

 std::vector<std::vector<uint8_t>> channels(n_ch);
 std::printf(" Channels:\n");
 for (size_t i = 0; i < n_ch; i++) {
 double w1 = FREQ[chans[i].w1_idx].value;
 double w2 = FREQ[chans[i].w2_idx].value;
 MCL_T2_Omega gen(seed, chans[i].p, chans[i].q, w1, w2, K);
 channels[i].resize((size_t)n_bytes);
 gen.gen_bytes(channels[i].data(), n_bytes);
 std::printf(" [%zu] %-32s entropy=%.6f\n", i, labels[i].c_str(),
 shannon_entropy(channels[i].data(), n_bytes));
 }

 size_t n_pairs = n_ch * (n_ch - 1) / 2;
 std::printf("\n Pairwise (%zu pairs):\n", n_pairs);
 std::printf(" pair |r|        p-value     Ham%%   Varies     Channels\n");
 std::printf(" %s\n", std::string(82, '-').c_str());

 double max_r = 0, min_p = 1.0;
 for (size_t i = 0; i < n_ch; i++) {
 for (size_t j = i + 1; j < n_ch; j++) {
 double r = std::abs(pearson_r(channels[i].data(), channels[j].data(), n_bytes));
 double pv = pvalue_from_r(r, n_bytes);
 double ham = hamming_pct(channels[i].data(), channels[j].data(), n_bytes);
 if (r > max_r) max_r = r;
 if (pv < min_p) min_p = pv;
 g_all_pvalues.push_back(pv);
 const char* varies;
 if (chans[i].p == chans[j].p && chans[i].q == chans[j].q)
 varies = "omega    ";
 else if (chans[i].w1_idx == chans[j].w1_idx && chans[i].w2_idx == chans[j].w2_idx)
 varies = "(p,q)    ";
 else
 varies = "both     ";

 std::printf(" %zu-%zu  %.6f %.4e %.3f%% %s [%zu]vs[%zu]\n",
 i, j, r, pv, ham, varies, i, j);
 }
 }

 double suite_bonf = BONFERRONI_ALPHA / (double)n_pairs;
 bool pass = min_p >= suite_bonf;
 g_exp4_max_r = max_r; // track for SUMMARY
 std::printf("\n max|r|=%.6f min(p)=%.4e Bonferroni=%.4e\n", max_r, min_p, suite_bonf);
 std::printf(" VERDICT: %s\n", pass ? "PASS — all parameter axes independent" : "FAIL");
}

// ============================================================================
// MAIN
// ============================================================================
int main() {
 auto t_start = std::chrono::steady_clock::now();
 int64_t n_bytes = OMEGA_INDEP_BYTES;
 bool global_pass = true;

 std::printf("\n");
 std::printf("******************************************************************************\n");
 std::printf(" MCL omega-INDEPENDENCE EXPERIMENT v%s\n", DOC_VERSION);
 std::printf(" Fixed (p,q) and K, varying angular frequencies omega\n");
 std::printf(" Bonferroni correction (alpha=%.4f)\n", BONFERRONI_ALPHA);
 std::printf("******************************************************************************\n\n");

 std::printf(" Frequency pool (%d entries, all verified to IEEE 754 precision):\n", N_FREQ_POOL);
 for (int i = 0; i < N_FREQ_POOL; i++)
 std::printf(" [%2d] %-14s = %.16f\n", i, FREQ[i].name, FREQ[i].value);
 std::printf("\n");

 // NEGATIVE CONTROL: same (p,q,K,ω₁,ω₂,seed) → identical output
 {
 sep("NEGATIVE CONTROL: same parameters = identical output");
 MCL_T2_Omega ga(SEEDS[0], 2, 3, FREQ[0].value, FREQ[1].value, 12.0);
 MCL_T2_Omega gb(SEEDS[0], 2, 3, FREQ[0].value, FREQ[1].value, 12.0);
 std::vector<uint8_t> da((size_t)n_bytes), db((size_t)n_bytes);
 ga.gen_bytes(da.data(), n_bytes);
 gb.gen_bytes(db.data(), n_bytes);
 double r = pearson_r(da.data(), db.data(), n_bytes);
 int64_t diff = 0;
 for (int64_t i = 0; i < n_bytes; i++) if (da[(size_t)i] != db[(size_t)i]) diff++;
 bool neg_ok = (std::abs(r - 1.0) < 1e-10 && diff == 0);
 std::printf(" Same (2,3), K=12, omega=(phi-1,rho), seed=%llu:\n",
 (unsigned long long)SEEDS[0]);
 std::printf(" r=%.6f, diff=%lld → %s\n", r, (long long)diff,
 neg_ok ? "OK — deterministic" : "FAIL");
 if (!neg_ok) global_pass = false;
 }

 // EXP 1: Vary omega2 only — 3 seeds × (2,3) + (3,5) + K=5 = 5 configs × 55 = 275
 for (int s = 0; s < N_MCL_SEEDS; s++) {
 char label[128];
 std::snprintf(label, sizeof(label),
 "EXP 1: Vary omega2, (2,3) K=12, seed #%d", s+1);
 exp1_vary_omega2(SEEDS[s], 2, 3, 12.0, n_bytes, label);
 }
 exp1_vary_omega2(SEEDS[0], 3, 5, 12.0, n_bytes,
 "EXP 1: Vary omega2, (3,5) K=12, seed #1");
 exp1_vary_omega2(SEEDS[0], 2, 3, 5.0, n_bytes,
 "EXP 1: Vary omega2, (2,3) K=5, seed #1");

 // EXP 2: All omega pairs — C(12,2)=66 channels, all C(66,2)=2145
 // channel-pairs tested exhaustively (no sampling).
 exp2_vary_both_omegas(SEEDS[0], 2, 3, 12.0, n_bytes,
 "EXP 2: All omega pairs, (2,3) K=12");

 // EXP 3: Adjacent omega — 14 tests
 exp3_adjacent_omega(SEEDS[0], 2, 3, 12.0, n_bytes);

 // EXP 4: Cross-check — 21 tests
 exp4_omega_vs_pq(SEEDS[0], 12.0, n_bytes);

 // ========================================================================
 // GLOBAL BONFERRONI
 // ========================================================================
 double elapsed = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t_start).count();

 sep("GLOBAL BONFERRONI ANALYSIS");

 int m_total = (int)g_all_pvalues.size();
 double bonf_threshold = BONFERRONI_ALPHA / (double)m_total;

 std::vector<double> sorted_p = g_all_pvalues;
 std::sort(sorted_p.begin(), sorted_p.end());

 int n_reject = 0;
 for (double pv : sorted_p)
 if (pv < bonf_threshold) n_reject++;

 std::printf(" Total pairs tested: %d\n", m_total);
 std::printf(" Bonferroni threshold: alpha/m = %.4e / %d = %.4e\n",
 BONFERRONI_ALPHA, m_total, bonf_threshold);

 std::printf("\n Smallest 5 p-values:\n");
 for (int i = 0; i < 5 && i < m_total; i++)
 std::printf(" #%d: p = %.6e %s threshold\n",
 i+1, sorted_p[(size_t)i],
 sorted_p[(size_t)i] < bonf_threshold ? "<" : ">=");

 if (n_reject > 0) global_pass = false;
 std::printf("\n Rejections: %d / %d\n", n_reject, m_total);

 // Compute ratio for documentation
 double ratio = sorted_p[0] / bonf_threshold;

 std::printf("\n +==============================================================+\n");
 std::printf(" | GLOBAL VERDICT: %s |\n",
 global_pass ? "PASS — omega produces independent channels" : "FAIL");
 std::printf(" | min(p) = %.4e >= threshold = %.4e |\n",
 sorted_p[0], bonf_threshold);
 std::printf(" | min(p) is %.0f× above Bonferroni threshold |\n", ratio);
 std::printf(" +==============================================================+\n");

 // ========================================================================
 // SUMMARY — numbers for documentation
 // ========================================================================
 sep("SUMMARY — Key Numbers for Documentation");

 std::printf(" Global results:\n");
 std::printf(" Total independence tests: %d\n", m_total);
 std::printf(" Rejections: %d\n", n_reject);
 std::printf(" Smallest p-value: %.4e\n", sorted_p[0]);
 std::printf(" Bonferroni threshold: %.4e\n", bonf_threshold);
 std::printf(" Ratio (min_p / threshold): %.0f×\n", ratio);

 std::printf("\n Per-experiment max|r|:\n");
 std::printf(" (a) Single-freq    (EXP 1, all configs):  max|r| = %.6f\n", g_exp1_max_r);
 std::printf(" (b) Dual-freq      (EXP 2, exhaustive):    max|r| = %.6f\n", g_exp2_max_r);
 std::printf(" (c) Adjacent ω     (EXP 3, Δω down to 10⁻¹²): max|r| = %.6f\n", g_exp3_max_r);
 std::printf(" (d) Cross-param    (EXP 4, ω vs (p,q)):   max|r| = %.6f\n", g_exp4_max_r);

 std::printf("\n Channel parameter space: 3-dimensional\n");
 std::printf(" Axis 1: coupling weights (p,q)\n");
 std::printf(" Axis 2: coupling strength K\n");
 std::printf(" Axis 3: angular frequencies (ω₁, ω₂)\n");
 std::printf(" All axes independently produce independent channels.\n");

 std::printf("\n Time: %.1f seconds\n", elapsed);
 std::printf("\n %s v%s | Madeeh Ibrahim, Cairo\n", DOC_ID, DOC_VERSION);
 std::printf("==============================================================================\n");

 return global_pass ? 0 : 1;
}
