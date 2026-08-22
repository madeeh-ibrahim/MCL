/*
 * ============================================================================
 * MCL K-Independence Experiment
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-K-INDEPENDENCE-2026-0526-001
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
 * PURPOSE: Verify that different coupling strengths K, with FIXED topology
 *          (p,q), produce statistically independent byte streams across
 *          T2, T3, T4 engines.
 *
 * TESTS:
 *   1-2. T2 wide-K + close-K:  3 topos × 3 seeds × C(11,2) + C(6,2)
 *   3-4. T3 wide-K + close-K:  2 triples × 3 seeds
 *   5-6. T4 wide-K + close-K:  1 sextet × 3 seeds
 *   7.   Adjacent-K:  T2+T3+T4, delta ±0.001..±5.0
 *   8.   Cross-dimension:  same K across T2/T3/T4
 *   9.   Negative control:  same K + same seed = |r|=1.0
 *   Total: 1,137 pairwise independence tests across all engines
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_k_independence mcl_k_independence.cpp -lm && ./mcl_k_independence
 *
 * EXPECTED RESULTS: 0 rejections, VERDICT: PASS
 *
 * REFERENCES:
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

// Document metadata (mirror of file header — keep in sync)
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-K-INDEPENDENCE-2026-0526-001";

// Per-channel byte budget. 1M bytes gives noise floor expected |r| ≈ 7.98e-4.
static constexpr int64_t K_INDEP_BYTES = 1000000;

// Hamming sanity bounds: ±0.5% around 50%. Loose by design — for 8M bits the
// 1-σ noise is only ~0.018%, so this catches gross failures (all-zeros,
// bit-stuck channels) while remaining robust to platform FP variation.
static constexpr double HAMMING_LOWER = 49.5;
static constexpr double HAMMING_UPPER = 50.5;

// Adjacent-K skip threshold: K below this is rejected from the perturbation
// sweep. Well above MCL_K_MIN_PHYS (1e-12) and below the smallest base K (2.0).
static constexpr double ADJACENT_K_MIN = 0.1;

static std::vector<double> g_all_pvalues;
static int g_suites = 0, g_pass_suites = 0;

static const uint64_t SEEDS[] = {
 12345678901234ULL, 98765432109876ULL, 31415926535897ULL
};
static constexpr int N_SEEDS = sizeof(SEEDS) / sizeof(SEEDS[0]);

static const double K_WIDE[] = {1.0, 2.0, 3.0, 5.0, 8.0, 12.0, 16.0, 20.0, 28.0, 36.0, 50.0};
static constexpr int N_K_WIDE = sizeof(K_WIDE) / sizeof(K_WIDE[0]);

static const double K_CLOSE[] = {10.0, 11.0, 12.0, 13.0, 14.0, 15.0};
static constexpr int N_K_CLOSE = sizeof(K_CLOSE) / sizeof(K_CLOSE[0]);

// Minimum acceptable per-channel entropy. Healthy MCL byte streams give
// entropy ≥ 7.999. A value below 7.99 indicates a degenerate channel
// (stuck bits, periodic pattern); the Hamming check alone misses these.
static constexpr double ENTROPY_MIN = 7.99;

// ── Pairwise test with full metrics ──
void test_pairwise(std::vector<std::vector<uint8_t>>& channels,
 const double* k_vals, int n_k, int64_t n_bytes,
 const char* label, bool print_quality) {
 // Defensive: a pairwise independence test needs at least 2 channels.
 // Calling with n_k < 2 in this file would indicate a programming bug
 // upstream; abort with a clear diagnostic rather than silently passing.
 if (n_k < 2) {
 std::fprintf(stderr,
 "FATAL: test_pairwise(\"%s\") called with n_k=%d (need ≥ 2)\n",
 label, n_k);
 std::abort();
 }

 int n_pairs = n_k * (n_k - 1) / 2;
 size_t pv_start = g_all_pvalues.size();
 double sigma = 1.0 / std::sqrt((double)n_bytes);
 double expected_mean_r = sigma * std::sqrt(2.0 / MCL_PI);

 // Compute per-channel entropy. Tracked into min_ent so degenerate
 // (stuck-bit / periodic) channels are caught even if Hamming distance
 // happens to land near 50% by coincidence.
 double min_ent = 8.0;
 if (print_quality) {
 std::printf(" Channel quality:\n K Entropy\n");
 }
 for (int i = 0; i < n_k; i++) {
 double ent = shannon_entropy(channels[(size_t)i].data(), n_bytes);
 if (ent < min_ent) min_ent = ent;
 if (print_quality) {
 std::printf(" %-8.1f %.6f\n", k_vals[i], ent);
 }
 }

 double max_r = 0, sum_r = 0, min_p = 1.0;
 double min_ham = 100, max_ham = 0;
 bool nan_seen = false; // catches degenerate (constant-stream) cases

 for (int i = 0; i < n_k; i++) {
 for (int j = i + 1; j < n_k; j++) {
 double r = std::abs(pearson_r(channels[(size_t)i].data(),
 channels[(size_t)j].data(), n_bytes));
 double pv = pvalue_from_r(r, n_bytes);
 double ham = hamming_pct(channels[(size_t)i].data(),
 channels[(size_t)j].data(), n_bytes);
 // NaN can arise only from zero-variance (constant) streams. MCL
 // output never produces these in practice, but we defend against
 // a silent pass: a NaN propagates through < / > as false, which
 // would let a degenerate suite skip every check.
 if (!std::isfinite(r) || !std::isfinite(pv) || !std::isfinite(ham)) {
 nan_seen = true;
 // push a sentinel so global Bonferroni count still reflects
 // that this pair was tested (and the test failed)
 g_all_pvalues.push_back(0.0);
 continue;
 }
 g_all_pvalues.push_back(pv);
 if (r > max_r) max_r = r;
 sum_r += r;
 if (pv < min_p) min_p = pv;
 if (ham < min_ham) min_ham = ham;
 if (ham > max_ham) max_ham = ham;
 }
 }

 // Suite-level early-warning rejection count using RAW α (not Bonferroni-
 // corrected). The authoritative test is the GLOBAL Bonferroni at the end
 // of main(), which corrects for all m_total tests across the whole file.
 // A suite-level "FAIL" here therefore means "this suite has at least one
 // p-value below the raw α threshold of 0.001"; it does not necessarily
 // imply global rejection. Per-suite Bonferroni is intentionally avoided
 // because it would be inconsistent with the global criterion (per-suite
 // threshold = α/n_pairs is more lenient than α/m_total).
 int reject = 0;
 for (size_t k = pv_start; k < g_all_pvalues.size(); k++)
 if (g_all_pvalues[k] < BONFERRONI_ALPHA) reject++;

 bool pass = (reject == 0)
 && (min_ham > HAMMING_LOWER) && (max_ham < HAMMING_UPPER)
 && (min_ent >= ENTROPY_MIN)
 && (!nan_seen);
 g_suites++;
 if (pass) g_pass_suites++;

 std::printf(" %s: %d pairs, max|r|=%.6f, mean|r|=%.6f (exp=%.6f)\n",
 label, n_pairs, max_r, sum_r / n_pairs, expected_mean_r);
 std::printf(" Hamming: [%.3f%%, %.3f%%], min(ent)=%.6f, min(p)=%.4e, %d raw-rej → %s\n",
 min_ham, max_ham, min_ent, min_p, reject, pass ? "PASS" : "FAIL");
}

// ── Adjacent-K helper for one engine ──
void adjacent_k_engine(const char* dim_label,
 int64_t n_bytes,
 // factory: generates n_bytes into buf at given K
 void (*gen_fn)(uint64_t seed, double K, uint8_t* buf, int64_t n)) {
 double bases[] = {2.0, 12.0};
 const size_t n_bases = sizeof(bases) / sizeof(bases[0]);
 double deltas[] = {-5.0, -1.0, -0.1, -0.01, -0.001, 0.001, 0.01, 0.1, 1.0, 5.0};
 const size_t n_d = sizeof(deltas) / sizeof(deltas[0]);

 // Track suite-level rejections (separate from test_pairwise's accounting).
 size_t pv_start = g_all_pvalues.size();

 // Pre-allocate the perturbation buffer once and reuse across iterations
 // (was reallocated 9-10 times per base previously). Saves ~60 alloc/free
 // pairs of 1 MB each across the 3 engines.
 std::vector<uint8_t> d_base((size_t)n_bytes);
 std::vector<uint8_t> d2((size_t)n_bytes);

 for (size_t b = 0; b < n_bases; b++) {
 double base_k = bases[b];
 std::printf(" %s Adjacent-K (base=%.1f):\n", dim_label, base_k);
 std::printf(" delta K_b |r| p-value ham%%\n");
 std::printf(" %s\n", std::string(56, '-').c_str());

 gen_fn(SEEDS[0], base_k, d_base.data(), n_bytes);

 for (size_t d = 0; d < n_d; d++) {
 double k2 = base_k + deltas[d];
 if (k2 < ADJACENT_K_MIN) continue; // skip invalid K

 gen_fn(SEEDS[0], k2, d2.data(), n_bytes);

 double r = std::abs(pearson_r(d_base.data(), d2.data(), n_bytes));
 double pv = pvalue_from_r(r, n_bytes);
 double ham = hamming_pct(d_base.data(), d2.data(), n_bytes);
 // Defend against NaN from a hypothetical zero-variance stream:
 // push a sentinel rejection rather than letting NaN silently bypass
 // the < / > comparisons in the global Bonferroni count.
 if (!std::isfinite(r) || !std::isfinite(pv)) {
 g_all_pvalues.push_back(0.0);
 std::printf(" %+8.3f %-8.3f NaN NaN NaN (degenerate stream!)\n",
 deltas[d], k2);
 continue;
 }
 g_all_pvalues.push_back(pv);

 std::printf(" %+8.3f %-8.3f %.6f %.4e %.3f%%\n",
 deltas[d], k2, r, pv, ham);
 }
 std::printf("\n");
 }

 // Suite-level early-warning summary across all bases for this engine
 // (uses RAW α, not Bonferroni-corrected — global Bonferroni at end of
 // main() is the authoritative test).
 size_t n_pushed = g_all_pvalues.size() - pv_start;
 if (n_pushed > 0) {
 int reject = 0;
 double min_p = 1.0;
 for (size_t k = pv_start; k < g_all_pvalues.size(); k++) {
 if (g_all_pvalues[k] < BONFERRONI_ALPHA) reject++;
 if (g_all_pvalues[k] < min_p) min_p = g_all_pvalues[k];
 }
 bool pass = (reject == 0);
 g_suites++;
 if (pass) g_pass_suites++;
 std::printf(" %s Adjacent-K summary: %zu pairs, min(p)=%.4e, %d raw-rej → %s\n\n",
 dim_label, n_pushed, min_p, reject, pass ? "PASS" : "FAIL");
 }
}

int main() {
 auto t_start = std::chrono::steady_clock::now();

 std::printf("\n******************************************************************************\n");
 std::printf(" MCL K-INDEPENDENCE v%s — K-Independence Verification\n", DOC_VERSION);
 std::printf(" Different K with fixed topology → independent streams\n");
 std::printf("******************************************************************************\n\n");

 const int64_t N_BYTES = K_INDEP_BYTES;

 // ========================================================================
 // TEST 1: T2 WIDE-K
 // ========================================================================
 sep("T2 K-INDEPENDENCE (wide K range)");

 struct T2T { int64_t p, q; };
 T2T t2t[] = {{2,3}, {3,5}, {5,7}};

 for (auto& tp : t2t) {
 for (int s = 0; s < N_SEEDS; s++) {
 std::vector<std::vector<uint8_t>> channels((size_t)N_K_WIDE);
 for (int k = 0; k < N_K_WIDE; k++) {
 channels[(size_t)k].resize((size_t)N_BYTES);
 MCL_T2 gen(SEEDS[s], tp.p, tp.q, K_WIDE[k]);
 gen.gen_bytes(channels[(size_t)k].data(), N_BYTES);
 }
 char label[64];
 std::snprintf(label, sizeof(label), "T2(%lld,%lld) s#%d",
 (long long)tp.p, (long long)tp.q, s+1);
 test_pairwise(channels, K_WIDE, N_K_WIDE, N_BYTES, label, s == 0);
 }
 }

 // ========================================================================
 // TEST 2: T2 CLOSE-K STRESS
 // ========================================================================
 sep("T2 CLOSE-K STRESS TEST (K=10..15)");
 {
 std::vector<std::vector<uint8_t>> channels((size_t)N_K_CLOSE);
 for (int k = 0; k < N_K_CLOSE; k++) {
 channels[(size_t)k].resize((size_t)N_BYTES);
 MCL_T2 gen(SEEDS[0], 3, 5, K_CLOSE[k]);
 gen.gen_bytes(channels[(size_t)k].data(), N_BYTES);
 }
 test_pairwise(channels, K_CLOSE, N_K_CLOSE, N_BYTES, "T2(3,5) close-K", true);
 }

 // ========================================================================
 // TEST 3-4: T3
 // ========================================================================
 sep("T3 K-INDEPENDENCE (wide K range)");

 // Test the first N_T3_TRIPLES_TESTED entries from t3_triples(). The full
 // table has more triples available but 2 is sufficient to demonstrate that
 // K-independence holds across distinct triple selections; adding more
 // triples here would dilute time on T2/T4 coverage with diminishing returns.
 const int N_T3_TRIPLES_TESTED = 2;
 const CouplingTriple* t3t = t3_triples();
 for (int t = 0; t < N_T3_TRIPLES_TESTED; t++) {
 for (int s = 0; s < N_SEEDS; s++) {
 std::vector<std::vector<uint8_t>> channels((size_t)N_K_WIDE);
 for (int k = 0; k < N_K_WIDE; k++) {
 channels[(size_t)k].resize((size_t)N_BYTES);
 MCL_T3 gen(SEEDS[s], t3t[t], K_WIDE[k]);
 gen.gen_bytes(channels[(size_t)k].data(), N_BYTES);
 }
 char label[64];
 std::snprintf(label, sizeof(label), "T3-triple%d s#%d", t, s+1);
 test_pairwise(channels, K_WIDE, N_K_WIDE, N_BYTES, label, s == 0 && t == 0);
 }
 }

 sep("T3 CLOSE-K STRESS TEST");
 {
 std::vector<std::vector<uint8_t>> channels((size_t)N_K_CLOSE);
 for (int k = 0; k < N_K_CLOSE; k++) {
 channels[(size_t)k].resize((size_t)N_BYTES);
 MCL_T3 gen(SEEDS[0], t3t[0], K_CLOSE[k]);
 gen.gen_bytes(channels[(size_t)k].data(), N_BYTES);
 }
 test_pairwise(channels, K_CLOSE, N_K_CLOSE, N_BYTES, "T3-triple0 close-K", true);
 }

 // ========================================================================
 // TEST 5-6: T4
 // ========================================================================
 sep("T4 K-INDEPENDENCE (wide K range)");

 const CouplingSextet* t4s = t4_sextets();
 for (int s = 0; s < N_SEEDS; s++) {
 std::vector<std::vector<uint8_t>> channels((size_t)N_K_WIDE);
 for (int k = 0; k < N_K_WIDE; k++) {
 channels[(size_t)k].resize((size_t)N_BYTES);
 MCL_T4 gen(SEEDS[s], t4s[0], K_WIDE[k]);
 gen.gen_bytes(channels[(size_t)k].data(), N_BYTES);
 }
 char label[64];
 std::snprintf(label, sizeof(label), "T4-sextet0 s#%d", s+1);
 test_pairwise(channels, K_WIDE, N_K_WIDE, N_BYTES, label, s == 0);
 }

 sep("T4 CLOSE-K STRESS TEST");
 {
 std::vector<std::vector<uint8_t>> channels((size_t)N_K_CLOSE);
 for (int k = 0; k < N_K_CLOSE; k++) {
 channels[(size_t)k].resize((size_t)N_BYTES);
 MCL_T4 gen(SEEDS[0], t4s[0], K_CLOSE[k]);
 gen.gen_bytes(channels[(size_t)k].data(), N_BYTES);
 }
 test_pairwise(channels, K_CLOSE, N_K_CLOSE, N_BYTES, "T4-sextet0 close-K", true);
 }

 // ========================================================================
 // TEST 7: ADJACENT-K (T2 + T3 + T4, ±deltas)
 // ========================================================================
 sep("ADJACENT-K TEST (T2, T3, T4 — delta ±0.001..±5.0)");

 // T2 — uses (3,5) primary topology to match the rest of this file.
 // (Earlier code had label "T2(2,3)" but generated (3,5) data — a label
 // bug. Fixed by aligning label and implementation.)
 adjacent_k_engine("T2(3,5)", N_BYTES,
 [](uint64_t seed, double K, uint8_t* buf, int64_t n) {
 MCL_T2 g(seed, 3, 5, K); g.gen_bytes(buf, n); });

 // T3 — references the actual core table at runtime, so any update to
 // t3_triples()[0] in mcl_core.hpp is automatically picked up (no drift).
 adjacent_k_engine("T3-triple0", N_BYTES,
 [](uint64_t seed, double K, uint8_t* buf, int64_t n) {
 MCL_T3 g(seed, t3_triples()[0], K); g.gen_bytes(buf, n); });

 // T4 — same drift-resistant pattern as T3 above.
 adjacent_k_engine("T4-sextet0", N_BYTES,
 [](uint64_t seed, double K, uint8_t* buf, int64_t n) {
 MCL_T4 g(seed, t4_sextets()[0], K); g.gen_bytes(buf, n); });

 // ========================================================================
 // TEST 8: CROSS-DIMENSION
 // ========================================================================
 sep("CROSS-DIMENSION: same K across T2/T3/T4");

 double cross_ks[] = {1.0, 5.0, 8.0, 12.0, 20.0};
 const size_t n_ck = sizeof(cross_ks) / sizeof(cross_ks[0]);
 size_t cross_pv_start = g_all_pvalues.size();
 double cross_max_r = 0;

 for (int s = 0; s < N_SEEDS; s++) {
 std::printf(" Seed #%d:\n", s + 1);
 std::printf(" K        T2vsT3|r|  T2vsT4|r|  T3vsT4|r|  min(p)\n");
 std::printf(" %s\n", std::string(60, '-').c_str());

 for (size_t ki = 0; ki < n_ck; ki++) {
 double k = cross_ks[ki];
 std::vector<uint8_t> d2((size_t)N_BYTES), d3((size_t)N_BYTES), d4((size_t)N_BYTES);

 MCL_T2 g2(SEEDS[s], 3, 5, k);
 MCL_T3 g3(SEEDS[s], t3t[0], k);
 MCL_T4 g4(SEEDS[s], t4s[0], k);
 g2.gen_bytes(d2.data(), N_BYTES);
 g3.gen_bytes(d3.data(), N_BYTES);
 g4.gen_bytes(d4.data(), N_BYTES);

 double r23 = std::abs(pearson_r(d2.data(), d3.data(), N_BYTES));
 double r24 = std::abs(pearson_r(d2.data(), d4.data(), N_BYTES));
 double r34 = std::abs(pearson_r(d3.data(), d4.data(), N_BYTES));
 double pv23 = pvalue_from_r(r23, N_BYTES);
 double pv24 = pvalue_from_r(r24, N_BYTES);
 double pv34 = pvalue_from_r(r34, N_BYTES);
 double min_p_row = std::min({pv23, pv24, pv34});

 // Defensive NaN guard: replace any non-finite p-value with 0.0
 // (a sentinel rejection) so the global Bonferroni count cannot
 // silently miss a degenerate cross-engine stream.
 g_all_pvalues.push_back(std::isfinite(pv23) ? pv23 : 0.0);
 g_all_pvalues.push_back(std::isfinite(pv24) ? pv24 : 0.0);
 g_all_pvalues.push_back(std::isfinite(pv34) ? pv34 : 0.0);
 if (r23 > cross_max_r) cross_max_r = r23;
 if (r24 > cross_max_r) cross_max_r = r24;
 if (r34 > cross_max_r) cross_max_r = r34;

 std::printf(" %-7.1f  %.6f   %.6f   %.6f   %.4e\n",
 k, r23, r24, r34, min_p_row);
 }
 std::printf("\n");
 }

 // Suite-level early-warning summary for cross-dimension test
 // (raw α; authoritative test is global Bonferroni below).
 {
 size_t n_pushed = g_all_pvalues.size() - cross_pv_start;
 int reject = 0;
 double min_p = 1.0;
 for (size_t k = cross_pv_start; k < g_all_pvalues.size(); k++) {
 if (g_all_pvalues[k] < BONFERRONI_ALPHA) reject++;
 if (g_all_pvalues[k] < min_p) min_p = g_all_pvalues[k];
 }
 bool pass = (reject == 0);
 g_suites++;
 if (pass) g_pass_suites++;
 std::printf(" Cross-dim summary: %zu pairs, max|r|=%.6f, min(p)=%.4e, %d raw-rej → %s\n",
 n_pushed, cross_max_r, min_p, reject, pass ? "PASS" : "FAIL");
 }

 // ========================================================================
 // TEST 9: NEGATIVE CONTROL (Rule D4)
 // ========================================================================
 sep("NEGATIVE CONTROL — same K must correlate");

 bool neg_pass = true;
 double neg_ks[] = {2.0, 12.0, 50.0};
 for (double k : neg_ks) {
 std::vector<uint8_t> a((size_t)N_BYTES), b((size_t)N_BYTES);
 MCL_T2 ga(SEEDS[0], 3, 5, k);
 MCL_T2 gb(SEEDS[0], 3, 5, k);
 ga.gen_bytes(a.data(), N_BYTES);
 gb.gen_bytes(b.data(), N_BYTES);

 double r = pearson_r(a.data(), b.data(), N_BYTES);
 // diff is int64_t to remain correct if N_BYTES is ever bumped above 2 GB.
 int64_t diff = 0;
 for (int64_t i = 0; i < N_BYTES; i++)
 if (a[(size_t)i] != b[(size_t)i]) diff++;

 // Negative control demands: identical params → identical streams. Either
 // r being non-finite (degenerate) or diff != 0 means determinism broke.
 bool ok = std::isfinite(r) && (r > 0.999) && (diff == 0);
 if (!ok) neg_pass = false;
 std::printf(" K=%-5.1f r=%.6f diff=%lld %s\n", k, r, (long long)diff,
 ok ? "OK — identical" : "BROKEN!");
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
 std::printf(" Bonferroni threshold: %.4e / %d = %.4e\n",
 BONFERRONI_ALPHA, m_total, bonf_threshold);
 std::printf(" Bonferroni rejections: %d / %d  (authoritative)\n", n_reject, m_total);
 std::printf(" Suite raw-α checks:    %d / %d PASS  (early-warning, not Bonferroni)\n",
 g_pass_suites, g_suites);
 std::printf(" Negative control:      %s\n", neg_pass ? "PASS" : "FAIL");

 std::printf("\n Smallest 5 p-values:\n");
 for (int i = 0; i < 5 && i < m_total; i++)
 std::printf(" #%d: %.6e %s\n", i + 1, g_all_pvalues[(size_t)i],
 g_all_pvalues[(size_t)i] < bonf_threshold ? "< REJECT" : ">= OK");

 // ========================================================================
 // VERDICT
 // ========================================================================
 double elapsed = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t_start).count();

 bool gp = (n_reject == 0 && neg_pass);

 sep("VERDICT");
 std::printf(" K-independence across T2, T3, T4: %d pairs tested\n", m_total);
 std::printf(" Rejections: %d\n", n_reject);
 std::printf(" Negative control: %s\n", neg_pass ? "PASS" : "FAIL");

 std::printf("\n +================================================================+\n");
 std::printf(" | VERDICT: %s |\n",
 gp ? "PASS — K-independence verified (all engines) "
 : "FAIL — K-dependence detected ");
 std::printf(" +================================================================+\n");

 std::printf("\n Time: %.1f seconds\n", elapsed);
 std::printf("\n %s v%s | Madeeh Ibrahim, Cairo\n", DOC_ID, DOC_VERSION);
 std::printf("==============================================================================\n");

 return gp ? 0 : 1;
}
