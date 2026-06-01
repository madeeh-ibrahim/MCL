/*
 * ============================================================================
 * MCL Generality Experiment — Multi-System Verification
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-GENERALITY-2026-0526-001
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
 * PURPOSE: Verify that the MCL coupling principle generalizes beyond
 *          phase oscillators. Tests three fundamentally different chaotic
 *          systems — Henon (strange attractor), Logistic (interval map),
 *          Tent (piecewise linear) — all using the same MCL framework.
 *
 * TESTS:
 *   - "coupled chaotic dynamical system" is system-agnostic
 *   - 3 systems × 6 topologies × 3 seeds × C(6,2) = 135 pairs (per-system)
 *   - Cross-system: 3 topologies × C(3,2) = 9 pairs (total: 144)
 *   - Per-channel quality (entropy, chi-square) reported separately
 *   - Negative control: identical params → |r| = 1.0
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_generality mcl_generality.cpp -lm && ./mcl_generality
 *
 * EXPECTED RESULTS: (with default constants):
 *   144 independence pairs:  0 Bonferroni rejections
 *   Cross-system (9 pairs):  0 rejections
 *   Negative control:        3/3 systems PASS
 *   VERDICT:                 PASS
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
#include <algorithm>
#include <functional>

// Document metadata (mirror of file header — keep in sync)
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-GENERALITY-2026-0526-001";

// Per-channel byte budget. 1M bytes gives noise floor expected |r| ≈ 7.98e-4.
static constexpr int64_t GENERALITY_BYTES = 1000000;

// Entropy floor for non-oscillator systems. Set at 7.99 (not 7.999) because
// Henon/Logistic/Tent have different invariant measures; their byte streams
// are slightly less uniform than MCL_T2 phase output. Independence is the
// PRIMARY verification target — quality is reported separately and does not affect the
// pass criterion (the comment block above explains the rationale).
static constexpr double GENERALITY_ENTROPY_MIN = 7.99;

static std::vector<double> g_all_pvalues;

// 6 topologies for testing
static const Topology TOPOS[] = {
 {2,3},{3,5},{5,7},{7,11},{8,13},{11,17}
};
static constexpr int N_TOPOS = sizeof(TOPOS) / sizeof(TOPOS[0]);

static const uint64_t SEEDS[] = {
 12345678901234ULL, 98765432109876ULL, 31415926535897ULL
};
static constexpr int N_SEEDS = sizeof(SEEDS) / sizeof(SEEDS[0]);

// Quality counters (informational only — does NOT affect the verdict).
// Tracking total + low-quality channel COUNTS (not a sticky bool) gives
// readers a rate they can interpret instead of a binary "did anything ever
// trip" that pollutes the report once a single channel was suboptimal.
static int g_quality_total = 0;
static int g_quality_low   = 0;

// ── Generic system test ──
// factory(seed, p, q, buf, n) → fills buf with n bytes, returns ok
using GenFactory = std::function<bool(uint64_t, int64_t, int64_t, uint8_t*, int64_t)>;

void test_system(GenFactory factory, const char* name, int64_t n_bytes) {
 sep(name);
 std::printf(" %d topologies x %d seeds x C(%d,2)=%d pairs = %d tests\n",
 N_TOPOS, N_SEEDS, N_TOPOS, N_TOPOS*(N_TOPOS-1)/2,
 N_SEEDS * N_TOPOS*(N_TOPOS-1)/2);
 std::printf(" Bytes per channel: %lld\n\n", (long long)n_bytes);

 int sys_pairs = 0, sys_raw_reject = 0, sys_diverged = 0, sys_nan = 0;
 size_t pv_start = g_all_pvalues.size(); // track THIS system's start
 double max_abs_r = 0;

 for (int s = 0; s < N_SEEDS; s++) {
 std::printf(" --- Seed #%d ---\n", s + 1);

 // Generate channels
 std::vector<std::vector<uint8_t>> channels((size_t)N_TOPOS);
 std::vector<bool> valid((size_t)N_TOPOS, false);

 for (int t = 0; t < N_TOPOS; t++) {
 channels[(size_t)t].resize((size_t)n_bytes);
 valid[(size_t)t] = factory(SEEDS[s], TOPOS[t].p, TOPOS[t].q,
 channels[(size_t)t].data(), n_bytes);
 if (!valid[(size_t)t]) {
 sys_diverged++;
 std::printf(" (%lld,%lld): DIVERGED — skipped\n",
 (long long)TOPOS[t].p, (long long)TOPOS[t].q);
 }
 }

 // Per-channel quality (informational; does not affect pass criterion).
 // Threshold relaxed to 7.99 because non-oscillator systems (Henon,
 // Logistic, Tent) have different invariant measures than MCL_T2 phase
 // output. Independence is the primary verification target; quality is reported
 // separately and DOES NOT affect the verdict.
 for (int t = 0; t < N_TOPOS; t++) {
 if (!valid[(size_t)t]) continue;
 double ent = shannon_entropy(channels[(size_t)t].data(), n_bytes);
 double chi = chi_square(channels[(size_t)t].data(), n_bytes);
 bool q_pass = (ent > GENERALITY_ENTROPY_MIN) && (chi < CHI2_THRESHOLD);
 g_quality_total++;
 if (!q_pass) g_quality_low++;
 if (s == 0) // print only first seed to save space
 std::printf(" (%lld,%lld): ent=%.4f chi2=%.1f %s\n",
 (long long)TOPOS[t].p, (long long)TOPOS[t].q,
 ent, chi, q_pass ? "OK" : "LOW");
 }

 // Pairwise independence
 for (int i = 0; i < N_TOPOS; i++) {
 if (!valid[(size_t)i]) continue;
 for (int j = i + 1; j < N_TOPOS; j++) {
 if (!valid[(size_t)j]) continue;
 double r = pearson_r(channels[(size_t)i].data(),
 channels[(size_t)j].data(), n_bytes);
 double abs_r = std::abs(r);
 double pv = pvalue_from_r(abs_r, n_bytes);
 // Defensive NaN guard: a zero-variance (constant) stream would
 // produce NaN, which silently bypasses < / > comparisons. Push a
 // sentinel rejection so global Bonferroni count remains correct.
 if (!std::isfinite(abs_r) || !std::isfinite(pv)) {
 g_all_pvalues.push_back(0.0);
 sys_nan++;
 sys_pairs++;
 continue;
 }
 g_all_pvalues.push_back(pv);
 sys_pairs++;
 if (abs_r > max_abs_r) max_abs_r = abs_r;
 }
 }
 }

 // Per-system EARLY-WARNING using RAW α (not Bonferroni-corrected). The
 // authoritative test is the GLOBAL Bonferroni at the end of main(). This
 // avoids the per-suite-vs-global inconsistency that arises if α/sys_pairs
 // is used (per-system threshold is more lenient than α/m_total).
 for (size_t k = pv_start; k < g_all_pvalues.size(); k++)
 if (g_all_pvalues[k] < BONFERRONI_ALPHA) sys_raw_reject++;

 std::printf("\n %s: %d pairs tested, %d raw-α rejections (early-warning)\n",
 name, sys_pairs, sys_raw_reject);
 std::printf(" Max |r| across all pairs: %.6f\n", max_abs_r);
 if (sys_diverged > 0)
 std::printf(" Note: %d topology runs diverged and were skipped\n", sys_diverged);
 if (sys_nan > 0)
 std::printf(" Note: %d pairs produced non-finite r (degenerate stream!)\n", sys_nan);
}

int main() {
 auto t_start = std::chrono::steady_clock::now();

 std::printf("\n******************************************************************************\n");
 std::printf(" MCL GENERALITY — MULTI-SYSTEM VERIFICATION v%s\n", DOC_VERSION);
 std::printf(" Henon + Logistic + Tent: Proving system-agnostic independence\n");
 std::printf("******************************************************************************\n\n");

 const int64_t N_BYTES = GENERALITY_BYTES;

 // ========================================================================
 // SINGLE SOURCE OF TRUTH for the three coupled systems under test.
 // Declared once and reused by:
 //   (a) per-system pairwise tests (test_system for SYSTEM 1, 2, 3)
 //   (b) cross-system independence  (Henon vs Logistic vs Tent)
 //   (c) negative control            (same params → identical streams)
 // Adding a fourth system only requires extending this array; all three
 // phases pick it up automatically (no magic numbers, no parallel arrays).
 // ========================================================================
 struct SysGen {
 const char* name;
 const char* description;
 GenFactory factory;
 };
 const SysGen systems[] = {
 {"Henon",    "strange attractor, discrete, 2D",
 [](uint64_t s, int64_t p, int64_t q, uint8_t* b, int64_t n) -> bool {
 CoupledHenon g(s, p, q); g.gen_bytes(b, n); return g.ok(); }},
 {"Logistic", "interval map, 1D, r=3.99",
 [](uint64_t s, int64_t p, int64_t q, uint8_t* b, int64_t n) -> bool {
 CoupledLogistic g(s, p, q); g.gen_bytes(b, n); return true; }},
 {"Tent",     "piecewise linear, 1D",
 [](uint64_t s, int64_t p, int64_t q, uint8_t* b, int64_t n) -> bool {
 CoupledTent g(s, p, q); g.gen_bytes(b, n); return true; }},
 };
 const size_t n_systems = sizeof(systems) / sizeof(systems[0]);

 // ========================================================================
 // PHASE A: Per-system pairwise independence
 // ========================================================================
 for (size_t s = 0; s < n_systems; s++) {
 char title[96];
 std::snprintf(title, sizeof(title),
 "SYSTEM %zu: COUPLED %s — %s",
 s + 1, systems[s].name, systems[s].description);
 test_system(systems[s].factory, title, N_BYTES);
 }

 // ========================================================================
 // PHASE B: CROSS-SYSTEM INDEPENDENCE (Henon ch vs Logistic ch vs Tent ch)
 // ========================================================================
 sep("CROSS-SYSTEM INDEPENDENCE");
 std::printf(" Testing if channels from DIFFERENT systems are independent.\n\n");

 int cross_pairs = 0;
 size_t cross_pv_start = g_all_pvalues.size();
 double cross_max_r = 0;

 // Cross-system topology subset spanning the (p,q) range:
 //   (2,3)   — smallest topology
 //   (3,5)   — middle topology
 //   (7,11)  — larger topology
 // These three sample low/medium/high coprime densities. Testing all 6
 // would triple the runtime without adding evidence — three is sufficient
 // to verify independence holds across DIFFERENT generators (which is the
 // point of the cross-system phase).
 const Topology cross_topos[] = {{2,3}, {3,5}, {7,11}};
 const size_t n_cross_topos = sizeof(cross_topos) / sizeof(cross_topos[0]);
 // Use SEEDS[0] (consistent with the per-system tests) rather than
 // DEFAULT_SEED — single seed source across the file.
 const uint64_t cross_seed = SEEDS[0];

 for (size_t tk = 0; tk < n_cross_topos; tk++) {
 Topology tp = cross_topos[tk];
 for (size_t i = 0; i < n_systems; i++) {
 for (size_t j = i + 1; j < n_systems; j++) {
 std::vector<uint8_t> a((size_t)N_BYTES), b((size_t)N_BYTES);
 bool ok_a = systems[i].factory(cross_seed, tp.p, tp.q, a.data(), N_BYTES);
 bool ok_b = systems[j].factory(cross_seed, tp.p, tp.q, b.data(), N_BYTES);
 if (!ok_a || !ok_b) {
 std::printf(" %s vs %s (%lld,%lld): DIVERGED\n",
 systems[i].name, systems[j].name,
 (long long)tp.p, (long long)tp.q);
 continue;
 }
 double r = pearson_r(a.data(), b.data(), N_BYTES);
 double abs_r = std::abs(r);
 double pv = pvalue_from_r(abs_r, N_BYTES);
 // NaN guard — push sentinel rejection if degenerate stream
 if (!std::isfinite(abs_r) || !std::isfinite(pv)) {
 g_all_pvalues.push_back(0.0);
 cross_pairs++;
 std::printf(" %s vs %s (%lld,%lld): NaN (degenerate stream!)\n",
 systems[i].name, systems[j].name,
 (long long)tp.p, (long long)tp.q);
 continue;
 }
 g_all_pvalues.push_back(pv);
 cross_pairs++;
 if (abs_r > cross_max_r) cross_max_r = abs_r;
 std::printf(" %s vs %s (%lld,%lld): |r|=%.6f p=%.4e\n",
 systems[i].name, systems[j].name,
 (long long)tp.p, (long long)tp.q,
 abs_r, pv);
 }
 }
 }

 // Cross-system raw-α early-warning summary
 {
 size_t n_pushed = g_all_pvalues.size() - cross_pv_start;
 int reject = 0;
 double min_p = 1.0;
 for (size_t k = cross_pv_start; k < g_all_pvalues.size(); k++) {
 if (g_all_pvalues[k] < BONFERRONI_ALPHA) reject++;
 if (g_all_pvalues[k] < min_p) min_p = g_all_pvalues[k];
 }
 std::printf("\n Cross-system summary: %zu pairs, max|r|=%.6f, "
 "min(p)=%.4e, %d raw-α rej (early-warning)\n",
 n_pushed, cross_max_r, min_p, reject);
 }

 // ========================================================================
 // PHASE C: NEGATIVE CONTROL (Rule D4)
 // ========================================================================
 sep("NEGATIVE CONTROL — identical parameters must correlate");
 std::printf(" Same system + same (p,q) + same seed → |r| MUST = 1.0\n\n");

 int neg_tested = 0, neg_passed = 0, neg_diverged = 0;

 for (size_t sys = 0; sys < n_systems; sys++) {
 std::vector<uint8_t> d1((size_t)N_BYTES), d2((size_t)N_BYTES);
 bool ok1 = systems[sys].factory(SEEDS[0], 2, 3, d1.data(), N_BYTES);
 bool ok2 = systems[sys].factory(SEEDS[0], 2, 3, d2.data(), N_BYTES);

 if (!ok1 || !ok2) {
 // Divergence isn't a determinism failure (the engine couldn't even
 // run), but we record it so the verdict can flag incomplete coverage.
 neg_diverged++;
 std::printf(" %-10s DIVERGED (skipped)\n", systems[sys].name);
 continue;
 }

 double r = pearson_r(d1.data(), d2.data(), N_BYTES);
 // diff is int64_t to remain correct if N_BYTES is bumped above 2 GB.
 int64_t diff = 0;
 for (int64_t i = 0; i < N_BYTES; i++)
 if (d1[(size_t)i] != d2[(size_t)i]) diff++;

 // Demand identity: finite r ≈ 1 AND zero byte-level differences.
 bool ok = std::isfinite(r) && (r > 0.999) && (diff == 0);
 neg_tested++;
 if (ok) neg_passed++;

 std::printf(" %-10s r=%.6f diff=%lld/%lld %s\n",
 systems[sys].name, r, (long long)diff, (long long)N_BYTES,
 ok ? "OK — identical" : "BROKEN!");
 }
 // If any system diverged, the negative-control coverage is incomplete.
 // Flag this so the reader knows not all systems were exercised — even
 // though the verdict's neg_pass flag only fires on actual mismatch.
 if (neg_diverged > 0) {
 std::printf("\n  WARNING: %d/%zu systems diverged — coverage incomplete\n",
 neg_diverged, n_systems);
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

 std::printf(" Total pairs: %d (3 systems + cross-system)\n", m_total);
 std::printf(" Bonferroni threshold: %.4e / %d = %.4e\n",
 BONFERRONI_ALPHA, m_total, bonf_threshold);
 std::printf(" Bonferroni rejections: %d / %d  (authoritative)\n", n_reject, m_total);

 std::printf("\n Smallest 5 p-values:\n");
 for (int i = 0; i < 5 && i < m_total; i++)
 std::printf(" #%d: %.6e %s\n", i + 1, g_all_pvalues[(size_t)i],
 g_all_pvalues[(size_t)i] < bonf_threshold ? "< REJECT" : ">= OK");

 // PASS criterion: zero Bonferroni rejections AND every system was both
 // tested AND passed its negative control. The earlier `neg_pass` flag
 // alone is not sufficient — if every system diverged, neg_pass would
 // remain at its initial `true` value despite zero actual tests, which
 // is a silent-PASS hazard.
 bool gp = (n_reject == 0
            && m_total > 0
            && neg_passed == (int)n_systems);

 // ========================================================================
 // VERDICT
 // ========================================================================
 double elapsed = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t_start).count();

 sep("VERDICT");

 // Dynamic system list — no hardcoding. If a fourth system is added to
 // systems[], it appears here automatically.
 std::printf(" Systems tested: ");
 for (size_t i = 0; i < n_systems; i++)
 std::printf("%s%s", systems[i].name, i + 1 < n_systems ? ", " : "\n");

 std::printf(" Independence pairs: %d (%d Bonferroni rejections)\n", m_total, n_reject);
 std::printf(" Cross-system pairs: %d\n", cross_pairs);
 std::printf(" Negative control: %d/%d systems passed%s\n",
 neg_passed, neg_tested,
 neg_diverged > 0 ? " (some diverged)" : "");
 if (g_quality_total > 0) {
 std::printf(" Per-channel quality: %d/%d channels OK%s\n",
 g_quality_total - g_quality_low, g_quality_total,
 g_quality_low > 0 ? " (some LOW — expected for non-oscillator systems)"
 : "");
 }

 // Dynamic verdict message — uses n_systems, not a hardcoded count.
 char verdict_msg[80];
 if (gp) {
 std::snprintf(verdict_msg, sizeof(verdict_msg),
 "PASS — MCL principle generalizes to %zu systems",
 n_systems);
 } else {
 std::snprintf(verdict_msg, sizeof(verdict_msg),
 "FAIL — independence not established");
 }

 std::printf("\n +================================================================+\n");
 std::printf(" | VERDICT: %-54s |\n", verdict_msg);
 std::printf(" +================================================================+\n");

 std::printf("\n Time: %.1f seconds\n", elapsed);
 std::printf("\n %s v%s | Madeeh Ibrahim, Cairo\n", DOC_ID, DOC_VERSION);
 std::printf("==============================================================================\n");

 return gp ? 0 : 1;
}
