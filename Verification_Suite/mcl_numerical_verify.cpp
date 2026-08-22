/*
 * ============================================================================
 * MCL Numerical Reference Verification
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-NUM-VERIFY-2026-0526-001
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
 * PURPOSE: Empirically verify four numerical reference values that appear
 *          in the MCL technical specifications. Each value is checked
 *          against an explicit threshold that bounds the reported number.
 *
 *   - r ≈ 0.005 at 500,000 bytes — channel vs multiplex correlation
 *   - r ≈ 0.005 at 500,000 bytes — same-ratio pair correlation
 *   - N ≥ 3,000,000 recommendation for production
 *   - σ ≈ 0.03 bits/byte — windowed entropy std deviation at hop boundary
 *
 * EXPERIMENT A — Multiplex + Same-Ratio
 *   For N ∈ {500K, 1M, 3M, 10M}:
 *     Generate 20 T2 channels + XOR multiplex
 *     Measure max|r| between each channel and multiplex
 *     Measure |r| between (4,6) and (6,9) — same-ratio pair
 *     Report noise_floor = 1/√N for reference
 *
 * EXPERIMENT B — Hop Boundary Invisibility
 *   Generate 200,000 bytes, hop (3,5)→(7,11) at byte 100,000
 *   Sliding window entropy: W=500, step S=100
 *   Report: mean_pre, mean_post, max_diff, σ_measured
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_numerical_verify mcl_numerical_verify.cpp -lm && ./mcl_numerical_verify
 *
 * EXPECTED RESULTS:
 *   max|r| < 0.0075 at 500K     (measured ~0.003, well under bound)
 *   same-ratio |r| < 0.0075     (measured ~0.002, well under bound)
 *   σ ≈ 0.03 ± 0.01 bits/byte   (measured ~0.035, within tolerance)
 *   hop boundary invisible      (mean shift within 3σ)
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
#include <limits>     // for std::numeric_limits (used for ±infinity sentinels)

// Document metadata (mirror of file header — keep in sync)
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-NUM-VERIFY-2026-0526-001";

// Three distinct constant categories follow:
//
//   REF_*     — reference values reported in the MCL technical
//               specifications. Treated as immutable measurement targets;
//               changing them means the underlying reference document
//               changed. Naming "REF" (not "PATENT") is intentional —
//               these are reported numerical values, not legal claims.
//
//   VERIFY_*  — pass/fail criteria for the test harness. These are chosen
//               by the verification author (not by any external document)
//               and document how strictly each REF_* value is checked.
//               Their justification is empirical (FP variance, scientific
//               convention, observed measurement spread) — not a published
//               disclosure.
//
//   EVT_*     — derived from extreme-value theory; mathematical, not
//               from any single source.
//
// Documentation of each value:
//   REF_R                 — reported max|r| at 500K bytes (~0.005).
//   VERIFY_R_BOUND        — pass threshold for r checks: 1.5× the reference.
//                           Tight enough that a 50% degradation fails, loose
//                           enough to absorb FP variance across platforms.
//   REF_SIGMA             — reported windowed-entropy σ at hop boundary.
//   VERIFY_SIGMA_TOL      — tolerance for σ check. ±0.01 is ~33% relative,
//                           reflecting that the reported "σ ≈ 0.03" depends
//                           on window size W and is approximate by design.
//   VERIFY_BOUNDARY_K     — boundary invisibility expressed as k·σ multiple
//                           (3σ = standard statistical convention).
//   REF_MAX_DIFF          — reported |μ_pre − μ_post| value (bits/byte).
//   VERIFY_MAX_DIFF_BOUND — pass threshold for max_diff = 1.5× the reference.
//   EVT_RATIO_BOUND       — EVT bound on max|r|/noise_floor ratio. For 15
//                           pairs, theoretical EVT factor ≈ 2.33; 3.0 adds
//                           a small margin to absorb finite-N variance.

// --- Reference values (from the MCL technical specification) ----------
static constexpr double  REF_R               = 0.005;
static constexpr double  REF_SIGMA           = 0.03;
static constexpr double  REF_MAX_DIFF        = 0.067;
static constexpr int64_t REF_RECOMMENDED_N   = 3000000;

// --- Verification criteria (test author's choice) ---------------------
static constexpr double VERIFY_R_BOUND        = REF_R * 1.5;        // = 0.0075
static constexpr double VERIFY_SIGMA_TOL      = 0.01;               // ~33% relative
static constexpr double VERIFY_BOUNDARY_K     = 3.0;
static constexpr double VERIFY_MAX_DIFF_BOUND = REF_MAX_DIFF * 1.5; // = 0.1005

// --- Mathematical / theoretical ---------------------------------------
static constexpr double EVT_RATIO_BOUND       = 3.0;

// Display windows around the hop point for the per-window entropy printout.
static constexpr int HOP_DISPLAY_HALF = 10;

// Byte budget for the same-ratio multi-seed cross-check. Matches test_sizes[0]
// so the multi-seed pass-rate is comparable to the single-seed entry above.
static constexpr int64_t SAME_RATIO_N = 500000;

int main() {
 auto t_start = std::chrono::steady_clock::now();
 bool global_pass = true;

 std::printf("\n******************************************************************************\n");
 std::printf(" MCL NUMERICAL REFERENCE VERIFICATION v%s\n", DOC_VERSION);
 std::printf(" Multiplex invisibility, same-ratio independence, hop boundary σ\n");
 std::printf("******************************************************************************\n\n");

 // ========================================================================
 // EXPERIMENT A: MULTIPLEX + SAME-RATIO at multiple N
 //   Verifies the two r ≈ 0.005 reference values at 500K bytes
 // ========================================================================
 sep("EXPERIMENT A: Multiplex Channel Invisibility + Same-Ratio Independence");

 const Topology topos20[] = {
 {2,3},{3,5},{5,7},{7,11},{8,13},{11,17},{13,19},{17,23},
 {19,29},{23,31},{29,37},{31,41},{37,43},{41,47},{43,53},
 {47,59},{53,61},{59,67},{61,71},{67,73}
 };
 const int NCH = (int)(sizeof(topos20) / sizeof(topos20[0]));

 const int64_t test_sizes[] = {SAME_RATIO_N, 1000000, 3000000, 10000000};
 const int n_sizes = (int)(sizeof(test_sizes) / sizeof(test_sizes[0]));

 // Number of head/tail channels printed in the per-channel detail view.
 // Middle channels are summarised by a single "..." row.
 const int HEAD_PRINT = 5, TAIL_PRINT = 2;

 std::printf(" Channels: %d topologies, seed=%llu\n", NCH, (unsigned long long)DEFAULT_SEED);
 std::printf(" Same-ratio pair: (4,6) vs (6,9) — both ratio 2/3\n\n");

 std::printf(" %-12s %-14s %-14s %-14s %-14s\n",
 "N (bytes)", "noise_floor", "max|r|_mux", "|r|_same_ratio", "Ref check");
 std::printf(" %s\n", std::string(72, '-').c_str());

 // Only saved_max_mux is reused after the loop (in the SUMMARY); the rest
 // are scratch values printed once for the N=500K detail line.
 double saved_max_mux = 0;

 for (int si = 0; si < n_sizes; si++) {
 int64_t N = test_sizes[si];

 // Generate 20 channels
 std::vector<std::vector<uint8_t>> ch((size_t)NCH);
 for (int i = 0; i < NCH; i++) {
 ch[(size_t)i].resize((size_t)N);
 MCL_T2 gen(DEFAULT_SEED, topos20[i].p, topos20[i].q);
 gen.gen_bytes(ch[(size_t)i].data(), N);
 }

 // XOR multiplex
 std::vector<uint8_t> mux((size_t)N, 0);
 for (int k = 0; k < NCH; k++)
 for (int64_t i = 0; i < N; i++) mux[(size_t)i] ^= ch[(size_t)k][(size_t)i];

 // max|r| between each channel and multiplex
 double max_r_mux = 0, sum_r_mux = 0;
 int nan_seen = 0;
 for (int i = 0; i < NCH; i++) {
 double r = std::abs(pearson_r(ch[(size_t)i].data(), mux.data(), N));
 // Defensive NaN guard: zero-variance stream produces NaN, which
 // silently bypasses < / > comparisons. Flag it explicitly.
 if (!std::isfinite(r)) { nan_seen++; continue; }
 if (r > max_r_mux) max_r_mux = r;
 sum_r_mux += r;

 // Detailed per-channel output at N=500K
 if (si == 0) {
 if (i < HEAD_PRINT || i >= NCH - TAIL_PRINT)
 std::printf(" ch[%2d] (%lld,%lld): |r| = %.6f\n",
 i, (long long)topos20[i].p, (long long)topos20[i].q, r);
 else if (i == HEAD_PRINT)
 std::printf(" ... (%d channels) ...\n",
 NCH - HEAD_PRINT - TAIL_PRINT);
 }
 }
 if (nan_seen > 0)
 std::printf(" WARNING: %d channels produced non-finite r (degenerate)\n",
 nan_seen);

 // Save N=500K results for summary
 if (si == 0) {
 saved_max_mux = max_r_mux;
 const double mean_mux = sum_r_mux / std::max(1, NCH - nan_seen);
 const double nf500    = 1.0 / std::sqrt((double)N);
 // EVT factor for max of NCH samples ≈ √(2 ln NCH).
 // NCH derives from sizeof(topos20[]) — hardcoding 20 here would drift
 // silently if the topology array is resized.
 const double evt_nch = std::sqrt(2.0 * std::log((double)NCH)) * nf500;
 std::printf(" max|r| = %.6f, mean|r| = %.6f\n", saved_max_mux, mean_mux);
 std::printf(" noise_floor = %.6f, EVT(%dch) = %.6f\n\n",
 nf500, NCH, evt_nch);
 }

 // Same-ratio pair: (4,6) vs (6,9)
 std::vector<uint8_t> d46((size_t)N), d69((size_t)N);
 MCL_T2 g46(DEFAULT_SEED, 4, 6); g46.gen_bytes(d46.data(), N);
 MCL_T2 g69(DEFAULT_SEED, 6, 9); g69.gen_bytes(d69.data(), N);
 double r_same = std::abs(pearson_r(d46.data(), d69.data(), N));
 // NaN propagates through abs and fails the < check; explicit guard
 // for clearer failure reporting.
 if (!std::isfinite(r_same)) r_same = 1.0;  // sentinel: failure

 double nf = 1.0 / std::sqrt((double)N);

 std::printf(" %-12lld %-14.6f %-14.6f %-14.6f %s\n",
 (long long)N, nf, max_r_mux, r_same,
 (max_r_mux < VERIFY_R_BOUND && r_same < VERIFY_R_BOUND) ? "PASS" : "CHECK");
 }

 // Pairwise correlation for same-ratio across all available seeds.
 // Uses SAME_RATIO_N = test_sizes[0] so the multi-seed result is on the
 // same footing as the single-seed entry already in the table above.
 std::printf("\n Same-ratio (4,6) vs (6,9) across %d seeds (N=%lld):\n",
             N_MCL_SEEDS, (long long)SAME_RATIO_N);
 const uint64_t* seeds = mcl_seeds();
 double max_same_ratio = 0;
 int sr_nan = 0;
 for (int s = 0; s < N_MCL_SEEDS; s++) {
 std::vector<uint8_t> a((size_t)SAME_RATIO_N), b((size_t)SAME_RATIO_N);
 MCL_T2 ga(seeds[s], 4, 6); ga.gen_bytes(a.data(), SAME_RATIO_N);
 MCL_T2 gb(seeds[s], 6, 9); gb.gen_bytes(b.data(), SAME_RATIO_N);
 double r = std::abs(pearson_r(a.data(), b.data(), SAME_RATIO_N));
 if (!std::isfinite(r)) { sr_nan++; continue; }
 if (r > max_same_ratio) max_same_ratio = r;
 std::printf(" seed %llu: |r| = %.6f\n", (unsigned long long)seeds[s], r);
 }
 if (sr_nan > 0) {
 std::printf(" WARNING: %d seeds produced non-finite r\n", sr_nan);
 max_same_ratio = 1.0; // sentinel: failure
 }

 // ========================================================================
 // N ≥ 3,000,000 recommendation verification
 // ========================================================================
 sep("N >= 3,000,000 RECOMMENDATION VERIFICATION");

 std::printf(" Question: at what N does max|r| stabilize below noise_floor?\n\n");
 std::printf(" %-12s %-14s %-14s %-8s %-7s %s\n",
 "N", "noise_floor", "max|r|(6ch)", "ratio", "valid", "Stable?");
 std::printf(" %s\n", std::string(72, '-').c_str());

 int64_t sweep_sizes[] = {100000, 250000, 500000, 1000000, 2000000, 3000000, 5000000, 10000000};
 // Track whether the recommended N (3M) and every N above it are stable
 // (ratio < EVT bound). The summary line reports "JUSTIFIED" only if so —
 // hardcoded JUSTIFIED would silently mask sweep failures.
 bool recommended_stable = true;
 bool recommended_seen   = false;
 for (int64_t N : sweep_sizes) {
 // Generate 6 channels and measure max pairwise |r| (15 pairs)
 double max_pw = 0;
 // Use a subset for speed: 6 channels, 15 pairs
 const int NSUB = 6;
 std::vector<std::vector<uint8_t>> sub((size_t)NSUB);
 for (int i = 0; i < NSUB; i++) {
 sub[(size_t)i].resize((size_t)N);
 MCL_T2 gen(DEFAULT_SEED, topos20[i].p, topos20[i].q);
 gen.gen_bytes(sub[(size_t)i].data(), N);
 }
 int sweep_nan = 0;
 int sweep_pairs_ok = 0;
 const int n_pairs_total = NSUB * (NSUB - 1) / 2;
 for (int i = 0; i < NSUB; i++) for (int j = i+1; j < NSUB; j++) {
 double r = std::abs(pearson_r(sub[(size_t)i].data(), sub[(size_t)j].data(), N));
 if (!std::isfinite(r)) { sweep_nan++; continue; }
 sweep_pairs_ok++;
 if (r > max_pw) max_pw = r;
 }
 double nf = 1.0 / std::sqrt((double)N);
 double ratio = max_pw / nf;
 // Stability check requires (a) some pairs were valid, AND (b) max_pw is
 // within the EVT bound. If ALL pairs produced NaN, max_pw stays at 0
 // and ratio < bound trivially — flag as unstable to avoid silent-PASS.
 const bool any_valid = (sweep_pairs_ok > 0);
 const bool stable    = any_valid && (ratio < EVT_RATIO_BOUND);
 // Update recommendation tracking: every N at or above the recommended
 // value must be stable AND have produced valid measurements.
 if (N >= REF_RECOMMENDED_N) {
 recommended_seen = true;
 if (!stable) recommended_stable = false;
 }
 const char* status = stable ? "YES — within EVT"
 : (any_valid ? "marginal" : "DEGENERATE (all NaN)");
 char valid_col[16];
 std::snprintf(valid_col, sizeof(valid_col), "%d/%d",
 sweep_pairs_ok, n_pairs_total);
 std::printf(" %-12lld %-14.6f %-14.6f %-8.2f %-7s %s\n",
 (long long)N, nf, max_pw, ratio, valid_col, status);
 // Sanity check: a fully-NaN N invalidates the whole table.
 if (sweep_nan == n_pairs_total)
 std::printf(" WARNING: every pair at N=%lld degenerate\n", (long long)N);
 }
 // Pass criterion for the recommendation: at least one N at/above the
 // recommended value was sampled, AND every such N was stable.
 const bool pass_recommendation = recommended_seen && recommended_stable;

 if (pass_recommendation) {
 std::printf("\n CONCLUSION: At N >= %lldM, max|r|/noise_floor ratios were all\n",
 (long long)(REF_RECOMMENDED_N / 1000000));
 std::printf(" below the EVT bound (%.1f) for 15 pairs.\n", EVT_RATIO_BOUND);
 std::printf(" N >= %lld is a justified recommendation.\n",
 (long long)REF_RECOMMENDED_N);
 } else {
 std::printf("\n CONCLUSION: One or more N >= %lld showed ratio above EVT bound.\n",
 (long long)REF_RECOMMENDED_N);
 std::printf(" The N >= %lld recommendation is NOT confirmed by this run.\n",
 (long long)REF_RECOMMENDED_N);
 }

 // ========================================================================
 // EXPERIMENT B: HOP BOUNDARY INVISIBILITY — Windowed Entropy
 //   Verifies the σ ≈ 0.03 bits/byte reference at the hop boundary.
 // ========================================================================
 sep("EXPERIMENT B: Hop Boundary Invisibility — Windowed Entropy");

 // Hop test parameters. Named so changing the test setup touches only
 // these declarations (the format string and pass logic adapt automatically).
 constexpr int64_t L           = 200000;   // total bytes in stream
 constexpr int64_t HOP_AT      = 100000;   // hop point (mid-stream)
 constexpr int     W           = 500;      // sliding window size
 constexpr int     S           = 100;      // sliding window step
 constexpr int64_t HOP_FROM_P  = 3;        // pre-hop topology p
 constexpr int64_t HOP_FROM_Q  = 5;        // pre-hop topology q
 constexpr int64_t HOP_TO_P    = 7;        // post-hop topology p
 constexpr int64_t HOP_TO_Q    = 11;       // post-hop topology q
 constexpr int     HOP_BURNIN  = 50;       // micro-warmup iterations after hop

 std::printf(" Stream: %lldK bytes, hop (%lld,%lld)→(%lld,%lld) at byte %lldK\n",
 (long long)(L/1000),
 (long long)HOP_FROM_P, (long long)HOP_FROM_Q,
 (long long)HOP_TO_P,   (long long)HOP_TO_Q,
 (long long)(HOP_AT/1000));
 std::printf(" Window: W=%d bytes, step S=%d\n", W, S);
 std::printf(" Hop burnin: %d iterations\n\n", HOP_BURNIN);

 // Generate hopping stream
 std::vector<uint8_t> hop_stream((size_t)L);
 MCL_T2 hop_gen(DEFAULT_SEED, HOP_FROM_P, HOP_FROM_Q);
 hop_gen.gen_bytes(hop_stream.data(), HOP_AT);
 hop_gen.hop(HOP_TO_P, HOP_TO_Q, HOP_BURNIN);
 hop_gen.gen_bytes(hop_stream.data() + HOP_AT, L - HOP_AT);

 // Sliding window entropy
 int n_windows = (int)((L - W) / S) + 1;
 if (n_windows < 1) {
 std::fprintf(stderr, "ERROR: hop test parameters yield zero windows\n");
 return 1;
 }
 std::vector<double> win_ent((size_t)n_windows);

 for (int wi = 0; wi < n_windows; wi++) {
 int64_t start = (int64_t)wi * S;
 win_ent[(size_t)wi] = shannon_entropy(hop_stream.data() + start, W);
 }

 // Split into pre-hop, boundary, post-hop windows.
 // hop_window_idx = first window whose start position is at or beyond the
 // hop point. Windows BEFORE this index can still STRADDLE the hop if their
 // start is within W bytes of HOP_AT — those go into the boundary bucket.
 const int hop_window_idx = (int)(HOP_AT / S);

 // Boundary half-width = W/S = number of windows that overlap the hop
 // point (each step S advances S bytes; W/S steps span one window). This
 // captures every window that has any pre-hop AND post-hop bytes.
 const int BOUNDARY_HALF = W / S;
 const int boundary_lo = std::max(0, hop_window_idx - BOUNDARY_HALF);
 const int boundary_hi = std::min(n_windows - 1, hop_window_idx + BOUNDARY_HALF);

 // Welford's online algorithm for numerically stable variance.
 //   E[X²] − E[X]² is mathematically identical but suffers catastrophic
 //   cancellation when σ ≪ |μ| (here σ ≈ 0.035, μ ≈ 7.58 → ~3 decimal
 //   digits of cancellation). Welford avoids this by accumulating M2
 //   (sum of squared deviations from the running mean) directly.
 double sum_pre = 0, sum_post = 0, sum_bnd = 0;
 int n_pre = 0, n_post = 0, n_bnd = 0;
 // Use ±infinity sentinels so the first observed entropy always overrides.
 double min_ent = std::numeric_limits<double>::infinity();
 double max_ent = -std::numeric_limits<double>::infinity();
 double w_mean_all = 0;     // Welford running mean
 double w_M2_all   = 0;     // Welford running M2 = Σ(x_i − μ_i)²
 int    w_n_all    = 0;

 for (int wi = 0; wi < n_windows; wi++) {
 const double e = win_ent[(size_t)wi];
 // Welford update: μ_n = μ_{n−1} + (x − μ_{n−1})/n
 //                 M2_n = M2_{n−1} + (x − μ_{n−1})·(x − μ_n)
 w_n_all++;
 const double delta1 = e - w_mean_all;
 w_mean_all += delta1 / w_n_all;
 const double delta2 = e - w_mean_all;
 w_M2_all += delta1 * delta2;

 if (e < min_ent) min_ent = e;
 if (e > max_ent) max_ent = e;

 if (wi < boundary_lo) { sum_pre += e; n_pre++; }
 else if (wi > boundary_hi) { sum_post += e; n_post++; }
 else { sum_bnd += e; n_bnd++; }
 }

 const double mean_pre  = sum_pre  / std::max(1, n_pre);
 const double mean_post = sum_post / std::max(1, n_post);
 const double mean_bnd  = sum_bnd  / std::max(1, n_bnd);
 const double mean_all  = w_mean_all;
 // Population variance (divide by N), matching the prior formula.
 const double var_all   = (w_n_all > 0) ? w_M2_all / w_n_all : 0.0;
 const double sigma     = std::sqrt(std::max(0.0, var_all));
 const double max_diff  = std::abs(mean_pre - mean_post);
 const double bnd_diff  = std::abs(mean_bnd - mean_all);

 // Non-overlapping σ — same Welford treatment.
 // Step is W/S = number of S-steps to cover one window. Floor-divide
 // could yield 0 if W < S (degenerate case), so std::max(1, ...) prevents
 // an infinite loop.
 const int step_nonoverlap = std::max(1, W / S);
 double w_mean_no = 0, w_M2_no = 0;
 int    w_n_no    = 0;
 for (int wi = 0; wi < n_windows; wi += step_nonoverlap) {
 const double e = win_ent[(size_t)wi];
 w_n_no++;
 const double delta1 = e - w_mean_no;
 w_mean_no += delta1 / w_n_no;
 const double delta2 = e - w_mean_no;
 w_M2_no += delta1 * delta2;
 }
 const double var_no          = (w_n_no > 0) ? w_M2_no / w_n_no : 0.0;
 const double sigma_nonoverlap = std::sqrt(std::max(0.0, var_no));
 const int    n_nonoverlap     = w_n_no;

 // Edge-case warning: if hop is near the start or end, one of the buckets
 // could be empty, making mean_pre or mean_post == 0 (sentinel divide).
 // For default parameters n_pre = ~995, n_post = ~990 — non-issue. But we
 // surface a warning so unusual parameter sets don't silently mislead.
 if (n_pre == 0 || n_post == 0) {
 std::fprintf(stderr,
 "WARNING: degenerate window split (n_pre=%d, n_post=%d) — "
 "hop too close to stream edge; max_diff is meaningless\n",
 n_pre, n_post);
 }

 std::printf(" Results:\n");
 std::printf(" Total windows: %d\n", n_windows);
 std::printf(" Pre-hop mean entropy: %.6f (%d windows)\n", mean_pre, n_pre);
 std::printf(" Boundary mean entropy: %.6f (%d windows)\n", mean_bnd, n_bnd);
 std::printf(" Post-hop mean entropy: %.6f (%d windows)\n", mean_post, n_post);
 std::printf(" Overall mean entropy: %.6f\n", mean_all);
 std::printf(" Min entropy (any win): %.6f\n", min_ent);
 std::printf(" Max entropy (any win): %.6f\n", max_ent);
 std::printf(" σ (overlapping S=%d): %.6f bits/byte (%d windows)\n", S, sigma, n_windows);
 std::printf(" σ (non-overlapping S=%d): %.6f bits/byte (%d windows)\n", W, sigma_nonoverlap, n_nonoverlap);
 std::printf(" NOTE: overlapping windows inflate σ due to autocorrelation\n");
 std::printf(" non-overlapping σ is the independent measurement\n");
 std::printf(" |pre - post| diff: %.6f bits/byte\n", max_diff);
 std::printf(" |boundary - overall|: %.6f bits/byte\n\n", bnd_diff);

 // Pre-compute pass criteria so they can be displayed in reference verification
 // AND reused in the SUMMARY without duplicate computation. Using
 // sigma_nonoverlap consistently — see comment block above on why this is
 // the correct σ for the boundary check.
 const bool sigma_consistent  = std::abs(sigma_nonoverlap - REF_SIGMA)
                                < VERIFY_SIGMA_TOL;
 const bool max_diff_consistent = (max_diff < VERIFY_MAX_DIFF_BOUND);
 const bool boundary_invisible  = (bnd_diff
                                   < VERIFY_BOUNDARY_K * sigma_nonoverlap);

 // Reference verification (uses the pre-computed flags above)
 std::printf(" Reference verification:\n");
 std::printf(" Reference: σ ≈ %.2f bits/byte\n", REF_SIGMA);
 std::printf(" Measured (overlapping): σ = %.4f bits/byte\n", sigma);
 std::printf(" Measured (non-overlapping): σ = %.4f bits/byte %s\n",
 sigma_nonoverlap,
 sigma_consistent ? "✓ CONSISTENT" : "⚠ CHECK");
 std::printf(" Reference: max diff %.3f b/B Measured: %.4f bits/byte %s\n",
 REF_MAX_DIFF, max_diff,
 max_diff_consistent ? "✓ CONSISTENT" : "⚠ DIFFERENT");
 std::printf(" Boundary invisible: %s (k=%.1f × σ_nonoverlap = %.4f)\n",
 boundary_invisible ? "YES — within 3σ" : "NO — detectable",
 VERIFY_BOUNDARY_K, VERIFY_BOUNDARY_K * sigma_nonoverlap);

 // Print a few windows around the hop boundary.
 // If the display half is smaller than the boundary half, some boundary
 // windows fall outside the print range — warn so reader knows the
 // displayed slice is incomplete.
 static_assert(HOP_DISPLAY_HALF >= 0, "HOP_DISPLAY_HALF must be non-negative");
 if (HOP_DISPLAY_HALF < BOUNDARY_HALF) {
 std::fprintf(stderr,
 "NOTE: HOP_DISPLAY_HALF=%d < BOUNDARY_HALF=%d; "
 "some boundary windows omitted from display\n",
 HOP_DISPLAY_HALF, BOUNDARY_HALF);
 }
 std::printf("\n Entropy around hop boundary (window index %d):\n", hop_window_idx);
 std::printf(" Window Position Entropy Note\n");
 std::printf(" %s\n", std::string(52, '-').c_str());
 for (int wi = hop_window_idx - HOP_DISPLAY_HALF;
      wi <= hop_window_idx + HOP_DISPLAY_HALF; wi++) {
 if (wi < 0 || wi >= n_windows) continue;
 int64_t pos = (int64_t)wi * S;
 // Determine how many bytes of this window fall before/after the hop.
 // The three cases below are exhaustive — no defensive default needed.
 int64_t pre, post;
 if (pos >= HOP_AT)              { pre = 0;            post = W; }
 else if (pos + W <= HOP_AT)     { pre = W;            post = 0; }
 else                            { pre = HOP_AT - pos; post = W - pre; }

 const char* note = "";
 if (pre > 0 && post > 0) note = "← STRADDLE";
 else if (wi == hop_window_idx) note = "← first all-post";
 std::printf(" %-8d %-13lld %.6f %s\n",
 wi, (long long)pos, win_ent[(size_t)wi], note);
 }

 // ========================================================================
 // SUMMARY
 // ========================================================================
 double elapsed = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t_start).count();

 sep("REFERENCE VALUE VERIFICATION SUMMARY");

 // Reuse pre-computed flags from the reference-verification block above —
 // a single source of truth, no duplicated arithmetic.
 const bool pass_mux       = (saved_max_mux  < VERIFY_R_BOUND);
 const bool pass_sameratio = (max_same_ratio < VERIFY_R_BOUND);
 const bool pass_boundary  = boundary_invisible;
 const bool pass_sigma     = sigma_consistent;
 const bool pass_max_diff  = max_diff_consistent;

 std::printf(" max|r| ch vs mux at 500K:  %.6f %s (bound %.4f, ref %.4f)\n",
 saved_max_mux, pass_mux ? "PASS" : "FAIL", VERIFY_R_BOUND, REF_R);
 std::printf(" |r| same-ratio (%d seeds):  %.6f %s (bound %.4f)\n",
 N_MCL_SEEDS, max_same_ratio, pass_sameratio ? "PASS" : "FAIL", VERIFY_R_BOUND);
 std::printf(" N >= %lld recommendation:  %s (EVT convergence)\n",
 (long long)REF_RECOMMENDED_N,
 pass_recommendation ? "JUSTIFIED" : "NOT CONFIRMED");
 std::printf(" σ windowed entropy:        %.4f bits/byte %s (ref %.3f ± %.3f)\n",
 sigma_nonoverlap, pass_sigma ? "PASS" : "FAIL",
 REF_SIGMA, VERIFY_SIGMA_TOL);
 std::printf(" max|μ_pre−μ_post|:         %.4f bits/byte %s (ref %.3f, bound %.4f)\n",
 max_diff, pass_max_diff ? "PASS" : "FAIL",
 REF_MAX_DIFF, VERIFY_MAX_DIFF_BOUND);
 std::printf(" hop boundary invisible:    %s (|μ_bnd−μ_all|=%.4f, k=%.1fσ)\n",
 pass_boundary ? "YES" : "NO", bnd_diff, VERIFY_BOUNDARY_K);

 // All reference checks must pass for the global verdict. The σ check, max_diff
 // check, and N≥3M recommendation were previously informational only
 // (silent inconsistency hazards); all are now explicit.
 if (!pass_mux)            global_pass = false;
 if (!pass_sameratio)      global_pass = false;
 if (!pass_recommendation) global_pass = false;
 if (!pass_sigma)          global_pass = false;
 if (!pass_max_diff)       global_pass = false;
 if (!pass_boundary)       global_pass = false;

 std::printf("\n +================================================================+\n");
 std::printf(" | VERDICT: %-54s |\n",
 global_pass ? "PASS — all reference values verified"
 : "FAIL — one or more values inconsistent");
 std::printf(" +================================================================+\n");

 std::printf("\n Time: %.1f seconds\n", elapsed);
 std::printf("\n %s v%s | Madeeh Ibrahim, Cairo\n", DOC_ID, DOC_VERSION);
 std::printf("==============================================================================\n");

 return global_pass ? 0 : 1;
}
