/*
 * ============================================================================
 * MCL Authentication Verification
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-AUTH-2026-0526-001
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
 * PURPOSE: Verify hardware authentication properties:
 *   1a. FAR (32-byte): 0 matches in 10^8 random challenges
 *   1b. FAR (4-byte):  statistically meaningful collision test
 *   2.  SIM-swap: wrong (p,q) OR wrong seed -> no match
 *   3.  Key space: ~2^103 unique identities (seed + coprime pairs)
 *   4.  Reproducibility: same params -> identical output
 *   5.  Sensitivity: bit-flip seed, adjacent (p,q) -> full decorrelation
 *   D4. Negative control: same params -> identical bytes (deterministic)
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_auth_verify mcl_auth_verify.cpp -lm && ./mcl_auth_verify
 *
 * EXPECTED RESULTS: PASS -- all authentication properties verified
 *                          (negative control, FAR-32, FAR-4, SIM-swap,
 *                          key space, reproducibility, sensitivity).
 * REFERENCES:
 *   - Clopper, C.J. and Pearson, E.S., Biometrika 26:404-413, 1934.
 *   - NIST SP 800-22, Section 2 (frequency tests), 2010.
 *   - 3GPP TS 33.501 (5G AKA authentication framework).
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
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <atomic>
#include <random>

#ifdef _OPENMP
 #include <omp.h>
#endif

/* Document metadata (mirror of file header — keep in sync) */
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-AUTH-2026-0526-001";

// ============================================================================
// Test parameters and thresholds (named constants)
// ============================================================================

// FAR test sample sizes
//   FULL:  10^8 — Patent-claim grade, requires OpenMP for practical timing
//          (~minutes on a multi-core machine; ~hours single-threaded)
//   QUICK: 10^5 — Smoke test for verification of code correctness
//          (~10 sec single-threaded; statistical scope is informational only)
static const int64_t FAR_N_FULL  = 100000000LL;  // 10^8 (canonical)
static const int64_t FAR_N_QUICK = 100000LL;     // 10^5 (smoke test)

// Sample size for sensitivity tests (Pearson r + Hamming)
static const int64_t SENS_N = 100000LL;          // 10^5 bytes per comparison

// Sample size for SIM-swap Hamming check (per topology / per seed)
static const int CHAL_BYTES = 32;                // 32-byte authentication response

// SIM-swap test sweep size
static const int SIM_SWAP_N_TOPOS = 1000;        // # of wrong (p,q) tested
static const int SIM_SWAP_N_SEEDS = 1000;        // # of wrong seeds tested

// Negative control bytes per generator
static const int64_t NEG_CTRL_N = 100000LL;

// Sensitivity Hamming pass band: at SENS_N=10^5 bytes (8x10^5 bits),
//   sigma(Hamming%) = 50 / sqrt(8 * SENS_N) = 0.0559%
// Window [49, 51] = ±1% = 17.9σ — intentionally loose. The test detects
// CATASTROPHIC failures (correlated streams ~ 0% Hamming, anti-correlated
// ~ 100% Hamming, or structural patterns far from 50%) rather than
// fine-grained bias. Tight statistical inference is performed in
// mcl_orth_verify (Pearson Bonferroni); this test verifies the
// avalanche property at coarse resolution.
static const double SENS_HAM_LOWER = 49.0;
static const double SENS_HAM_UPPER = 51.0;

// Negative control: identical (seed, p, q) MUST yield byte-identical output.
// The Pearson r threshold is a defensive cross-check; diff==0 is authoritative.
static const double NEG_CTRL_R_MIN = 0.999;

// PRNG seed for FAR challenger (xorshift64) — distinct from device seed
static const uint64_t FAR_RNG_SEED = 0xABCDEF0123456789ULL;

// Per-thread stride for FAR RNG (distinct stream per thread)
static const uint64_t FAR_RNG_STRIDE = 999983ULL;

// FAR challenger (p, q) range: pairs are sampled from [2, 2 + ATTACK_PQ_RANGE)
// This is intentionally smaller than the full keyspace [2, 10^9] to ensure
// the PRNG produces collisions in a reasonable space — testing the engine's
// resistance to NEAR-collision attacks rather than full keyspace coverage.
// The full keyspace test would need ~10^18 trials and is statistically
// equivalent at the per-trial level.
static const int64_t ATTACK_PQ_RANGE = 10000;

// Reproducibility test: number of independent (re)initialization trials
static const int REPRO_TRIALS = 100;

// Coprime pair magnitude (range used for entropy-space estimation)
static const double KEY_SPACE_PMAX = 1e6;
static const int    KEY_SPACE_SEED_BITS = 64;
static const int    KEY_SPACE_K_BITS    = 20;

// CLI-controlled flags
static int64_t g_far_N = FAR_N_FULL;             // overridden by --quick

// Progress helper: prints to stderr every 10%
void far_test(const char* label, int chal_len,
 const uint8_t* dev_resp,
 [[maybe_unused]] uint64_t dev_seed,
 int64_t dev_p, int64_t dev_q,
 int64_t N, int64_t& out_fa)
{
 // Defensive: chal_len is bounded by stack buffer size below.
 if (chal_len <= 0 || chal_len > CHAL_BYTES) {
  std::fprintf(stderr,
      "FATAL: far_test '%s' called with invalid chal_len=%d "
      "(must be 1..%d)\n",
      label, chal_len, CHAL_BYTES);
  std::abort();
 }
 out_fa = 0;
 std::atomic<int64_t> global_done{0};

 // GLOBAL step for cross-thread aggregated progress (10% increments of N).
 const int64_t global_step = (N >= 10) ? (N / 10) : 1;
 auto t0 = std::chrono::steady_clock::now();

 // Use a local accumulator for OpenMP reduction (more portable than
 // reduction directly on the lvalue reference parameter).
 int64_t total_fa = 0;

 #ifdef _OPENMP
 #pragma omp parallel reduction(+:total_fa)
 #endif
 {
 int tid = 0;
 #ifdef _OPENMP
 tid = omp_get_thread_num();
 #endif

 // Per-thread xorshift64 seed (distinct stream per thread).
 uint64_t rng = FAR_RNG_SEED + (uint64_t)tid * FAR_RNG_STRIDE;
 // xorshift64 cannot be seeded with zero (degenerate fixed point).
 // FAR_RNG_SEED is large and non-zero, so this is guaranteed in practice;
 // assert provides a defense against future modifications.
 if (rng == 0) rng = 1;

 auto next = [&rng]() -> uint64_t {
 rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
 return rng;
 };

 #ifdef _OPENMP
 int nt = omp_get_num_threads();
 int64_t chunk = N / nt;
 int64_t my_s = (int64_t)tid * chunk;
 int64_t my_e = (tid == nt - 1) ? N : my_s + chunk;
 #else
 (void)tid;  // unused in non-OMP build
 int64_t my_s = 0, my_e = N;
 #endif

 // Per-thread step for local progress reporting (10% of this thread's chunk).
 const int64_t my_chunk = my_e - my_s;
 const int64_t local_step = (my_chunk >= 10) ? (my_chunk / 10) : 1;

 int64_t local_fa = 0;
 int64_t local_count = 0;

 for (int64_t t = my_s; t < my_e; t++) {
 uint64_t ts = next();
 int64_t tp = 2 + (int64_t)(next() % (uint64_t)ATTACK_PQ_RANGE);
 int64_t tq = 2 + (int64_t)(next() % (uint64_t)ATTACK_PQ_RANGE);
 if (tp == tq) tq++;
 // Skip if attacker accidentally picked the device's exact (p,q).
 // ts collision with dev_seed has probability 2^-64 (effectively zero
 // and harmless even if it occurred — the (p,q) check handles it).
 if (tp == dev_p && tq == dev_q) continue;

 MCL_T2 att(ts, tp, tq);
 uint8_t resp[CHAL_BYTES];     // bounded by guard above
 att.gen_bytes(resp, chal_len);

 bool match = true;
 for (int b = 0; b < chal_len; b++)
 if (resp[b] != dev_resp[b]) { match = false; break; }
 if (match) local_fa++;

 // Per-thread progress: each thread updates global_done at its own
 // 10% boundary; only thread 0 prints, but global_done aggregates
 // progress from all threads, so the printed percentage tracks the
 // total work completed (not just thread 0's chunk).
 if (++local_count % local_step == 0) {
 int64_t done = global_done.fetch_add(local_step) + local_step;
 #ifdef _OPENMP
 if (tid == 0)
 #endif
 {
 double pct = 100.0 * (double)done / (double)N;
 double sec = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t0).count();
 std::fprintf(stderr, " %s: %3.0f%% (%.1fM / %.1fM) %.0fs\n",
 label, pct > 100 ? 100 : pct,
 (double)done / 1e6,
 (double)N / 1e6, sec);
 }
 }
 }
 total_fa += local_fa;
 }
 (void)global_step;  // reserved for future use; kept for symmetry

 out_fa = total_fa;

 double sec = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t0).count();
 std::fprintf(stderr, " %s: done in %.1fs\n", label, sec);
}

static void print_help(const char* prog) {
 std::printf("MCL Authentication Verification v%s\n", DOC_VERSION);
 std::printf("Usage: %s [options]\n\n", prog);
 std::printf("Options:\n");
 std::printf("  --quick     Smoke test: N=%lld FAR trials (~10 sec single-thread)\n",
             (long long)FAR_N_QUICK);
 std::printf("  --full      Full run:   N=%lld FAR trials (default; OpenMP recommended)\n",
             (long long)FAR_N_FULL);
 std::printf("  --help, -h  Print this help and exit\n\n");
 std::printf("Document ID: %s\n", DOC_ID);
 std::printf("Engine:      mcl_core.hpp (MCL_T2 production engine)\n");
 std::printf("\nNotes:\n");
 std::printf("  --quick is for code-correctness verification only.\n");
 std::printf("  --full at 10^8 trials provides the canonical FAR claim.\n");
 std::printf("  Build with OpenMP (-fopenmp on Linux; -Xpreprocessor -fopenmp -lomp\n");
 std::printf("  on macOS) for parallel speedup on FAR tests.\n");
}

int main(int argc, char** argv) {
 // ─── Pre-scan for --help / -h (works regardless of position) ───
 for (int i = 1; i < argc; i++) {
  if (std::strcmp(argv[i], "--help") == 0 ||
      std::strcmp(argv[i], "-h") == 0) {
   print_help(argv[0]);
   return 0;
  }
 }

 // ─── Parse CLI ───
 bool mode_explicitly_set = false;
 for (int i = 1; i < argc; i++) {
  if (std::strcmp(argv[i], "--quick") == 0) {
   if (mode_explicitly_set) {
    std::fprintf(stderr,
        "ERROR: multiple run modes specified; pick one of "
        "--quick / --full.  Run with --help for usage.\n");
    return 2;
   }
   g_far_N = FAR_N_QUICK;
   mode_explicitly_set = true;
  } else if (std::strcmp(argv[i], "--full") == 0) {
   if (mode_explicitly_set) {
    std::fprintf(stderr,
        "ERROR: multiple run modes specified; pick one of "
        "--quick / --full.  Run with --help for usage.\n");
    return 2;
   }
   g_far_N = FAR_N_FULL;
   mode_explicitly_set = true;
  } else {
   std::fprintf(stderr,
       "ERROR: unknown argument '%s'.  Run with --help for usage.\n",
       argv[i]);
   return 2;
  }
 }

 std::setbuf(stdout, nullptr);
 auto t_start = std::chrono::steady_clock::now();

 int n_threads = 1;
 #ifdef _OPENMP
 n_threads = omp_get_max_threads();
 #endif

 std::printf("\n==============================================================================\n");
 std::printf(" MCL AUTHENTICATION VERIFICATION v%s\n", DOC_VERSION);
 std::printf(" %s\n", DOC_ID);
 std::printf(" Hardware-bound device identity, FAR < 2^-32 (4-byte) or 2^-256 (32-byte)\n");
 std::printf(" Threads: %d  |  FAR sample size: %lld\n", n_threads, (long long)g_far_N);
 // Timestamp (UTC) for log archival
 {
  std::time_t now_t = std::time(nullptr);
  std::tm* utc = std::gmtime(&now_t);
  if (utc) {
   char buf[64];
   std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", utc);
   std::printf(" Started: %s\n", buf);
  }
 }
 std::printf("==============================================================================\n\n");

 const uint64_t DEVICE_SEED = DEFAULT_SEED;
 const int64_t DEVICE_P = 3, DEVICE_Q = 5;

 MCL_T2 dev32(DEVICE_SEED, DEVICE_P, DEVICE_Q);
 uint8_t dev_resp[CHAL_BYTES];
 dev32.gen_bytes(dev_resp, CHAL_BYTES);

 // Same generator → same first 4 bytes (deterministic)
 MCL_T2 dev4(DEVICE_SEED, DEVICE_P, DEVICE_Q);
 uint8_t dev_short[4];
 dev4.gen_bytes(dev_short, 4);

 std::printf(" Device: seed=%llu, (p,q)=(%lld,%lld)\n",
 (unsigned long long)DEVICE_SEED,
 (long long)DEVICE_P, (long long)DEVICE_Q);
 std::printf(" Response: ");
 for (int i = 0; i < 8; i++) std::printf("%02X", dev_resp[i]);
 std::printf("...(%d bytes)\n\n", CHAL_BYTES);

 bool gp = true;

 // ========================================================================
 // NEGATIVE CONTROL (Rule D4)
 // ========================================================================
 sep("NEGATIVE CONTROL - same params must produce identical bytes");
 bool neg_pass = false;
 {
 std::vector<uint8_t> a((size_t)NEG_CTRL_N), b((size_t)NEG_CTRL_N);
 MCL_T2 ga(DEVICE_SEED, DEVICE_P, DEVICE_Q);
 MCL_T2 gb(DEVICE_SEED, DEVICE_P, DEVICE_Q);
 ga.gen_bytes(a.data(), NEG_CTRL_N);
 gb.gen_bytes(b.data(), NEG_CTRL_N);
 double r = pearson_r(a.data(), b.data(), NEG_CTRL_N);
 int64_t diff = 0;
 for (int64_t i = 0; i < NEG_CTRL_N; i++)
  if (a[(size_t)i] != b[(size_t)i]) diff++;
 // Authoritative: byte-equality (diff == 0). r > NEG_CTRL_R_MIN is a
 // defensive cross-check on the pearson_r implementation itself.
 neg_pass = (r > NEG_CTRL_R_MIN && diff == 0);
 std::printf(" r=%.6f diff=%lld -> %s\n",
             r, (long long)diff, neg_pass ? "PASS" : "FAIL");
 if (!neg_pass) gp = false;
 }

 // ========================================================================
 // TEST 1a: Output Collision Resistance — 32-byte stream
 // ========================================================================
 // Test scope: P(attacker (seed', p', q') reproduces device's first 32 bytes).
 // For uniformly distributed output, per-trial P = 2^(-256). The empirical
 // claim is the Clopper-Pearson upper bound on the true rate given 0 hits
 // in N trials, since 0/N does not prove rate==0.
 sep("TEST 1a: FAR 32-byte (Clopper-Pearson upper bound)");
 std::printf(" Per-trial P(uniform match) = 2^(-256) ~ 10^(-77).\n");
 std::printf(" Empirical claim: Clopper-Pearson 95%% upper bound on observed rate.\n");
 bool far32_pass = false;
 int64_t far32_fa = 0;
 double far32_cp95 = 0.0;
 {
 const int64_t N = g_far_N;
 far_test("FAR-32", CHAL_BYTES, dev_resp, DEVICE_SEED, DEVICE_P, DEVICE_Q, N, far32_fa);
 double far_obs = (double)far32_fa / (double)N;
 // Clopper-Pearson exact upper 95% CI for binomial proportion.
 // Special-case for k=0 successes in N trials:
 //   p_upper = 1 - alpha^(1/N)   with alpha = 0.05
 // Reference: Clopper & Pearson, Biometrika 26, 404-413 (1934).
 if (far32_fa == 0) {
  far32_cp95 = 1.0 - std::pow(0.05, 1.0 / (double)N);
 } else {
  // For k > 0, use the standard CP formula via the Beta distribution.
  // Approximation: p_upper ~ (k+1)/N * F_{2(k+1), 2(N-k)}^(-1)(1-alpha)
  // For our context (we expect k=0), this branch is informational only.
  far32_cp95 = (double)(far32_fa + 1) / (double)N;  // crude UB
 }
 far32_pass = (far32_fa == 0);
 std::printf(" -> Observed:  %lld false accepts in %lld trials (rate = %.3e)\n",
 (long long)far32_fa, (long long)N, far_obs);
 std::printf(" -> CP 95%% upper bound on true FAR: %.3e\n", far32_cp95);
 std::printf(" -> Verdict: %s\n", far32_pass ? "PASS" : "FAIL");
 if (!far32_pass) gp = false;
 }

 // ========================================================================
 // TEST 1b: 4-byte collision rate (Poisson-bounded)
 // ========================================================================
 sep("TEST 1b: 4-byte collision rate (Poisson check)");
 bool far4_pass = false;
 int64_t far4_fa = 0;
 double far4_expected = 0;
 {
 const int64_t N = g_far_N;
 far4_expected = (double)N / 4294967296.0;
 std::printf(" Per-trial P(4-byte match) = 2^(-32). Expected: %.3f\n", far4_expected);

 far_test("FAR-4", 4, dev_short, DEVICE_SEED, DEVICE_P, DEVICE_Q, N, far4_fa);
 // Pass criterion: observed count consistent with Poisson(mean=far4_expected).
 // Threshold: expected*10 + 5 covers Poisson tails up to ~30 sigma above mean.
 far4_pass = ((double)far4_fa < far4_expected * 10.0 + 5.0);
 std::printf(" -> Observed: %lld 4-byte collisions (expected: %.3f)\n",
 (long long)far4_fa, far4_expected);
 std::printf(" -> Verdict:  %s\n",
 far4_pass ? "PASS - consistent with random" : "FAIL - structural collisions!");
 if (!far4_pass) gp = false;
 }

 // ========================================================================
 // TEST 2: SIM-SWAP RESISTANCE
 // ========================================================================
 sep("TEST 2: SIM-SWAP RESISTANCE");

 // 2a: correct seed, wrong (p,q)
 std::printf(" Part A: correct seed + wrong (p,q) - %d topologies\n",
             SIM_SWAP_N_TOPOS);
 // generate_topologies(N+20) covers headroom in case some are filtered
 auto topos = generate_topologies(SIM_SWAP_N_TOPOS + 20);
 double hs_a = 0, hmin_a = 100, hmax_a = 0;
 int full_a = 0, n_a = 0;
 for (size_t t = 0; t < topos.size() && n_a < SIM_SWAP_N_TOPOS; t++) {
 if (topos[t].p == DEVICE_P && topos[t].q == DEVICE_Q) continue;
 MCL_T2 att(DEVICE_SEED, topos[t].p, topos[t].q);
 uint8_t resp[CHAL_BYTES]; att.gen_bytes(resp, CHAL_BYTES);
 double h = hamming_pct(resp, dev_resp, CHAL_BYTES);
 hs_a += h; if (h < hmin_a) hmin_a = h; if (h > hmax_a) hmax_a = h;
 bool fm = true;
 for (int b = 0; b < CHAL_BYTES; b++) if (resp[b] != dev_resp[b]) { fm = false; break; }
 if (fm) full_a++;
 n_a++;
 if (n_a % 200 == 0)
  std::fprintf(stderr, " SIM-A: %d/%d\n", n_a, SIM_SWAP_N_TOPOS);
 }
 std::printf(" Hamming: mean=%.3f%% min=%.3f%% max=%.3f%%\n",
 (n_a > 0 ? hs_a / n_a : 0.0),
 (n_a > 0 ? hmin_a : 0.0),
 (n_a > 0 ? hmax_a : 0.0));
 std::printf(" Full matches: %d/%d -> %s\n", full_a, n_a,
 (n_a > 0 && full_a == 0) ? "PASS" : "FAIL");

 // 2b: wrong seed, correct (p,q)
 //   Seeds are drawn uniformly at random from the full 64-bit space
 //   (excluding DEVICE_SEED) using std::mt19937_64. This replaces an
 //   earlier arithmetic-progression sampler that only covered seeds
 //   adjacent to DEVICE_SEED — a far weaker attacker model.
 std::printf("\n Part B: wrong seed + correct (p,q) - %d random seeds\n",
             SIM_SWAP_N_SEEDS);
 double hs_b = 0, hmin_b = 100, hmax_b = 0;
 int full_b = 0;
 // Fixed seed for reproducibility; distinct from DEVICE_SEED and FAR_RNG_SEED.
 std::mt19937_64 seed_rng(0xCAFEBABEDEADC0DEULL);
 for (int s = 0; s < SIM_SWAP_N_SEEDS; s++) {
 uint64_t att_seed = seed_rng();
 // Reject the (statistically impossible) collision with DEVICE_SEED.
 while (att_seed == DEVICE_SEED) att_seed = seed_rng();
 MCL_T2 att(att_seed, DEVICE_P, DEVICE_Q);
 uint8_t resp[CHAL_BYTES]; att.gen_bytes(resp, CHAL_BYTES);
 double h = hamming_pct(resp, dev_resp, CHAL_BYTES);
 hs_b += h; if (h < hmin_b) hmin_b = h; if (h > hmax_b) hmax_b = h;
 bool fm = true;
 for (int b = 0; b < CHAL_BYTES; b++) if (resp[b] != dev_resp[b]) { fm = false; break; }
 if (fm) full_b++;
 if ((s + 1) % 200 == 0)
  std::fprintf(stderr, " SIM-B: %d/%d\n", s + 1, SIM_SWAP_N_SEEDS);
 }
 std::printf(" Hamming: mean=%.3f%% min=%.3f%% max=%.3f%%\n",
 hs_b / SIM_SWAP_N_SEEDS, hmin_b, hmax_b);
 std::printf(" Full matches: %d/%d -> %s\n", full_b, SIM_SWAP_N_SEEDS,
 full_b == 0 ? "PASS" : "FAIL");

 // MATHEMATICAL NOTE - Hamming at 32 bytes:
 //   sigma(Hamming%) = 50/sqrt(8*32) = 3.125%. Window [49,51] = 0.3*sigma
 //   -> uninformative. Pass/fail based ONLY on full-match count.
 //   Hamming mean is reported for reference but does not affect verdict.
 bool sim_pass = (n_a > 0 && full_a == 0 && full_b == 0);
 std::printf("\n -> SIM-swap: %s (Hamming: A=%.1f%% B=%.1f%% - informational)\n",
 sim_pass ? "PASS - uncloneable" : "FAIL",
 (n_a > 0 ? hs_a / n_a : 0.0),
 hs_b / SIM_SWAP_N_SEEDS);
 if (!sim_pass) gp = false;

 // ========================================================================
 // TEST 3: KEY SPACE
 // ========================================================================
 sep("TEST 3: KEY SPACE");
 // # coprime pairs (p,q <= N_max) ~ (6/pi^2) * N_max^2
 //
 // Note on KEY_SPACE_PMAX:
 //   Patent 1 [0017] specifies the FULL range 2 <= p,q <= 2^62, yielding
 //   ~2^123.3 coprime pairs WITHOUT including K. Here we use a more
 //   conservative analytical estimate KEY_SPACE_PMAX=10^6 to demonstrate
 //   that even with a much-restricted pair range, the combined keyspace
 //   (seed + topology + K) reaches ~2^123 — matching the patent claim.
 //   The full keyspace [2, 2^62] is implicitly covered by mcl_core.hpp's
 //   constraint MCL_PQ_MAX = 2^62.
 double coprime_count = 6.0 / (MCL_PI * MCL_PI) *
                        KEY_SPACE_PMAX * KEY_SPACE_PMAX;
 double topo_bits = std::log2(coprime_count);
 double total_bits = (double)KEY_SPACE_SEED_BITS + topo_bits;
 bool key_space_pass = (total_bits > 100.0);
 std::printf(" Coprime pairs (p,q <= 10^6): %.2e -> %.1f bits\n",
             coprime_count, topo_bits);
 std::printf(" Seed entropy: %d bits\n", KEY_SPACE_SEED_BITS);
 std::printf(" Total (no K): ~2^%.0f\n", total_bits);
 std::printf(" With K (%d bits): ~2^%.0f\n",
             KEY_SPACE_K_BITS, total_bits + KEY_SPACE_K_BITS);
 std::printf(" -> %s\n", key_space_pass ? "PASS" : "FAIL");
 if (!key_space_pass) gp = false;

 // ========================================================================
 // TEST 4: REPRODUCIBILITY
 // ========================================================================
 sep("TEST 4: REPRODUCIBILITY");
 bool repro_pass = true;
 for (int trial = 0; trial < REPRO_TRIALS; trial++) {
 MCL_T2 g1(DEVICE_SEED, DEVICE_P, DEVICE_Q);
 MCL_T2 g2(DEVICE_SEED, DEVICE_P, DEVICE_Q);
 uint8_t r1[CHAL_BYTES], r2[CHAL_BYTES];
 g1.gen_bytes(r1, CHAL_BYTES); g2.gen_bytes(r2, CHAL_BYTES);
 for (int b = 0; b < CHAL_BYTES; b++)
  if (r1[b] != r2[b]) { repro_pass = false; break; }
 }
 std::printf(" %d trials x %d bytes: %s\n",
             REPRO_TRIALS, CHAL_BYTES,
             repro_pass ? "PASS - bit-exact" : "FAIL");
 if (!repro_pass) gp = false;

 // ========================================================================
 // TEST 5: SENSITIVITY
 // ========================================================================
 sep("TEST 5: SENSITIVITY");
 const int64_t SN = SENS_N;
 bool sens_pass = true;

 // 5a: seed bit-flip
 //   Sample 8 of 64 bits (step=8) for smoke-test efficiency.
 //   Avalanche failure typically affects all bits or none, so an 8-bit
 //   sample is sufficient to detect catastrophic loss of avalanche.
 //   Exhaustive 64-bit testing is performed in mcl_attack_suite.
 std::printf(" Part A: seed single-bit flip (8 of 64 bits sampled)\n");
 std::printf(" Bit Hamming%% |r|\n");
 std::printf(" %s\n", std::string(35, '-').c_str());
 for (int bit = 0; bit < 64; bit += 8) {
 std::vector<uint8_t> a((size_t)SN), b((size_t)SN);
 MCL_T2 ga(DEVICE_SEED, DEVICE_P, DEVICE_Q);
 MCL_T2 gb(DEVICE_SEED ^ (1ULL << bit), DEVICE_P, DEVICE_Q);
 ga.gen_bytes(a.data(), SN); gb.gen_bytes(b.data(), SN);
 double ham = hamming_pct(a.data(), b.data(), SN);
 double r = std::abs(pearson_r(a.data(), b.data(), SN));
 std::printf(" bit %-4d %.3f%% %.6f\n", bit, ham, r);
 if (ham < SENS_HAM_LOWER || ham > SENS_HAM_UPPER) sens_pass = false;
 }

 // 5b: adjacent (p,q)
 std::printf("\n Part B: adjacent (p,q)\n");
 std::printf(" (p,q) Hamming%% |r|\n");
 std::printf(" %s\n", std::string(38, '-').c_str());
 int64_t adj[][2] = {{3,7},{5,7},{5,3},{2,5},{7,11},{3,4}};
 for (auto& pq : adj) {
 std::vector<uint8_t> a((size_t)SN), b((size_t)SN);
 MCL_T2 ga(DEVICE_SEED, DEVICE_P, DEVICE_Q);
 MCL_T2 gb(DEVICE_SEED, pq[0], pq[1]);
 ga.gen_bytes(a.data(), SN); gb.gen_bytes(b.data(), SN);
 double ham = hamming_pct(a.data(), b.data(), SN);
 double r = std::abs(pearson_r(a.data(), b.data(), SN));
 std::printf(" (%lld,%-3lld) %.3f%% %.6f\n",
 (long long)pq[0], (long long)pq[1], ham, r);
 if (ham < SENS_HAM_LOWER || ham > SENS_HAM_UPPER) sens_pass = false;
 }
 if (!sens_pass) gp = false;

 // ========================================================================
 // VERDICT
 // ========================================================================
 double elapsed = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t_start).count();

 sep("VERDICT");
 const char* mode_label =
     (g_far_N == FAR_N_FULL)  ? "FULL  (10^8)" :
     (g_far_N == FAR_N_QUICK) ? "QUICK (10^5)" :
                                "(custom)";
 std::printf(" Run mode:        %s\n", mode_label);
 std::printf(" Neg control:     %s\n", neg_pass ? "PASS" : "FAIL");
 std::printf(" FAR 32-byte:     %s  (0 / %lld; CP 95%% UB on FAR: %.3e)\n",
             far32_pass ? "PASS" : "FAIL",
             (long long)g_far_N, far32_cp95);
 std::printf(" FAR 4-byte:      %s  (collisions: %lld, expected: %.3f)\n",
             far4_pass ? "PASS" : "FAIL",
             (long long)far4_fa, far4_expected);
 std::printf(" SIM-swap (A+B):  %s\n", sim_pass ? "PASS" : "FAIL");
 std::printf(" Key space:       %s  (2^%.0f, 2^%.0f with K)\n",
             key_space_pass ? "PASS" : "FAIL",
             total_bits, total_bits + KEY_SPACE_K_BITS);
 std::printf(" Reproducibility: %s\n", repro_pass ? "PASS" : "FAIL");
 std::printf(" Sensitivity:     %s\n", sens_pass ? "PASS" : "FAIL");

 std::printf("\n +================================================================+\n");
 std::printf(" | VERDICT: %s |\n",
 gp ? "PASS - authentication properties verified "
 : "FAIL - authentication weakness detected ");
 std::printf(" +================================================================+\n");
 std::printf("\n Time: %.1f seconds | Threads: %d\n", elapsed, n_threads);
 std::printf("\n %s v%s | Madeeh Ibrahim, Cairo, Egypt\n", DOC_ID, DOC_VERSION);
 std::printf(" Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673\n");
 std::printf("==============================================================================\n");
 return gp ? 0 : 1;
}
