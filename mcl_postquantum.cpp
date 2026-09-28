/*
 * ============================================================================
 * MCL Classical Diagnostics of the Two-Oscillator Engine
 * (file name kept: mcl_postquantum.cpp -- NOT a quantum-security test)
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-PQ-2026-0526-001
 * Version:       6.1.0
 * Date:          September 28, 2026   (6.0.0: May 26, 2026, 10:00 UTC)
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
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673, PCT/IB2026/058860.
 * ============================================================================
 *
 * PURPOSE: Classical diagnostics of the two-oscillator engine; NOT a quantum-security test.
 * Five measurements on the output and the trajectory of MCL_T2 (3,5), and
 * one accounting table. No part of this program runs, simulates or bounds a
 * quantum algorithm. Statistical tests (entropy, chi², B-M, etc.) are in
 * mcl_reference.cpp.
 *
 * WHAT CHANGED IN 6.1.0 (2026-09-28) -- see QUANTUM_SCOPE_NOTE.md
 *   Version 6.0.0 printed conclusions about quantum attacks that its
 *   measurements do not support. They are withdrawn:
 *     - the verdict "MCL resists all known quantum attacks";
 *     - the "quantum algorithm completeness" table (Simon, BHT, quantum
 *       walks, ... each marked "NO");
 *     - "positive Lyapunov exponent => aperiodic => Shor inapplicable": a
 *       spectral test on 65,536 bytes and a period scan over 2*10^5 bytes
 *       cannot show the absence of periods, and every finite-precision
 *       realization is eventually periodic (the retired 64-bit-state integer
 *       path closes its orbit with cycle length 1,671,196,332 --
 *       T4_CycleStructure/, VDF128_T4/);
 *     - the "PQ security 73.6 / 105.6 bits" figures, which counted a 128-bit
 *       seed (and, in the "enhanced" rows, 64 further phase bits) as secret.
 *       The seed is the public challenge; the secret is (p, q);
 *     - the "T-gates per Grover oracle" figure (8.27e+07), obtained from a
 *       formula that models no circuit;
 *     - "no quantum parallelism within the oracle", inferred from the update
 *       order of the classical map;
 *     - the comparison table and the remarks about third-party schemes.
 *   Every MEASURED number of Parts 1-4B is unchanged, digit for digit. The
 *   6.0.0 output is kept as results/mcl_postquantum_v6.0.0_20260526.txt.
 *
 * PARTS:
 * Part 1: Negative Control (RANDU + glibc-LSB must FAIL)
 * Part 2: Spectral test (Goertzel DFT over 2000 frequencies)
 * Part 3: Period scan (byte-level periods 2..20000)
 * Part 4: Update order (Gauss-Seidel vs parallel update divergence)
 * Part 4B: Sensitivity (growth of an initial perturbation)
 * Part 5: Secret-size accounting under generic key search
 * Part 6: What these diagnostics do not show
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_pq mcl_postquantum.cpp -lm && ./mcl_pq
 *
 * EXPECTED RESULTS:
 * Negative control: weak generators FAIL (validates methodology)
 * Parts 2-4B: pass
 * DIAGNOSTICS: 5 / 5
 * REFERENCES:       QUANTUM_SCOPE_NOTE.md
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
#include <random>

// Document metadata (mirror of file header — keep in sync)
static const char* DOC_VERSION = "6.1.0";
static const char* DOC_ID      = "MCL-PQ-2026-0526-001";

// Empirically measured Lyapunov exponent λ₁ for the (3,5) topology at K=12
// (see mcl_reference.cpp EXP 10 and mcl_lyapunov.cpp). Used here for chaos
// barrier amplification analysis. Centralized to avoid drift across the
// multiple printfs that reference this value.
static constexpr double LAMBDA_1_EMPIRICAL = 5.78;

// Period-scan threshold. For uniformly random bytes, the expected match
// rate at any non-trivial lag is 1/256 ≈ 0.39%. Flag the byte stream as
// suspicious if any tested period yields a match rate exceeding 1%.
static constexpr double PERIOD_SCAN_THRESHOLD = 0.01;

// Negative control sample size and entropy threshold.
// The plug-in MLE Shannon entropy estimator has a known downward bias for
// finite samples: bias = (k-1)/(2N ln 2). For 256-bin uniform random data
// at N=65536, expected H ≈ 7.99719 (NOT 8.0). A flat threshold of "ent <
// 7.999" would therefore false-positive on genuinely random data.
// The threshold below is set at 5× the bias below the theoretical maximum:
// at N=65536 this gives ≈ 7.986, lenient enough to accept true random
// while still detecting catastrophic entropy collapse (e.g. LSB → 0).
static constexpr int    NEG_CTRL_N_BYTES        = 65536;
static constexpr double NEG_CTRL_LN2            = 0.6931471805599453;
static constexpr double NEG_CTRL_ENTROPY_BIAS   =
    255.0 / (2.0 * (double)NEG_CTRL_N_BYTES * NEG_CTRL_LN2);
static constexpr double NEG_CTRL_ENTROPY_THRESH = 8.0 - 5.0 * NEG_CTRL_ENTROPY_BIAS;

// Spectral test (Goertzel DFT) — number of frequency bins probed per stream.
// Used identically for both negative-control generators and the MCL stream
// to ensure a fair comparison.
static constexpr int    SPECTRAL_TEST_K         = 2000;

// Period-scan parameters (PART 3).
// The scan tests every period p ∈ [2, MAX_PERIOD] for byte-level repetition
// in PERIOD_SCAN_BYTES of generated output.
static constexpr int64_t PERIOD_SCAN_BYTES      = 200000;
static constexpr int     PERIOD_SCAN_MAX_PERIOD = 20000;

// Chaos-saturation parameters (PART 4 — divergence-amplification test).
// CHAOS_MAX_ITER     — upper bound on iterations to detect saturation.
//                      Theoretical saturation iters ≈ ln(2π/ε) / λ. For the
//                      smallest ε=1e-15 and measured λ≈5.78, this gives
//                      ≈16 iters. 200 provides a comfortable safety factor
//                      while keeping the inner loop cheap.
// CHAOS_SAT_THRESH   — divergence (in radians, composite over both phases)
//                      considered "saturated". Composite divergence ranges
//                      over [0, π√2 ≈ 4.44]; 1.0 rad ≈ 57° corresponds to
//                      ~22% of the maximum and is well-clear of transient
//                      growth, so the iteration where dv first exceeds 1.0
//                      is a reliable saturation marker.
// CHAOS_DIVERGENCE_MIN — qualitative threshold for "sequential ≠ parallel"
//                      (PART 4A). For two random points on T² the expected
//                      raw |a−b| is 2π/3 ≈ 2.094; 0.1 is ~21× below that
//                      and is well clear of any reasonable noise floor —
//                      a binary "did the dynamics diverge" signal, not a
//                      precise distance bound.
static constexpr int    CHAOS_MAX_ITER         = 200;
static constexpr double CHAOS_SAT_THRESH       = 1.0;
static constexpr double CHAOS_DIVERGENCE_MIN   = 0.1;

static int g_total = 0, g_passed = 0;

void pq_check(const char* name, bool pass, const char* detail) {
 g_total++;
 if (pass) g_passed++;
 std::printf(" [%s] %-30s %s\n", pass ? "PASS" : "FAIL", name, detail);
}

// ============================================================================
// WEAK GENERATORS (Negative Control)
// ============================================================================
// WeakRANDU — IBM's RANDU LCG (1969) reproduced as 1D negative control.
//
// Seed handling: RANDU uses a 32-bit state and requires an odd seed. The
// constructor truncates the upper 32 bits of the supplied 64-bit seed, then
// forces the lowest bit to 1 via "| 1". For DEFAULT_SEED = 12345678901234
// this produces a deterministic 32-bit RANDU seed; if DEFAULT_SEED is ever
// changed, the upper 32 bits are silently discarded — bit-exact output is
// still reproducible across platforms because the truncation rule is fixed.
class WeakRANDU {
 uint32_t state_;
public:
 explicit WeakRANDU(uint64_t seed) : state_((uint32_t)(seed | 1)) {}
 uint8_t gen_byte() {
 state_ = (uint32_t)(65539ULL * state_) & 0x7FFFFFFFU;
 return (uint8_t)(state_ >> 16);
 }
 void gen_bytes(uint8_t* out, int64_t n) {
 for (int64_t i = 0; i < n; i++) out[i] = gen_byte();
 }
};

// WeakLSB — extracts only the LSB of consecutive PCG-XSL LCG states.
//
// Mathematical note on output structure:
//   The LCG state recurrence x_{n+1} = M·x_n + C (with M, C odd) yields
//   LSB(x_{n+1}) = LSB(x_n) ⊕ 1 — i.e., the LSB has period 2 and simply
//   alternates 0/1/0/1/.... Bytes built from 8 consecutive LSBs are
//   therefore CONSTANT — either 0xAA or 0x55 for the entire stream,
//   depending on the seed parity.
//
// Detection by PART 1 tests:
//   - Entropy ≈ 0 (single byte value present) → FAILS entropy threshold
//   - Chi² ≈ 16M (255 empty bins, 1 saturated bin) → FAILS chi-square
//   - Spectral SNR ≈ 0 (pure DC, no AC content) → SILENTLY PASSES
//
// The spectral test is designed to detect SINUSOIDAL periodicities; it
// does not catch constant-output failures by construction. The negative
// control here therefore exercises only the entropy and chi² methodologies;
// a separate constant-output check would be needed to validate spectral
// detection of degenerate streams. This is acknowledged scope, not a bug.
class WeakLSB {
 uint64_t state_;
public:
 explicit WeakLSB(uint64_t seed) : state_(seed) {}
 uint8_t gen_byte() {
 uint8_t b = 0;
 for (int i = 0; i < 8; i++) {
 state_ = 6364136223846793005ULL * state_ + 1442695040888963407ULL;
 b = (uint8_t)(((unsigned)b << 1) | (unsigned)(state_ & 1U));
 }
 return b;
 }
 void gen_bytes(uint8_t* out, int64_t n) {
 for (int64_t i = 0; i < n; i++) out[i] = gen_byte();
 }
};

// spectral_test() and SpectralResult already provided by mcl_core.hpp

// ============================================================================
// PERIOD SCAN
// Direct search for byte-level periodicity in output.
// For random: match rate ≈ 1/256 = 0.39%. Flag if > 1%.
// ============================================================================
struct PeriodResult { bool found; int max_period; double best_match; };

PeriodResult period_scan(const uint8_t* data, int64_t n, int max_period) {
 double best = 0;
 for (int p = 2; p <= max_period && p < n/4; p++) {
 int match = 0, tested = 0;
 for (int64_t i = 0; i + p < n && tested < 10000; i++, tested++)
 if (data[i] == data[i + p]) match++;
 double rate = (double)match / tested;
 if (rate > best) best = rate;
 }
 return {best > PERIOD_SCAN_THRESHOLD, max_period, best};
}

// ============================================================================
// SEQUENTIAL DEPENDENCY TEST
// MCL uses Gauss-Seidel: f₂ depends on f₁ (sequential).
// A parallel update (wrong) produces divergent output.
// A classical statement about the dynamics; it carries no claim about the
// cost of any quantum oracle (6.1.0).
// ============================================================================
struct SeqDepResult { double divergence; bool verified; };

SeqDepResult seq_dependency_test(uint64_t seed, int iters) {
 // Sequential (correct MCL — Gauss-Seidel)
 MCL_T2 seq_gen(seed, 3, 5);

 // Parallel (wrong — uses old θ₁ in f₂ instead of new f₁)
 // Uses mcl_core.hpp utilities (ECR compliance)
 double t1, t2;
 mcl_init_state(seed, t1, t2);
 for (int i = 0; i < BURNIN; i++)
 mcl_iterate_jacobi(t1, t2, 3, 5);

 // Distance metric choice: raw |a-b|, NOT torus min(|a-b|, 2π-|a-b|).
 // For two random points on T² that have decorrelated, E[raw |a-b|] = 2π/3
 // ≈ 2.094. CHAOS_DIVERGENCE_MIN is well clear of any reasonable noise
 // floor — a binary "did the dynamics diverge" check, not a precise
 // distance measurement. PART 4B (chaos barrier) uses torus distance because
 // there we reason about saturation at π; here we only need the qualitative
 // signal that sequential ≠ parallel.
 double total_div = 0;
 for (int i = 0; i < iters; i++) {
 seq_gen.iterate();
 mcl_iterate_jacobi(t1, t2, 3, 5);
 total_div += std::abs(seq_gen.theta1() - t1) + std::abs(seq_gen.theta2() - t2);
 }
 double mean_div = total_div / (2.0 * iters);
 return {mean_div, mean_div > CHAOS_DIVERGENCE_MIN};
}

// ============================================================================
// SECRET-SIZE ACCOUNTING (6.1.0)
// The secret of the two-oscillator configuration is the coprime pair (p, q).
// The seed is the PUBLIC challenge and contributes nothing. The number of
// ordered coprime pairs with p, q <= nmax is about (6/pi^2) * nmax^2.
// Generic key search halves the exponent; that is the only quantum statement
// made here, and it is a generic one.
// ============================================================================
struct PairSpace { double classical_bits; double generic_search_bits; };

PairSpace pair_space(double nmax) {
 double cl = std::log2(6.0 / (MCL_PI * MCL_PI) * nmax * nmax);
 return {cl, cl / 2.0};
}

// ============================================================================
// MAIN
// ============================================================================
int main() {
 auto t_start = std::chrono::steady_clock::now();

 std::printf("\n******************************************************************************\n");
 std::printf(" MCL CLASSICAL DIAGNOSTICS v%s  (file mcl_postquantum)\n", DOC_VERSION);
 std::printf(" NOT a quantum-security test -- see QUANTUM_SCOPE_NOTE.md\n");
 std::printf("******************************************************************************\n\n");
 std::printf(" Engine: MCL_T2, (3,5), K=%.1f, seed=%llu\n\n",
 K_DEFAULT, (unsigned long long)DEFAULT_SEED);

 const int64_t N = 1000000; // 1M bytes for spectral/period tests
 bool global_pass = true;

 // ========================================================================
 // PART 1: NEGATIVE CONTROL (Weak LCG → must FAIL)
 // ========================================================================
 sep("PART 1: NEGATIVE CONTROL (Weak RANDU + glibc-LSB)");

 std::printf(" Purpose: validate that our tests detect weaknesses.\n\n");
 int lcg_fails = 0;

 // Shared buffer for both negative-control generators. Each block fills,
 // tests, and reports independently — no inter-block state leakage.
 uint8_t neg_data[NEG_CTRL_N_BYTES];

 // RANDU
 {
 WeakRANDU randu(DEFAULT_SEED);
 randu.gen_bytes(neg_data, NEG_CTRL_N_BYTES);
 double ent = shannon_entropy(neg_data, NEG_CTRL_N_BYTES);
 double chi = chi_square(neg_data, NEG_CTRL_N_BYTES);
 auto spec = spectral_test(neg_data, NEG_CTRL_N_BYTES, SPECTRAL_TEST_K);

 std::printf(" RANDU (IBM, 1969):\n");
 std::printf(" Entropy: %.4f %s\n", ent,
 ent < NEG_CTRL_ENTROPY_THRESH ? "(WEAK)" : "(OK)");
 std::printf(" Chi²: %.0f %s\n", chi, chi > CHI2_THRESHOLD ? "(FAIL)" : "(OK)");
 std::printf(" Spectral SNR: %.1f %s\n", spec.snr, !spec.pass ? "(FAIL — periodic)" : "(OK)");
 // Note: RANDU's well-known weakness is its 3D spectral failure (lattice
 // structure with only 15 hyperplanes), which 1D byte-level tests do not
 // probe directly. RANDU is included as a "boundary case" generator;
 // the primary detection target is glibc-LSB below.
 if (ent < NEG_CTRL_ENTROPY_THRESH || chi > CHI2_THRESHOLD || !spec.pass) lcg_fails++;
 }

 // glibc LSB
 {
 WeakLSB lsb(DEFAULT_SEED);
 lsb.gen_bytes(neg_data, NEG_CTRL_N_BYTES);
 double ent = shannon_entropy(neg_data, NEG_CTRL_N_BYTES);
 double chi = chi_square(neg_data, NEG_CTRL_N_BYTES);
 auto spec = spectral_test(neg_data, NEG_CTRL_N_BYTES, SPECTRAL_TEST_K);

 std::printf("\n glibc-LSB (linear congruential, LSB extraction):\n");
 std::printf(" Entropy: %.4f %s\n", ent,
 ent < NEG_CTRL_ENTROPY_THRESH ? "(WEAK)" : "(OK)");
 std::printf(" Chi²: %.0f %s\n", chi, chi > CHI2_THRESHOLD ? "(FAIL)" : "(OK)");
 std::printf(" Spectral SNR: %.1f %s\n", spec.snr, !spec.pass ? "(FAIL — periodic)" : "(OK)");
 if (ent < NEG_CTRL_ENTROPY_THRESH || chi > CHI2_THRESHOLD || !spec.pass) lcg_fails++;
 }

 std::printf("\n Weak generator failures: %d (need ≥ 1 to validate methodology)\n", lcg_fails);
 pq_check("Negative Control", lcg_fails > 0,
 lcg_fails > 0 ? "tests detect weaknesses" : "WARNING — weak generators not caught");
 if (lcg_fails == 0) global_pass = false;

 // ========================================================================
 // PART 2: SPECTRAL PURITY (Goertzel DFT on MCL output)
 // ========================================================================
 sep("PART 2: SPECTRAL TEST (Goertzel DFT)");

 MCL_T2 gen_spec(DEFAULT_SEED, 3, 5);
 std::vector<uint8_t> spec_data((size_t)std::min(N, (int64_t)NEG_CTRL_N_BYTES));
 gen_spec.gen_bytes(spec_data.data(), (int64_t)spec_data.size());

 auto spec = spectral_test(spec_data.data(), (int64_t)spec_data.size(),
 SPECTRAL_TEST_K);
 std::printf(" Data: %zu bytes, K=%d frequencies tested\n",
 spec_data.size(), SPECTRAL_TEST_K);
 std::printf(" Max peak: %.6e at freq %d\n", spec.max_peak, spec.peak_freq);
 std::printf(" Noise floor: %.6e\n", spec.noise_avg);
 std::printf(" SNR: %.2f (threshold < %.1f)\n", spec.snr, SPECTRAL_SNR_THRESHOLD);
 pq_check("Spectral (Goertzel)", spec.pass,
 spec.pass ? "no peak above threshold" : "spectral peak detected");
 if (!spec.pass) global_pass = false;

 // ========================================================================
 // PART 3: PERIOD SCAN (direct period search)
 // ========================================================================
 sep("PART 3: PERIOD SCAN (Direct Search)");

 MCL_T2 gen_per(DEFAULT_SEED, 3, 5);
 std::vector<uint8_t> per_data((size_t)PERIOD_SCAN_BYTES);
 gen_per.gen_bytes(per_data.data(), PERIOD_SCAN_BYTES);

 auto per = period_scan(per_data.data(), PERIOD_SCAN_BYTES,
 PERIOD_SCAN_MAX_PERIOD);
 std::printf(" Data: %lld bytes, periods 2..%d tested\n",
 (long long)PERIOD_SCAN_BYTES, per.max_period);
 std::printf(" Best match rate: %.4f%% (threshold < %.2f%%)\n",
 per.best_match * 100, PERIOD_SCAN_THRESHOLD * 100);
 std::printf(" Expected (random): %.2f%% (1/256)\n", 100.0/256.0);
 pq_check("Period Scan", !per.found,
 !per.found ? "no period in tested range" : "periodicity detected");
 if (per.found) global_pass = false;

 // ========================================================================
 // PART 4: SEQUENTIAL DEPENDENCY (Gauss-Seidel vs Parallel)
 // ========================================================================
 sep("PART 4: UPDATE ORDER (Gauss-Seidel vs Parallel)");

 auto dep = seq_dependency_test(DEFAULT_SEED, 10000);
 std::printf(" Iterations: 10000\n");
 std::printf(" Mean divergence (seq vs par): %.4f (threshold > 0.1)\n", dep.divergence);
 std::printf(" Meaning: the two update orders give different trajectories.\n");
 std::printf(" A statement about the classical dynamics; it says nothing about\n");
 std::printf(" the cost of a quantum oracle.\n");
 pq_check("Sequential Dependency", dep.verified,
 dep.verified ? "Gauss-Seidel divergence confirmed" : "no divergence — check");
 if (!dep.verified) global_pass = false;

 // ========================================================================
 // PART 4B: CHAOS BARRIER (Exponential Divergence from ε Perturbation)
 // ========================================================================
 sep("PART 4B: SENSITIVITY (Growth of a Perturbation)");

 // Theoretical chaos amplification over the burn-in window. Computed once
 // and reused in both the introductory description and the closing note.
 const double log10_amp = LAMBDA_1_EMPIRICAL * (double)BURNIN / std::log(10.0);

 std::printf(" A perturbation of ε in the initial state grows by e^(λ₁×N)\n");
 std::printf(" after N iterations. With λ₁ ≈ %.2f and N = %d (burn-in):\n",
 LAMBDA_1_EMPIRICAL, BURNIN);
 std::printf(" amplification = e^(%.2f × %d) = 10^%.0f\n\n",
 LAMBDA_1_EMPIRICAL, BURNIN, log10_amp);

 std::printf(" Empirical verification (ε = 10⁻¹⁵ to 10⁻³):\n");
 std::printf(" ε Sat iters Amplification bits Status\n");
 std::printf(" %s\n", std::string(58, '-').c_str());

 double epsilons[] = {1e-15, 1e-12, 1e-9, 1e-6, 1e-3};
 bool chaos_pass = true;

 for (double eps : epsilons) {
 // Two trajectories from same seed: one exact, one perturbed by ε
 // Uses mcl_core.hpp utilities (ECR compliance)
 double t1, t2;
 mcl_init_state(DEFAULT_SEED, t1, t2);
 double p1 = mod2pi(t1 + eps), p2 = t2;

 double max_div = 0;
 int sat_iter = CHAOS_MAX_ITER;   // sentinel: "no saturation seen"

 for (int i = 1; i <= CHAOS_MAX_ITER; i++) {
 // Unperturbed
 mcl_iterate_raw(t1, t2, 3, 5);
 // Perturbed
 mcl_iterate_raw(p1, p2, 3, 5);

 double d1 = std::abs(t1 - p1);
 d1 = std::min(d1, MCL_TWO_PI - d1);
 double d2 = std::abs(t2 - p2);
 d2 = std::min(d2, MCL_TWO_PI - d2);
 double dv = std::sqrt(d1*d1 + d2*d2);
 if (dv > max_div) max_div = dv;
 if (dv > CHAOS_SAT_THRESH && sat_iter == CHAOS_MAX_ITER) sat_iter = i;
 }

 double amp_bits = (max_div > 0 && eps > 0) ? std::log2(max_div / eps) : 0;
 std::printf(" %.0e %3d %.1f %s\n",
 eps, sat_iter, amp_bits,
 sat_iter < CHAOS_MAX_ITER ? "SATURATED" : "GROWING");
 if (sat_iter >= CHAOS_MAX_ITER) chaos_pass = false;
 }

 std::printf("\n Theoretical (unbounded system): e^(%.2f × %d) = 10^%.0f\n",
 LAMBDA_1_EMPIRICAL, BURNIN, log10_amp);
 std::printf(" NOTE: On the torus T² = [0,2π)², divergence SATURATES at ≈ π.\n");
 std::printf(" The 10^%.0f figure is a linear extrapolation of the Lyapunov\n",
 log10_amp);
 std::printf(" exponent for an unbounded system. Empirically, small ε saturates\n");
 std::printf(" within ~50 iterations (see table above). Any perturbation, no matter\n");
 std::printf(" how small, reaches full decorrelation — the RATE is exponential,\n");
 std::printf(" the AMOUNT is bounded by π. This is sensitivity of the iteration;\n");
 std::printf(" a finite-precision realization is still eventually periodic.\n");
 pq_check("Sensitivity", chaos_pass,
 chaos_pass ? "exponential divergence confirmed" : "insufficient divergence");
 if (!chaos_pass) global_pass = false;

 // ========================================================================
 // PART 5: SECRET-SIZE ACCOUNTING UNDER GENERIC KEY SEARCH
 // ========================================================================
 sep("PART 5: SECRET-SIZE ACCOUNTING (Generic Key Search)");

 std::printf(" The secret of this configuration is the coprime pair (p, q).\n");
 std::printf(" The seed is the PUBLIC challenge and is not counted.\n");
 std::printf(" Generic key search (Grover) halves the exponent of any secret.\n");
 std::printf(" NIST Categories 1 / 3 / 5 are anchored to key search on AES-128 /\n");
 std::printf(" 192 / 256, i.e. 64 / 96 / 128 bits after halving (query count).\n\n");

 std::printf(" %-22s %-16s %-16s %s\n", "Range of p, q", "Classical bits", "After halving", "Against 64");
 std::printf(" %s\n", std::string(70, '-').c_str());
 struct Rng { const char* name; double nmax; };
 Rng ranges[] = {
 {"[2, 10^6]",  1e6},
 {"[2, 10^9]",  1e9},
 {"[2, 10^12]", 1e12},
 {"[2, 10^15]", 1e15},
 {"[2, 2^53] (engine cap)", 9007199254740992.0}
 };
 for (auto& r : ranges) {
 auto k = pair_space(r.nmax);
 std::printf(" %-22s %-16.1f %-16.1f %s\n", r.name, k.classical_bits,
 k.generic_search_bits, k.generic_search_bits < 64 ? "below" : "at or above");
 }
 std::printf("\n A pair (p, q) alone is below the 64-bit level at every range, up to and\n");
 std::printf(" including the engine's cap: weights above 2^53 are not exactly\n");
 std::printf(" representable in double precision (MCL_PQ_MAX).\n");
 std::printf(" The 256-bit keyed configuration (keyed_q30_PQ/) carries the key in\n");
 std::printf(" twelve weights; for it generic key search costs about 2^128 oracle\n");
 std::printf(" calls.\n");
 std::printf(" That is a generic figure. It holds only in the absence of a structural\n");
 std::printf(" attack, which this program does not examine.\n");

 // ========================================================================
 // PART 6: WHAT THESE DIAGNOSTICS DO NOT SHOW
 // ========================================================================
 sep("PART 6: WHAT THESE DIAGNOSTICS DO NOT SHOW");

 std::printf(" 1. No quantum algorithm is run, simulated or bounded by this program.\n");
 std::printf(" 2. A spectral test on %d bytes and a period scan up to %d say nothing\n",
 NEG_CTRL_N_BYTES, PERIOD_SCAN_MAX_PERIOD);
 std::printf("    about longer periods. Every finite-precision realization is\n");
 std::printf("    eventually periodic; cycle lengths are measured in T4_CycleStructure/.\n");
 std::printf(" 3. The construction has no public key, no modulus to factor and no\n");
 std::printf("    discrete logarithm to take. That is read off the construction, not\n");
 std::printf("    measured here, and it says nothing about other period-finding\n");
 std::printf("    attacks (point 4).\n");
 std::printf(" 4. The integer map has an exact translation symmetry of its state\n");
 std::printf("    (T4_CycleStructure/). Absence of structure is therefore not claimed.\n");
 std::printf(" 5. Whether a quantum algorithm shortens the sequential depth of the\n");
 std::printf("    iteration is open.\n");
 std::printf(" 6. No proof, no reduction to a standard assumption, and no independent\n");
 std::printf("    cryptanalysis exist for the map.\n");

 // ========================================================================
 // SUMMARY
 // ========================================================================
 double elapsed = std::chrono::duration<double>(
 std::chrono::steady_clock::now() - t_start).count();

 sep("SUMMARY OF THE DIAGNOSTICS");

 std::printf(" Diagnostics passed: %d / %d\n\n", g_passed, g_total);
 std::printf(" Negative control: weak generators detected (%d %s)\n",
 lcg_fails, lcg_fails == 1 ? "failure" : "failures");
 std::printf(" Spectral SNR: %.2f < %.1f\n", spec.snr, SPECTRAL_SNR_THRESHOLD);
 std::printf(" Period scan: %.4f%% < %.2f%%\n",
 per.best_match * 100, PERIOD_SCAN_THRESHOLD * 100);
 std::printf(" Update order: %.4f (Gauss-Seidel vs parallel, mean divergence)\n", dep.divergence);
 std::printf(" Sensitivity: saturation reached for every tested perturbation: %s\n",
 chaos_pass ? "yes" : "no");

 std::printf("\n +================================================================+\n");
 std::printf(" | DIAGNOSTICS: %s |\n",
 global_pass ? "ALL PASSED                                       "
 : "ISSUES DETECTED                                  ");
 std::printf(" | No statement about quantum security is made by this program.  |\n");
 std::printf(" +================================================================+\n");

 std::printf("\n Time: %.1f seconds\n", elapsed);
 std::printf("\n %s v%s | Madeeh Ibrahim, Cairo\n", DOC_ID, DOC_VERSION);
 std::printf("==============================================================================\n");

 return global_pass ? 0 : 1;
}
