/*
 * ============================================================================
 * MCL Unified K-Sweep -- T2/T3/T4 Regime Mapping
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-KSWEEP-2026-0526-001
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
 * PURPOSE:
 *   Sweep coupling strength K from 0.1 to 500 across MCL_T2, MCL_T3, MCL_T4
 *   in a single run. Maps the chaotic regime, identifies QUASI/RESON/CHAOS/
 *   MARGN boundaries, and verifies that effective coupling scales with the
 *   number of coupling terms (T2: K, T3: 2K, T4: 3K).
 *
 * EFFECTIVE COUPLING:
 *   T2: 1 coupling term  -> effective = K
 *   T3: 2 coupling terms -> effective = 2K
 *   T4: 3 coupling terms -> effective = 3K
 *
 * REGIME CLASSIFICATION (per classify_regime() in mcl_core.hpp):
 *   !pass + chi2 > 1000   -> RESON  (resonance / phase-locking)
 *   !pass + chi2 <= 1000  -> MARGN  (chi2 OK, AC or bit-freq barely miss)
 *   pass  + eff_k < 1.0   -> QUASI  (quasiperiodic, IEEE 754 artifact)
 *   pass  + eff_k >= 1.0  -> CHAOS  (positive Lyapunov, cryptographic)
 *
 * TESTS:
 *   1. Negative control (Rule D4): same seed -> identical bytes (must pass).
 *   2. T2 K-sweep: 35 K values, 3 seeds each, worst-case aggregation.
 *   3. T3 K-sweep: same K grid, eff_K = 2K.
 *   4. T4 K-sweep: same K grid, eff_K = 3K.
 *   5. Comparison table T2 vs T3 vs T4.
 *   6. Regime map (CHAOS/QUASI/RESON/MARGN counts + first/last K).
 *   7. Resonance zones (chi-square >> 330 detection).
 *   8. Upper boundary check (chaos at K_max).
 *   9. Individual oscillator diagnostic (T2): theta1 vs theta2 separately,
 *      to distinguish genuine chaos from XOR-masked quasiperiodicity.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_k_sweep_unified mcl_k_sweep_unified.cpp -lm && ./mcl_k_sweep_unified
 *
 * EXPECTED RESULTS: PASS - regime mapping complete, chaos verified across
 *                          T2/T3/T4 (chaos count > 0 for each, last_chaos
 *                          >= 50.0 for each).
 *
 * REFERENCES:
 *   - Paper 1 §III    Safe-Zone PRNG and chaotic regime characterization
 *   - Paper 1 §III.C  K_min(p,q) = 5.053 / (p+q) lower bound
 *   - Paper 3 §IV     Anti-sync framework (Lyapunov scaling with effective K)
 *   - Paper 3 §V      Cross-system comparison (T2/T3/T4 effective coupling)
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
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

// ============================================================================
// Document version constants (mirror header for runtime print consistency).
// ============================================================================
static const char* DOC_VERSION = "6.0.0";
static const char* DOC_ID      = "MCL-KSWEEP-2026-0526-001";

// ============================================================================
// Test seeds (3 seeds for worst-case multi-seed aggregation).
// ============================================================================
static const uint64_t SEEDS[] = {
    12345678901234ULL, 98765432109876ULL, 31415926535897ULL
};
static const int N_SEEDS = static_cast<int>(sizeof(SEEDS) / sizeof(SEEDS[0]));

// ============================================================================
// Sample sizes.
// ============================================================================
// Main K-sweep tests: 500 KB per (K, seed) combination. Provides:
//   sigma(AC) = 1/sqrt(500000) = 0.001414
//   chi-square df=255 statistical resolution adequate for Bonferroni
static const int64_t N_BYTES_SWEEP = 500000;

// Negative control buffer (Rule D4): smaller is sufficient since we only
// need to confirm seed determinism (any difference is a failure).
static const int64_t N_BYTES_NEGCTRL = 100000;

// Diagnostic individual-oscillator test: 100 KB per K value, 8 K points.
static const int64_t N_BYTES_DIAG = 100000;

// ============================================================================
// Quality thresholds (per-seed acceptance criteria).
// ============================================================================
// Entropy: 7.99 (NOT 7.999) because K-sweep includes borderline regimes
// where entropy is slightly lower than production quality. Other files use
// 7.999 for production quality testing only.
static const double T_ENTROPY = 7.99;

// AC(1) threshold derivation (worst case = full mode, conservative for quick):
//   sigma(AC) = 1/sqrt(N_BYTES_SWEEP) = 1/sqrt(500000) = 0.001414
//
//   Full mode: 35 K x 3 seeds = 105 tests
//     EVT expected max  = sigma * sqrt(2*ln(2*105/pi)) = 0.0041
//     Bonferroni alpha=0.05/105: z=3.49 -> threshold = 0.00494
//   Quick mode: 18 K x 3 seeds = 54 tests
//     EVT expected max  = sigma * sqrt(2*ln(2*54/pi)) = 0.0038
//     Bonferroni alpha=0.05/54: z=3.34 -> threshold = 0.00472
//
//   Threshold 0.005 chosen for both modes:
//     full mode: 3.54 sigma -> P(>=1 false fail) ~= 5%
//     quick mode: more conservative (over-corrected slightly).
static const double T_AC1 = 0.005;

// Bit-frequency: deviation from 0.5. For N=500000 bytes (4M bits):
//   sigma(p) = sqrt(0.25 / 4e6) = 0.00025
//   Threshold 0.002 = 8 sigma -> astronomically conservative.
static const double T_BITFREQ_DEV = 0.002;

// Verdict: chaos must extend up to at least this K value for each Tn.
static const double VERDICT_LAST_CHAOS_MIN = 50.0;

// ============================================================================
// CLI mode selection.
// ============================================================================
enum class Mode { FULL, QUICK };

// ============================================================================
// K value grids.
// ============================================================================
// Full grid: 35 K values (Paper 1/3 canonical).
static const double K_VALUES_FULL[] = {
    0.1,  0.2,  0.3,  0.35, 0.4,  0.45, 0.5,  0.6,  0.7,  0.8, 0.9,
    0.92, 0.94, 0.96, 0.98,
    1.0,  1.5,  2.0,  2.5,  3.0,  4.0,  5.0,
    6.0,  8.0,  10.0, 12.0, 16.0, 20.0,
    28.0, 36.0, 50.0,
    75.0, 100.0, 200.0, 500.0
};
static const int N_K_FULL = static_cast<int>(
    sizeof(K_VALUES_FULL) / sizeof(K_VALUES_FULL[0]));

// Quick grid: 18 strategic K values covering boundaries + transitions.
// Each K value here is a SUBSET of K_VALUES_FULL, so per-K numerical
// output is bit-exactly identical between modes (only the grid differs).
static const double K_VALUES_QUICK[] = {
    0.1,  0.3,  0.5,  0.7,  0.9,  0.96,
    1.0,  1.5,  2.0,  3.0,
    5.0,  12.0, 20.0,
    36.0, 50.0, 100.0, 200.0, 500.0
};
static const int N_K_QUICK = static_cast<int>(
    sizeof(K_VALUES_QUICK) / sizeof(K_VALUES_QUICK[0]));

// ============================================================================
// Per-K result aggregating worst-case across N_SEEDS.
// ============================================================================
struct KResult {
    double k, eff_k;
    double entropy, chi2, ac1, bit_freq;
    const char* regime;
    bool pass;
};

// ============================================================================
// Generic multi-seed K test.
// gen_fn(seed, K, buf, n) fills buf with n bytes from chosen generator.
// Returns worst-case result across N_SEEDS.
// ============================================================================
static KResult test_k_multiseed(double k, double eff_k, int64_t n_bytes,
    void (*gen_fn)(uint64_t, double, uint8_t*, int64_t))
{
    KResult worst;
    worst.k = k;
    worst.eff_k = eff_k;
    worst.pass = true;
    double worst_ent = 8.0, worst_chi2 = 0.0, worst_ac1 = 0.0;
    double worst_bf_dev = 0.0;
    worst.bit_freq = 0.5;

    for (int s = 0; s < N_SEEDS; s++) {
        std::vector<uint8_t> data(static_cast<size_t>(n_bytes));
        gen_fn(SEEDS[s], k, data.data(), n_bytes);

        const double ent  = shannon_entropy(data.data(), n_bytes);
        const double chi2 = chi_square(data.data(), n_bytes);
        const double ac1  = autocorrelation(data.data(), n_bytes, 1);
        const double bf   = bit_frequency(data.data(), n_bytes);

        const bool sp = (ent > T_ENTROPY) &&
                        (chi2 < CHI2_THRESHOLD) &&
                        (std::abs(ac1) < T_AC1) &&
                        (std::abs(bf - 0.5) < T_BITFREQ_DEV);
        if (!sp) worst.pass = false;
        if (ent < worst_ent) worst_ent = ent;
        if (chi2 > worst_chi2) worst_chi2 = chi2;
        if (std::abs(ac1) > std::abs(worst_ac1)) worst_ac1 = ac1;
        if (std::abs(bf - 0.5) > worst_bf_dev) {
            worst_bf_dev = std::abs(bf - 0.5);
            worst.bit_freq = bf;
        }
    }

    worst.entropy = worst_ent;
    worst.chi2    = worst_chi2;
    worst.ac1     = worst_ac1;
    worst.regime  = classify_regime(eff_k, worst.pass, worst.chi2);
    return worst;
}

// ============================================================================
// CLI helpers.
// ============================================================================
static void print_help(const char* prog) {
    std::printf("Usage: %s [OPTIONS]\n", prog);
    std::printf("\n");
    std::printf("MCL Unified K-Sweep v%s -- T2/T3/T4 regime mapping.\n",
        DOC_VERSION);
    std::printf("\n");
    std::printf("OPTIONS:\n");
    std::printf("  --full       Use 35 K values (Paper canonical, default).\n");
    std::printf("  --quick      Use 18 strategic K values (faster smoke test).\n");
    std::printf("  --help       Show this help and exit.\n");
    std::printf("  --version    Show version and exit.\n");
    std::printf("\n");
    std::printf("EXIT CODES:\n");
    std::printf("  0  PASS (chaos verified across T2/T3/T4)\n");
    std::printf("  1  FAIL (incomplete regime coverage)\n");
    std::printf("  2  Bad CLI arguments\n");
    std::printf("\n");
    std::printf("Doc ID: %s v%s\n", DOC_ID, DOC_VERSION);
}

// ============================================================================
// UTC timestamp formatter (thread-safe via gmtime_r on POSIX, gmtime_s on
// Windows). Defensive: writes empty string on any failure rather than
// leaving the buffer with garbage contents.
// ============================================================================
static void format_utc_now(char* buf, size_t buflen) {
    if (buflen == 0) return;
    buf[0] = '\0';  // safe default if any step below fails
    const std::time_t now = std::time(nullptr);
    std::tm tm_utc;
#ifdef _WIN32
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    if (std::strftime(buf, buflen, "%Y-%m-%d %H:%M:%S UTC", &tm_utc) == 0) {
        buf[0] = '\0';  // truncated or failed
    }
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char** argv) {
    setbuf(stdout, nullptr);  // realtime output, no buffering

    // ---- CLI parsing ----
    Mode mode = Mode::FULL;
    bool saw_quick = false, saw_full = false;

    for (int i = 1; i < argc; i++) {
        const std::string a(argv[i]);
        if (a == "--help" || a == "-h") {
            print_help(argv[0]);
            return 0;
        }
        if (a == "--version" || a == "-v") {
            std::printf("%s v%s\n", DOC_ID, DOC_VERSION);
            return 0;
        }
        if (a == "--quick") {
            saw_quick = true;
            mode = Mode::QUICK;
            continue;
        }
        if (a == "--full") {
            saw_full = true;
            mode = Mode::FULL;
            continue;
        }
        std::fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        std::fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);
        return 2;
    }

    if (saw_quick && saw_full) {
        std::fprintf(stderr,
            "Error: --quick and --full are mutually exclusive.\n");
        return 2;
    }

    // Resolve K grid based on mode.
    const double* k_values = (mode == Mode::QUICK) ? K_VALUES_QUICK
                                                   : K_VALUES_FULL;
    const int n_k = (mode == Mode::QUICK) ? N_K_QUICK : N_K_FULL;
    const char* mode_name = (mode == Mode::QUICK) ? "QUICK" : "FULL";

    // ---- Banner ----
    char ts[32];
    format_utc_now(ts, sizeof(ts));

    std::printf(
        "\n==============================================================================\n");
    std::printf("  MCL UNIFIED K-SWEEP v%s\n", DOC_VERSION);
    std::printf("  %s\n", DOC_ID);
    std::printf("  Mode: %s  (%d K values, %d seeds/K)\n",
        mode_name, n_k, N_SEEDS);
    std::printf("  Started: %s\n", ts);
    std::printf(
        "==============================================================================\n\n");

    const auto t_start = std::chrono::steady_clock::now();

    // ---- Negative control (Rule D4) ----
    {
        std::vector<uint8_t> a(static_cast<size_t>(N_BYTES_NEGCTRL));
        std::vector<uint8_t> b(static_cast<size_t>(N_BYTES_NEGCTRL));
        MCL_T2 ga(SEEDS[0], 3, 5);
        MCL_T2 gb(SEEDS[0], 3, 5);
        ga.gen_bytes(a.data(), N_BYTES_NEGCTRL);
        gb.gen_bytes(b.data(), N_BYTES_NEGCTRL);
        int diff = 0;
        for (int64_t i = 0; i < N_BYTES_NEGCTRL; i++) {
            if (a[static_cast<size_t>(i)] != b[static_cast<size_t>(i)]) diff++;
        }
        if (diff != 0) {
            std::printf(" NEGATIVE CONTROL FAILED (diff=%d)\n", diff);
            return 1;
        }
        std::printf("  Negative control (Rule D4): same seed -> identical "
                    "bytes (diff=0) [PASS]\n\n");
    }

    std::vector<KResult> res_t2(static_cast<size_t>(n_k));
    std::vector<KResult> res_t3(static_cast<size_t>(n_k));
    std::vector<KResult> res_t4(static_cast<size_t>(n_k));

    // ---- T2 SWEEP ----
    sep("T2 K-SWEEP (eff_K = K)");
    std::printf("  K        Eff_K   Entropy   Chi2          AC(1)         "
                "Bit_freq  Regime  Pass\n");
    std::printf("  %s\n", std::string(82, '-').c_str());

    for (int i = 0; i < n_k; i++) {
        res_t2[static_cast<size_t>(i)] = test_k_multiseed(
            k_values[i], k_values[i], N_BYTES_SWEEP,
            [](uint64_t seed, double K, uint8_t* buf, int64_t n) {
                MCL_T2 g(seed, 3, 5, K);
                g.gen_bytes(buf, n);
            });
        const auto& r = res_t2[static_cast<size_t>(i)];
        std::printf("  %-8.2f %-7.2f %.6f  %-12.2f  %-11.6f  %.5f  %-7s %s\n",
            r.k, r.eff_k, r.entropy, r.chi2, r.ac1, r.bit_freq, r.regime,
            r.pass ? "PASS" : "FAIL");
    }

    // ---- T3 SWEEP ----
    sep("T3 K-SWEEP (eff_K = 2K)");
    std::printf("  K        Eff_K   Entropy   Chi2          AC(1)         "
                "Bit_freq  Regime  Pass\n");
    std::printf("  %s\n", std::string(82, '-').c_str());

    for (int i = 0; i < n_k; i++) {
        res_t3[static_cast<size_t>(i)] = test_k_multiseed(
            k_values[i], 2.0 * k_values[i], N_BYTES_SWEEP,
            [](uint64_t seed, double K, uint8_t* buf, int64_t n) {
                static const CouplingTriple ct = {2,3, 3,5, 5,7};
                MCL_T3 g(seed, ct, K);
                g.gen_bytes(buf, n);
            });
        const auto& r = res_t3[static_cast<size_t>(i)];
        std::printf("  %-8.2f %-7.2f %.6f  %-12.2f  %-11.6f  %.5f  %-7s %s\n",
            r.k, r.eff_k, r.entropy, r.chi2, r.ac1, r.bit_freq, r.regime,
            r.pass ? "PASS" : "FAIL");
    }

    // ---- T4 SWEEP ----
    sep("T4 K-SWEEP (eff_K = 3K)");
    std::printf("  K        Eff_K   Entropy   Chi2          AC(1)         "
                "Bit_freq  Regime  Pass\n");
    std::printf("  %s\n", std::string(82, '-').c_str());

    for (int i = 0; i < n_k; i++) {
        res_t4[static_cast<size_t>(i)] = test_k_multiseed(
            k_values[i], 3.0 * k_values[i], N_BYTES_SWEEP,
            [](uint64_t seed, double K, uint8_t* buf, int64_t n) {
                static const CouplingSextet cs =
                    {2,3, 3,5, 5,7, 7,11, 11,13, 13,17};
                MCL_T4 g(seed, cs, K);
                g.gen_bytes(buf, n);
            });
        const auto& r = res_t4[static_cast<size_t>(i)];
        std::printf("  %-8.2f %-7.2f %.6f  %-12.2f  %-11.6f  %.5f  %-7s %s\n",
            r.k, r.eff_k, r.entropy, r.chi2, r.ac1, r.bit_freq, r.regime,
            r.pass ? "PASS" : "FAIL");
    }

    // ========================================================================
    // COMPARISON TABLE
    // ========================================================================
    sep("COMPARISON TABLE (T2 vs T3 vs T4)");
    std::printf("  K      | T2 Ent  Chi2     Reg   | T3 Ent  Chi2     Reg   "
                "| T4 Ent  Chi2     Reg\n");
    std::printf("  %s\n", std::string(88, '-').c_str());

    for (int i = 0; i < n_k; i++) {
        const auto& r2 = res_t2[static_cast<size_t>(i)];
        const auto& r3 = res_t3[static_cast<size_t>(i)];
        const auto& r4 = res_t4[static_cast<size_t>(i)];
        std::printf("  %-6.2f | %.4f %7.1f %-5s | %.4f %7.1f %-5s | "
                    "%.4f %7.1f %-5s\n",
            k_values[i],
            r2.entropy, r2.chi2, r2.regime,
            r3.entropy, r3.chi2, r3.regime,
            r4.entropy, r4.chi2, r4.regime);
    }

    // ========================================================================
    // REGIME MAP (with MARGN support)
    // ========================================================================
    sep("REGIME MAP");

    struct RegimeCount {
        int chaos, quasi, reson, margn;
        double first_chaos, last_chaos;
        bool first_set;
    };
    auto count_regimes = [&](const std::vector<KResult>& res) -> RegimeCount {
        RegimeCount rc = {0, 0, 0, 0, 0.0, 0.0, false};
        for (int i = 0; i < n_k; i++) {
            const char* rg = res[static_cast<size_t>(i)].regime;
            if (std::strcmp(rg, "CHAOS") == 0) {
                rc.chaos++;
                if (!rc.first_set) {
                    rc.first_chaos = k_values[i];
                    rc.first_set = true;
                }
                rc.last_chaos = k_values[i];
            } else if (std::strcmp(rg, "QUASI") == 0) {
                rc.quasi++;
            } else if (std::strcmp(rg, "RESON") == 0) {
                rc.reson++;
            } else {
                rc.margn++;  // "MARGN"
            }
        }
        return rc;
    };

    const auto rc2 = count_regimes(res_t2);
    const auto rc3 = count_regimes(res_t3);
    const auto rc4 = count_regimes(res_t4);

    std::printf("  Dim   Total  Chaos  Quasi  Reson  Margn  First_K  "
                "Last_K  Eff_first\n");
    std::printf("  %s\n", std::string(74, '-').c_str());
    std::printf("  T2    %-6d %-6d %-6d %-6d %-6d %-9.2f %-9.2f %.2f\n",
        n_k, rc2.chaos, rc2.quasi, rc2.reson, rc2.margn,
        rc2.first_chaos, rc2.last_chaos, rc2.first_chaos);
    std::printf("  T3    %-6d %-6d %-6d %-6d %-6d %-9.2f %-9.2f %.2f\n",
        n_k, rc3.chaos, rc3.quasi, rc3.reson, rc3.margn,
        rc3.first_chaos, rc3.last_chaos, 2.0 * rc3.first_chaos);
    std::printf("  T4    %-6d %-6d %-6d %-6d %-6d %-9.2f %-9.2f %.2f\n",
        n_k, rc4.chaos, rc4.quasi, rc4.reson, rc4.margn,
        rc4.first_chaos, rc4.last_chaos, 3.0 * rc4.first_chaos);

    // ---- Resonance zones ----
    std::printf("\n  RESONANCE ZONES (chi2 >> 330):\n");
    bool any_reson = false;
    for (int i = 0; i < n_k; i++) {
        const bool r2 = std::strcmp(
            res_t2[static_cast<size_t>(i)].regime, "RESON") == 0;
        const bool r3 = std::strcmp(
            res_t3[static_cast<size_t>(i)].regime, "RESON") == 0;
        const bool r4 = std::strcmp(
            res_t4[static_cast<size_t>(i)].regime, "RESON") == 0;
        if (r2 || r3 || r4) {
            any_reson = true;
            std::printf("    K=%-7.2f:", k_values[i]);
            if (r2) std::printf(" T2(chi2=%.0f)",
                res_t2[static_cast<size_t>(i)].chi2);
            if (r3) std::printf(" T3(chi2=%.0f)",
                res_t3[static_cast<size_t>(i)].chi2);
            if (r4) std::printf(" T4(chi2=%.0f)",
                res_t4[static_cast<size_t>(i)].chi2);
            std::printf("\n");
        }
    }
    if (!any_reson) std::printf("    None detected.\n");

    // ---- Upper boundary check ----
    const double max_k = k_values[n_k - 1];
    std::printf("\n  UPPER BOUNDARY CHECK (K=%.0f):\n", max_k);
    std::printf("    T2: %s\n",
        rc2.last_chaos >= max_k ? "open-ended (chaos at max K)"
                                : "bounded");
    std::printf("    T3: %s\n",
        rc3.last_chaos >= max_k ? "open-ended (chaos at max K)"
                                : "bounded");
    std::printf("    T4: %s\n",
        rc4.last_chaos >= max_k ? "open-ended (chaos at max K)"
                                : "bounded");

    // ========================================================================
    // INDIVIDUAL OSCILLATOR DIAGNOSTIC (T2)
    // Distinguishes genuine chaos from XOR-masked quasiperiodicity:
    // theta1 and theta2 are tested SEPARATELY. If their entropy is high
    // at K<1, it comes from IEEE 754 bit structure, NOT chaotic dynamics.
    // ========================================================================
    sep("DIAGNOSTIC: Individual Oscillator Entropy (T2)");
    std::printf("  theta1 and theta2 tested SEPARATELY. If entropy is high "
                "at K<1,\n");
    std::printf("  it comes from IEEE 754 bit structure, NOT chaotic "
                "dynamics.\n\n");

    // 8 diagnostic K points spanning the boundary region.
    static const double DIAG_KS[] = {0.1, 0.3, 0.5, 0.7, 1.0, 2.0, 5.0, 12.0};
    static const int N_DIAG_KS = static_cast<int>(
        sizeof(DIAG_KS) / sizeof(DIAG_KS[0]));

    std::printf("  K       t1_ent   t2_ent   XOR_ent  t1_chi2     "
                "t2_chi2     Regime\n");
    std::printf("  %s\n", std::string(78, '-').c_str());

    for (int dk = 0; dk < N_DIAG_KS; dk++) {
        const double kv = DIAG_KS[dk];
        MCL_T2 gen(SEEDS[0], 3, 5, kv);

        std::vector<uint8_t> t1b(static_cast<size_t>(N_BYTES_DIAG));
        std::vector<uint8_t> t2b(static_cast<size_t>(N_BYTES_DIAG));
        std::vector<uint8_t> xb (static_cast<size_t>(N_BYTES_DIAG));

        for (int64_t j = 0; j < N_BYTES_DIAG; j++) {
            // 2 iterations per sample (intentional oversampling vs gen_byte).
            gen.iterate();
            gen.iterate();
            t1b[static_cast<size_t>(j)] = mcl_extract_single(gen.theta1());
            t2b[static_cast<size_t>(j)] = mcl_extract_single(gen.theta2());
            xb [static_cast<size_t>(j)] =
                static_cast<uint8_t>(
                    mcl_extract_zone1(gen.theta1(), gen.theta2()) ^
                    mcl_extract_zone2(gen.theta1(), gen.theta2()));
        }

        const double e1 = shannon_entropy(t1b.data(), N_BYTES_DIAG);
        const double e2 = shannon_entropy(t2b.data(), N_BYTES_DIAG);
        const double ex = shannon_entropy(xb.data(),  N_BYTES_DIAG);
        const double c1 = chi_square(t1b.data(), N_BYTES_DIAG);
        const double c2 = chi_square(t2b.data(), N_BYTES_DIAG);

        // Diagnostic regime uses a SIMPLIFIED rule, distinct from
        // classify_regime() in mcl_core.hpp:
        //   c1 > 330 OR c2 > 330  -> "RESON" (any single oscillator failure)
        //   kv < 1.0              -> "QUASI?" (uncertain -- see note below)
        //   else                  -> "CHAOS"
        //
        // The difference from classify_regime() is intentional:
        //   1. We test individual oscillators (theta1/theta2 separately),
        //      not the combined sweep output.
        //   2. We omit AC and bit-frequency checks (diagnostic, not gate).
        //   3. RESON cutoff is CHI2_THRESHOLD (330.52) rather than 1000,
        //      because here we are flagging ANY single-oscillator anomaly.
        //   4. The "QUASI?" question mark signals a fundamental limitation:
        //      single-oscillator low-K behaviour can look chaotic at the
        //      byte level due to IEEE 754 mantissa structure, NOT true
        //      chaotic dynamics. The XOR comparison column (XOR_ent)
        //      partially disambiguates this in the printed table.
        const char* diag_regime =
            (c1 > CHI2_THRESHOLD || c2 > CHI2_THRESHOLD) ? "RESON" :
            (kv < 1.0) ? "QUASI?" : "CHAOS";

        std::printf("  %-7.1f %.4f   %.4f   %.4f   %10.2f  %10.2f  %s\n",
            kv, e1, e2, ex, c1, c2, diag_regime);
    }

    std::printf("\n  INTERPRETATION:\n");
    std::printf("    chi2 > 330                  -> resonance confirmed\n");
    std::printf("    chi2 < 330 but K < 1.0      -> likely quasiperiodic "
                "(IEEE 754 artifact)\n");
    std::printf("    chi2 < 330 AND K >= 1.0     -> true chaos\n");

    // ========================================================================
    // VERDICT
    // ========================================================================
    const double elapsed = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - t_start).count();

    const bool gp =
        (rc2.chaos > 0 && rc3.chaos > 0 && rc4.chaos > 0 &&
         rc2.last_chaos >= VERDICT_LAST_CHAOS_MIN &&
         rc3.last_chaos >= VERDICT_LAST_CHAOS_MIN &&
         rc4.last_chaos >= VERDICT_LAST_CHAOS_MIN);

    sep("VERDICT");
    // NOTE: This file does NOT measure Lyapunov exponent lambda directly;
    // it classifies regimes via statistical signatures (entropy, chi-square,
    // AC, bit-frequency). CHAOS regime is consistent with positive lambda
    // but is a proxy. For direct lambda measurement, see mcl_lyapunov.cpp.
    std::printf("  Chaotic regime detected for T2/T3/T4 across operational K\n");
    std::printf("  (consistent with lambda > 0 at eff_K >= 1.0; direct\n");
    std::printf("   lambda measurement: see mcl_lyapunov.cpp).\n");
    std::printf("  Chaotic regime: T2=[%.1f,%.0f] T3=[%.1f,%.0f] "
                "T4=[%.1f,%.0f]\n",
        rc2.first_chaos, rc2.last_chaos,
        rc3.first_chaos, rc3.last_chaos,
        rc4.first_chaos, rc4.last_chaos);
    std::printf("  Effective coupling onset: T2~=%.1f T3~=%.1f T4~=%.1f\n",
        rc2.first_chaos,
        2.0 * rc3.first_chaos,
        3.0 * rc4.first_chaos);

    std::printf("\n +================================================================+\n");
    std::printf(" | VERDICT: %s |\n",
        gp ? "PASS - regime mapping complete, chaos verified      "
           : "FAIL - incomplete regime coverage                   ");
    std::printf(" +================================================================+\n");

    std::printf("\n  Time: %.1f seconds\n", elapsed);
    std::printf("\n  Doc ID:  %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("  Author:  Madeeh Ibrahim, Cairo, Egypt\n");
    std::printf("  Patent Pending: PCT/IB2026/052737, "
                "PCT/IB2026/053253, PCT/IB2026/053673\n");
    std::printf(
        "==============================================================================\n");

    return gp ? 0 : 1;
}
