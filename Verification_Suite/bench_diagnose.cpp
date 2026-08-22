/*
 * ============================================================================
 * bench_diagnose.cpp — MCL Benchmark vs SIM-Swap Diagnostic
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-BENCH-DIAGNOSE-2026-0526-001
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
 * PURPOSE: Comprehensive diagnostic to isolate the 17-21% performance gap
 *   between benchmark and simswap tests. Runs 3 phases in a single binary:
 *   PHASE 1 (variants): Tests TU/inlining/const-prop with V1-V4 variants,
 *     shuffled order x 10 rounds to eliminate drift.
 *   PHASE 2 (thermal): 6 back-to-back Bench-6 runs to detect throttling.
 *   PHASE 3 (cooldown): 60s sleep then one final run to confirm thermal recovery.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O2 -DNDEBUG -std=c++17 -march=native -o bench_diagnose bench_diagnose.cpp -lm && ./bench_diagnose
 *
 * EXPECTED RESULTS: Thermal and variant diagnostics printed; each phase reports timing per variant.
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
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <random>
#include <algorithm>
#include <thread>

// ─── ثَوابِت تُطابِق benchmark Bench 6 و simswap بِالضَبط ─────────────────────
static constexpr int64_t  N_ENGINES_PER_VARIANT = 5000;   // engines per round
static constexpr int      ROUNDS                = 10;     // medians from 10
static constexpr int      THERMAL_RUNS          = 6;      // back-to-back
static constexpr int      RESP_LEN              = 32;
static constexpr int      COOLDOWN_SEC          = 60;
static constexpr uint64_t DIAG_SEED             = 0xDEADBEEFCAFEBABEULL;

// DCE-prevention sink
static volatile uint8_t g_sink = 0;

static inline double now_us() {
    using namespace std::chrono;
    return duration<double, std::micro>(
        steady_clock::now().time_since_epoch()).count();
}

// ─── PHASE 1 — variants ──────────────────────────────────────────────────────

// V1: monolithic (Bench 6 بالحَرف)
static double run_V1(uint64_t base) {
    double t0 = now_us();
    uint8_t buf[RESP_LEN];
    for (int64_t i = 0; i < N_ENGINES_PER_VARIANT; i++) {
        uint64_t s = base + (uint64_t)i;
        if (s == 0) s = 1;
        MCL_T2 e(s, 3, 5);                          // ← literal 3, 5 (نَفس Bench 6)
        e.gen_bytes(buf, RESP_LEN);
        g_sink ^= buf[RESP_LEN - 1];
    }
    return (now_us() - t0) / (double)N_ENGINES_PER_VARIANT;
}

// V2: function-wrapped genuine (نَفس simswap بِالضَبط — بِدون noinline)
// مَلاحَظَة: لو الـ compiler inlined هذه الدالَّة، فَالنَتيجة سَتُطابِق V1 ⇒
// هذا هو السُؤال الجَوهَري الذي تُريد إجابَتَه.
static constexpr int64_t DEV_P_TEST = 3;
static constexpr int64_t DEV_Q_TEST = 5;
static void V2_genuine(uint64_t challenge, uint8_t* resp) {
    MCL_T2 e(challenge, DEV_P_TEST, DEV_Q_TEST);
    e.gen_bytes(resp, RESP_LEN);
}
static double run_V2(uint64_t base) {
    double t0 = now_us();
    uint8_t buf[RESP_LEN];
    for (int64_t i = 0; i < N_ENGINES_PER_VARIANT; i++) {
        uint64_t s = base + (uint64_t)i;
        if (s == 0) s = 1;
        V2_genuine(s, buf);
        g_sink ^= buf[RESP_LEN - 1];
    }
    return (now_us() - t0) / (double)N_ENGINES_PER_VARIANT;
}

// V3: function-wrapped attacker (نَفس simswap attacker_response — runtime params)
static void V3_attacker(uint64_t challenge, int64_t ap, int64_t aq, uint8_t* resp) {
    MCL_T2 e(challenge, ap, aq);
    e.gen_bytes(resp, RESP_LEN);
}
static double run_V3(uint64_t base) {
    double t0 = now_us();
    uint8_t buf[RESP_LEN];
    for (int64_t i = 0; i < N_ENGINES_PER_VARIANT; i++) {
        uint64_t s = base + (uint64_t)i;
        if (s == 0) s = 1;
        // ap, aq قَيَم runtime مُتَنَوِّعة — نَفس config 1 (random p', q')
        int64_t ap = 7  + (int64_t)((s ^ 0xDEAD'BEEFULL) % 100);
        int64_t aq = 11 + (int64_t)((s ^ 0xCAFE'BABEULL) % 100);
        if (ap == aq) aq++;
        V3_attacker(s, ap, aq, buf);
        g_sink ^= buf[RESP_LEN - 1];
    }
    return (now_us() - t0) / (double)N_ENGINES_PER_VARIANT;
}

// V4: paired (genuine + attacker) — نَفس simswap configs 1-11 بالضَبط
// النَتيجة µs per TRIAL (يَحوي 2 engines)
static double run_V4(uint64_t base) {
    double t0 = now_us();
    uint8_t g[RESP_LEN], a[RESP_LEN];
    for (int64_t i = 0; i < N_ENGINES_PER_VARIANT; i++) {
        uint64_t s = base + (uint64_t)i;
        if (s == 0) s = 1;
        V2_genuine(s, g);
        int64_t ap = 7  + (int64_t)((s ^ 0xDEAD'BEEFULL) % 100);
        int64_t aq = 11 + (int64_t)((s ^ 0xCAFE'BABEULL) % 100);
        if (ap == aq) aq++;
        V3_attacker(s, ap, aq, a);
        g_sink ^= g[RESP_LEN - 1] ^ a[RESP_LEN - 1];
    }
    return (now_us() - t0) / (double)N_ENGINES_PER_VARIANT;
}

// ─── PHASE 2/3 — single Bench 6 (لِـ thermal test) ───────────────────────────
// مُطابِق لـ run_V1 لكِن بِاسم مُنفَصِل لِوُضوح القِراءَة في النَتائِج
static double run_bench6_once(uint64_t base) {
    return run_V1(base);
}

// ─── إخراج ──────────────────────────────────────────────────────────────────

static double median(std::vector<double> v) {
    std::sort(v.begin(), v.end());
    return v.empty() ? 0.0 : v[v.size() / 2];
}

static void print_platform_info() {
#if defined(__APPLE__) && defined(__aarch64__)
    std::printf("Platform: macOS Apple Silicon\n");
#elif defined(__APPLE__)
    std::printf("Platform: macOS x86_64\n");
#elif defined(__linux__) && defined(__aarch64__)
    std::printf("Platform: Linux ARM64\n");
#elif defined(__linux__)
    std::printf("Platform: Linux x86_64\n");
#else
    std::printf("Platform: unknown\n");
#endif
#if defined(__clang__)
    std::printf("Compiler: clang %d.%d.%d\n",
                __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    std::printf("Compiler: gcc %d.%d.%d\n",
                __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif
    std::printf("BURNIN: %d   DECIMATION: %d   iter/engine: %d\n",
                BURNIN, DECIMATION, BURNIN + RESP_LEN * DECIMATION);
    std::printf("\n");
}

// =============================================================================
int main(int argc, char** argv) {
    bool full_mode = false, csv_mode = false;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--full") full_mode = true;
        else if (a == "--csv") csv_mode = true;
    }

    print_platform_info();

    // warm-up (يَتَجاوَز initial cache miss + frequency ramp)
    {
        uint8_t b[RESP_LEN];
        for (int i = 0; i < 200; i++) {
            MCL_T2 e(0xCAFEBABEULL + static_cast<uint64_t>(i), 3, 5);
            e.gen_bytes(b, RESP_LEN);
            g_sink ^= b[0];
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 1 — variants test (TU / inlining / constant prop)
    // ─────────────────────────────────────────────────────────────────────────
    std::printf("=============================================================\n");
    std::printf("  PHASE 1 — VARIANTS  (%d rounds × %lld engines, shuffled)\n",
                ROUNDS, (long long)N_ENGINES_PER_VARIANT);
    std::printf("=============================================================\n");

    std::vector<double> v1, v2, v3, v4;
    std::mt19937 rng(0xC0FFEEU);
    std::vector<int> order = {1, 2, 3, 4};

    if (csv_mode) std::printf("phase,round,variant,us_per_engine\n");

    for (int r = 0; r < ROUNDS; r++) {
        std::shuffle(order.begin(), order.end(), rng);
        for (int v : order) {
            uint64_t base = DIAG_SEED + (uint64_t)r * 100000ULL;
            double t = 0;
            const char* name = "?";
            switch (v) {
                case 1: t = run_V1(base);            v1.push_back(t); name="V1_mono";   break;
                case 2: t = run_V2(base);            v2.push_back(t); name="V2_genuine";break;
                case 3: t = run_V3(base);            v3.push_back(t); name="V3_attacker";break;
                case 4: t = run_V4(base);            v4.push_back(t); name="V4_paired"; break;
            }
            if (csv_mode) std::printf("variants,%d,%s,%.3f\n", r, name, t);
            else std::printf("  round %2d  %s  %8.1f µs\n", r, name, t);
        }
    }

    double m1 = median(v1), m2 = median(v2), m3 = median(v3), m4 = median(v4);

    std::printf("\n  --- medians ---\n");
    std::printf("  V1  monolithic (literal 3,5)       : %8.1f µs/engine\n", m1);
    std::printf("  V2  wrapped genuine (literal)      : %8.1f µs/engine\n", m2);
    std::printf("  V3  wrapped attacker (runtime ap,aq): %8.1f µs/engine\n", m3);
    std::printf("  V4  paired (genuine+attacker, total): %8.1f µs/trial = %.1f µs/eng\n",
                m4, m4 / 2.0);
    std::printf("\n  --- ratios ---\n");
    std::printf("  V1/V2 = %.3f   (expect ~1.00 if NO TU/inlining effect)\n", m1/m2);
    std::printf("  V3/V2 = %.3f   (>1.00 means runtime params slow iterate)\n", m3/m2);
    std::printf("  V4/(V2+V3) = %.3f   (=1.00 if V4 is exactly genuine+attacker)\n",
                m4 / (m2 + m3));
    std::printf("\n");

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 2 — thermal test (يُشَغِّل Bench 6 ٦ مَرَّات بِدون sleep)
    // ─────────────────────────────────────────────────────────────────────────
    std::printf("=============================================================\n");
    std::printf("  PHASE 2 — THERMAL  (%d Bench-6-style runs back-to-back)\n",
                THERMAL_RUNS);
    std::printf("  لو الزَمَن يَنزَلِق صُعوداً ⇒ thermal/DVFS\n");
    std::printf("  لو ثابِت ⇒ ليس thermal\n");
    std::printf("=============================================================\n");

    std::vector<double> thermal;
    for (int r = 0; r < THERMAL_RUNS; r++) {
        uint64_t base = DIAG_SEED + 0xBEEF0000ULL + (uint64_t)r * 100000ULL;
        double t = run_bench6_once(base);
        thermal.push_back(t);
        if (csv_mode) std::printf("thermal,%d,bench6,%.3f\n", r, t);
        else std::printf("  run %d  %8.1f µs/engine   (delta from run 0: %+6.2f%%)\n",
                         r, t, 100.0 * (t - thermal[0]) / thermal[0]);
    }
    double thermal_drift_pct = 100.0 * (thermal.back() - thermal.front())
                                       / thermal.front();
    std::printf("\n  Total thermal drift: %+.2f%%\n", thermal_drift_pct);
    if (thermal_drift_pct > 5.0)
        std::printf("  ⇒ THERMAL THROTTLING DETECTED (run %d is %.1f%% slower than run 0)\n",
                    THERMAL_RUNS - 1, thermal_drift_pct);
    else
        std::printf("  ⇒ no thermal effect (drift < 5%%)\n");
    std::printf("\n");

    // ─────────────────────────────────────────────────────────────────────────
    // PHASE 3 (optional) — cooldown test
    // ─────────────────────────────────────────────────────────────────────────
    if (full_mode) {
        std::printf("=============================================================\n");
        std::printf("  PHASE 3 — COOLDOWN  (sleep %d sec, then re-measure)\n",
                    COOLDOWN_SEC);
        std::printf("=============================================================\n");
        std::printf("  cooling down... ");
        std::fflush(stdout);
        std::this_thread::sleep_for(std::chrono::seconds(COOLDOWN_SEC));
        std::printf("done.\n");

        double t_cold = run_bench6_once(DIAG_SEED + 0xC001'D00DULL);
        std::printf("  Bench 6 after cooldown: %.1f µs/engine\n", t_cold);
        double recovery_pct = 100.0 * (thermal.back() - t_cold) / thermal.back();
        std::printf("  Recovery from hot run: %+.2f%% (%.1f → %.1f)\n",
                    recovery_pct, thermal.back(), t_cold);
        if (csv_mode) std::printf("cooldown,0,bench6,%.3f\n", t_cold);
        std::printf("\n");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ─── الحُكم النِهائي ──────────────────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────
    std::printf("=============================================================\n");
    std::printf("  VERDICT\n");
    std::printf("=============================================================\n");

    bool tu_effect       = (m1/m2 > 1.05);
    bool const_prop      = (m3/m2 > 1.05);
    bool thermal_effect  = (thermal_drift_pct > 5.0);

    std::printf("  TU/inlining effect (V1 vs V2):       %s  (ratio %.3f)\n",
                tu_effect ? "✓ DETECTED" : "✗ NOT detected", m1/m2);
    std::printf("  Constant-prop effect (V3 vs V2):     %s  (ratio %.3f)\n",
                const_prop ? "✓ DETECTED" : "✗ NOT detected", m3/m2);
    std::printf("  Thermal throttling (Phase 2):        %s  (drift %+.2f%%)\n",
                thermal_effect ? "✓ DETECTED" : "✗ NOT detected",
                thermal_drift_pct);
    std::printf("\n");

    if (thermal_effect && !tu_effect && !const_prop)
        std::printf("  ⇒ ROOT CAUSE: thermal throttling. Bench 6 (last in sequence)\n"
                    "    runs slower than simswap (single-test) due to CPU heat/DVFS.\n"
                    "    FIX: add sleep(30) before Bench 6, or run Bench 6 alone.\n");
    else if (tu_effect)
        std::printf("  ⇒ ROOT CAUSE: TU/inlining (V1 monolithic ≠ V2 wrapped).\n"
                    "    Compiler emits different machine code for same iterate()\n"
                    "    based on caller TU context.\n");
    else if (const_prop)
        std::printf("  ⇒ PARTIAL CAUSE: runtime params (attacker ap,aq) slow iterate().\n");
    else if (!thermal_effect && !tu_effect && !const_prop)
        std::printf("  ⇒ NO MEASURABLE EFFECT in this binary. The original gap may be\n"
                    "    an artifact of the original measurement methodology, not the\n"
                    "    code itself. Re-measure simswap and Bench 6 with same flags.\n");

    std::printf("\nsink: %u\n", (unsigned)g_sink);
    return 0;
}
