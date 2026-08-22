/*
 * ============================================================================
 * mcl_vdf128_bench.cpp — Paper-4 Eval/Verify benchmark (CPU), VDF128-T4 path
 * Doc ID: MCL-VDF128-BENCH-2026-0821-001
 * ============================================================================
 * WHY
 *   Paper 4 states the Slow-and-Steady criterion and a checkpoint verification
 *   scheme, but publishes no measured Eval-vs-Verify separation on the
 *   normative VDF128-T4 path (the pre-Path-A numbers are from the broken Q30
 *   two-oscillator substrate). This binary measures, on one CPU:
 *     (1) Eval throughput (sequential iterations/second), 3 repeats/point;
 *     (2) Verify wall-clock under the checkpoint scheme with k parallel
 *         segments, using std::thread — the ACTUAL parallel verification the
 *         paper describes, not an analytic estimate;
 *     (3) the Eval/Verify wall-clock ratio and the parallel-verify speedup vs
 *         serial recomputation, per k;
 *     (4) a bit-exactness gate: checkpoint-segment recomputation must
 *         reproduce the Eval end state exactly, and the finalized y must match.
 *   Also reports the per-iteration cost in ns and the hardware identity, both
 *   required by TIFS/CiC benchmark convention.
 *
 * NOTE ON THE BURN-IN
 *   B = 10000 is part of Eval by definition (mcl_vdf128_eval_state). For the
 *   throughput figure the burn-in is measured separately and excluded from
 *   the per-iteration rate, then reported as fixed overhead — otherwise small
 *   N would report a rate dominated by B.
 *
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_vdf128_bench.cpp -o mcl_vdf128_bench
 *        (-I.. is required: the header includes ../mcl_core.hpp and the sidecar
 *         includes "mcl_core.hpp" by bare name.)
 * Deterministic inputs; timings are machine-dependent and printed with the
 * hardware string so the record is self-describing.
 * ============================================================================
 */
#include "mcl_vdf128_t4.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>
#include <sys/sysctl.h>

using clk = std::chrono::high_resolution_clock;
static double secs(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double>(b - a).count();
}
static std::string hw_string() {
    char buf[256]; size_t len = sizeof(buf);
    std::string cpu = (sysctlbyname("machdep.cpu.brand_string", buf, &len, nullptr, 0) == 0)
                      ? std::string(buf) : std::string("unknown");
    return cpu + ", " + std::to_string(std::thread::hardware_concurrency()) + " logical cores";
}

// Iterate the raw map n times from a given state (no burn-in, no hashing).
static inline void run_iters(VDF128_State& s, uint64_t n,
                             const MCL_Q30_Sextet& W, int64_t kp) {
    for (uint64_t i = 0; i < n; i++)
        mcl_q30t4_iterate_raw(s.t1, s.t2, s.t3, s.t4, W, kp);
}

int main() {
    const MCL_Q30_Sextet W = mcl_vdf128_public_weights();
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const uint64_t B = 10000;
    const uint8_t x[] = "MCL-VDF128-T4 benchmark input 2026-08-21";
    const size_t xlen = sizeof(x) - 1;

    std::printf("================================================================\n");
    std::printf("  VDF128_T4 — Eval/Verify CPU benchmark\n");
    std::printf("  MCL-VDF128-BENCH-2026-0821-001   engine: mcl_core v%s + sidecar\n",
                MCL_VERSION_STRING);
    std::printf("  HW: %s\n", hw_string().c_str());
    std::printf("================================================================\n\n");

    // ---------------- Part 1: Eval throughput -------------------------------
    std::printf("--- PART 1: Eval throughput (sequential, single core) ---\n");
    {
        // burn-in cost, measured alone
        double bt = 0;
        for (int r = 0; r < 3; r++) {
            VDF128_State s = mcl_vdf128_init(x, xlen);
            auto t0 = clk::now(); run_iters(s, B, W, kp); auto t1 = clk::now();
            bt += secs(t0, t1);
            if (s.t1 == 0xFFFFFFFF) std::printf("");   // keep the loop live
        }
        bt /= 3;
        std::printf("  burn-in B=%llu: %.3f ms (fixed Eval overhead)\n",
                    (unsigned long long)B, bt * 1e3);

        const uint64_t Ns[] = {1000000ull, 10000000ull, 100000000ull};
        std::printf("  %-14s %-12s %-14s %-12s\n", "N", "best (s)", "iters/s", "ns/iter");
        for (uint64_t N : Ns) {
            double best = 1e30;
            for (int r = 0; r < 3; r++) {
                VDF128_State s = mcl_vdf128_init(x, xlen);
                run_iters(s, B, W, kp);                       // burn-in excluded from timing
                auto t0 = clk::now(); run_iters(s, N, W, kp); auto t1 = clk::now();
                double d = secs(t0, t1); if (d < best) best = d;
                if (s.t1 == 0xFFFFFFFF) std::printf("");
            }
            std::printf("  %-14llu %-12.4f %-14.3e %-12.3f\n",
                        (unsigned long long)N, best, (double)N / best, best / N * 1e9);
        }
    }

    // ---------------- Part 2: checkpoint Verify (real threads) --------------
    std::printf("\n--- PART 2: Verify via checkpoints (k parallel segments) ---\n");
    const uint64_t N = 100000000ull;              // 1e8 delay
    // Prover-side Eval, recording k-1 interior checkpoints for each k tested.
    const int ks[] = {1, 2, 4, 8, 16};
    double eval_wall = 0;
    VDF128_State end_state{};
    uint8_t y_eval[32];
    {
        VDF128_State s = mcl_vdf128_init(x, xlen);
        auto t0 = clk::now();
        run_iters(s, B + N, W, kp);
        auto t1 = clk::now();
        eval_wall = secs(t0, t1);
        end_state = s;
        mcl_vdf128_output(s, x, xlen, N, y_eval);
        std::printf("  Eval(N=1e8, incl. burn-in): %.4f s  -> y = %02x%02x%02x%02x...\n",
                    eval_wall, y_eval[0], y_eval[1], y_eval[2], y_eval[3]);
    }
    // NOTE: Verify is a FULL recomputation distributed over k checkpoint
    // segments — not an asymptotically cheaper proof check. The Eval/Verify
    // ratio is therefore bounded by the verifier's core count, and saturates
    // once k exceeds the available performance cores. Report it as a
    // parallel-verification speedup, never as a succinctness property.
    std::printf("  %-5s %-12s %-14s %-10s\n",
                "k", "verify (s)", "Eval/Verify", "bit-exact");
    for (int k : ks) {
        // Prover publishes checkpoints at segment boundaries (public params:
        // raw states are not secret). Verifier recomputes segments in parallel.
        std::vector<VDF128_State> cps((size_t)k + 1);
        {
            VDF128_State s = mcl_vdf128_init(x, xlen);
            run_iters(s, B, W, kp);                  // checkpoint 0 = post-burn-in
            cps[0] = s;
            uint64_t seg = N / (uint64_t)k;
            for (int i = 1; i <= k; i++) {
                uint64_t len = (i == k) ? (N - seg * (uint64_t)(k - 1)) : seg;
                run_iters(s, len, W, kp);
                cps[(size_t)i] = s;
            }
        }
        std::vector<char> ok((size_t)k, 0);
        auto t0 = clk::now();
        {
            std::vector<std::thread> th;
            uint64_t seg = N / (uint64_t)k;
            for (int i = 0; i < k; i++) {
                th.emplace_back([&, i]() {
                    uint64_t len = (i == k - 1) ? (N - seg * (uint64_t)(k - 1)) : seg;
                    VDF128_State s = cps[(size_t)i];
                    run_iters(s, len, W, kp);
                    const VDF128_State& e = cps[(size_t)i + 1];
                    ok[(size_t)i] = (s.t1 == e.t1 && s.t2 == e.t2 &&
                                     s.t3 == e.t3 && s.t4 == e.t4) ? 1 : 0;
                });
            }
            for (auto& t : th) t.join();
        }
        auto t1 = clk::now();
        double vw = secs(t0, t1);
        bool all_ok = true;
        for (char c : ok) all_ok = all_ok && c;
        // final output check against the prover's y
        uint8_t y_v[32];
        mcl_vdf128_output(cps[(size_t)k], x, xlen, N, y_v);
        bool y_ok = std::memcmp(y_v, y_eval, 32) == 0;
        std::printf("  %-5d %-12.4f %-14.2f %-10s\n",
                    k, vw, eval_wall / vw, (all_ok && y_ok) ? "yes" : "NO");
    }

    // ---------------- Part 3: burn-in-inclusive Eval cost by N --------------
    std::printf("\n--- PART 3: end-to-end Eval (incl. burn-in + hashing) ---\n");
    std::printf("  %-14s %-12s %-16s\n", "N", "wall (s)", "note");
    for (uint64_t n : {10000ull, 1000000ull, 10000000ull, 100000000ull}) {
        uint8_t y[32];
        auto t0 = clk::now(); mcl_vdf128_eval(x, xlen, n, y); auto t1 = clk::now();
        std::printf("  %-14llu %-12.4f %-16s\n", (unsigned long long)n, secs(t0, t1),
                    n <= B ? "burn-in dominates" : "");
    }

    std::printf("\nNotes: single-core Eval by construction (Gauss-Seidel dependency);\n"
                "Verify parallelism is over checkpoint segments, so the Eval/Verify\n"
                "wall-clock ratio grows with k up to the core count. FPGA Eval/Verify\n"
                "measurement on Tang 138K Pro is a separate, pending record.\n");
    return 0;
}
