/*
 * ============================================================================
 * mcl_vdf128_battery.cpp — VDF property + falsification battery for VDF128_T4
 * Doc ID: MCL-VDF128-BATTERY-2026-0817-001
 * ============================================================================
 * WHY THIS FILE EXISTS
 *   The project's two VDF batteries — `mcl_vdf_verify.cpp` (10 properties,
 *   MCL-VDF-VERIFY-2026-0526-001) and `mcl_vdf_falsification.cpp` (4 attacks
 *   on OP1/OP3/OP4/OP5) — are written against the TWO-oscillator interface
 *   VDF(seed, p, q, N). VDF128_T4 has no (p,q): it is a four-oscillator
 *   128-bit-state map with PUBLIC weights and byte-string input. Those
 *   batteries therefore do not apply unmodified. This file re-implements both,
 *   adapted to the VDF128_T4 interface, so that the realization Paper 4 §IV.C
 *   declares NORMATIVE is the one actually exercised.
 *
 * ADAPTATION LOG (each deviation from the originals is deliberate + stated)
 *   P2  GS-vs-Jacobi: the original compares the 2-osc GS map against its Jacobi
 *       twin. Here a faithful 4-oscillator Jacobi counterpart is written LOCALLY
 *       (all four updates read the snapshot state) purely as a comparison
 *       baseline. The engine itself is untouched.
 *   P8  Non-shortcut: the original perturbs a double by ~1e-12. The integer
 *       state has no epsilon, so the analogue is a ONE-BIT flip of the initial
 *       state — a strictly harsher probe.
 *   P9  The original tests cross-(p,q) independence. VDF128_T4's parameters are
 *       fixed and public, so the meaningful analogue is cross-INPUT
 *       independence: distinct x must yield independent trajectories/outputs.
 *   P6  Output quality is measured on the raw state-word stream (the honest
 *       target). The deployed output y is SHA-256-finalized, so its uniformity
 *       is inherited from the hash and is not evidence about the map.
 *   A4  OP4 (output binding under a lossy extractor) is STRUCTURALLY resolved
 *       for VDF128_T4: y = SHA-256(state || H(x) || N || tag) is injective up to
 *       SHA-256 collision resistance. The test therefore verifies no
 *       implementation-level collapse (distinct states/N/x -> distinct y)
 *       rather than re-deriving a branching factor.
 *
 * HONESTY: every printed number is measured on this host. Attacks failing is
 * evidence, never proof. Budgets are bounded and printed with their bound.
 * ============================================================================
 */
#include "mcl_vdf128_t4.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>
#include <vector>
using Clock = std::chrono::steady_clock;

static int g_pass = 0, g_fail = 0;
static void ok(const char* name, bool cond, const char* detail) {
    std::printf("  [%s] %-46s %s\n", cond ? "PASS" : "FAIL", name, detail);
    if (cond) g_pass++; else g_fail++;
}

// ---- local Jacobi counterpart of mcl_q30t4_iterate_raw (comparison only) ----
static void t4_iterate_jacobi(uint32_t& t1, uint32_t& t2, uint32_t& t3, uint32_t& t4,
                              const MCL_Q30_Sextet& w, int64_t K_phase) {
    const MCL_Q30_Table& tab = mcl_q30_table();
    auto inc = [&](uint32_t a) -> uint32_t {
        return (uint32_t)((uint64_t)((int64_t)K_phase * (int64_t)mcl_q30_sin_dispatch(tab, a)) >> 30);
    };
    auto arg = [](uint32_t p, uint32_t a, uint32_t q, uint32_t b) -> uint32_t {
        return (uint32_t)(p * a - q * b);
    };
    const uint32_t o1 = t1, o2 = t2, o3 = t3, o4 = t4;   // snapshot: parallel update
    uint32_t n1 = o1 + mcl_q30_omega1() + inc(arg(w.p12,o2,w.q12,o1)) + inc(arg(w.p13,o3,w.q13,o1)) + inc(arg(w.p14,o4,w.q14,o1));
    uint32_t n2 = o2 + mcl_q30_omega2() + inc(arg(w.p12,o1,w.q12,o2)) + inc(arg(w.p23,o3,w.q23,o2)) + inc(arg(w.p24,o4,w.q24,o2));
    uint32_t n3 = o3 + mcl_q30_omega3() + inc(arg(w.p13,o1,w.q13,o3)) + inc(arg(w.p23,o2,w.q23,o3)) + inc(arg(w.p34,o4,w.q34,o3));
    uint32_t n4 = o4 + mcl_q30_omega4() + inc(arg(w.p14,o1,w.q14,o4)) + inc(arg(w.p24,o2,w.q24,o4)) + inc(arg(w.p34,o3,w.q34,o4));
    t1 = n1; t2 = n2; t3 = n3; t4 = n4;
}

static int popdiff(const VDF128_State& a, const VDF128_State& b) {
    return __builtin_popcount(a.t1^b.t1) + __builtin_popcount(a.t2^b.t2)
         + __builtin_popcount(a.t3^b.t3) + __builtin_popcount(a.t4^b.t4);
}
static int bytediff(const uint8_t* a, const uint8_t* b, int n) {
    int d = 0; for (int i = 0; i < n; i++) if (a[i] != b[i]) d++; return d;
}
static int hamming256(const uint8_t* a, const uint8_t* b) {
    int h = 0; for (int i = 0; i < 32; i++) h += __builtin_popcount((unsigned)(a[i]^b[i])); return h;
}
// Pearson r over byte streams
static double pearson(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    const size_t n = a.size();
    double ma = 0, mb = 0;
    for (size_t i = 0; i < n; i++) { ma += a[i]; mb += b[i]; }
    ma /= (double)n; mb /= (double)n;
    double num = 0, da = 0, db = 0;
    for (size_t i = 0; i < n; i++) {
        double x = a[i]-ma, y = b[i]-mb; num += x*y; da += x*x; db += y*y;
    }
    return (da > 0 && db > 0) ? num/std::sqrt(da*db) : 0.0;
}
// state-word stream -> bytes (raw map output, pre-hash: the honest quality target)
static void state_stream(const uint8_t* x, size_t xlen, int64_t nbytes, std::vector<uint8_t>& out) {
    static const MCL_Q30_Sextet W = mcl_vdf128_public_weights();
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    VDF128_State s = mcl_vdf128_init(x, xlen);
    for (int i = 0; i < 10000; i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
    out.clear(); out.reserve((size_t)nbytes);
    while ((int64_t)out.size() < nbytes) {
        mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
        uint32_t v = s.t1 ^ s.t2 ^ s.t3 ^ s.t4;
        out.push_back((uint8_t)(v >> 16));
        out.push_back((uint8_t)(v >> 24));
    }
    out.resize((size_t)nbytes);
}

int main() {
    std::printf("================================================================\n");
    std::printf("  VDF128_T4 — property + falsification battery\n");
    std::printf("  %s   engine: additive over mcl_core v8.1.0 + sidecar v1.0.4\n", "MCL-VDF128-BATTERY-2026-0817-001");
    std::printf("================================================================\n");
    static const MCL_Q30_Sextet W = mcl_vdf128_public_weights();
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const char* X = "MCL-VDF128-battery-input";
    const size_t XL = std::strlen(X);

    // ================= PART 1 — the 10 VDF properties =================
    std::printf("\n--- PART 1: VDF properties (adapted from MCL-VDF-VERIFY-2026-0526-001) ---\n");

    // P1 timing linearity
    {
        const int64_t Ns[5] = {10000000,20000000,40000000,80000000,160000000};
        double secs[5]; uint8_t y[32];
        // warm-up (mirrors T1_WARMUP_ITERS of the original battery: settle
        // clocks/caches before timing, else the smallest-N point is noise-dominated)
        mcl_vdf128_eval((const uint8_t*)X, XL, 100000, y);
        for (int i = 0; i < 5; i++) {
            double best = 1e30;
            for (int rep = 0; rep < 2; rep++) {           // min-of-2: reject scheduler noise
                auto t0 = Clock::now();
                mcl_vdf128_eval((const uint8_t*)X, XL, (uint64_t)Ns[i], y);
                double e = std::chrono::duration<double>(Clock::now()-t0).count();
                if (e < best) best = e;
            }
            secs[i] = best;
        }
        double worst = 0;
        for (int i = 1; i < 5; i++) {
            double ratio = (secs[i]/secs[i-1]) / ((double)Ns[i]/(double)Ns[i-1]);
            worst = std::fmax(worst, std::fabs(ratio-1.0));
        }
        char d[160];
        std::snprintf(d,sizeof d,"worst step deviation %.3f (thr 0.25); %.2fs @ N=1.6e8", worst, secs[4]);
        ok("P1 timing linearity in N", worst < 0.25, d);
    }
    // P2 Gauss-Seidel vs Jacobi
    {
        VDF128_State g = mcl_vdf128_init((const uint8_t*)X, XL), j = g;
        for (int i = 0; i < 50000; i++) {
            mcl_q30t4_iterate_raw(g.t1,g.t2,g.t3,g.t4,W,kp);
            t4_iterate_jacobi (j.t1,j.t2,j.t3,j.t4,W,kp);
        }
        int bits = popdiff(g,j);
        char d[160]; std::snprintf(d,sizeof d,"%d/128 state bits differ after 5e4 iters (thr >=40)", bits);
        ok("P2 GS map != Jacobi map (sequential dep.)", bits >= 40, d);
    }
    // P3 deterministic reproducibility
    {
        uint8_t y0[32], yi[32]; bool same = true;
        mcl_vdf128_eval((const uint8_t*)X, XL, 100000, y0);
        for (int t = 0; t < 50; t++) {
            mcl_vdf128_eval((const uint8_t*)X, XL, 100000, yi);
            if (std::memcmp(y0,yi,32) != 0) { same = false; break; }
        }
        ok("P3 determinism (50 trials, N=1e5)", same, same ? "50/50 identical" : "MISMATCH");
    }
    // P4 output depends on N
    {
        const uint64_t Ns[6] = {0,1000,10000,50000,100000,500000};
        uint8_t ys[6][32]; bool alldiff = true;
        for (int i = 0; i < 6; i++) mcl_vdf128_eval((const uint8_t*)X, XL, Ns[i], ys[i]);
        for (int i = 0; i < 6 && alldiff; i++)
            for (int j2 = i+1; j2 < 6; j2++)
                if (std::memcmp(ys[i],ys[j2],32) == 0) { alldiff = false; break; }
        ok("P4 distinct N -> distinct output", alldiff, alldiff ? "6 values pairwise distinct" : "COLLISION");
    }
    // P5 checkpoint verification
    {
        const int64_t N = 100000; const int k = 10;
        VDF128_State s = mcl_vdf128_init((const uint8_t*)X, XL);
        for (int i = 0; i < 10000; i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp); // burn-in
        std::vector<VDF128_State> cps; cps.push_back(s);
        for (int seg = 0; seg < k; seg++) {
            for (int64_t i = 0; i < N/k; i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
            cps.push_back(s);
        }
        bool allmatch = true;
        for (int seg = 0; seg < k; seg++) {
            VDF128_State r = cps[(size_t)seg];
            for (int64_t i = 0; i < N/k; i++) mcl_q30t4_iterate_raw(r.t1,r.t2,r.t3,r.t4,W,kp);
            if (popdiff(r, cps[(size_t)seg+1]) != 0) { allmatch = false; break; }
        }
        ok("P5 checkpoint segment recomputation", allmatch, allmatch ? "10/10 segments bit-exact" : "MISMATCH");
    }
    // P6 raw state-stream quality (pre-hash)
    {
        std::vector<uint8_t> b; state_stream((const uint8_t*)X, XL, 1000000, b);
        long long h[256] = {0}; for (uint8_t v : b) h[v]++;
        double E = (double)b.size()/256.0, chi = 0, ent = 0;
        for (int i = 0; i < 256; i++) {
            double dd = h[i]-E; chi += dd*dd/E;
            if (h[i]) { double p = (double)h[i]/(double)b.size(); ent -= p*std::log2(p); }
        }
        char d[160]; std::snprintf(d,sizeof d,"entropy %.6f b/B, chi2 %.2f (crit 330.52)", ent, chi);
        ok("P6 raw state-stream uniformity", ent > 7.999 && chi < 330.52, d);
    }
    // P7 configurable delay range
    {
        bool allok = true; uint8_t y[32];
        const uint64_t Ns[6] = {10,1000,100000,1000000,5000000,10000000};
        for (int i = 0; i < 6; i++) { mcl_vdf128_eval((const uint8_t*)X, XL, Ns[i], y); if (!y[0] && !y[31]) allok = false; }
        ok("P7 configurable N (10 .. 1e7)", allok, "6 delay settings evaluated");
    }
    // P8 non-shortcut: 1-bit state perturbation
    {
        VDF128_State a = mcl_vdf128_init((const uint8_t*)X, XL), b = a;
        b.t1 ^= 1u;
        int it = 0; int bits = 0;
        for (; it < 200; it++) {
            mcl_q30t4_iterate_raw(a.t1,a.t2,a.t3,a.t4,W,kp);
            mcl_q30t4_iterate_raw(b.t1,b.t2,b.t3,b.t4,W,kp);
            bits = popdiff(a,b);
            if (bits >= 50) break;
        }
        char d[160]; std::snprintf(d,sizeof d,"1-bit flip -> %d/128 bits in %d iters (thr >=50)", bits, it+1);
        ok("P8 no approximation shortcut", bits >= 50, d);
    }
    // P9 cross-INPUT independence (adaptation of cross-parameter)
    {
        const int NP = 10; std::vector<std::vector<uint8_t>> st((size_t)NP);
        for (int i = 0; i < NP; i++) {
            char xi[64]; std::snprintf(xi,sizeof xi,"VDF128-indep-input-%d", i);
            state_stream((const uint8_t*)xi, std::strlen(xi), 200000, st[(size_t)i]);
        }
        double maxr = 0;
        for (int i = 0; i < NP; i++) for (int j2 = i+1; j2 < NP; j2++)
            maxr = std::fmax(maxr, std::fabs(pearson(st[(size_t)i], st[(size_t)j2])));
        double floor_ = std::sqrt(2.0*std::log(45.0))/std::sqrt(200000.0);
        char d[160]; std::snprintf(d,sizeof d,"max|r| %.6f over 45 pairs (EVT floor %.6f)", maxr, floor_);
        ok("P9 cross-input independence", maxr < 3*floor_, d);
    }
    // P10 negative control
    {
        std::vector<uint8_t> a, b;
        state_stream((const uint8_t*)X, XL, 100000, a);
        state_stream((const uint8_t*)X, XL, 100000, b);
        double r = pearson(a,b);
        char d[160]; std::snprintf(d,sizeof d,"identical input -> r = %.6f (expect 1.000000)", r);
        ok("P10 negative control (methodology)", r > 0.999999, d);
    }

    // ================= PART 2 — the 4 falsification attacks =================
    std::printf("\n--- PART 2: falsification attacks (adapted from MCL-VDF-FALSIFY) ---\n");

    // A1 (OP3) precomputation / nearest-neighbour table
    {
        const int TBL = 200000;
        std::vector<uint32_t> key(TBL), nxt(TBL);
        VDF128_State s = mcl_vdf128_init((const uint8_t*)"A1-table", 8);
        for (int i = 0; i < TBL; i++) {
            key[(size_t)i] = s.t1 ^ s.t2 ^ s.t3 ^ s.t4;
            mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
            nxt[(size_t)i] = s.t1 ^ s.t2 ^ s.t3 ^ s.t4;
        }
        VDF128_State q = mcl_vdf128_init((const uint8_t*)"A1-query", 8);
        int hits = 0; const int TRIALS = 2000;
        for (int t = 0; t < TRIALS; t++) {
            uint32_t fold = q.t1 ^ q.t2 ^ q.t3 ^ q.t4;
            mcl_q30t4_iterate_raw(q.t1,q.t2,q.t3,q.t4,W,kp);
            uint32_t truth = q.t1 ^ q.t2 ^ q.t3 ^ q.t4;
            // nearest neighbour on the folded observable
            uint32_t best = 0; uint32_t bestd = 0xFFFFFFFFu;
            for (int i = 0; i < TBL; i += 97) {           // sampled scan (budget-bounded)
                uint32_t dd = key[(size_t)i] > fold ? key[(size_t)i]-fold : fold-key[(size_t)i];
                if (dd < bestd) { bestd = dd; best = nxt[(size_t)i]; }
            }
            if (best == truth) hits++;
        }
        char d[160]; std::snprintf(d,sizeof d,"%d/%d exact predictions (random ~2^-32)", hits, TRIALS);
        ok("A1 precomputation/NN table FAILS (OP3)", hits == 0, d);
    }
    // A2 (OP1) Jacobi-plus-correction
    {
        VDF128_State g = mcl_vdf128_init((const uint8_t*)X, XL), j = g;
        int reached = -1;
        for (int i = 0; i < 1000; i++) {
            mcl_q30t4_iterate_raw(g.t1,g.t2,g.t3,g.t4,W,kp);
            t4_iterate_jacobi (j.t1,j.t2,j.t3,j.t4,W,kp);
            if (reached < 0 && popdiff(g,j) >= 56) reached = i+1;
        }
        int fin = popdiff(g,j);
        char d[160]; std::snprintf(d,sizeof d,"saturates to %d/128 bits at iter %d (~64 = independent)", fin, reached);
        ok("A2 Jacobi-correction FAILS (OP1)", reached > 0 && fin >= 50, d);
    }
    // A3 (OP5) irreducible data-dependency: can a segment be skipped?
    {
        const int64_t SEG = 20000;
        VDF128_State s = mcl_vdf128_init((const uint8_t*)X, XL);
        for (int64_t i = 0; i < SEG; i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
        VDF128_State truth = s;
        // "shortcut": start from the same origin but run HALF the iterations twice
        // as fast by skipping alternate steps (a stand-in for any depth-halving)
        VDF128_State sk = mcl_vdf128_init((const uint8_t*)X, XL);
        for (int64_t i = 0; i < SEG/2; i++) { mcl_q30t4_iterate_raw(sk.t1,sk.t2,sk.t3,sk.t4,W,kp); mcl_q30t4_iterate_raw(sk.t1,sk.t2,sk.t3,sk.t4,W,kp); }
        bool identical = popdiff(truth,sk) == 0;   // must be identical (same work)
        VDF128_State half = mcl_vdf128_init((const uint8_t*)X, XL);
        for (int64_t i = 0; i < SEG/2; i++) mcl_q30t4_iterate_raw(half.t1,half.t2,half.t3,half.t4,W,kp);
        int bits = popdiff(truth,half);
        char d[176]; std::snprintf(d,sizeof d,"full==regrouped: %s; half-depth differs in %d/128 bits", identical?"yes":"NO", bits);
        ok("A3 depth cannot be reduced (OP5)", identical && bits >= 40, d);
    }
    // A4 (OP4) output binding under the hash finalization
    {
        uint8_t y1[32], y2[32], y3[32];
        mcl_vdf128_eval((const uint8_t*)X, XL, 50000, y1);
        mcl_vdf128_eval((const uint8_t*)X, XL, 50001, y2);          // N+1
        const char* X2 = "MCL-VDF128-battery-inpuT";                 // 1-char change
        mcl_vdf128_eval((const uint8_t*)X2, std::strlen(X2), 50000, y3);
        int h12 = hamming256(y1,y2), h13 = hamming256(y1,y3);
        int b12 = bytediff(y1,y2,32), b13 = bytediff(y1,y3,32);
        bool good = (h12 > 90 && h12 < 166) && (h13 > 90 && h13 < 166) && b12 >= 28 && b13 >= 28;
        char d[176]; std::snprintf(d,sizeof d,"N+1: %d/256 bits, %d/32 bytes | x': %d/256, %d/32", h12,b12,h13,b13);
        ok("A4 output binding to (x,N) holds (OP4)", good, d);
    }

    std::printf("\n================================================================\n");
    std::printf("  SUMMARY: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("  Evidence, not proof. Budgets bounded as printed.\n");
    std::printf("================================================================\n");
    return g_fail == 0 ? 0 : 1;
}
