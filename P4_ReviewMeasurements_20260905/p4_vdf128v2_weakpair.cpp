// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// P4 review measurement 2026-09-05, round 5 item R5-5 (part 2): WEAK-PAIR INSTANCES of VDF128-T4 v2 — one pair with BOTH lanes small.
// Such a pair is expected once per ~2^25 inputs (6 x 2^-14 x 2^-14), i.e. selectable by an adversary who grinds x; the 40M-input
// grind of p4_vdf128v2_weaklane.cpp found none, so part (a) probes CONSTRUCTED weight sets (a real input's set with one pair
// overwritten; the re-draw rules are re-checked) and part (b) --grind searches for a genuine input (cap given on the command line).
// With per-input weights an adversary who influences x can grind for a map F_x whose weight
// set has a very small lane (p or q of one pair), and ~1% of honest inputs already carry a
// lane below 2^20. This harness grinds such inputs and runs the structural probes of the
// battery (avalanche profile r=1..8, single-bit linear correlation r=1,2, cube/degree r=1)
// on their maps, against the battery input as control. Evidence, not a bound.
// Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. p4_vdf128v2_weakpair.cpp -o p4_vdf128v2_weakpair
#include "mcl_vdf128_t4_v2.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <chrono>
#include <vector>
#include <string>
static int popdiff(const VDF128_State& a, const VDF128_State& b) {
    return __builtin_popcount(a.t1^b.t1)+__builtin_popcount(a.t2^b.t2)+__builtin_popcount(a.t3^b.t3)+__builtin_popcount(a.t4^b.t4);
}
static uint64_t sm(uint64_t& z){ z += 0x9E3779B97F4A7C15ull; uint64_t r = z; r = (r^(r>>30))*0xBF58476D1CE4E5B9ull; r = (r^(r>>27))*0x94D049BB133111EBull; return r^(r>>31); }
static void lanes(const MCL_Q30_Sextet& W, uint32_t w[12]) {
    uint32_t t[12] = {W.p12,W.q12,W.p13,W.q13,W.p14,W.q14,W.p23,W.q23,W.p24,W.q24,W.p34,W.q34}; std::memcpy(w, t, sizeof t);
}
static void probes(const char* label, const std::string& x, const MCL_Q30_Sextet& W) {
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    uint32_t w[12]; lanes(W, w); uint32_t mn = w[0]; for (int i = 1; i < 12; i++) if (w[i] < mn) mn = w[i];
    std::printf("\n[%s] x = \"%s\"\n  weights:", label, x.c_str()); for (int i = 0; i < 12; i++) std::printf(" %u", w[i]);
    std::printf("\n  smallest lane = %u (2^%.1f)\n", mn, std::log2((double)mn));
    // S3 avalanche profile
    VDF128_State c0 = mcl_vdf128_init((const uint8_t*)x.data(), x.size());
    for (int i = 0; i < 10000; i++) mcl_q30t4_iterate_raw(c0.t1,c0.t2,c0.t3,c0.t4,W,kp);
    std::printf("  S3 avalanche profile r=1..8 (mean Hamming over 128 flip positions):");
    double a1 = 0;
    for (int r = 1; r <= 8; r++) {
        double a = 0;
        for (int b = 0; b < 128; b++) { VDF128_State p = c0, q = c0; uint32_t* ww = (&q.t1) + (b/32); *ww ^= (1u << (b%32)); for (int i = 0; i < r; i++) { mcl_q30t4_iterate_raw(p.t1,p.t2,p.t3,p.t4,W,kp); mcl_q30t4_iterate_raw(q.t1,q.t2,q.t3,q.t4,W,kp); } a += popdiff(p,q); }
        a /= 128; if (r == 1) a1 = a; std::printf(" %.1f", a);
    }
    std::printf("\n");
    // S3b per-word avalanche at r=1: which state word receives least diffusion (a coarse lane shows here first)
    {
        double perword[4] = {0,0,0,0};
        for (int b = 0; b < 128; b++) { VDF128_State p = c0, q = c0; uint32_t* ww = (&q.t1) + (b/32); *ww ^= (1u << (b%32)); mcl_q30t4_iterate_raw(p.t1,p.t2,p.t3,p.t4,W,kp); mcl_q30t4_iterate_raw(q.t1,q.t2,q.t3,q.t4,W,kp);
            perword[0] += __builtin_popcount(p.t1^q.t1); perword[1] += __builtin_popcount(p.t2^q.t2); perword[2] += __builtin_popcount(p.t3^q.t3); perword[3] += __builtin_popcount(p.t4^q.t4); }
        std::printf("  S3b r=1 mean flipped bits per state word t1..t4 (16 = half): %.1f %.1f %.1f %.1f\n", perword[0]/128, perword[1]/128, perword[2]/128, perword[3]/128);
    }
    // S1 single-bit linear correlation, r = 1, 2
    {
        const int LOGN = 18; const uint32_t n = 1u << LOGN; const double floor4 = 4.5/std::sqrt((double)n);
        static uint32_t cnt[128][128];
        for (int rr : {1, 2}) {
            std::memset(cnt, 0, sizeof cnt); uint64_t z = 0x5EED0905ull + (uint64_t)rr;
            for (uint32_t k = 0; k < n; k++) {
                uint64_t a = sm(z), b = sm(z); uint32_t in[4] = {(uint32_t)a,(uint32_t)(a>>32),(uint32_t)b,(uint32_t)(b>>32)};
                VDF128_State s{in[0],in[1],in[2],in[3]}; for (int i = 0; i < rr; i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
                uint32_t out[4] = {s.t1,s.t2,s.t3,s.t4};
                for (int j = 0; j < 128; j++) { uint32_t mask = 0u - ((out[j>>5] >> (j&31)) & 1u); for (int ww = 0; ww < 4; ww++) { uint32_t v = in[ww] ^ mask; for (int bb = 0; bb < 32; bb++) cnt[j][ww*32+bb] += (v >> bb) & 1u; } }
            }
            double maxc = 0; int above = 0; int imax = -1, jmax = -1;
            for (int j = 0; j < 128; j++) for (int i = 0; i < 128; i++) { double c = std::fabs(1.0 - 2.0*(double)cnt[j][i]/(double)n); if (c > maxc) { maxc = c; imax = i; jmax = j; } if (c > floor4) above++; }
            std::printf("  S1 linear correlation r=%d: max|corr| %.5f (in bit %d -> out bit %d), %d of 16,384 pairs above 4.5 sigma (%.5f)\n", rr, maxc, imax, jmax, above, floor4);
        }
    }
    // S2 cube/degree probe r = 1, d = 16 and 20
    {
        for (int dcube : {16, 20}) {
            uint64_t z = 0xC0BE0905ull + (uint64_t)(100 + dcube); int nonzero = 0; double pop = 0; const int CUBES = 32;
            for (int c = 0; c < CUBES; c++) {
                int pos[20]; int got = 0;
                while (got < dcube) { int p = (int)(sm(z) % 128); bool dup = false; for (int i = 0; i < got; i++) if (pos[i] == p) dup = true; if (!dup) pos[got++] = p; }
                uint64_t ba = sm(z), bb2 = sm(z); uint32_t base[4] = {(uint32_t)ba,(uint32_t)(ba>>32),(uint32_t)bb2,(uint32_t)(bb2>>32)}; uint32_t sum[4] = {0,0,0,0};
                for (uint32_t v = 0; v < (1u << dcube); v++) {
                    uint32_t st[4] = {base[0],base[1],base[2],base[3]};
                    for (int i = 0; i < dcube; i++) { int p = pos[i]; if ((v >> i) & 1u) st[p>>5] |= (1u << (p&31)); else st[p>>5] &= ~(1u << (p&31)); }
                    VDF128_State s{st[0],st[1],st[2],st[3]}; mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
                    sum[0]^=s.t1; sum[1]^=s.t2; sum[2]^=s.t3; sum[3]^=s.t4;
                }
                int pc = __builtin_popcount(sum[0])+__builtin_popcount(sum[1])+__builtin_popcount(sum[2])+__builtin_popcount(sum[3]); if (pc) nonzero++; pop += pc;
            }
            std::printf("  S2 cube/degree r=1 d=%d: %d/%d cubes non-zero, mean popcount %.1f/128\n", dcube, nonzero, CUBES, pop/CUBES);
        }
    }
    (void)a1;
}

static MCL_Q30_Sextet with_pair(MCL_Q30_Sextet W, int pair, uint32_t p, uint32_t q) {
    uint32_t* lanes_[12] = {&W.p12,&W.q12,&W.p13,&W.q13,&W.p14,&W.q14,&W.p23,&W.q23,&W.p24,&W.q24,&W.p34,&W.q34};
    *lanes_[2*pair] = p; *lanes_[2*pair+1] = q; return W;
}
int main(int argc, char** argv) {
    std::printf("VDF128-T4 v2 weak-PAIR instance probe (MCL-VDF128-WEAKPAIR-2026-0905-001; engine %d.%d.%d)\n", MCL_VERSION_MAJOR, MCL_VERSION_MINOR, MCL_VERSION_PATCH);
    if (argc > 2 && std::string(argv[1]) == "--grind") {
        uint64_t cap = std::strtoull(argv[2], nullptr, 10); auto t0 = std::chrono::steady_clock::now();
        for (uint64_t i = 40000000ull; i < 40000000ull + cap; i++) {
            char buf[48]; int L = std::snprintf(buf, sizeof buf, "weak-lane-%llu", (unsigned long long)i);
            MCL_Q30_Sextet W = mcl_vdf128v2_weights((const uint8_t*)buf, (size_t)L); uint32_t w[12]; lanes(W, w);
            for (int e = 0; e < 6; e++) if (w[2*e] < (1u<<16) && w[2*e+1] < (1u<<16)) {
                double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
                std::printf("GENUINE pair-small input found after %llu candidates (%.0f s): %s, pair %d = (%u, %u)\n", (unsigned long long)(i-40000000ull+1), secs, buf, e, w[2*e], w[2*e+1]);
                probes("genuine input, one pair with both lanes < 2^16", buf, W); return 0;
            }
        }
        std::printf("no pair-small input within %llu further candidates\n", (unsigned long long)cap); return 1;
    }
    const char* X = "weak-lane-1229";   // real input whose q13 = 31590 already (< 2^16)
    MCL_Q30_Sextet W0 = mcl_vdf128v2_weights((const uint8_t*)X, std::strlen(X));
    struct C { const char* label; int pair; uint32_t p, q; } cases[] = {
        {"CONSTRUCTED: pair (1,3) = (42714, 31590), both < 2^16 (reachable at ~2^25 candidates)", 1, 42714u, 31590u},
        {"CONSTRUCTED: pair (1,3) = (6, 31590) (beyond grinding reach, ~2^-37; stress case)", 1, 6u, 31590u},
        {"CONSTRUCTED: pair (1,3) = (6, 7) (unreachable, ~2^-50; extreme stress case)", 1, 6u, 7u},
    };
    for (const C& c : cases) {
        MCL_Q30_Sextet W = with_pair(W0, c.pair, c.p, c.q);
        std::printf("\n== %s ==\n  re-draw rules on this set: p!=q %s; seed-reachable symmetry %s\n", c.label, (c.p != c.q) ? "ok" : "VIOLATED",
                    mcl_t4_q30_has_reachable_symmetry(W) ? "PRESENT (the derivation would re-draw this set)" : "absent (set admissible)");
        probes(c.label, std::string(X) + " [pair overwritten]", W);
    }
    return 0;
}
