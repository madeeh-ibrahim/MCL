// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// P4 review measurement 2026-09-05, round 5 item R5-5: WEAK-LANE INSTANCES of VDF128-T4 v3.
// With per-input weights an adversary who influences x can grind for a map F_x whose weight
// set has a very small lane (p or q of one pair), and ~1% of honest inputs already carry a
// lane below 2^20. This harness grinds such inputs and runs the structural probes of the
// battery (avalanche profile r=1..8, single-bit linear correlation r=1,2, cube/degree r=1)
// on their maps, against the battery input as control. Evidence, not a bound.
// Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. p4_vdf128v2_weaklane.cpp -o p4_vdf128v2_weaklane
#include "mcl_vdf128_t4_v3.hpp"
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
int main() {
    std::printf("VDF128-T4 v3 weak-lane instance probe (MCL-VDF128-WEAKLANE-2026-0905-001; engine %d.%d.%d)\n", MCL_VERSION_MAJOR, MCL_VERSION_MINOR, MCL_VERSION_PATCH);
    std::printf("Grinding inputs \"weak-lane-<i>\" for weight sets with a small lane (the derivation of Algorithm 1, incl. pair and parity re-draws)\n");
    auto t0 = std::chrono::steady_clock::now();
    std::string best_le15, best_lt16, best_lt20, best_pair16; uint32_t v_le15 = 0, v_lt16 = 0, v_lt20 = 0; uint32_t pair16[2] = {0,0};
    uint64_t n_lt20 = 0, n_lt16 = 0, tried = 0;
    const uint64_t CAP = 40000000ull;
    for (uint64_t i = 0; i < CAP; i++) {
        char buf[48]; int L = std::snprintf(buf, sizeof buf, "weak-lane-v3-%llu", (unsigned long long)i);
        MCL_Q30_Sextet W = mcl_vdf128v3_weights((const uint8_t*)buf, (size_t)L); uint32_t w[12]; lanes(W, w); tried++;
        uint32_t mn = w[0]; for (int k = 1; k < 12; k++) if (w[k] < mn) mn = w[k];
        if (mn < (1u<<20)) { n_lt20++; if (best_lt20.empty()) { best_lt20 = buf; v_lt20 = mn; } }
        if (mn < (1u<<16)) { n_lt16++; if (best_lt16.empty()) { best_lt16 = buf; v_lt16 = mn; } }
        if (mn <= 15 && best_le15.empty()) { best_le15 = buf; v_le15 = mn; }
        if (best_pair16.empty()) for (int e = 0; e < 6; e++) if (w[2*e] < (1u<<16) && w[2*e+1] < (1u<<16)) { best_pair16 = buf; pair16[0] = w[2*e]; pair16[1] = w[2*e+1]; }
        if (!best_le15.empty() && !best_pair16.empty() && i >= 4000000) break;   // enough statistics for the frequencies
    }
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("tried %llu inputs in %.0f s: lane < 2^20 in %.3f%% of inputs (%llu), lane < 2^16 in %.4f%% (%llu)\n", (unsigned long long)tried, secs, 100.0*n_lt20/tried, (unsigned long long)n_lt20, 100.0*n_lt16/tried, (unsigned long long)n_lt16);
    std::printf("first lane <= 15: %s (lane %u); first lane < 2^16: %s (%u); first lane < 2^20: %s (%u); first pair with both lanes < 2^16: %s (%u, %u)\n",
        best_le15.empty()?"(none)":best_le15.c_str(), v_le15, best_lt16.c_str(), v_lt16, best_lt20.c_str(), v_lt20, best_pair16.empty()?"(none)":best_pair16.c_str(), pair16[0], pair16[1]);
    const char* X = "VDF128-T4-battery-input";
    probes("control: battery input", X, mcl_vdf128v3_weights((const uint8_t*)X, std::strlen(X)));
    if (!best_lt20.empty()) probes("lane < 2^20 (~1% of inputs)", best_lt20, mcl_vdf128v3_weights((const uint8_t*)best_lt20.data(), best_lt20.size()));
    if (!best_lt16.empty()) probes("lane < 2^16", best_lt16, mcl_vdf128v3_weights((const uint8_t*)best_lt16.data(), best_lt16.size()));
    if (!best_le15.empty()) probes("lane <= 15 (ground)", best_le15, mcl_vdf128v3_weights((const uint8_t*)best_le15.data(), best_le15.size()));
    if (!best_pair16.empty()) probes("both lanes of one pair < 2^16 (ground)", best_pair16, mcl_vdf128v3_weights((const uint8_t*)best_pair16.data(), best_pair16.size()));
    std::printf("\nInterpretation: a coarse lane weakens ONE coupling term of ONE pair; the other two pairs of each oscillator carry ~2^30 weights,\nso diffusion should survive. Numbers above are the measurement of that expectation. Evidence, not a bound.\n");
    return 0;
}
