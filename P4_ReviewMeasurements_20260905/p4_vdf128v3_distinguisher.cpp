// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// P4 round 6 (R6-5), 2026-09-05: distinguisher search on VDF128-T4 v3 over 1..3 iterations, of the kind
// applied to block-cipher rounds. (A) differential bias matrix: for every single-bit input difference and
// every output bit, |P[output bit flips] - 1/2| over n random states (SAC matrix), plus the largest
// multiplicity of any full 128-bit output difference; (B) the same for 512 random two-bit input differences;
// (C) linear: 512 random two-bit input masks x 128 single output bits. Sampling floors are printed.
// Evidence, not bounds. Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. p4_vdf128v3_distinguisher.cpp -o p4_vdf128v3_distinguisher
#include "mcl_vdf128_t4_v3.hpp"
#include "mcl_vdf128_t4_v2.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>
#include <vector>
#include <unordered_map>
static uint64_t sm(uint64_t& z){ z += 0x9E3779B97F4A7C15ull; uint64_t r = z; r = (r^(r>>30))*0xBF58476D1CE4E5B9ull; r = (r^(r>>27))*0x94D049BB133111EBull; return r^(r>>31); }
struct Key128 { uint32_t a,b,c,d; bool operator==(const Key128& o) const { return a==o.a&&b==o.b&&c==o.c&&d==o.d; } };
struct H128 { size_t operator()(const Key128& k) const { uint64_t z = ((uint64_t)k.a<<32|k.b) ^ (((uint64_t)k.c<<32|k.d)*0x9E3779B97F4A7C15ull); return (size_t)(z ^ (z>>29)); } };
int main() {
    const char* X = "VDF128-T4-battery-input"; const MCL_Q30_Sextet W = mcl_vdf128v3_weights((const uint8_t*)X, std::strlen(X));
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    std::printf("VDF128-T4 v3 distinguisher search (MCL-VDF128-DISTING-2026-0905-001; engine %d.%d.%d), map instance of \"%s\"\n", MCL_VERSION_MAJOR, MCL_VERSION_MINOR, MCL_VERSION_PATCH, X);
    auto iter = [&](VDF128_State& s, int r){ for (int i = 0; i < r; i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp); };
    auto setbit = [](VDF128_State& s, int b){ uint32_t* w = (&s.t1) + (b/32); *w ^= (1u << (b%32)); };
    // (A) single-bit differences
    {
        const int LOGN = 16; const uint32_t n = 1u << LOGN; const double floor45 = 4.5/(2.0*std::sqrt((double)n));
        for (int r = 1; r <= 3; r++) {
            double maxb = 0; int imax=-1, jmax=-1, above = 0; uint32_t maxmult = 0; int dmax = -1;
            static uint32_t cnt[128][128]; std::memset(cnt, 0, sizeof cnt);
            uint64_t z = 0xD1FF0905ull + (uint64_t)r;
            for (int d = 0; d < 128; d++) {
                std::unordered_map<Key128,uint32_t,H128> mult; mult.reserve(n*2);
                for (uint32_t k = 0; k < n; k++) {
                    uint64_t a = sm(z), b = sm(z); VDF128_State s{(uint32_t)a,(uint32_t)(a>>32),(uint32_t)b,(uint32_t)(b>>32)}, t = s; setbit(t, d);
                    iter(s, r); iter(t, r);
                    uint32_t o[4] = {s.t1^t.t1, s.t2^t.t2, s.t3^t.t3, s.t4^t.t4};
                    for (int j = 0; j < 128; j++) cnt[d][j] += (o[j>>5] >> (j&31)) & 1u;
                    uint32_t m = ++mult[Key128{o[0],o[1],o[2],o[3]}]; if (m > maxmult) { maxmult = m; dmax = d; }
                }
            }
            for (int d = 0; d < 128; d++) for (int j = 0; j < 128; j++) { double bias = std::fabs((double)cnt[d][j]/n - 0.5); if (bias > maxb) { maxb = bias; imax = d; jmax = j; } if (bias > floor45) above++; }
            std::printf("(A) r=%d single-bit differences, n=2^%d per difference: max |P(flip)-1/2| = %.5f (diff bit %d -> out bit %d), %d of 16,384 above 4.5 sigma (%.5f); "
                        "largest multiplicity of one full output difference = %u of %u (diff bit %d; 1 expected for a random map)\n", r, LOGN, maxb, imax, jmax, above, floor45, maxmult, n, dmax);
        }
    }
    // (B) two-bit differences (512 random pairs)
    {
        const int LOGN = 15; const uint32_t n = 1u << LOGN; const double floor45 = 4.5/(2.0*std::sqrt((double)n)); const int PAIRS = 512;
        for (int r = 1; r <= 2; r++) {
            double maxb = 0; int above = 0; uint32_t maxmult = 0; uint64_t z = 0x2B170905ull + (uint64_t)r;
            for (int p = 0; p < PAIRS; p++) {
                int b1 = (int)(sm(z) % 128), b2 = (int)(sm(z) % 128); if (b2 == b1) b2 = (b1 + 1) % 128;
                static uint32_t cnt[128]; std::memset(cnt, 0, sizeof cnt); std::unordered_map<Key128,uint32_t,H128> mult; mult.reserve(n*2);
                for (uint32_t k = 0; k < n; k++) {
                    uint64_t a = sm(z), b = sm(z); VDF128_State s{(uint32_t)a,(uint32_t)(a>>32),(uint32_t)b,(uint32_t)(b>>32)}, t = s; setbit(t, b1); setbit(t, b2);
                    iter(s, r); iter(t, r); uint32_t o[4] = {s.t1^t.t1, s.t2^t.t2, s.t3^t.t3, s.t4^t.t4};
                    for (int j = 0; j < 128; j++) cnt[j] += (o[j>>5] >> (j&31)) & 1u;
                    uint32_t m = ++mult[Key128{o[0],o[1],o[2],o[3]}]; if (m > maxmult) maxmult = m;
                }
                for (int j = 0; j < 128; j++) { double bias = std::fabs((double)cnt[j]/n - 0.5); if (bias > maxb) maxb = bias; if (bias > floor45) above++; }
            }
            std::printf("(B) r=%d two-bit differences, %d random pairs, n=2^%d each: max |P(flip)-1/2| = %.5f, %d of %d above 4.5 sigma (%.5f); largest full-difference multiplicity = %u\n", r, PAIRS, LOGN, maxb, above, PAIRS*128, floor45, maxmult);
        }
    }
    // (C) linear: two-bit input masks x single output bits
    {
        const int LOGN = 17; const uint32_t n = 1u << LOGN; const double floor45 = 4.5/std::sqrt((double)n); const int MASKS = 512;
        for (int r = 1; r <= 2; r++) {
            uint64_t z = 0x11AE0905ull + (uint64_t)r; int mb1[512], mb2[512];
            for (int m = 0; m < MASKS; m++) { mb1[m] = (int)(sm(z) % 128); mb2[m] = (int)(sm(z) % 128); if (mb2[m] == mb1[m]) mb2[m] = (mb1[m]+1)%128; }
            static uint32_t cnt[512][128]; std::memset(cnt, 0, sizeof cnt);
            for (uint32_t k = 0; k < n; k++) {
                uint64_t a = sm(z), b = sm(z); uint32_t in[4] = {(uint32_t)a,(uint32_t)(a>>32),(uint32_t)b,(uint32_t)(b>>32)};
                VDF128_State s{in[0],in[1],in[2],in[3]}; iter(s, r); uint32_t out[4] = {s.t1,s.t2,s.t3,s.t4};
                for (int m = 0; m < MASKS; m++) {
                    uint32_t pin = ((in[mb1[m]>>5] >> (mb1[m]&31)) ^ (in[mb2[m]>>5] >> (mb2[m]&31))) & 1u; uint32_t mask = 0u - pin;
                    for (int w = 0; w < 4; w++) { uint32_t v = out[w] ^ mask; for (int bb = 0; bb < 32; bb++) cnt[m][w*32+bb] += (v >> bb) & 1u; }
                }
            }
            double maxc = 0; int above = 0;
            for (int m = 0; m < MASKS; m++) for (int j = 0; j < 128; j++) { double c = std::fabs(1.0 - 2.0*(double)cnt[m][j]/n); if (c > maxc) maxc = c; if (c > floor45) above++; }
            std::printf("(C) r=%d linear, %d random two-bit input masks x 128 output bits, n=2^%d: max |corr| = %.5f, %d of %d above 4.5 sigma (%.5f; ~%.1f expected by chance)\n", r, MASKS, LOGN, maxc, above, MASKS*128, floor45, MASKS*128*6.8e-6);
        }
    }

    // (D) cube-sum (algebraic-degree) PROFILE across iterations and instances. On the v3 battery instance the battery's
    //     S2 probe found zero cube sums (30/32, 27/32 non-zero at r=1) where the v2 instance gave 32/32 — the structure is
    //     instance-dependent. Here: r = 1..6, d in {12,16,20}, 64 random cubes, several instances, plus the v2 instance.
    {
        struct Inst { const char* label; MCL_Q30_Sextet W; };
        std::vector<Inst> insts;
        const char* names[] = {"VDF128-T4-battery-input", "VDF128-T4-KAT-01", "profile-input-A", "profile-input-B", "profile-input-C", "profile-input-D"};
        for (const char* nm : names) insts.push_back({nm, mcl_vdf128v3_weights((const uint8_t*)nm, std::strlen(nm))});
        insts.push_back({"v2 instance (MCL-VDF128-battery-input, v2 derivation)", mcl_vdf128v2_weights((const uint8_t*)"MCL-VDF128-battery-input", 24)});
        std::printf("(D) cube-sum profile: fraction of 64 random cubes with NON-ZERO sum / mean popcount of the sum (64 = balanced), d = 12,16,20\n");
        for (const Inst& in : insts) {
            uint32_t w[12] = {in.W.p12,in.W.q12,in.W.p13,in.W.q13,in.W.p14,in.W.q14,in.W.p23,in.W.q23,in.W.p24,in.W.q24,in.W.p34,in.W.q34};
            int maxv = 0, minlog = 31; for (int i = 0; i < 12; i++) { int v = __builtin_ctz(w[i]); if (v > maxv) maxv = v; int l = 31 - __builtin_clz(w[i]); if (l < minlog) minlog = l; }
            std::printf("  [%s] weights:", in.label); for (int i = 0; i < 12; i++) std::printf(" %u", w[i]); std::printf("  (max 2-adic valuation %d, smallest lane ~2^%d)\n", maxv, minlog);
            for (int r = 1; r <= 6; r++) {
                std::printf("    r=%d:", r);
                for (int dcube : {12, 16, 20}) {
                    uint64_t z = 0xC0BE0905ull + (uint64_t)(r*100 + dcube); int nonzero = 0; double pop = 0; const int CUBES = 64;
                    for (int c = 0; c < CUBES; c++) {
                        int pos[20]; int got = 0;
                        while (got < dcube) { int pp = (int)(sm(z) % 128); bool dup = false; for (int i = 0; i < got; i++) if (pos[i] == pp) dup = true; if (!dup) pos[got++] = pp; }
                        uint64_t ba = sm(z), bb2 = sm(z); uint32_t base[4] = {(uint32_t)ba,(uint32_t)(ba>>32),(uint32_t)bb2,(uint32_t)(bb2>>32)}; uint32_t sum[4] = {0,0,0,0};
                        for (uint32_t v = 0; v < (1u << dcube); v++) {
                            uint32_t st[4] = {base[0],base[1],base[2],base[3]};
                            for (int i = 0; i < dcube; i++) { int pp = pos[i]; if ((v >> i) & 1u) st[pp>>5] |= (1u << (pp&31)); else st[pp>>5] &= ~(1u << (pp&31)); }
                            VDF128_State s{st[0],st[1],st[2],st[3]}; for (int i = 0; i < r; i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,in.W,kp);
                            sum[0]^=s.t1; sum[1]^=s.t2; sum[2]^=s.t3; sum[3]^=s.t4;
                        }
                        int pc = __builtin_popcount(sum[0])+__builtin_popcount(sum[1])+__builtin_popcount(sum[2])+__builtin_popcount(sum[3]); if (pc) nonzero++; pop += pc;
                    }
                    std::printf("  d=%d %2d/64 %5.1f", dcube, nonzero, pop/CUBES);
                }
                std::printf("\n");
            }
        }
    }

    // (E) translation-symmetry statistics: fraction of derived weight sets whose parity matrix is rank-deficient
    //     under the previous rule (seed-reachable global test only) and under the full-rank rule of Algorithm 1 v3;
    //     and a direct check that no single-word or global half-turn shift commutes with the battery instance's map.
    {
        const uint32_t NI = 1u << 18; uint32_t def_old = 0, def_new = 0, single_old = 0, global_old = 0;
        for (uint32_t i = 0; i < NI; i++) {
            char buf[32]; int L = std::snprintf(buf, sizeof buf, "sym-stat-%u", i); uint8_t h[32]; mcl_sha256((const uint8_t*)buf, (size_t)L, h);
            MCL_Q30_Sextet Wo = mcl_vdf128v3_params_from_key_oldrule(h, 0), Wn = mcl_vdf128v3_params_from_key(h, 0);
            int64_t wo[12] = {Wo.p12,Wo.q12,Wo.p13,Wo.q13,Wo.p14,Wo.q14,Wo.p23,Wo.q23,Wo.p24,Wo.q24,Wo.p34,Wo.q34};
            int64_t wn[12] = {Wn.p12,Wn.q12,Wn.p13,Wn.q13,Wn.p14,Wn.q14,Wn.p23,Wn.q23,Wn.p24,Wn.q24,Wn.p34,Wn.q34};
            if (mcl_vdf128v3_parity_rank(wo) < 4) def_old++;
            if (mcl_vdf128v3_parity_rank(wn) < 4) def_new++;
            // single-word: all six weights touching a word even; global: p == q (mod 2) for all pairs
            static const int I[6] = {0,0,0,1,1,2}, J[6] = {1,2,3,2,3,3}; bool sw = false; for (int word = 0; word < 4 && !sw; word++) { bool alleven = true; for (int e = 0; e < 6; e++) if (I[e] == word || J[e] == word) { if ((wo[2*e] & 1) || (wo[2*e+1] & 1)) alleven = false; } if (alleven) sw = true; }
            bool gl = true; for (int e = 0; e < 6; e++) if (((wo[2*e] ^ wo[2*e+1]) & 1)) gl = false;
            if (sw) single_old++; if (gl) global_old++;
        }
        std::printf("(E) translation symmetries over %u derived weight sets: previous rule -> parity matrix rank-deficient in %.3f%% (single-word all-even %.3f%%, global equal-parity %.3f%%); full-rank rule of Algorithm 1 v3 -> %.4f%%\n",
                    NI, 100.0*def_old/NI, 100.0*single_old/NI, 100.0*global_old/NI, 100.0*def_new/NI);
        // direct commutation check on the battery instance (new rule): 4 single-word half-turns + global half-turn, 64 random states
        int commute = 0; uint64_t z = 0x5A5A0905ull;
        for (int which = 0; which < 5; which++) { int ok = 0; for (int k = 0; k < 64; k++) { uint64_t a = sm(z), b = sm(z); VDF128_State s{(uint32_t)a,(uint32_t)(a>>32),(uint32_t)b,(uint32_t)(b>>32)}, t = s;
            uint32_t* tw = &t.t1; if (which < 4) tw[which] += 0x80000000u; else { t.t1 += 0x80000000u; t.t2 += 0x80000000u; t.t3 += 0x80000000u; t.t4 += 0x80000000u; }
            mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp); mcl_q30t4_iterate_raw(t.t1,t.t2,t.t3,t.t4,W,kp);
            uint32_t* sw_ = &s.t1; uint32_t* tw2 = &t.t1; bool same = true; for (int q = 0; q < 4; q++) { uint32_t exp = sw_[q] + ((which == q || which == 4) ? 0x80000000u : 0u); if (tw2[q] != exp) same = false; } if (same) ok++; }
            if (ok == 64) commute++; }
        std::printf("(E) half-turn shifts commuting with the battery instance's map (new rule): %d of 5 (expected 0)\n", commute);
    }
    std::printf("Interpretation: values at the sampling floor with ~0 exceedances mean no differential or linear structure detectable at this sensitivity after one iteration; evidence, not a bound.\n");
    return 0;
}
