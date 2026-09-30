// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// qseq_struct.cpp -- Doc ID MCL-P4-QSEQ-STRUCT-2026-0930-001
// ---------------------------------------------------------------------------
// Structural probes of the VDF128-T4 v4 clocked map that bear on QUANTUM
// FAST-FORWARDING, i.e. on the gap between the concrete map and the ideal model
// of Proposition Q1 (QSEQ_PROOF.md). Each part tests one necessary condition of
// the structural hypothesis H-FF; passing a part is evidence, not a bound.
//
//   Part 1  (N1) translations that commute with the clocked round: the exact
//           parity-rank criterion, and the engine run on every half-turn and
//           quarter-turn offset. Abelian structure of this kind is what hidden-
//           shift algorithms exploit.
//   Part 1b (N1, probabilistic) offsets that move only one or two of the twelve
//           coupling arguments: how often they commute with one round, the rate
//           the sine table predicts, and whether it ever holds two rounds running.
//   Part 2  (N2) additive (mod 2^32, word-wise) differences through r = 1, 2, 3
//           clocked rounds: largest multiplicity of one output difference, and
//           how often the difference passes unchanged. An affine or translation
//           map -- fast-forwardable by matrix powering -- gives multiplicity n.
//   Part 3  (N3) image fraction of each single-word Gauss-Seidel update at FULL
//           32-bit width (all 2^32 inputs enumerated): how much a round
//           contracts against a random function (1 - 1/e).
//   Part 4  (N4) amplitude of the nonlinear term, in turns of the circle.
//   Part 5  (N5) birthday probe of one full clocked round on 2^24 states.
//
// Tags follow ../Quantum_Structural_Analysis_20260927/README.md section 2.
// A failed [CONTROL] or [CONSISTENCY] row makes the program exit with code 2;
// such a run must not be quoted. Expectations are written below BEFORE the run
// and compared at the end; a differing expectation is a result, not an error.
//
// Build (from this folder):
//   g++ -std=c++17 -O3 -DNDEBUG -Wall -Wextra -pthread -I.. qseq_struct.cpp -o qseq_struct
//   ./qseq_struct > qseq_struct_20260930.log
// ---------------------------------------------------------------------------
#include "../P4_ReviewMeasurements_20260925/mcl_vdf128_t4_v4.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <unordered_map>
#include <vector>

static uint64_t sm(uint64_t& z) { z += 0x9E3779B97F4A7C15ull; uint64_t r = z; r = (r ^ (r >> 30)) * 0xBF58476D1CE4E5B9ull; r = (r ^ (r >> 27)) * 0x94D049BB133111EBull; return r ^ (r >> 31); }
static double now_s() { return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

static int g_controls_run = 0, g_controls_failed = 0, g_checks_run = 0, g_checks_failed = 0;
static int g_expect_run = 0, g_expect_differ = 0;
static void control(bool ok, const char* what) { g_controls_run++; if (!ok) g_controls_failed++; std::printf("  [CONTROL] %-70s %s\n", what, ok ? "ok" : "FAILED"); }
static void check(bool ok, const char* what) { g_checks_run++; if (!ok) g_checks_failed++; std::printf("  [CONSISTENCY] %-66s %s\n", what, ok ? "ok" : "FAILED"); }
static void expect(bool ok, const char* what) { g_expect_run++; if (!ok) g_expect_differ++; std::printf("  [EXPECTATION] %-66s %s\n", what, ok ? "as written" : "DIFFERS"); }

static const uint64_t CLK0 = 10000;   // probes start at clock B = 10,000, as in the P4 v4 harnesses
static const int NT = 4;              // threads for Part 3

struct S128 { uint32_t w[4]; bool operator<(const S128& o) const { for (int i = 0; i < 4; i++) if (w[i] != o.w[i]) return w[i] < o.w[i]; return false; }
              bool operator==(const S128& o) const { return w[0]==o.w[0] && w[1]==o.w[1] && w[2]==o.w[2] && w[3]==o.w[3]; } };
static S128 from(const VDF128_State& s) { return S128{{s.t1, s.t2, s.t3, s.t4}}; }
static VDF128_State to(const S128& a) { return VDF128_State{a.w[0], a.w[1], a.w[2], a.w[3]}; }
static S128 rnd(uint64_t& z) { uint64_t a = sm(z), b = sm(z); return S128{{(uint32_t)a, (uint32_t)(a >> 32), (uint32_t)b, (uint32_t)(b >> 32)}}; }
static S128 add(const S128& a, const S128& b) { S128 r; for (int i = 0; i < 4; i++) r.w[i] = a.w[i] + b.w[i]; return r; }
static S128 sub(const S128& a, const S128& b) { S128 r; for (int i = 0; i < 4; i++) r.w[i] = a.w[i] - b.w[i]; return r; }

// r clocked rounds from clock CLK0 through the ENGINE (mcl_vdf128v4_iterate; kp = 0 is the affine control)
static S128 rounds(const S128& x, const MCL_Q30_Sextet& W, int64_t kp, int r) {
    VDF128_State s = to(x); for (int i = 0; i < r; i++) mcl_vdf128v4_iterate(s, W, kp, CLK0 + (uint64_t)i); return from(s);
}
// linear-coupling control: the engine's Gauss-Seidel sweep with inc(a) := a (an affine map of (Z/2^32)^4)
static S128 rounds_linear(const S128& x, const MCL_Q30_Sextet& w, int r) {
    VDF128_State s = to(x);
    for (int i = 0; i < r; i++) {
        mcl_vdf128v4_clock(s, CLK0 + (uint64_t)i);
        uint32_t &t1 = s.t1, &t2 = s.t2, &t3 = s.t3, &t4 = s.t4;
        t1 += mcl_q30_omega1() + (w.p12*t2 - w.q12*t1) + (w.p13*t3 - w.q13*t1) + (w.p14*t4 - w.q14*t1);
        t2 += mcl_q30_omega2() + (w.p12*t1 - w.q12*t2) + (w.p23*t3 - w.q23*t2) + (w.p24*t4 - w.q24*t2);
        t3 += mcl_q30_omega3() + (w.p13*t1 - w.q13*t3) + (w.p23*t2 - w.q23*t3) + (w.p34*t4 - w.q34*t3);
        t4 += mcl_q30_omega4() + (w.p14*t1 - w.q14*t4) + (w.p24*t2 - w.q24*t4) + (w.p34*t3 - w.q34*t4);
    }
    return from(s);
}

// ---- word-level re-expression of one Gauss-Seidel sweep (for Part 3) -------
// word k (0..3) is updated as v <- v + omega_k + sum_j inc(p_kj * t_j - q_kj * v), exactly as in
// mcl_q30t4_iterate_raw (orientation of each argument copied from the engine source).
struct WordMap { uint32_t omega; uint32_t p[3], q[3]; int other[3]; };
static void word_maps(const MCL_Q30_Sextet& w, WordMap M[4]) {
    M[0] = WordMap{mcl_q30_omega1(), {w.p12, w.p13, w.p14}, {w.q12, w.q13, w.q14}, {1, 2, 3}};
    M[1] = WordMap{mcl_q30_omega2(), {w.p12, w.p23, w.p24}, {w.q12, w.q23, w.q24}, {0, 2, 3}};
    M[2] = WordMap{mcl_q30_omega3(), {w.p13, w.p23, w.p34}, {w.q13, w.q23, w.q34}, {0, 1, 3}};
    M[3] = WordMap{mcl_q30_omega4(), {w.p14, w.p24, w.p34}, {w.q14, w.q24, w.q34}, {0, 1, 2}};
}
static inline uint32_t inc_of(const int32_t* lut, int64_t kp, uint32_t a) {
    return (uint32_t)((uint64_t)((int64_t)kp * (int64_t)lut[a >> 16]) >> 30);
}
static inline uint32_t word_update(const WordMap& m, const int32_t* lut, int64_t kp, uint32_t v, const uint32_t t[4]) {
    return v + m.omega + inc_of(lut, kp, m.p[0] * t[m.other[0]] - m.q[0] * v)
                       + inc_of(lut, kp, m.p[1] * t[m.other[1]] - m.q[1] * v)
                       + inc_of(lut, kp, m.p[2] * t[m.other[2]] - m.q[2] * v);
}

// image fraction of f over all 2^32 inputs; per-thread bitmaps (2^32 bits = 512 MiB each), OR-merged
template <class F> static double image_fraction(F f) {
    const size_t WORDS = (size_t)1 << 26;
    std::vector<uint64_t*> bm(NT);
    for (int t = 0; t < NT; t++) { bm[t] = (uint64_t*)std::calloc(WORDS, sizeof(uint64_t)); if (!bm[t]) { std::printf("out of memory\n"); std::exit(3); } }
    std::vector<std::thread> th;
    for (int t = 0; t < NT; t++) th.emplace_back([&, t] {
        const uint64_t lo = ((uint64_t)t << 32) / NT, hi = ((uint64_t)(t + 1) << 32) / NT; uint64_t* b = bm[t];
        for (uint64_t v = lo; v < hi; v++) { uint32_t y = f((uint32_t)v); b[y >> 6] |= 1ull << (y & 63); }
    });
    for (auto& x : th) x.join();
    uint64_t cnt = 0;
    for (size_t i = 0; i < WORDS; i++) { uint64_t u = 0; for (int t = 0; t < NT; t++) u |= bm[t][i]; cnt += (uint64_t)__builtin_popcountll(u); }
    for (int t = 0; t < NT; t++) std::free(bm[t]);
    return (double)cnt / 4294967296.0;
}

static void print_weights(const char* name, const MCL_Q30_Sextet& w) {
    std::printf("  weights of \"%s\": p12=%u q12=%u p13=%u q13=%u p14=%u q14=%u p23=%u q23=%u p24=%u q24=%u p34=%u q34=%u\n",
                name, w.p12, w.q12, w.p13, w.q13, w.p14, w.q14, w.p23, w.q23, w.p24, w.q24, w.p34, w.q34);
}
static int parity_rank(const MCL_Q30_Sextet& w) {
    const int64_t a[12] = {w.p12, w.q12, w.p13, w.q13, w.p14, w.q14, w.p23, w.q23, w.p24, w.q24, w.p34, w.q34};
    return mcl_vdf128v3_parity_rank(a);
}

int main() {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    const double T0 = now_s();
    std::printf("qseq_struct (MCL-P4-QSEQ-STRUCT-2026-0930-001) -- engine %d.%d.%d, VDF128-T4 v4 clocked map, probes from clock %llu\n",
                MCL_VERSION_MAJOR, MCL_VERSION_MINOR, MCL_VERSION_PATCH, (unsigned long long)CLK0);
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const int32_t* lut = mcl_q30_table().lut;
    const char* X1 = "VDF128-T4-KAT-01";          // Vector 5 input
    const char* X2 = "VDF128-T4-battery-input";   // instance of the v4 battery and distinguisher
    const MCL_Q30_Sextet W1 = mcl_vdf128v4_weights((const uint8_t*)X1, std::strlen(X1));
    const MCL_Q30_Sextet W2 = mcl_vdf128v4_weights((const uint8_t*)X2, std::strlen(X2));
    print_weights(X1, W1); print_weights(X2, W2);
    std::printf("  K = %.1f, K_phase = %lld\n", K_DEFAULT, (long long)kp);

    // ---- consistency: the table in memory is the normative table file of P4 v4 ----
    {
        FILE* f = std::fopen("../P4_ReviewMeasurements_20260925/q30_lut_int32le.bin", "rb");
        bool same = false;
        if (f) { std::vector<unsigned char> buf(65536 * 4); size_t n = std::fread(buf.data(), 1, buf.size(), f); std::fclose(f);
                 same = (n == buf.size());
                 for (int i = 0; same && i < 65536; i++) { uint32_t v = (uint32_t)buf[4*i] | ((uint32_t)buf[4*i+1] << 8) | ((uint32_t)buf[4*i+2] << 16) | ((uint32_t)buf[4*i+3] << 24); same = ((int32_t)v == lut[i]); } }
        check(same, "sine table in memory == ../P4_ReviewMeasurements_20260925/q30_lut_int32le.bin");
    }
    // ---- consistency: word-level re-expression == engine iterate ----
    {
        WordMap M[4]; word_maps(W1, M); uint64_t z = 0x51E0930ull; int bad = 0;
        for (int k = 0; k < 65536; k++) {
            S128 x = rnd(z); VDF128_State e = to(x); mcl_q30t4_iterate_raw(e.t1, e.t2, e.t3, e.t4, W1, kp);
            uint32_t t[4] = {x.w[0], x.w[1], x.w[2], x.w[3]};
            for (int j = 0; j < 4; j++) t[j] = word_update(M[j], lut, kp, t[j], t);
            if (!(t[0] == e.t1 && t[1] == e.t2 && t[2] == e.t3 && t[3] == e.t4)) bad++;
        }
        check(bad == 0, "four word updates composed == mcl_q30t4_iterate_raw (65,536 states)");
    }

    // =====================================================================
    std::printf("\n== Part 1 (N1): translations commuting with one clocked round ==\n");
    // =====================================================================
    // control weight set: every weight of W1 made even (and p != q kept) -> parity rank 0
    MCL_Q30_Sextet Wev = W1;
    {
        uint32_t* a = &Wev.p12;
        for (int i = 0; i < 12; i++) { a[i] &= ~1u; if (a[i] < 2) a[i] = 2; }
        for (int e = 0; e < 6; e++) if (a[2*e] == a[2*e+1]) a[2*e+1] += 2;
    }
    auto commute_count = [&](const MCL_Q30_Sextet& W, const S128& d, int n, uint64_t seed) {
        uint64_t z = seed; int c = 0;
        for (int k = 0; k < n; k++) { S128 x = rnd(z); if (rounds(add(x, d), W, kp, 1) == add(rounds(x, W, kp, 1), d)) c++; }
        return c;
    };
    const int NCOMM = 4096;
    int total_commuting_W[2] = {0, 0};
    const MCL_Q30_Sextet* WS[2] = {&W1, &W2}; const char* XS[2] = {X1, X2};
    for (int wi = 0; wi < 2; wi++) {
        const int rk = parity_rank(*WS[wi]);
        std::printf("  [COMPUTED] \"%s\": parity rank %d of 4 -> %s\n", XS[wi], rk,
                    rk == 4 ? "no non-zero translation of (Z/2^32)^4 commutes with the round (exact criterion)" : "a translation symmetry exists");
        int half = 0, quarter = 0, nq = 0;
        for (int m = 1; m < 256; m++) {   // offsets with every word in {0, 1, 2, 3} * 2^30
            S128 d{{(uint32_t)((m & 3) << 30), (uint32_t)(((m >> 2) & 3) << 30), (uint32_t)(((m >> 4) & 3) << 30), (uint32_t)(((m >> 6) & 3) << 30)}};
            const int c = commute_count(*WS[wi], d, NCOMM, 0xC0DE0000ull + (uint64_t)m * 7 + (uint64_t)wi);
            const bool is_half = ((m & 0x55) == 0);   // every word in {0, 2^31}
            if (c == NCOMM) { if (is_half) half++; else quarter++; }
            nq++;
            total_commuting_W[wi] += (c > 0);
        }
        std::printf("  [MEASURED] \"%s\": %d offsets (every word in {0,1,2,3}*2^30, 15 of them half-turns); commuting on all %d states: %d half-turn, %d other; offsets with any commuting state: %d\n",
                    XS[wi], nq, NCOMM, half, quarter, total_commuting_W[wi]);
        char buf[160]; std::snprintf(buf, sizeof buf, "\"%s\": parity rank 4 and 0 of 255 offsets commute on any state", XS[wi]);
        expect(rk == 4 && total_commuting_W[wi] == 0, buf);
    }
    {
        const int rk = parity_rank(Wev); int half = 0;
        for (int m = 1; m < 16; m++) {
            S128 d{{(uint32_t)((m & 1) << 31), (uint32_t)(((m >> 1) & 1) << 31), (uint32_t)(((m >> 2) & 1) << 31), (uint32_t)(((m >> 3) & 1) << 31)}};
            if (commute_count(Wev, d, NCOMM, 0xE7E70000ull + (uint64_t)m) == NCOMM) half++;
        }
        std::printf("  control weight set (every weight of the first instance made even): parity rank %d, half-turn offsets commuting on all %d states: %d of 15\n", rk, NCOMM, half);
        control(rk == 0 && half == 15, "all-even weights: rank 0 and 15 of 15 half-turns commute on the engine");
    }

    // =====================================================================
    std::printf("\n== Part 1b (N1, probabilistic): offsets that change few coupling arguments ==\n");
    std::printf("  (part added after trial run 1 of 2026-09-30, whose Part 1 found one commuting state for the second instance;\n"
                "   its expectation below was written after that run, not before it)\n");
    // =====================================================================
    bool p1b_ok = true;
    {
        // a coupling argument moved by m quarter turns moves its table index by m*2^14 exactly (only bits 30..31 change)
        std::vector<uint32_t> incv(65536);
        for (int i = 0; i < 65536; i++) incv[(size_t)i] = (uint32_t)((uint64_t)((int64_t)kp * (int64_t)lut[i]) >> 30);
        auto incq = [&](int i) { return incv[(size_t)(i & 65535)]; };
        int eq[4] = {0, 0, 0, 0};
        for (int i = 0; i < 65536; i++) for (int m = 1; m < 4; m++) eq[m] += (incq(i) == incq(i + 16384 * m));
        std::printf("  [COMPUTED] table indices i with inc(i) == inc(i + m*2^14): m=1 %d, m=2 %d, m=3 %d (of 65,536)\n", eq[1], eq[2], eq[3]);
        const int I6[6] = {0, 0, 0, 1, 1, 2}, J6[6] = {1, 2, 3, 2, 3, 3};
        struct Moved { int word, from, shift; };   // argument a_{word,from} of word update `word`, moved by `shift` quarter turns
        auto offset_of = [](int m, uint32_t d[4]) { for (int w = 0; w < 4; w++) d[w] = (uint32_t)(((m >> (2 * w)) & 3) << 30); };
        auto moved_args = [&](const MCL_Q30_Sextet& W, const uint32_t d[4]) {
            const uint32_t P6[6] = {W.p12, W.p13, W.p14, W.p23, W.p24, W.p34}, Q6[6] = {W.q12, W.q13, W.q14, W.q23, W.q24, W.q34};
            std::vector<Moved> mv;
            for (int e = 0; e < 6; e++) {
                const uint32_t f = P6[e] * d[J6[e]] - Q6[e] * d[I6[e]], r = P6[e] * d[I6[e]] - Q6[e] * d[J6[e]];
                if (f) mv.push_back(Moved{I6[e], J6[e], (int)(f >> 30)});   // a_IJ = p t_J - q t_I feeds word I
                if (r) mv.push_back(Moved{J6[e], I6[e], (int)(r >> 30)});   // a_JI = p t_I - q t_J feeds word J
            }
            return mv;
        };
        auto words_touched = [](const std::vector<Moved>& mv) { unsigned mask = 0; for (const Moved& a : mv) mask |= 1u << a.word; return __builtin_popcount(mask); };
        // per-round rate if the moved table indices are independent and uniform: per word update, the probability that its
        // increment sum is unchanged (one moved argument: equal table values; two: the two changes cancel), multiplied over words
        auto predicted_rate = [&](const std::vector<Moved>& mv) {
            double rate = 1.0;
            for (int w = 0; w < 4; w++) {
                std::vector<int> s; for (const Moved& a : mv) if (a.word == w) s.push_back(a.shift);
                if (s.empty()) continue;
                if (s.size() == 1) { rate *= eq[s[0]] / 65536.0; continue; }
                if (s.size() == 2) {
                    std::unordered_map<uint32_t, uint32_t> h; h.reserve(1 << 17);
                    for (int i2 = 0; i2 < 65536; i2++) h[incq(i2 + 16384 * s[1]) - incq(i2)]++;
                    uint64_t cnt = 0;
                    for (int i1 = 0; i1 < 65536; i1++) { auto it = h.find(incq(i1) - incq(i1 + 16384 * s[0])); if (it != h.end()) cnt += it->second; }
                    rate *= (double)cnt / 4294967296.0; continue;
                }
                return -1.0;   // three or more moved arguments in one word update: not computed
            }
            return rate;
        };
        for (int wi = 0; wi < 2; wi++) {
            const MCL_Q30_Sextet& W = *WS[wi];
            int hist[13] = {0}; int minc = 12, minw = 4;
            std::vector<int> few;
            for (int m = 1; m < 256; m++) {
                uint32_t d[4]; offset_of(m, d); const std::vector<Moved> mv = moved_args(W, d);
                hist[mv.size()]++; minc = std::min(minc, (int)mv.size()); minw = std::min(minw, words_touched(mv));
                if (mv.size() <= 2) few.push_back(m);
            }
            std::printf("  [COMPUTED] \"%s\": over the 255 offsets, fewest arguments moved = %d, fewest word updates touched = %d; offsets moving 1 / 2 / 3 arguments: %d / %d / %d\n",
                        XS[wi], minc, minw, hist[1], hist[2], hist[3]);
            const int LOGB = 22; const long nb = 1L << LOGB;
            for (int m : few) {
                uint32_t d[4]; offset_of(m, d); const std::vector<Moved> mv = moved_args(W, d);
                char args[160] = ""; for (const Moved& a : mv) { char t[48]; std::snprintf(t, sizeof t, " a%d%d(+%d/4 turn)", a.word + 1, a.from + 1, a.shift); std::strncat(args, t, sizeof args - std::strlen(args) - 1); }
                const S128 dd{{d[0], d[1], d[2], d[3]}};
                uint64_t z = 0x1B0930ull + (uint64_t)m * 31 + (uint64_t)wi; long c1 = 0, c2 = 0;
                for (long k = 0; k < nb; k++) {
                    const S128 x = rnd(z); const S128 a = rounds(x, W, kp, 1), b = rounds(add(x, dd), W, kp, 1);
                    if (b == add(a, dd)) {
                        c1++;
                        VDF128_State sa = to(a), sb = to(b); mcl_vdf128v4_iterate(sa, W, kp, CLK0 + 1); mcl_vdf128v4_iterate(sb, W, kp, CLK0 + 1);
                        if (from(sb) == add(from(sa), dd)) c2++;
                    }
                }
                const double pr = predicted_rate(mv), e = pr * (double)nb;
                std::printf("  [MEASURED] \"%s\" offset (%08x,%08x,%08x,%08x) moves%s -- %d word update(s): one round commutes on %ld of 2^%d states; "
                            "predicted 2^%.2f per round = %.2f states (z = %+.1f); two rounds running: %ld\n",
                            XS[wi], d[0], d[1], d[2], d[3], args, words_touched(mv), c1, LOGB, std::log2(pr), e, (c1 - e) / std::sqrt(e > 0 ? e : 1), c2);
                if (c2 != 0 || pr < 0 || std::fabs((double)c1 - e) > 5 * std::sqrt(e) + 1) p1b_ok = false;
            }
        }
        // census over the weight derivation of v4: how often a weight set has an offset that touches a single word update
        {
            const int NC = 20000; int wmin_hist[5] = {0, 0, 0, 0, 0}, one_arg = 0;
            for (int c = 0; c < NC; c++) {
                char in[32]; std::snprintf(in, sizeof in, "qseq-census-%05d", c);
                const MCL_Q30_Sextet W = mcl_vdf128v4_weights((const uint8_t*)in, std::strlen(in));
                int minw = 4, minc = 12;
                for (int m = 1; m < 256; m++) { uint32_t d[4]; offset_of(m, d); const std::vector<Moved> mv = moved_args(W, d); minw = std::min(minw, words_touched(mv)); minc = std::min(minc, (int)mv.size()); }
                wmin_hist[minw]++; one_arg += (minc == 1);
            }
            std::printf("  [COMPUTED] census, %d inputs \"qseq-census-00000..\" through the v4 derivation: fewest word updates touched by an offset = 1 / 2 / 3 / 4 for %d / %d / %d / %d weight sets; "
                        "an offset moving a single argument: %d (%.2f%%)\n", NC, wmin_hist[1], wmin_hist[2], wmin_hist[3], wmin_hist[4], one_arg, 100.0 * one_arg / NC);
            std::printf("  reading: a weight set whose fewest-touched count is w has a one-round relation F(x + delta) = F(x) + delta of probability about 2^(-15 w)\n");
        }
    }
    expect(p1b_ok, "every offset moving <= 2 arguments commutes at the table-predicted rate (5 sd); never two rounds running");

    // =====================================================================
    std::printf("\n== Part 2 (N2): additive differences (word-wise mod 2^32) through r clocked rounds ==\n");
    // =====================================================================
    const int LOGN2 = 14; const int N2 = 1 << LOGN2;
    std::vector<S128> deltas; std::vector<int> dclass;   // 0 random, 1 single-word power of two, 2 half-turn
    { uint64_t z = 0xADD0930ull; for (int i = 0; i < 64; i++) { deltas.push_back(rnd(z)); dclass.push_back(0); } }
    for (int w = 0; w < 4; w++) for (int b = 0; b < 32; b++) { S128 d{{0,0,0,0}}; d.w[w] = 1u << b; deltas.push_back(d); dclass.push_back(1); }
    for (int m = 1; m < 16; m++) { S128 d{{(uint32_t)((m & 1) << 31), (uint32_t)(((m >> 1) & 1) << 31), (uint32_t)(((m >> 2) & 1) << 31), (uint32_t)(((m >> 3) & 1) << 31)}}; deltas.push_back(d); dclass.push_back(2); }
    std::printf("  %zu input differences: 64 random, 128 single-word 2^b, 15 half-turn; n = 2^%d random states per difference\n", deltas.size(), LOGN2);
    // returns {largest multiplicity of one output difference, count of output difference == input difference}
    auto diff_stats = [&](auto mapfn, const S128& d, uint64_t seed) {
        std::vector<S128> out(N2); uint64_t z = seed; int same = 0;
        for (int k = 0; k < N2; k++) { S128 x = rnd(z); S128 o = sub(mapfn(add(x, d)), mapfn(x)); out[k] = o; same += (o == d); }
        std::sort(out.begin(), out.end()); int best = 1, run = 1;
        for (int k = 1; k < N2; k++) { run = (out[k] == out[k-1]) ? run + 1 : 1; best = std::max(best, run); }
        return std::pair<int,int>(best, same);
    };
    bool r23_ok = true;
    for (int wi = 0; wi < 2; wi++) {
        const MCL_Q30_Sextet& W = *WS[wi];
        for (int r = 1; r <= 3; r++) {
            int maxm[3] = {0,0,0}, maxs[3] = {0,0,0}, argm[3] = {-1,-1,-1}, above2[3] = {0,0,0};
            for (size_t i = 0; i < deltas.size(); i++) {
                auto st = diff_stats([&](const S128& x) { return rounds(x, W, kp, r); }, deltas[i], 0xD1FFull * 131 + i * 17 + (uint64_t)r * 7919 + (uint64_t)wi);
                const int c = dclass[i];
                if (st.first > maxm[c]) { maxm[c] = st.first; argm[c] = (int)i; }
                maxs[c] = std::max(maxs[c], st.second);
                if (st.first > 2) above2[c]++;
            }
            auto desc = [&](int i) { static char b[64]; if (i < 0) return (const char*)"-"; const S128& d = deltas[i];
                                     std::snprintf(b, sizeof b, "(%08x,%08x,%08x,%08x)", d.w[0], d.w[1], d.w[2], d.w[3]); return (const char*)b; };
            std::printf("  [MEASURED] \"%s\" r=%d: largest multiplicity (of %d) -- random %d; single-word %d at %s (%d of 128 above 2); half-turn %d (%d of 15 above 2); "
                        "most frequent 'difference unchanged' count: %d / %d / %d\n",
                        XS[wi], r, N2, maxm[0], maxm[1], desc(argm[1]), above2[1], maxm[2], above2[2], maxs[0], maxs[1], maxs[2]);
            if (r >= 2 && (maxm[0] > 2 || maxm[1] > 2 || maxm[2] > 2)) r23_ok = false;
        }
    }
    expect(r23_ok, "r = 2 and r = 3: largest multiplicity <= 2 for every difference, both instances");
    {   // controls through the same counting code: nonlinearity off (engine, K_phase = 0) and linear coupling
        int minm_k0 = N2, minm_lin = N2, mins_k0 = N2;
        for (int r = 1; r <= 3; r++) for (size_t i = 0; i < deltas.size(); i += 8) {
            auto a = diff_stats([&](const S128& x) { return rounds(x, W1, 0, r); }, deltas[i], 0xC7A1ull + i + (uint64_t)r * 1000);
            auto b = diff_stats([&](const S128& x) { return rounds_linear(x, W1, r); }, deltas[i], 0xC7A2ull + i + (uint64_t)r * 1000);
            minm_k0 = std::min(minm_k0, a.first); mins_k0 = std::min(mins_k0, a.second); minm_lin = std::min(minm_lin, b.first);
        }
        std::printf("  controls on 26 of the differences, r = 1..3: engine with K_phase = 0 -> smallest multiplicity %d, smallest 'unchanged' %d; linear coupling -> smallest multiplicity %d (of %d)\n",
                    minm_k0, mins_k0, minm_lin, N2);
        control(minm_k0 == N2 && mins_k0 == N2, "engine with K_phase = 0 (a translation map): every difference unchanged");
        control(minm_lin == N2, "linear-coupling sweep (affine map): one output difference per input difference");
    }

    // =====================================================================
    std::printf("\n== Part 3 (N3): image fraction of each single-word update, all 2^32 inputs ==\n");
    // =====================================================================
    const double rf = 1.0 - std::exp(-1.0), sd = std::sqrt((std::exp(-1.0) - 2.0 * std::exp(-2.0)) / 4294967296.0);
    std::printf("  random function on 2^32 points: E = 1 - 1/e = %.6f, sd = %.2e\n", rf, sd);
    {
        double t = now_s();
        const double a = image_fraction([](uint32_t v) { return v + 0x9E3779B9u; });
        uint64_t key = 0x0F0E0930ull;
        const double b = image_fraction([key](uint32_t v) { uint64_t z = key ^ ((uint64_t)v * 0xD1B54A32D192ED03ull); return (uint32_t)(sm(z) >> 32); });
        std::printf("  controls: bijection v + c -> %.6f ; hashed random function -> %.6f (z = %+.2f)   [time] %.1f s\n", a, b, (b - rf) / sd, now_s() - t);
        control(a == 1.0, "bijection v + c: image fraction exactly 1");
        control(std::fabs(b - rf) < 1e-4, "hashed random function: image fraction within 1e-4 of 1 - 1/e");
    }
    bool n3_ok = true; double n3_min = 1, n3_max = 0;
    struct Ctx { int wi; uint64_t seed; };
    const Ctx ctxs[3] = {{0, 0x31A6E0930ull}, {0, 0x31A6E0931ull}, {1, 0x31A6E0932ull}};
    for (const Ctx& c : ctxs) {
        const MCL_Q30_Sextet& W = *WS[c.wi]; WordMap M[4]; word_maps(W, M);
        uint64_t z = c.seed; S128 x = rnd(z); VDF128_State s = to(x); mcl_vdf128v4_clock(s, CLK0);
        uint32_t t[4] = {s.t1, s.t2, s.t3, s.t4};
        for (int k = 0; k < 4; k++) {   // word k varies over all 2^32 values; the other words are as the sweep sees them
            double tt = now_s(); uint32_t tc[4] = {t[0], t[1], t[2], t[3]}; const WordMap m = M[k];
            const double f = image_fraction([&, tc, m](uint32_t v) { return word_update(m, lut, kp, v, tc); });
            n3_min = std::min(n3_min, f); n3_max = std::max(n3_max, f);
            if (std::fabs(f - rf) > 0.01) n3_ok = false;
            std::printf("  [MEASURED] \"%s\" context %llx, word %d (q = %u, %u, %u): image fraction %.6f (z = %+.1f against a random function)   [time] %.1f s\n",
                        XS[c.wi], (unsigned long long)c.seed, k + 1, m.q[0], m.q[1], m.q[2], f, (f - rf) / sd, now_s() - tt);
            t[k] = word_update(M[k], lut, kp, t[k], t);   // advance the sweep to the next word
        }
    }
    std::printf("  range over the 12 enumerations: %.6f .. %.6f\n", n3_min, n3_max);
    expect(n3_ok, "every single-word image fraction within 0.01 of 1 - 1/e");

    // =====================================================================
    std::printf("\n== Part 4 (N4): amplitude of the nonlinear term ==\n");
    // =====================================================================
    {
        int32_t mx = 0; for (int i = 0; i < 65536; i++) mx = std::max(mx, (int32_t)std::abs(lut[i]));
        const double amp = (double)kp * (double)mx / 1073741824.0 / 4294967296.0;
        std::printf("  [COMPUTED] max |sin| entry = %d (2^30 = 1073741824); one coupling term moves a phase by up to %.4f turns; three terms per word: up to %.4f turns\n", mx, amp, 3 * amp);
        std::printf("  reading: the nonlinear term wraps the circle; there is no small-parameter regime in which the round is close to affine\n");
    }

    // =====================================================================
    std::printf("\n== Part 5 (N5): birthday probe of one clocked round ==\n");
    // =====================================================================
    {
        const int LOG5 = 24; const size_t n = (size_t)1 << LOG5;
        auto colliding = [&](auto mapfn, uint64_t seed) {
            std::vector<S128> v(n); uint64_t z = seed;
            for (size_t k = 0; k < n; k++) v[k] = mapfn(rnd(z));
            std::sort(v.begin(), v.end()); size_t c = 0; for (size_t k = 1; k < n; k++) c += (v[k] == v[k-1]); return c;
        };
        double t = now_s();
        const size_t c1 = colliding([&](const S128& x) { return rounds(x, W1, kp, 1); }, 0xB1D0930ull);
        const size_t c0 = colliding([&](const S128& x) { S128 y = rounds(x, W1, kp, 1); y.w[0] &= 0xFFFFFu; y.w[1] = y.w[2] = y.w[3] = 0; return y; }, 0xB1D0931ull);
        std::printf("  [MEASURED] 2^%d random states, one clocked round: %zu repeated outputs (random function on 2^128: expected 2^-81)   [time] %.1f s\n", LOG5, c1, now_s() - t);
        std::printf("  control: the same round with its output cut to 20 bits: %zu repeated outputs\n", c0);
        control(c0 > 0, "20-bit output cut: repeated outputs found by the same code");
        expect(c1 == 0, "one clocked round, 2^24 states: 0 repeated outputs");
    }

    std::printf("\n== Summary ==\n");
    std::printf("  controls %d of %d ok; consistency checks %d of %d ok; expectations written before the run: %d compared, %d differ\n",
                g_controls_run - g_controls_failed, g_controls_run, g_checks_run - g_checks_failed, g_checks_run, g_expect_run, g_expect_differ);
    std::printf("  [time] total %.1f s\n", now_s() - T0);
    if (g_controls_failed || g_checks_failed) { std::printf("  A CONTROL OR CONSISTENCY CHECK FAILED -- DO NOT QUOTE THIS RUN\n"); return 2; }
    return 0;
}
