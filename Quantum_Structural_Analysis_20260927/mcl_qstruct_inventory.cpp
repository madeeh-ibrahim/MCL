// mcl_qstruct_inventory.cpp -- Doc ID MCL-QSTRUCT-2026-0927-001 rev 3
// ---------------------------------------------------------------------------
// Structural inventory of the live MCL maps against FOUR families of quantum
// attack on symmetric primitives. CLASSICAL probe: it runs no quantum
// algorithm and proves nothing about quantum cost or security (Paper 4 OP2).
//
// rev 3 (2026-09-28): construction C5 is measured BEFORE and AFTER the
// symmetry check that sidecar v1.0.7 applies to the cascade, and the text
// names the seed rule it scans (Legacy, the default). Every other row is
// computed by the code of rev 2, the revision of the first record run
// (2026-09-27). Built against sidecar v1.0.6, rev 2 reports the cascade before
// the check only.
//
// EVERY PRINTED ROW CARRIES ONE TAG
//   [MEASURED]      obtained by running the unmodified engine map or an engine
//                   class; could have come out otherwise.
//   [COMPUTED]      exact algebra on weights that the engine's own derivation
//                   produced (rank, group order, reachability). Wherever a
//                   [COMPUTED] row matters, a [MEASURED] row checks it.
//   [INSPECTION]    read off the source code; no run can change it.
//   [CONSTRUCTION]  forced by how the object was built; a consistency check,
//                   NOT evidence.
//   [CONTROL]       a case whose answer is known in advance, run through the
//                   SAME code path, to show the detector fires / stays silent.
//   [GENERIC]       a bound that holds for any function of that size.
//   [DERIVED]       arithmetic on a cited theorem; the citation is in the row.
//   [NOT MEASURABLE HERE]  a property of the protocol or of the adversary's
//                   access, which no run of the map can settle.
// A run whose controls do not all pass must not be quoted.
//
// FAMILIES COVERED
//   F1 hidden translation subgroup of the state map (abelian HSP; hidden shift
//      over Z/2^32 -- Kuperberg; Bonnetain & Naya-Plasencia, ASIACRYPT 2018).
//      Part 1: EXACT translation group of each weight set by 2-adic lifting,
//      every element verified on the engine, plus which elements a PUBLIC SEED
//      can reach. rank 4 of the parity matrix <=> trivial group.
//   F2 period / collision structure of the INPUT channel (Simon 1994; Kaplan,
//      Leurent, Leverrier, Naya-Plasencia, CRYPTO 2016). Part 2.
//      LIMIT, stated once: finding an unknown XOR period over n input bits
//      costs a classical prober ~2^(n/2) evaluations -- that gap IS Simon's
//      speed-up. Part 2 therefore does two things it can afford:
//        (a) structured candidates over the FULL 64-bit input word;
//        (b) a birthday search that covers EVERY period inside a 32-bit
//            sub-domain, with a stated confidence.
//      And periodicity of the RAW function is neither necessary nor sufficient
//      for a Simon-type attack: in Even-Mansour / FX the raw function has no
//      period and the attack builds one (Part 3); a raw period that does not
//      depend on the key gives the attacker nothing (channel A below).
//   F3 FX / Grover-meets-Simon on the LEGACY transaction tag (Leander & May,
//      ASIACRYPT 2017, Theorem 2; offline Simon: Bonnetain, Hosoyamada,
//      Naya-Plasencia, Sasaki, Schrottenloher, ASIACRYPT 2019). Part 3.
//   F4 generic collision search (Brassard, Hoyer, Tapp, LATIN 1998; Chailloux,
//      Naya-Plasencia, Schrottenloher, ASIACRYPT 2017). Printed as [GENERIC].
//
// FAMILIES NOT COVERED (nothing here supports any statement about them)
//   quantum differential / linear cryptanalysis (Kaplan, Leurent, Leverrier,
//   Naya-Plasencia, IACR ToSC 2016(1), doi 10.13154/tosc.v2016.i1.71-94);
//   quantum slide and related-key attacks; claw finding / meet-in-the-middle
//   on the cascade; any reduction of the sequential DEPTH of the iteration
//   (Paper 4 OP2); Grover key search itself (mcl_grover_resource_estimate).
//
// CONSTRUCTIONS
//   C1 two-oscillator (3,5) raw Q30  -- RETIRED path, known group of order 16.
//   C2 keyed T4-Q30 (weight derivation of sidecar v1.0.6, unchanged in v1.0.7).
//   C3 VDF128-T4 public weights.
//   C4 VDF128-T4 v3/v4 per-input weights (full-rank re-draw).
//   C5 keyed cascade over the two-oscillator engine (sidecar construction B),
//      before and after the symmetry check of sidecar v1.0.7.
//
// ADDITIVE: no engine file is modified. Engine of record mcl_core.hpp v8.1.3
// (SHA-256 416ad145e79c...), sidecar v1.0.7 (05c01cf8a156...).
// NOTHING is executed by building this file.
// Build:
//   clang++ -std=c++17 -O3 -DNDEBUG -Wall -Wextra -Wpedantic -pthread -I.. \
//       mcl_qstruct_inventory.cpp -o mcl_qstruct_inventory
// ---------------------------------------------------------------------------
#include "../mcl_core.hpp"
#include "../keyed_q30_PQ/mcl_keyed_q30.hpp"
#include "../VDF128_T4/mcl_vdf128_t4.hpp"
#include "../VDF128_T4/mcl_vdf128_t4_v3.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <cmath>
#include <array>
#include <vector>
#include <string>
#include <algorithm>
#include <thread>
#include <chrono>
#include <utility>

// ===========================================================================
// Small helpers
// ===========================================================================
typedef std::array<uint32_t, 4> V4;
typedef std::array<uint8_t, 32> Key32;

static void rule(char c = '=') { for (int i = 0; i < 78; i++) std::putchar(c); std::putchar('\n'); }
static void head(const char* t) { std::putchar('\n'); rule(); std::printf("  %s\n", t); rule(); }

// SplitMix64. One independent stream per part, derived from the master seed,
// so changing one sample size never changes another part's samples.
struct Rng {
    uint64_t s;
    uint64_t next() {
        uint64_t z = (s += 0x9E3779B97F4A7C15ULL);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    uint32_t next32() { return (uint32_t)(next() >> 32); }
};
static Rng stream(uint64_t master, uint64_t tag) {
    return Rng{ fmix64(master ^ fmix64(tag ^ 0xA5A5A5A5A5A5A5A5ULL)) };
}
// Bijection on 32-bit words (MurmurHash3 fmix32): distinct i -> distinct values.
static uint32_t mix32(uint32_t h) {
    h ^= h >> 16; h *= 0x85EBCA6BU; h ^= h >> 13; h *= 0xC2B2AE35U; h ^= h >> 16;
    return h;
}
static uint64_t le64(const uint8_t* b) {
    uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)b[i] << (8 * i); return v;
}
static uint32_t inv32(uint32_t a) {           // inverse of an ODD a modulo 2^32
    uint32_t x = a;                            // correct to 3 bits
    for (int i = 0; i < 5; i++) x *= 2u - a * x;
    return x;
}
static int v2_32(uint32_t x) { if (x == 0) return 32; int v = 0; while (((x >> v) & 1u) == 0u) v++; return v; }
static Key32 derived_key(const char* domain, uint64_t i) {
    uint8_t buf[64]; size_t n = std::strlen(domain); if (n > 48) n = 48;
    std::memcpy(buf, domain, n);
    for (int k = 0; k < 8; k++) buf[n + (size_t)k] = (uint8_t)(i >> (8 * k));
    Key32 out; mcl_sha256(buf, n + 8, out.data());
    return out;
}
static std::string bits_to_string(uint64_t m) {
    if (m == 0) return "{}";
    std::string s = "{"; bool first = true;
    for (int b = 0; b < 64; ) {
        if (!((m >> b) & 1ULL)) { b++; continue; }
        int e = b; while (e + 1 < 64 && ((m >> (e + 1)) & 1ULL)) e++;
        if (!first) s += ","; first = false;
        s += std::to_string(b); if (e > b) { s += ".."; s += std::to_string(e); }
        b = e + 1;
    }
    return s + "}";
}
static int popcount64(uint64_t m) { int c = 0; while (m) { m &= m - 1; c++; } return c; }

// ---- run bookkeeping --------------------------------------------------------
static int g_ctrl_total = 0, g_ctrl_pass = 0;       // [CONTROL] rows
static int g_cons_total = 0, g_cons_fail = 0;       // internal consistency checks
static int g_prereg_total = 0, g_prereg_diff = 0;   // pre-registered expectations
static void control(const char* name, bool pass, const std::string& detail) {
    g_ctrl_total++; if (pass) g_ctrl_pass++;
    std::printf("  [CONTROL] %-46s %s  %s\n", name, pass ? "PASS" : "FAIL", detail.c_str());
}
static void consistency(bool ok, const char* what) {
    g_cons_total++;
    if (!ok) { g_cons_fail++; std::printf("  [!! CONSISTENCY FAILURE] %s\n", what); }
}
static const char* prereg(bool matches) {
    g_prereg_total++; if (!matches) g_prereg_diff++;
    return matches ? "[matches pre-registered]" : "[!! DIFFERS FROM PRE-REGISTERED]";
}

// ===========================================================================
// PART 1 algebra -- translation symmetries
// ---------------------------------------------------------------------------
// A state offset d commutes with the map, F(t+d) = F(t)+d for every t, when
// every coupling argument is unchanged:  sum_k c[k]*d[k] == 0 (mod 2^32) for
// each argument row c. For pair e = (I,J) with weights (p,q) the two rows are
//     a_IJ = p*t_J - q*t_I   ->  c[J] = p, c[I] = -q
//     a_JI = p*t_I - q*t_J   ->  c[I] = p, c[J] = -q
// (mcl_q30t4_iterate_raw in the sidecar). The solutions form a group.
// ===========================================================================
static const int PAIR_I[6] = { 0, 0, 0, 1, 1, 2 };
static const int PAIR_J[6] = { 1, 2, 3, 2, 3, 3 };
static void weights_array(const MCL_Q30_Sextet& W, uint32_t P[6], uint32_t Q[6]) {
    P[0] = W.p12; Q[0] = W.q12; P[1] = W.p13; Q[1] = W.q13; P[2] = W.p14; Q[2] = W.q14;
    P[3] = W.p23; Q[3] = W.q23; P[4] = W.p24; Q[4] = W.q24; P[5] = W.p34; Q[5] = W.q34;
}
static std::vector<V4> rows_t4(const MCL_Q30_Sextet& W) {
    uint32_t P[6], Q[6]; weights_array(W, P, Q);
    std::vector<V4> rows;
    for (int e = 0; e < 6; e++) {
        V4 a{ 0, 0, 0, 0 }, b{ 0, 0, 0, 0 };
        a[(size_t)PAIR_J[e]] = P[e]; a[(size_t)PAIR_I[e]] = 0u - Q[e];
        b[(size_t)PAIR_I[e]] = P[e]; b[(size_t)PAIR_J[e]] = 0u - Q[e];
        rows.push_back(a); rows.push_back(b);
    }
    return rows;
}
static std::vector<V4> rows_osc2(int64_t p, int64_t q) {
    const uint32_t pp = (uint32_t)p, qq = (uint32_t)q;
    return std::vector<V4>{ V4{ 0u - qq, pp, 0, 0 }, V4{ pp, 0u - qq, 0, 0 } };
}
static bool rows_hold(const std::vector<V4>& rows, const V4& x, uint32_t mask) {
    for (const V4& r : rows) {
        uint32_t acc = 0;
        for (size_t k = 0; k < 4; k++) acc += r[k] * x[k];
        if (acc & mask) return false;
    }
    return true;
}
// (i) rank by Gaussian elimination over GF(2) -- the algorithm of
//     mcl_vdf128v3_parity_rank, on the parities of the rows.
static int rank_gf2(const std::vector<V4>& rows, int nvars) {
    std::vector<unsigned> m;
    for (const V4& r : rows) { unsigned b = 0; for (int k = 0; k < nvars; k++) b |= (r[(size_t)k] & 1u) << k; m.push_back(b); }
    int rank = 0;
    for (int bit = 0; bit < nvars; bit++) {
        int piv = -1;
        for (size_t r = (size_t)rank; r < m.size(); r++) if ((m[r] >> bit) & 1u) { piv = (int)r; break; }
        if (piv < 0) continue;
        std::swap(m[(size_t)piv], m[(size_t)rank]);
        for (size_t r = 0; r < m.size(); r++)
            if ((int)r != rank && ((m[r] >> bit) & 1u)) m[r] ^= m[(size_t)rank];
        rank++;
    }
    return rank;
}
// (ii) kernel by exhaustion -- shares NO code with the elimination above.
static int kernel_count_bruteforce(const std::vector<V4>& rows, int nvars) {
    int n = 0;
    for (unsigned d = 0; d < (1u << nvars); d++) {
        bool ok = true;
        for (const V4& r : rows) {
            unsigned par = 0;
            for (int k = 0; k < nvars; k++) par ^= (r[(size_t)k] & 1u) & ((d >> k) & 1u);
            if (par) { ok = false; break; }
        }
        if (ok) n++;
    }
    return n;
}
// (iii) the engine's own function, for the four-oscillator sets.
static int rank_engine(const MCL_Q30_Sextet& W) {
    const int64_t w[12] = { W.p12, W.q12, W.p13, W.q13, W.p14, W.q14,
                            W.p23, W.q23, W.p24, W.q24, W.p34, W.q34 };
    return mcl_vdf128v3_parity_rank(w);
}
// EXACT group: lift solutions from modulus 2^j to 2^(j+1), j = 0..31. The
// number of solutions modulo 2^j never exceeds the final group order (Smith
// normal form), so the lists stay as small as the group.
static bool exact_group(const std::vector<V4>& rows, int nvars, std::vector<V4>& group, size_t cap) {
    std::vector<V4> sols(1, V4{ 0, 0, 0, 0 });
    for (int j = 0; j < 32; j++) {
        const uint32_t mask = (j == 31) ? 0xFFFFFFFFu : ((1u << (j + 1)) - 1u);
        std::vector<V4> next;
        for (const V4& e : sols)
            for (unsigned eta = 0; eta < (1u << nvars); eta++) {
                V4 c = e;
                for (int k = 0; k < nvars; k++) if ((eta >> k) & 1u) c[(size_t)k] |= (1u << j);
                if (rows_hold(rows, c, mask)) {
                    next.push_back(c);
                    if (next.size() > cap) return false;
                }
            }
        sols.swap(next);
    }
    std::sort(sols.begin(), sols.end());
    group = sols;
    return true;
}
static bool is_zero(const V4& v) { return v[0] == 0 && v[1] == 0 && v[2] == 0 && v[3] == 0; }

// Which group elements can a PUBLIC SEED reach? The keyed engines start from
// t_k = hash_seed(s) * omega_k (mod 2^32), so a seed offset D moves the state
// by (D*omega_k). omega_1 is odd, hence D = d[0] * omega_1^{-1} is forced and
// the remaining coordinates either agree or the element is unreachable.
static bool seed_reachable(const V4& d, const uint32_t* om, int nvars, uint32_t& D_out) {
    const uint32_t D = d[0] * inv32(om[0]);
    for (int k = 0; k < nvars; k++) if ((uint32_t)(D * om[(size_t)k]) != d[(size_t)k]) return false;
    D_out = D; return true;
}

// ---- engine checks ----------------------------------------------------------
static int t4_translation_holds(const MCL_Q30_Sextet& W, int64_t kp, const V4& d,
                                int R, int iters, Rng& rng) {
    int held = 0;
    for (int r = 0; r < R; r++) {
        uint32_t x[4], y[4];
        for (size_t k = 0; k < 4; k++) { x[k] = rng.next32(); y[k] = x[k] + d[k]; }
        for (int i = 0; i < iters; i++) {
            mcl_q30t4_iterate_raw(x[0], x[1], x[2], x[3], W, kp);
            mcl_q30t4_iterate_raw(y[0], y[1], y[2], y[3], W, kp);
        }
        bool ok = true;
        for (size_t k = 0; k < 4; k++) if (y[k] != (uint32_t)(x[k] + d[k])) { ok = false; break; }
        if (ok) held++;
    }
    return held;
}
static int osc2_translation_holds(int64_t p, int64_t q, int64_t kp, uint32_t d1, uint32_t d2,
                                  int R, int iters, Rng& rng) {
    int held = 0;
    for (int r = 0; r < R; r++) {
        uint32_t x1 = rng.next32(), x2 = rng.next32();
        uint32_t y1 = x1 + d1, y2 = x2 + d2;
        for (int i = 0; i < iters; i++) {
            mcl_q30_iterate_raw(x1, x2, p, q, kp);
            mcl_q30_iterate_raw(y1, y2, p, q, kp);
        }
        if (y1 == (uint32_t)(x1 + d1) && y2 == (uint32_t)(x2 + d2)) held++;
    }
    return held;
}

struct T4Analysis {
    int rank_elim, rank_eng, kernel, top_level;
    bool group_ok; std::vector<V4> group;
    int reachable_nontrivial;       // nontrivial group elements a seed can reach
};
static T4Analysis analyse_t4(const MCL_Q30_Sextet& W, const uint32_t om[4]) {
    T4Analysis a;
    const std::vector<V4> rows = rows_t4(W);
    a.rank_elim = rank_gf2(rows, 4);
    a.rank_eng  = rank_engine(W);
    a.kernel    = kernel_count_bruteforce(rows, 4);
    a.group_ok  = exact_group(rows, 4, a.group, 65536);
    a.top_level = 0; a.reachable_nontrivial = 0;
    if (a.group_ok)
        for (const V4& g : a.group) {
            bool top = true;
            for (size_t k = 0; k < 4; k++) if (g[k] != 0u && g[k] != 0x80000000u) top = false;
            if (top) a.top_level++;
            uint32_t D = 0;
            if (!is_zero(g) && seed_reachable(g, om, 4, D)) a.reachable_nontrivial++;
        }
    // three independent rank computations + the lifted group must agree
    consistency(a.rank_elim == a.rank_eng, "rank: elimination != engine function");
    consistency(a.kernel == (1 << (4 - a.rank_elim)), "rank: elimination != exhaustive kernel");
    if (a.group_ok) {
        consistency(a.top_level == a.kernel, "lifted group: top-level elements != kernel");
        consistency((a.group.size() == 1) == (a.rank_elim == 4), "lifted group: trivial <=> rank 4 violated");
    }
    return a;
}
// verify every nontrivial element of a group on the engine, plus one offset
// that is NOT in the group (must fail).
static bool verify_t4_group_on_engine(const MCL_Q30_Sextet& W, int64_t kp, const std::vector<V4>& group,
                                      int R, Rng& rng, int& members_ok, int& members, bool& nonmember_fails) {
    members_ok = 0; members = 0;
    for (const V4& g : group) {
        if (is_zero(g)) continue;
        members++;
        if (t4_translation_holds(W, kp, g, R, 1, rng) == R &&
            t4_translation_holds(W, kp, g, R, 16, rng) == R) members_ok++;
    }
    V4 out{ 0, 0, 0, 0 }; bool found = false;          // first top-level offset outside the group
    for (unsigned d = 1; d < 16 && !found; d++) {
        V4 c{ 0, 0, 0, 0 };
        for (size_t k = 0; k < 4; k++) if ((d >> k) & 1u) c[k] = 0x80000000u;
        if (!std::binary_search(group.begin(), group.end(), c)) { out = c; found = true; }
    }
    nonmember_fails = found ? (t4_translation_holds(W, kp, out, R, 1, rng) < R) : true;
    return members_ok == members && nonmember_fails;
}

// ===========================================================================
// PART 2 machinery -- input channels, 64-bit input word, 64-bit output
// ===========================================================================
template <typename G>
static void eval_many(const G& g, const std::vector<uint64_t>& xs, std::vector<uint64_t>& ys, int threads) {
    ys.assign(xs.size(), 0);
    const size_t n = xs.size();
    if (threads <= 1 || n < 64) { for (size_t i = 0; i < n; i++) ys[i] = g(xs[i]); return; }
    std::vector<std::thread> th;
    for (int t = 0; t < threads; t++)
        th.emplace_back([&g, &xs, &ys, n, t, threads]() {
            for (size_t i = (size_t)t; i < n; i += (size_t)threads) ys[i] = g(xs[i]);
        });
    for (std::thread& x : th) x.join();
}

struct CandidateScan { uint64_t exact = 0, partial = 0; int best_random = 0; };
// kind 0: x XOR 2^b ; kind 1: x + 2^b (mod 2^64). regime 1: x < 2^52, 2: x > 2^52.
template <typename G>
static CandidateScan scan_candidates(const G& g, int kind, int regime, int M, int n_random,
                                     Rng& rng, int threads) {
    std::vector<uint64_t> xs((size_t)M), base;
    for (size_t i = 0; i < (size_t)M; i++) {
        uint64_t x = rng.next();
        if (regime == 1) {                       // identity range of hash_seed: x < 2^52.
            x >>= (kind == 1) ? 16 : 12;        // additive offsets up to 2^51 must not carry past it
            if (x == 0) x = 1;
        } else if (x <= (1ULL << 52)) x |= (1ULL << 60);
        xs[i] = x;
    }
    eval_many(g, xs, base, threads);
    std::vector<uint64_t> cand;
    for (int b = 0; b < 64; b++) cand.push_back(1ULL << b);
    const size_t n_struct = cand.size();
    if (kind == 0) for (int i = 0; i < n_random; i++) { uint64_t s = rng.next(); if (s == 0) s = 1; cand.push_back(s); }
    std::vector<uint64_t> in; in.reserve(cand.size() * (size_t)M);
    for (uint64_t s : cand)
        for (size_t i = 0; i < (size_t)M; i++) in.push_back(kind == 0 ? (xs[i] ^ s) : (xs[i] + s));
    std::vector<uint64_t> out;
    eval_many(g, in, out, threads);
    CandidateScan r;
    for (size_t c = 0; c < cand.size(); c++) {
        int hits = 0;
        for (size_t i = 0; i < (size_t)M; i++) if (out[c * (size_t)M + i] == base[i]) hits++;
        if (c < n_struct) {
            if (hits == M) r.exact |= cand[c];
            else if (hits > 0) r.partial |= cand[c];
        } else if (hits > r.best_random) r.best_random = hits;
    }
    return r;
}
// closure: XOR of any subset of exact period bits must again be a period.
template <typename G>
static int closure_check(const G& g, uint64_t exact_mask, int trials, int M, Rng& rng, int threads, int& full) {
    full = 0; if (popcount64(exact_mask) < 2) return 0;
    int done = 0;
    for (int t = 0; t < trials; t++) {
        uint64_t s = rng.next() & exact_mask; if (s == 0) continue;
        std::vector<uint64_t> xs((size_t)M), a, b;
        for (size_t i = 0; i < (size_t)M; i++) { uint64_t x = rng.next() >> 12; if (x == 0) x = 1; xs[i] = x; }
        std::vector<uint64_t> xs2(xs); for (uint64_t& x : xs2) x ^= s;
        eval_many(g, xs, a, threads); eval_many(g, xs2, b, threads);
        bool all = true; for (size_t i = 0; i < a.size(); i++) if (a[i] != b[i]) all = false;
        done++; if (all) full++;
    }
    return done;
}

struct Collision { uint64_t x1, x2; };
// Birthday search on the sub-domain  hi | (32 random low bits): N distinct
// inputs, 64-bit outputs. If ANY exact period (XOR or additive) lies inside
// the sub-domain, the expected number of colliding pairs is N^2 / 2^33.
template <typename G>
static std::vector<Collision> birthday(const G& g, uint64_t hi, int log2N, uint32_t offset, int threads) {
    const size_t N = (size_t)1 << log2N;
    std::vector<uint64_t> xs; xs.reserve(N);
    for (size_t i = 0; i < N; i++) {
        const uint64_t x = hi | (uint64_t)mix32(offset + (uint32_t)i);
        if (x != 0) xs.push_back(x);              // 0 is remapped by the engine contract
    }
    std::vector<uint64_t> ys;
    eval_many(g, xs, ys, threads);
    std::vector<std::pair<uint64_t, uint64_t> > v; v.reserve(xs.size());
    for (size_t i = 0; i < xs.size(); i++) v.push_back(std::make_pair(ys[i], xs[i]));
    std::sort(v.begin(), v.end());
    std::vector<Collision> out;
    for (size_t i = 1; i < v.size(); i++)
        if (v[i].first == v[i - 1].first) out.push_back(Collision{ v[i - 1].second, v[i].second });
    return out;
}
template <typename G>
static int verify_xor_period(const G& g, uint64_t hi, uint64_t s, int M, Rng& rng, int threads) {
    std::vector<uint64_t> xs((size_t)M), a, b;
    for (size_t i = 0; i < (size_t)M; i++) { uint64_t x = hi | (uint64_t)rng.next32(); if (x == 0) x = 1; xs[i] = x; }
    std::vector<uint64_t> xs2(xs); for (uint64_t& x : xs2) x ^= s;
    eval_many(g, xs, a, threads); eval_many(g, xs2, b, threads);
    int hits = 0; for (size_t i = 0; i < a.size(); i++) if (a[i] == b[i]) hits++;
    return hits;
}

// ---- the four channels -------------------------------------------------------
static uint64_t ch_seed_t4(const Key32& key, uint64_t seed) {
    if (seed == 0) seed = 1;                                  // engine contract
    MCL_T4_Q30 e(key.data(), 0, seed);
    uint8_t b[8]; e.gen_bytes(b, 8); return le64(b);
}
static uint64_t ch_challenge_t4(const Key32& key, uint64_t challenge) {
    MCL_T4_Q30 e(key.data(), challenge, DEFAULT_SEED);
    uint8_t b[8]; e.gen_bytes(b, 8); return le64(b);
}
static uint64_t ch_seed_cascade(const Key32& key, uint64_t seed) {
    if (seed == 0) seed = 1;
    uint8_t o[32]; mcl_cascade_q30(key.data(), o, MCL_CASCADE_DEFAULT_EPOCHS, 0, seed);
    return le64(o);
}

// ---- legacy transaction tag: a VARIANT of the superseded input-composition
// form (mcl_txn_verify.cpp, RETIRED_mcl_txn_verify.md) in which a 64-bit word
// W, folded from a device secret, is XORed into the engine input. The
// published program has no such word: its device secret is the pair (p, q).
// The variant is modelled because a secret word XORed into the input gives
// the tag the FX shape that Part 3 examines.
static const uint64_t FNV_OFFSET_BASIS = 0xCBF29CE484222325ULL;
static const uint64_t FNV_PRIME        = 0x100000001B3ULL;
static const uint64_t GOLDEN           = 0x9E3779B97F4A7C15ULL;
static uint64_t legacy_sdevice_fold(const uint64_t w[4]) {
    return fmix64(w[0]) ^ fmix64(w[1] + GOLDEN) ^ fmix64(w[2] + 2 * GOLDEN) ^ fmix64(w[3] + 3 * GOLDEN);
}
static uint64_t legacy_hash_tx(const char* tx) {
    uint64_t h = FNV_OFFSET_BASIS;
    for (const char* p = tx; *p; ++p) { h ^= (uint8_t)*p; h *= FNV_PRIME; }
    return fmix64(h);
}
static uint64_t legacy_nonce(uint64_t counter) { return fmix64(counter); }
static uint64_t fmix64_inv(uint64_t k) {
    k ^= k >> 31; k ^= k >> 62;
    k *= 0x319642B2D24D8EC3ULL;            // inverse of 0x94D049BB133111EB mod 2^64
    k ^= k >> 27; k ^= k >> 54;
    k *= 0x96DE1B173F119089ULL;            // inverse of 0xBF58476D1CE4E5B9 mod 2^64
    k ^= k >> 30; k ^= k >> 60;
    return k;
}
// E_{p,q}(u): the engine as a public function of its 64-bit input word.
static uint64_t legacy_E(int64_t p, int64_t q, uint64_t u) {
    if (u == 0) u = 1;                                        // engine contract
    MCL_T2 e(u, p, q);
    uint8_t b[8]; e.gen_bytes(b, 8); return le64(b);
}
// Tag oracle with a fixed secret (p,q,W): Tag(u) = E_{p,q}(u XOR W).
static uint64_t ch_legacy(int64_t p, int64_t q, uint64_t W, uint64_t u) { return legacy_E(p, q, u ^ W); }

// ---- cascade replica (state evolution of mcl_cascade_q30, raw state out) ----
typedef std::vector<std::pair<int64_t, int64_t> > Epochs;
static void cascade_raw(const Epochs& ep, uint64_t seed, uint8_t raw[32]) {
    uint32_t t1, t2; mcl_q30_init_state(seed, t1, t2);
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    for (size_t e = 0; e < ep.size(); e++) {
        const int it = (e == 0) ? MCL_CASCADE_FIRST_EPOCH_ITERS : MCL_CASCADE_LATER_EPOCH_ITERS;
        for (int i = 0; i < it; i++) mcl_q30_iterate_raw(t1, t2, ep[e].first, ep[e].second, kp);
    }
    for (size_t b = 0; b < 4; b++) {
        mcl_q30_iterate_raw(t1, t2, ep.back().first, ep.back().second, kp);
        for (size_t k = 0; k < 4; k++) raw[b * 8 + k]     = (uint8_t)(t1 >> (k * 8));
        for (size_t k = 0; k < 4; k++) raw[b * 8 + 4 + k] = (uint8_t)(t2 >> (k * 8));
    }
}
static std::vector<V4> rows_cascade(const Epochs& ep) {
    std::vector<V4> rows;
    for (const std::pair<int64_t, int64_t>& e : ep) {
        const std::vector<V4> r = rows_osc2(e.first, e.second);
        rows.insert(rows.end(), r.begin(), r.end());
    }
    return rows;
}

// ===========================================================================
// Command line (strict)
// ===========================================================================
struct Opt {
    long keys = 20000, v3_inputs = 2000, cascade_keys = 200000;
    long engine_states = 64, refl = 100000, verify = 32, random_s = 64;
    long birthday_log2 = 18, whiten_log2 = 22, threads = 1;
    uint64_t seed = 0xC0FFEEULL;
    bool selftest = false;
    bool part[4] = { true, true, true, true };      // index 1..3 used
};
static void usage(const char* a0) {
    std::printf(
      "usage: %s [options]\n"
      "  --keys N            keyed T4-Q30 population sweep           (default 20000)\n"
      "  --v3-inputs N       VDF128-T4 v3 inputs sampled             (default 2000)\n"
      "  --cascade-keys N    cascade population sweep                (default 200000)\n"
      "  --engine-states R   random states per engine symmetry test  (default 64)\n"
      "  --refl N            states for the reflection distribution  (default 100000)\n"
      "  --verify M          inputs per period candidate             (default 32)\n"
      "  --random-s n        random 64-bit XOR candidates            (default 64)\n"
      "  --birthday-log2 b   birthday sample = 2^b per channel       (default 18)\n"
      "  --whiten-log2 w     whitening-image sample = 2^w            (default 22)\n"
      "  --threads T         evaluation threads (results identical)  (default 1)\n"
      "  --seed S            master seed, decimal or 0x hex          (default 0xC0FFEE)\n"
      "  --part P            1, 2, 3 or all (controls always run)    (default all)\n"
      "  --selftest          controls + every part at reduced size; exit 0 iff all pass\n"
      "  --help\n", a0);
}
static bool parse_long(const char* s, long lo, long hi, long& out) {
    errno = 0; char* e = nullptr; const long v = std::strtol(s, &e, 10);
    if (errno != 0 || e == s || *e != '\0' || v < lo || v > hi) return false;
    out = v; return true;
}
static bool parse_u64(const char* s, uint64_t& out) {
    errno = 0; char* e = nullptr; const unsigned long long v = std::strtoull(s, &e, 0);
    if (errno != 0 || e == s || *e != '\0' || s[0] == '-') return false;
    out = (uint64_t)v; return true;
}

// ===========================================================================
int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IOLBF, 0);
    Opt o;
    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "--help") { usage(argv[0]); return 0; }
        if (a == "--selftest") { o.selftest = true; continue; }
        if (i + 1 >= argc) { std::fprintf(stderr, "error: option %s needs a value\n", a.c_str()); usage(argv[0]); return 2; }
        const char* v = argv[++i];
        bool ok = false;
        if      (a == "--keys")          ok = parse_long(v, 1, 10000000, o.keys);
        else if (a == "--v3-inputs")     ok = parse_long(v, 1, 10000000, o.v3_inputs);
        else if (a == "--cascade-keys")  ok = parse_long(v, 1, 100000000, o.cascade_keys);
        else if (a == "--engine-states") ok = parse_long(v, 1, 1000000, o.engine_states);
        else if (a == "--refl")          ok = parse_long(v, 256, 100000000, o.refl);
        else if (a == "--verify")        ok = parse_long(v, 1, 100000, o.verify);
        else if (a == "--random-s")      ok = parse_long(v, 0, 100000, o.random_s);
        else if (a == "--birthday-log2") ok = parse_long(v, 8, 24, o.birthday_log2);
        else if (a == "--whiten-log2")   ok = parse_long(v, 10, 26, o.whiten_log2);
        else if (a == "--threads")       ok = parse_long(v, 1, 64, o.threads);
        else if (a == "--seed")          ok = parse_u64(v, o.seed);
        else if (a == "--part") {
            const std::string p = v; ok = true;
            if (p == "all") { o.part[1] = o.part[2] = o.part[3] = true; }
            else if (p == "1" || p == "2" || p == "3") {
                o.part[1] = o.part[2] = o.part[3] = false; o.part[(size_t)(p[0] - '0')] = true;
            } else ok = false;
        }
        else { std::fprintf(stderr, "error: unknown option %s\n", a.c_str()); usage(argv[0]); return 2; }
        if (!ok) { std::fprintf(stderr, "error: bad value '%s' for %s\n", v, a.c_str()); return 2; }
    }
    if (o.selftest) {                       // reduced sizes; every code path still runs
        o.keys = 2000; o.v3_inputs = 200; o.cascade_keys = 20000; o.engine_states = 32;
        o.refl = 20000; o.verify = 16; o.random_s = 8; o.birthday_log2 = 11; o.whiten_log2 = 16;
        o.part[1] = o.part[2] = o.part[3] = true;
    }
    const int R = (int)o.engine_states, M = (int)o.verify, TH = (int)o.threads;
    const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    const uint32_t om[4] = { mcl_q30_omega1(), mcl_q30_omega2(), mcl_q30_omega3(), mcl_q30_omega4() };
    (void)mcl_q30_table();                  // build the sine table before any thread starts
    const std::chrono::steady_clock::time_point t_start = std::chrono::steady_clock::now();

    std::printf("MCL-QSTRUCT-2026-0927-001 rev 3   structural inventory (classical probe)\n");
    std::printf("engine mcl_core %s (UNMODIFIED) + sidecar v1.0.7 + VDF128-T4 v1/v3 headers\n", MCL_VERSION_STRING);
    {   // a record run is the DEFAULT configuration, all three parts; anything else says so
        const Opt d;
        const bool is_default = o.keys == d.keys && o.v3_inputs == d.v3_inputs && o.cascade_keys == d.cascade_keys
            && o.engine_states == d.engine_states && o.refl == d.refl && o.verify == d.verify
            && o.random_s == d.random_s && o.birthday_log2 == d.birthday_log2 && o.whiten_log2 == d.whiten_log2
            && o.seed == d.seed && o.part[1] && o.part[2] && o.part[3];
        std::printf("mode: %s\n", o.selftest ? "SELFTEST (reduced sizes -- not a record run)"
                                  : is_default ? "RECORD configuration (default parameters, all parts)"
                                               : "CUSTOM parameters (not the record configuration)");
    }
    std::printf("parameters: keys=%ld v3-inputs=%ld cascade-keys=%ld engine-states=%ld refl=%ld\n",
                o.keys, o.v3_inputs, o.cascade_keys, o.engine_states, o.refl);
    std::printf("            verify=%ld random-s=%ld birthday-log2=%ld whiten-log2=%ld threads=%ld seed=0x%llx\n",
                o.verify, o.random_s, o.birthday_log2, o.whiten_log2, o.threads, (unsigned long long)o.seed);
    std::printf("parts: 1=%d 2=%d 3=%d (controls always run)   BURNIN=%d DECIMATION=%d K=%g\n",
                (int)o.part[1], (int)o.part[2], (int)o.part[3], BURNIN, DECIMATION, K_DEFAULT);
    std::printf("omega (Q32): %08x %08x %08x %08x   parity: %s %s %s %s\n", om[0], om[1], om[2], om[3],
                (om[0] & 1) ? "odd" : "even", (om[1] & 1) ? "odd" : "even",
                (om[2] & 1) ? "odd" : "even", (om[3] & 1) ? "odd" : "even");
    std::printf("This probe bounds the ATTACK SURFACE of four attack families. It is not a security proof.\n");

    // =====================================================================
    head("PART 0 -- controls (the detectors must fire, and must stay silent)");
    // =====================================================================
    {   // PC-1: a weight set with a KNOWN translation symmetry
        Rng rng = stream(o.seed, 0x0101);
        const MCL_Q30_Sextet W{ 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25 };   // all odd
        const T4Analysis a = analyse_t4(W, om);
        int mo = 0, mm = 0; bool nf = false;
        const bool eng = a.group_ok && verify_t4_group_on_engine(W, kp, a.group, R, rng, mo, mm, nf);
        const V4 all{ 0x80000000u, 0x80000000u, 0x80000000u, 0x80000000u };
        const bool has_all = a.group_ok && std::binary_search(a.group.begin(), a.group.end(), all);
        char d[200]; std::snprintf(d, sizeof(d), "rank %d, exact group order %zu, engine-verified %d/%d, non-member fails: %s",
                                   a.rank_elim, a.group.size(), mo, mm, nf ? "yes" : "NO");
        control("PC-1 all-odd weights: symmetry DETECTED", a.rank_elim == 3 && has_all && eng && mm >= 1, d);
    }
    {   // PC-2: a weight set whose symmetry a public seed CAN reach (the class
        //       the v1.0.6 guard exists to reject), and a seed-level engine check.
        Rng rng = stream(o.seed, 0x0102);
        const MCL_Q30_Sextet W{ 3, 5, 7, 9, 4, 6, 11, 13, 8, 10, 12, 14 };
        const T4Analysis a = analyse_t4(W, om);
        const bool pred = mcl_t4_q30_has_reachable_symmetry(W);
        int held = 0;
        for (int r = 0; r < R; r++) {                  // states of seeds s and s + 2^31
            const uint32_t s = rng.next32() | 1u;
            uint32_t x[4], y[4];
            for (size_t k = 0; k < 4; k++) { x[k] = s * om[k]; y[k] = (s + 0x80000000u) * om[k]; }
            const uint32_t d0[4] = { y[0] - x[0], y[1] - x[1], y[2] - x[2], y[3] - x[3] };
            for (int i = 0; i < 64; i++) {
                mcl_q30t4_iterate_raw(x[0], x[1], x[2], x[3], W, kp);
                mcl_q30t4_iterate_raw(y[0], y[1], y[2], y[3], W, kp);
            }
            bool ok = true;
            for (size_t k = 0; k < 4; k++) if ((uint32_t)(y[k] - x[k]) != d0[k]) ok = false;
            if (ok) held++;
        }
        char d[200]; std::snprintf(d, sizeof(d), "engine predicate %s, reachable elements %d, seed pair (s, s+2^31) related in %d/%d",
                                   pred ? "true" : "false", a.reachable_nontrivial, held, R);
        control("PC-2 seed-reachable weak set: REACHABILITY DETECTED", pred && a.reachable_nontrivial >= 1 && held == R, d);
    }
    {   // PC-3: the birthday detector on a function with a PLANTED period
        Rng rng = stream(o.seed, 0x0103);
        uint32_t sstar = 0; while (popcount64(sstar) < 2) sstar = rng.next32();
        const uint64_t C = rng.next();
        auto planted = [sstar, C](uint64_t x) -> uint64_t {
            const uint32_t lo = (uint32_t)x, alt = lo ^ sstar;
            return fmix64((uint64_t)(lo < alt ? lo : alt) ^ C);
        };
        auto generic = [C](uint64_t x) -> uint64_t { return fmix64(x ^ C); };
        const int lg = 18;                                  // engine-free: always full size
        const std::vector<Collision> cp = birthday(planted, 0, lg, rng.next32(), TH);
        bool all_same = !cp.empty();
        for (const Collision& c : cp) if ((uint32_t)(c.x1 ^ c.x2) != sstar) all_same = false;
        const int v = cp.empty() ? 0 : verify_xor_period(planted, 0, cp[0].x1 ^ cp[0].x2, M, rng, TH);
        char d[200]; std::snprintf(d, sizeof(d), "N=2^%d: %zu collisions (expected %.1f), period recovered: %s, verified %d/%d",
                                   lg, cp.size(), std::ldexp(1.0, 2 * lg - 33), all_same ? "yes" : "NO", v, M);
        control("PC-3a planted XOR period: DETECTED by birthday search", all_same && v == M, d);
        const std::vector<Collision> cg = birthday(generic, 0, lg, rng.next32(), TH);
        std::snprintf(d, sizeof(d), "N=2^%d: %zu collisions (expected %.1e)", lg, cg.size(), std::ldexp(1.0, 2 * lg - 65));
        control("PC-3b injective function: birthday search SILENT", cg.empty(), d);
    }
    {   // PC-6: the candidate scanner on functions with a KNOWN answer
        Rng rng = stream(o.seed, 0x0106);
        const uint64_t C = rng.next();
        auto planted = [C](uint64_t x) -> uint64_t { return fmix64((x & ~((1ULL << 17) | (1ULL << 40))) ^ C); };
        auto generic = [C](uint64_t x) -> uint64_t { return fmix64(x ^ C); };
        const CandidateScan a = scan_candidates(planted, 0, 1, M, 8, rng, TH);
        const CandidateScan b = scan_candidates(generic, 0, 1, M, 8, rng, TH);
        const uint64_t want = (1ULL << 17) | (1ULL << 40);
        char d[200]; std::snprintf(d, sizeof(d), "planted bits {17,40}: found %s, partial %s",
                                   bits_to_string(a.exact).c_str(), bits_to_string(a.partial).c_str());
        control("PC-6a planted period bits: DETECTED by the scanner", a.exact == want && a.partial == 0, d);
        std::snprintf(d, sizeof(d), "found %s, partial %s, best random %d/%d",
                      bits_to_string(b.exact).c_str(), bits_to_string(b.partial).c_str(), b.best_random, M);
        control("PC-6b injective function: scanner SILENT", b.exact == 0 && b.partial == 0 && b.best_random == 0, d);
    }
    {   // PC-5: the cascade replica used below reproduces the real API byte for byte
        int okc = 0;
        for (uint64_t k = 0; k < 3; k++) {
            const Key32 key = derived_key("MCL-QSTRUCT-CASCADE-REPLICA", k);
            const Epochs ep = mcl_cascade_q30_params_from_key(key.data(), MCL_CASCADE_DEFAULT_EPOCHS, 0);
            uint8_t raw[32], h[32], api[32];
            cascade_raw(ep, 1000 + k, raw); mcl_sha256(raw, 32, h);
            mcl_cascade_q30(key.data(), api, MCL_CASCADE_DEFAULT_EPOCHS, 0, 1000 + k);
            if (std::memcmp(h, api, 32) == 0) okc++;
        }
        char d[120]; std::snprintf(d, sizeof(d), "SHA-256(replica raw state) == mcl_cascade_q30 output in %d/3", okc);
        control("PC-5 cascade replica == engine API", okc == 3, d);
    }

    // =====================================================================
    if (o.part[1]) {
    head("PART 1 -- F1: translation symmetries of the state map");
    // =====================================================================
    std::printf("  rank r of the parity matrix <=> 2^(4-r) symmetries at the 2^31 level; the EXACT group\n"
                "  (all 2-adic levels) is computed by lifting and every element is run on the engine.\n\n");

    {   // ---- C1 two-oscillator (3,5), retired path
        Rng rng = stream(o.seed, 0x1101);
        const int64_t p = 3, q = 5;
        const std::vector<V4> rows = rows_osc2(p, q);
        std::vector<V4> grp; const bool gok = exact_group(rows, 2, grp, 65536);
        const uint32_t diff = (uint32_t)(p * p - q * q);
        const int v = v2_32(diff);
        int ok = 0, n = 0;
        for (const V4& g : grp) {
            if (is_zero(g)) continue;
            n++;
            if (osc2_translation_holds(p, q, kp, g[0], g[1], R, 1, rng) == R &&
                osc2_translation_holds(p, q, kp, g[0], g[1], R, 16, rng) == R) ok++;
        }
        const uint32_t fine = (v < 31) ? (1u << (32 - v - 1)) : 1u;           // one level finer than the group
        const int neg = osc2_translation_holds(p, q, kp, fine, (uint32_t)(inv32((uint32_t)p) * (uint32_t)q * fine), R, 1, rng);
        const uint32_t om2[2] = { om[0], om[1] };
        int reach = 0;
        for (const V4& g : grp) { uint32_t D = 0; if (!is_zero(g) && seed_reachable(g, om2, 2, D)) reach++; }
        std::printf("  [C1 two-oscillator (3,5) raw Q30 -- RETIRED path]\n");
        std::printf("     [COMPUTED] parity rank %d/2; p^2-q^2 = %lld, 2-adic valuation %d\n",
                    rank_gf2(rows, 2), (long long)(p * p - q * q), v);
        std::printf("     [COMPUTED] exact translation group: order %zu %s\n", grp.size(),
                    prereg(gok && grp.size() == 16));
        std::printf("                (pre-registered: 16, record T4_CycleStructure tool -004, 2026-08-22)\n");
        std::printf("     [MEASURED] engine: %d/%d non-trivial elements commute (1 and 16 iterations, %d states each);\n"
                    "                an offset one level finer commutes on %d/%d states\n", ok, n, R, neg, R);
        std::printf("     [COMPUTED] reachable from a public seed: %d of %d\n", reach, n);
        std::printf("     note: this is the related-input break of the RETIRED raw path, not a live construction.\n");
        consistency(gok && (((size_t)1 << v) == grp.size()), "C1: group order != 2^v2(p^2-q^2)");
        consistency(ok == n && neg < R, "C1: engine verification of the group");
    }

    {   // ---- C2 keyed T4-Q30: the four keys of record -004, then a population
        Rng rng = stream(o.seed, 0x1102);
        static const size_t REC_ORDER[4] = { 1, 2, 1, 4 };
        // elements printed in symmetry_group_exact_apple_20260822.log
        static const V4 REC_ELEM[4] = { V4{ 0x00000000u, 0x00000000u, 0x00000000u, 0x80000000u },   // key1
                                        V4{ 0x40000000u, 0xc0000000u, 0xc0000000u, 0xc0000000u },   // key3
                                        V4{ 0x80000000u, 0x80000000u, 0x80000000u, 0x80000000u },   // key3
                                        V4{ 0xc0000000u, 0x40000000u, 0x40000000u, 0x40000000u } }; // key3
        std::printf("\n  [C2 keyed T4-Q30, weight derivation of sidecar v1.0.6 (unchanged in v1.0.7) -- the four keys of\n"
                    "   record -004 (key[i] = i + k*0x11)]\n");
        for (int k = 0; k < 4; k++) {
            uint8_t key[32]; for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + k * 0x11);
            const MCL_Q30_Sextet W = mcl_t4_q30_params_from_key(key, 0);
            const T4Analysis a = analyse_t4(W, om);
            int mo = 0, mm = 0; bool nf = false;
            const bool eng = a.group_ok && verify_t4_group_on_engine(W, kp, a.group, R, rng, mo, mm, nf);
            std::printf("     key%d [COMPUTED] rank %d/4, exact group order %zu %s\n", k, a.rank_elim,
                        a.group.size(), prereg(a.group_ok && a.group.size() == REC_ORDER[k]));
            if (mm == 0)
                std::printf("          [MEASURED] engine: group is trivial; an offset at the 2^31 level fails to commute: %s\n",
                            nf ? "yes" : "NO");
            else
                std::printf("          [MEASURED] engine: %d/%d non-trivial elements commute, non-member fails: %s; seed-reachable: %d\n",
                            mo, mm, nf ? "yes" : "NO", a.reachable_nontrivial);
            for (const V4& g : a.group) if (!is_zero(g))
                std::printf("             element %08x %08x %08x %08x\n", g[0], g[1], g[2], g[3]);
            consistency(eng, "C2 record key: engine verification of the group");
            if (k == 1) consistency(a.group_ok && std::binary_search(a.group.begin(), a.group.end(), REC_ELEM[0]),
                                    "C2 key1: recorded element missing");
            if (k == 3) for (int e = 1; e < 4; e++)
                consistency(a.group_ok && std::binary_search(a.group.begin(), a.group.end(), REC_ELEM[e]),
                            "C2 key3: recorded element missing");
        }

        long hist_rank[5] = { 0, 0, 0, 0, 0 }, order_hist[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };
        long reach_keys = 0, pred_keys = 0, overflow = 0, verified_sets = 0, verified_ok = 0;
        long related_seed_hits = 0, related_seed_tests = 0;
        for (long n = 0; n < o.keys; n++) {
            const Key32 key = derived_key("MCL-QSTRUCT-KEY", (uint64_t)n);
            const MCL_Q30_Sextet W = mcl_t4_q30_params_from_key(key.data(), 0);
            const T4Analysis a = analyse_t4(W, om);
            hist_rank[a.rank_elim]++;
            if (!a.group_ok) { overflow++; continue; }
            int lg = 0; while (((size_t)1 << lg) < a.group.size()) lg++;
            order_hist[lg > 7 ? 7 : lg]++;
            if (a.reachable_nontrivial > 0) reach_keys++;
            if (mcl_t4_q30_has_reachable_symmetry(W)) pred_keys++;
            if (a.group.size() > 1 && verified_sets < 64) {         // engine-verify the first 64 symmetric sets
                int mo = 0, mm = 0; bool nf = false;
                verified_sets++;
                if (verify_t4_group_on_engine(W, kp, a.group, R, rng, mo, mm, nf)) verified_ok++;
            }
            if (n < 256)                                            // independent of the guard's predicate
                for (int e = 31; e >= 28; e--) {
                    const uint32_t D = 1u << e;
                    const V4 b{ D * om[0], D * om[1], D * om[2], D * om[3] };
                    related_seed_tests++;
                    if (t4_translation_holds(W, kp, b, R, 1, rng) == R) related_seed_hits++;
                }
        }
        const long deficient = o.keys - hist_rank[4];
        std::printf("\n  [C2 population: %ld keys, key_n = SHA-256(\"MCL-QSTRUCT-KEY\" || LE64(n))]\n", o.keys);
        std::printf("     [COMPUTED] parity rank 4/3/2/1/0 : %ld / %ld / %ld / %ld / %ld\n",
                    hist_rank[4], hist_rank[3], hist_rank[2], hist_rank[1], hist_rank[0]);
        std::printf("     [COMPUTED] weight sets WITH a translation symmetry (rank < 4): %ld = %.2f%% %s\n",
                    deficient, 100.0 * (double)deficient / (double)o.keys,
                    prereg(100.0 * (double)deficient / (double)o.keys > 5.0 && 100.0 * (double)deficient / (double)o.keys < 9.0));
        std::printf("                (pre-registered 5%%..9%%; an earlier sample of 20,000 other keys gave 7.00%%)\n");
        std::printf("     [COMPUTED] exact group order 1/2/4/8/16/32/64/>=128 : %ld / %ld / %ld / %ld / %ld / %ld / %ld / %ld%s\n",
                    order_hist[0], order_hist[1], order_hist[2], order_hist[3], order_hist[4],
                    order_hist[5], order_hist[6], order_hist[7], overflow ? "  (+ overflow)" : "");
        std::printf("     [MEASURED] engine verification of the first %ld symmetric sets: %ld/%ld groups confirmed\n",
                    verified_sets, verified_ok, verified_sets);
        std::printf("     [COMPUTED] weight sets with a symmetry a PUBLIC SEED can reach (exact, every group element): %ld %s\n",
                    reach_keys, prereg(reach_keys == 0));
        std::printf("     [MEASURED] seed offsets 2^31, 2^30, 2^29, 2^28 on the engine, first %ld keys: %ld of %ld commute\n",
                    o.keys < 256 ? o.keys : 256L, related_seed_hits, related_seed_tests);
        std::printf("     [CONSTRUCTION] sidecar guard predicate true on %ld keys (the derivation loops until it is false)\n",
                    pred_keys);
        std::printf("     reading: a symmetric weight set is NOT a weak key here -- no pair of public seeds is related\n"
                    "              by the symmetry. It is a structural fact of the state map (the functional graph\n"
                    "              is a cover of that order) and is reported as such.\n");
        consistency(verified_ok == verified_sets, "C2 population: engine verification of symmetric sets");
        consistency(overflow == 0, "C2 population: group enumeration overflow");
        consistency(related_seed_hits == 0 || reach_keys > 0, "C2: engine seed-offset test contradicts the algebra");
    }

    {   // ---- C3 VDF128-T4 public weights
        Rng rng = stream(o.seed, 0x1103);
        const MCL_Q30_Sextet W = mcl_vdf128_public_weights();
        const T4Analysis a = analyse_t4(W, om);
        int fails = 0;
        for (unsigned d = 1; d < 16; d++) {
            V4 c{ 0, 0, 0, 0 }; for (size_t k = 0; k < 4; k++) if ((d >> k) & 1u) c[k] = 0x80000000u;
            if (t4_translation_holds(W, kp, c, R, 1, rng) < R) fails++;
        }
        std::printf("\n  [C3 VDF128-T4 public weights]\n");
        std::printf("     [COMPUTED] rank %d/4, exact group order %zu %s\n", a.rank_elim, a.group.size(),
                    prereg(a.group_ok && a.group.size() == 1));
        std::printf("     [MEASURED] engine: %d of the 15 offsets at the 2^31 level FAIL to commute\n", fails);
        consistency(fails == 15 || a.group.size() > 1, "C3: engine contradicts a trivial group");
        uint32_t P[6], Q[6]; weights_array(W, P, Q);
        int eq = 0;
        for (int i = 0; i < 6; i++) for (int j = i + 1; j < 6; j++)
            if ((P[i] == P[j] && Q[i] == Q[j]) || (P[i] == Q[j] && Q[i] == P[j])) eq++;
        std::printf("     [COMPUTED] coincidentally equal coupling pairs: %d of 15\n", eq);
    }

    {   // ---- C4 VDF128-T4 v3/v4 per-input weights
        Rng rng = stream(o.seed, 0x1104);
        long r4 = 0, triv = 0, eng_ok = 0, eng_n = 0;
        for (long n = 0; n < o.v3_inputs; n++) {
            uint8_t xb[8]; for (int k = 0; k < 8; k++) xb[k] = (uint8_t)((uint64_t)n >> (8 * k));
            const MCL_Q30_Sextet W = mcl_vdf128v3_weights(xb, 8);
            const T4Analysis a = analyse_t4(W, om);
            if (a.rank_elim == 4) r4++;
            if (a.group_ok && a.group.size() == 1) triv++;
            if (n < 16) {
                int fails = 0;
                for (unsigned d = 1; d < 16; d++) {
                    V4 c{ 0, 0, 0, 0 }; for (size_t k = 0; k < 4; k++) if ((d >> k) & 1u) c[k] = 0x80000000u;
                    if (t4_translation_holds(W, kp, c, R, 1, rng) < R) fails++;
                }
                eng_n++; if (fails == 15) eng_ok++;
            }
        }
        std::printf("\n  [C4 VDF128-T4 v3/v4 per-input weights: %ld inputs x = LE64(n)]\n", o.v3_inputs);
        std::printf("     [CONSTRUCTION] rank 4 on %ld/%ld (the derivation re-draws until the rank is 4)\n", r4, o.v3_inputs);
        std::printf("     [COMPUTED] exact group trivial on %ld/%ld %s -- by an algorithm the derivation does not use\n",
                    triv, o.v3_inputs, prereg(triv == o.v3_inputs));
        std::printf("     [MEASURED] engine, first %ld inputs: all 15 offsets at the 2^31 level fail on %ld/%ld\n",
                    eng_n, eng_ok, eng_n);
        std::printf("     v4 adds an iteration clock and leaves the weights unchanged; its rows are these rows.\n");
        consistency(eng_ok == eng_n, "C4: engine contradicts trivial groups");
    }

    {   // ---- C5 keyed cascade
        Rng rng = stream(o.seed, 0x1105);
        const uint32_t om2[2] = { om[0], om[1] };
        const size_t m = (size_t)MCL_CASCADE_DEFAULT_EPOCHS;
        long hist_odd[9] = { 0, 0, 0, 0, 0, 0, 0, 0, 0 }, sym = 0, reach = 0, overflow = 0;
        long sym_after = 0, reach_after = 0, changed_outside = 0, changed_inside = 0;
        bool have = false; Key32 weak{}; uint32_t weakD = 0;
        for (long n = 0; n < o.cascade_keys; n++) {
            const Key32 key = derived_key("MCL-QSTRUCT-CASCADE", (uint64_t)n);
            // BEFORE: the derivation of sidecar v1.0.6 and earlier, exposed by v1.0.7 for measurement
            const Epochs ep = mcl_cascade_q30_derive_unchecked(key.data(), (int)m, 0);
            // AFTER: what the engine uses since v1.0.7
            const Epochs fin = mcl_cascade_q30_params_from_key(key.data(), (int)m, 0);
            size_t odd_after = 0;
            for (const std::pair<int64_t, int64_t>& e : fin) if ((e.first & 1) && (e.second & 1)) odd_after++;
            if (odd_after == m) {
                std::vector<V4> ga;
                if (!exact_group(rows_cascade(fin), 2, ga, 65536)) { overflow++; }
                else {
                    if (ga.size() > 1) sym_after++;
                    bool ra = false;
                    for (const V4& g : ga) { uint32_t D = 0; if (!is_zero(g) && seed_reachable(g, om2, 2, D)) ra = true; }
                    if (ra) reach_after++;
                }
            }
            size_t odd = 0;
            for (const std::pair<int64_t, int64_t>& e : ep) if ((e.first & 1) && (e.second & 1)) odd++;
            hist_odd[odd > 8 ? 8 : odd]++;
            if (ep != fin) { if (odd < m) changed_outside++; else changed_inside++; }
            if (odd < m) continue;            // an epoch with p,q of different parity has a trivial group
            std::vector<V4> grp;
            if (!exact_group(rows_cascade(ep), 2, grp, 65536)) { overflow++; continue; }
            if (grp.size() > 1) sym++;
            bool r = false; uint32_t Dfound = 0;
            for (const V4& g : grp) { uint32_t D = 0; if (!is_zero(g) && seed_reachable(g, om2, 2, D)) { r = true; Dfound = D; } }
            if (r) { reach++; if (!have) { have = true; weak = key; weakD = Dfound; } }
        }
        double tot = 0; for (size_t c = 0; c <= m; c++) tot += (double)c * (double)hist_odd[c];
        const double pe = tot / ((double)m * (double)o.cascade_keys);
        std::printf("\n  [C5 keyed cascade, m = %zu epochs: %ld keys, key_n = SHA-256(\"MCL-QSTRUCT-CASCADE\" || LE64(n))]\n",
                    m, o.cascade_keys);
        std::printf("     [INSPECTION] an epoch with p and q both odd has p - q even, so the offset (2^31, 2^31)\n"
                    "                  leaves both arguments unchanged; omega_1 and omega_2 are odd, so the seed\n"
                    "                  offset 2^31 produces exactly that state offset.\n");
        std::printf("     [COMPUTED] epochs with p,q both odd: rate %.4f per epoch\n", pe);
        std::printf("     BEFORE the check (derivation of sidecar v1.0.6 and earlier):\n");
        std::printf("     [COMPUTED] keys whose WHOLE cascade has a translation symmetry: %ld; seed-reachable: %ld = %.4f%% %s\n",
                    sym, reach, 100.0 * (double)reach / (double)o.cascade_keys,
                    prereg(o.selftest || (reach >= 1 && 100.0 * (double)reach / (double)o.cascade_keys < 0.05)));
        std::printf("                (pre-registered: between 1 key and 0.05%%; an earlier sample gave 7 of 200,000)\n");
        std::printf("     AFTER the check (sidecar v1.0.7, what the engine runs):\n");
        std::printf("     [COMPUTED] keys whose WHOLE cascade has a translation symmetry: %ld; seed-reachable: %ld %s\n",
                    sym_after, reach_after, prereg(sym_after == 0 && reach_after == 0));
        std::printf("                (pre-registered: 0 and 0)\n");
        std::printf("     [COMPUTED] epoch lists changed by the check: %ld inside the class, %ld outside it %s\n",
                    changed_inside, changed_outside, prereg(changed_inside == reach && changed_outside == 0));
        std::printf("                (pre-registered: every key of the class, no other key)\n");
        // engine check: a found key, else a constructed epoch list (always available)
        Epochs ep; uint32_t D = 0x80000000u; const char* src;
        if (have) { ep = mcl_cascade_q30_derive_unchecked(weak.data(), (int)m, 0); D = weakD; src = "first key found in the sweep"; }
        else { static const int64_t pq[7][2] = { {3,5},{7,9},{11,13},{15,17},{19,21},{23,25},{27,29} };
               for (size_t e = 0; e < 7; e++) ep.push_back(std::make_pair(pq[e][0], pq[e][1]));
               src = "constructed epoch list (no key in the sample)"; }
        int held = 0;
        for (int r = 0; r < R; r++) {
            const uint64_t s = (rng.next() >> 13) | 1ULL;
            uint8_t a[32], b[32];
            cascade_raw(ep, s, a); cascade_raw(ep, s + (uint64_t)D, b);
            bool ok = true;
            for (size_t blk = 0; blk < 4 && ok; blk++) {
                uint32_t a1 = 0, a2 = 0, b1 = 0, b2 = 0;
                for (size_t k = 0; k < 4; k++) {
                    a1 |= (uint32_t)a[blk * 8 + k] << (8 * k);     a2 |= (uint32_t)a[blk * 8 + 4 + k] << (8 * k);
                    b1 |= (uint32_t)b[blk * 8 + k] << (8 * k);     b2 |= (uint32_t)b[blk * 8 + 4 + k] << (8 * k);
                }
                if ((uint32_t)(b1 - a1) != (uint32_t)(D * om[0]) || (uint32_t)(b2 - a2) != (uint32_t)(D * om[1])) ok = false;
            }
            if (ok) held++;
        }
        std::printf("     [MEASURED] engine, BEFORE the check, %s, seed offset D = 0x%08x:\n"
                    "                raw final states of seeds s and s+D differ by (D*omega_1, D*omega_2) in %d/%d pairs\n",
                    src, D, held, R);
        int held_after = 0;
        if (have) {
            uint8_t r1[32], r2[32], o1[32], o2[32];
            cascade_raw(ep, 12345ULL, r1); cascade_raw(ep, 12345ULL + (uint64_t)D, r2);
            mcl_sha256(r1, 32, o1); mcl_sha256(r2, 32, o2);
            int hd = 0; for (int i = 0; i < 32; i++) hd += popcount64((uint64_t)(o1[i] ^ o2[i]));
            std::printf("     [MEASURED] SHA-256 of those raw states (the output of v1.0.6): s and s+D differ in %d/256 bits\n", hd);
            // AFTER: the list the engine uses, same key, same seed pairs
            const Epochs fin = mcl_cascade_q30_params_from_key(weak.data(), (int)m, 0);
            Rng rng2 = stream(o.seed, 0x1107);
            for (int r = 0; r < R; r++) {
                const uint64_t s = (rng2.next() >> 13) | 1ULL;
                uint8_t a[32], b[32];
                cascade_raw(fin, s, a); cascade_raw(fin, s + (uint64_t)D, b);
                bool ok = true;
                for (size_t blk = 0; blk < 4 && ok; blk++) {
                    uint32_t a1 = 0, a2 = 0, b1 = 0, b2 = 0;
                    for (size_t k = 0; k < 4; k++) {
                        a1 |= (uint32_t)a[blk * 8 + k] << (8 * k);     a2 |= (uint32_t)a[blk * 8 + 4 + k] << (8 * k);
                        b1 |= (uint32_t)b[blk * 8 + k] << (8 * k);     b2 |= (uint32_t)b[blk * 8 + 4 + k] << (8 * k);
                    }
                    if ((uint32_t)(b1 - a1) != (uint32_t)(D * om[0]) || (uint32_t)(b2 - a2) != (uint32_t)(D * om[1])) ok = false;
                }
                if (ok) held_after++;
            }
            std::printf("     [MEASURED] engine, AFTER the check, same key: the relation holds in %d/%d pairs %s\n",
                        held_after, R, prereg(held_after == 0));
            mcl_cascade_q30(weak.data(), o1, (int)m, 0, 12345ULL);
            mcl_cascade_q30(weak.data(), o2, (int)m, 0, 12345ULL + (uint64_t)D);
            hd = 0; for (int i = 0; i < 32; i++) hd += popcount64((uint64_t)(o1[i] ^ o2[i]));
            std::printf("     [MEASURED] the API output (v1.0.7): outputs for s and s+D differ in %d/256 bits\n", hd);
        }
        std::printf("     reading: before the check the relation lived in the raw state, which the API never emitted,\n"
                    "              and the hashed output did not show it. The check removes it at the source.\n");
        consistency(held == R, "C5: engine verification of the cascade symmetry");
        consistency(overflow == 0, "C5: group enumeration overflow");
    }

    {   // ---- 1b reflection
        Rng rng = stream(o.seed, 0x1106);
        const MCL_Q30_Table& tab = mcl_q30_table();
        int64_t worst = 0; long odd_cells = 0;
        for (uint32_t i = 0; i < 65536u; i++)
            for (uint32_t lo = 0; lo < 2u; lo++) {
                const uint32_t a = (i << 16) | lo;
                const uint32_t ia = (uint32_t)((uint64_t)((int64_t)kp * (int64_t)tab.sin_q30(a)) >> 30);
                const uint32_t ib = (uint32_t)((uint64_t)((int64_t)kp * (int64_t)tab.sin_q30(0u - a)) >> 30);
                const int32_t s = (int32_t)(ia + ib);
                const int64_t mag = s < 0 ? -(int64_t)s : (int64_t)s;
                if (mag > worst) worst = mag;
                if (lo == 1u && s == 0) odd_cells++;
            }
        const int32_t two = (int32_t)(2u * om[0]);
        const int64_t need = two < 0 ? -(int64_t)two : (int64_t)two;
        std::printf("\n  [1b reflection t -> -t]\n");
        std::printf("     [INSPECTION] F(-x) = -F(x) needs, for the first oscillator, 2*omega_1 + sum of three terms\n"
                    "                  inc(a)+inc(-a) == 0 (mod 2^32). Exhaustive over the table: |inc(a)+inc(-a)| <= %lld,\n"
                    "                  so the sum is at most %lld, while |2*omega_1| = %lld.\n",
                    (long long)worst, (long long)(3 * worst), (long long)need);
        std::printf("                  => pure negation is %s for every state and every weight set.\n",
                    need > 3 * worst ? "IMPOSSIBLE" : "NOT excluded by this bound");
        std::printf("     [MEASURED] table cells on which the sine is exactly odd (generic low bits): %ld of 65536\n", odd_cells);
        const MCL_Q30_Sextet W = mcl_vdf128_public_weights();
        for (int it = 1; it <= 2; it++) {
            std::vector<std::vector<char> > seen(4, std::vector<char>(256, 0));
            int64_t mx[4] = { 0, 0, 0, 0 };
            for (long n = 0; n < o.refl; n++) {
                uint32_t x[4], y[4];
                for (size_t k = 0; k < 4; k++) { x[k] = rng.next32(); y[k] = 0u - x[k]; }
                for (int i = 0; i < it; i++) {
                    mcl_q30t4_iterate_raw(x[0], x[1], x[2], x[3], W, kp);
                    mcl_q30t4_iterate_raw(y[0], y[1], y[2], y[3], W, kp);
                }
                for (size_t k = 0; k < 4; k++) {
                    const uint32_t d = x[k] + y[k] - (uint32_t)(2 * it) * om[k];
                    const int32_t sd = (int32_t)d; const int64_t mag = sd < 0 ? -(int64_t)sd : (int64_t)sd;
                    if (mag > mx[k]) mx[k] = mag;
                    seen[k][d >> 24] = 1;
                }
            }
            int distinct[4];
            for (size_t k = 0; k < 4; k++) { distinct[k] = 0; for (char c : seen[k]) if (c) distinct[k]++; }
            std::printf("     [MEASURED] after %d iteration%s, top byte of F(-x)+F(x)-%d*omega, distinct values per coordinate:\n"
                        "                %d, %d, %d, %d of 256   (max deviation 2^%.1f, 2^%.1f, 2^%.1f, 2^%.1f)\n",
                        it, it == 1 ? "" : "s", 2 * it, distinct[0], distinct[1], distinct[2], distinct[3],
                        std::log2((double)mx[0] + 1.0), std::log2((double)mx[1] + 1.0),
                        std::log2((double)mx[2] + 1.0), std::log2((double)mx[3] + 1.0));
            if (it == 1) std::printf("                %s (pre-registered: first coordinate <= 4 values, the other three 256)\n",
                                     prereg(distinct[0] <= 4 && distinct[1] == 256 && distinct[2] == 256 && distinct[3] == 256));
            else         std::printf("                %s (pre-registered: 256 on all four -- nothing survives a second step)\n",
                                     prereg(distinct[0] == 256 && distinct[1] == 256 && distinct[2] == 256 && distinct[3] == 256));
        }
        std::printf("     reading: one step leaves an APPROXIMATE reflection on the first-updated oscillator only;\n"
                    "              the Gauss-Seidel order destroys it for the other three inside the same step.\n");
    }

    {   // ---- 1c permutation
        bool alldiff = true;
        for (int a = 0; a < 4; a++) for (int b = a + 1; b < 4; b++) if (om[a] == om[b]) alldiff = false;
        std::printf("\n  [1c oscillator permutation]\n");
        std::printf("     [INSPECTION] a permutation commutes with the map only if it fixes every omega; the four\n"
                    "                  omegas are %s, and the update order is fixed => %s\n",
                    alldiff ? "pairwise distinct" : "NOT distinct",
                    alldiff ? "no permutation symmetry." : "INVESTIGATE.");
    }
    } // part 1

    // =====================================================================
    if (o.part[2]) {
    head("PART 2 -- F2: period and collision structure of the input channels");
    // =====================================================================
    const double lam = std::ldexp(1.0, 2 * (int)o.birthday_log2 - 33);
    std::printf("  64-bit input word, 64-bit output. Chance agreement of two outputs: 2^-64.\n");
    std::printf("  birthday sub-domain: 32 low bits, N = 2^%ld inputs; a period inside it would give\n"
                "  N^2/2^33 = %.3g colliding pairs on average => detection probability %.4f%%.\n",
                o.birthday_log2, lam, 100.0 * (1.0 - std::exp(-lam)));
    if (lam < 3.0) std::printf("  NOTE: at this sample size the birthday rows are WEAK evidence (use --birthday-log2 18).\n");
    std::printf("\n");

    const Key32 keyA = derived_key("MCL-QSTRUCT-CHANNEL-KEY", 0), keyA2 = derived_key("MCL-QSTRUCT-CHANNEL-KEY", 1);
    uint64_t Sdev[4] = { 0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL, 0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL };
    const uint64_t Wd = legacy_sdevice_fold(Sdev);
    const int64_t lp = 3, lq = 5;

    struct Chan { const char* id; const char* name; int kind; const char* exp_r1; uint64_t exp_mask_r1; };
    static const Chan chans[4] = {
        { "CH-A", "keyed T4-Q30, input = PUBLIC SEED", 0, "{32..51}", 0x000FFFFF00000000ULL },
        { "CH-B", "keyed T4-Q30, input = CHALLENGE (enters the key derivation); seed fixed", 1, "{}", 0ULL },
        { "CH-C", "keyed cascade, input = PUBLIC SEED (output = hashed commitment)", 2, "{32..51}", 0x000FFFFF00000000ULL },
        { "CH-D", "legacy tag, input = 64-bit engine-input word u (seed = u XOR W)", 3, "{}", 0ULL },
    };
    for (int c = 0; c < 4; c++) {
        Rng rng = stream(o.seed, 0x2100 + (uint64_t)c);
        auto g = [c, keyA, Wd](uint64_t x) -> uint64_t {
            switch (c) {
                case 0:  return ch_seed_t4(keyA, x);
                case 1:  return ch_challenge_t4(keyA, x);
                case 2:  return ch_seed_cascade(keyA, x);
                default: return ch_legacy(lp, lq, Wd, x);
            }
        };
        const std::chrono::steady_clock::time_point t0 = std::chrono::steady_clock::now();
        // drawn first: the birthday sample must not depend on --verify or --random-s
        const uint64_t hi = (c == 3) ? (rng.next() & 0xFFFFFFFF00000000ULL) : 0ULL;   // CH-D: fixed random high half of u
        const uint32_t bd_offset = rng.next32();
        std::printf("  [%s %s]\n", chans[c].id, chans[c].name);
        if (c == 1) std::printf("     (the challenge never meets hash_seed; the 2^52 split is kept only so that all four channels\n"
                                "      are scanned by identical code)\n");
        if (c == 3) std::printf("     (the word that meets hash_seed is u XOR W, almost always above 2^52 whatever u is)\n");
        const CandidateScan x1 = scan_candidates(g, 0, 1, M, (int)o.random_s, rng, TH);
        const CandidateScan x2 = scan_candidates(g, 0, 2, M, (int)o.random_s, rng, TH);
        const CandidateScan a1 = scan_candidates(g, 1, 1, M, 0, rng, TH);
        const CandidateScan a2 = scan_candidates(g, 1, 2, M, 0, rng, TH);
        std::printf("     [MEASURED] XOR 2^b, inputs below 2^52 : exact periods at bits %s, partial %s  %s\n",
                    bits_to_string(x1.exact).c_str(), bits_to_string(x1.partial).c_str(),
                    prereg(x1.exact == chans[c].exp_mask_r1 && x1.partial == 0));
        std::printf("                (pre-registered: %s exact, no partial)\n", chans[c].exp_r1);
        std::printf("     [MEASURED] XOR 2^b, inputs above 2^52 : exact periods at bits %s, partial %s  %s\n",
                    bits_to_string(x2.exact).c_str(), bits_to_string(x2.partial).c_str(),
                    prereg(x2.exact == 0 && x2.partial == 0));
        std::printf("     [MEASURED] ADD 2^b (mod 2^64)         : below 2^52 exact %s partial %s; above 2^52 exact %s partial %s\n",
                    bits_to_string(a1.exact).c_str(), bits_to_string(a1.partial).c_str(),
                    bits_to_string(a2.exact).c_str(), bits_to_string(a2.partial).c_str());
        std::printf("                (an exact additive period forces dependence on the low bits only, so it must\n"
                    "                 reappear among the XOR rows; this row is a cross-check of the row above)\n");
        std::printf("     [MEASURED] %ld random 64-bit XOR offsets, %d inputs each: best agreement %d/%d and %d/%d\n",
                    o.random_s, M, x1.best_random, M, x2.best_random, M);
        if (x1.exact) {
            int full = 0; const int done = closure_check(g, x1.exact, 16, M, rng, TH, full);
            std::printf("     [MEASURED] closure: %d of %d random XOR-combinations of those bits are exact periods\n", full, done);
            consistency(full == done, "Part 2: exact period bits are not closed under XOR");
            std::printf("     => exact XOR-period subgroup of dimension %d on inputs below 2^52.\n", popcount64(x1.exact));
        }
        if (c == 0 || c == 2) {                                     // does the period depend on the KEY ?
            auto g2 = [c, keyA2](uint64_t x) -> uint64_t { return c == 0 ? ch_seed_t4(keyA2, x) : ch_seed_cascade(keyA2, x); };
            const CandidateScan y1 = scan_candidates(g2, 0, 1, M, 0, rng, TH);
            std::printf("     [MEASURED] same scan under a second key: exact periods at bits %s -> %s\n",
                        bits_to_string(y1.exact).c_str(),
                        y1.exact == x1.exact ? "IDENTICAL: the period does not depend on the key" : "DIFFERENT: key-dependent, investigate");
            std::printf("     [INSPECTION] t_k = hash_seed(seed)*omega_k mod 2^32 and hash_seed is the identity up to 2^52\n"
                        "                  (sidecar, mcl_q30_seed_state4 and mcl_q30_seed_state2, Legacy rule; mcl_core.hpp,\n"
                        "                  hash_seed and mcl_q30_init_state): the seed enters the state modulo 2^32, so the\n"
                        "                  engine has 2^32 initial states. This is the DEFAULT rule. The opt-in Hashed rule\n"
                        "                  of sidecar v1.0.7 is not scanned here.\n");
            std::printf("     reading: a PUBLIC, key-independent period. Simon's algorithm would recover a period the\n"
                        "              attacker already knows; it yields nothing about the key. The consequence is\n"
                        "              classical: two seeds equal modulo 2^32 give the same keystream.\n");
        }
        const std::vector<Collision> col = birthday(g, hi, (int)o.birthday_log2, bd_offset, TH);
        std::printf("     [MEASURED] birthday search, sub-domain 0x%08x:xxxxxxxx : %zu colliding pairs %s\n",
                    (uint32_t)(hi >> 32), col.size(), prereg(col.empty()));
        for (size_t i = 0; i < col.size() && i < 8; i++) {
            const uint64_t s = col[i].x1 ^ col[i].x2;
            const int v = verify_xor_period(g, hi, s, M, rng, TH);
            std::printf("                pair %016llx / %016llx : XOR offset %016llx holds on %d/%d fresh inputs -> %s\n",
                        (unsigned long long)col[i].x1, (unsigned long long)col[i].x2, (unsigned long long)s, v, M,
                        v == M ? "EXACT PERIOD" : (v == 0 ? "isolated collision" : "PARTIAL structure"));
        }
        if (col.empty()) {
            if (1.0 - std::exp(-lam) >= 0.95)
                std::printf("                => an EXACT period (XOR or additive) inside that sub-domain would have produced a\n"
                            "                   collision with probability %.4f%%; none was found.\n", 100.0 * (1.0 - std::exp(-lam)));
            else
                std::printf("                => INCONCLUSIVE at this sample size (an exact period would show with probability %.4f%% only).\n",
                            100.0 * (1.0 - std::exp(-lam)));
        }
        const double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        std::printf("     [time] %.1f s\n\n", sec);
    }
    std::printf("  what Part 2 does NOT show: a period outside the tested candidates and outside the 32-bit\n"
                "  sub-domain; any period of a function the attacker BUILDS from the oracle (Part 3).\n");
    } // part 2

    // =====================================================================
    if (o.part[3]) {
    head("PART 3 -- F3: the legacy transaction tag as an FX construction");
    // =====================================================================
    Rng rng = stream(o.seed, 0x3100);
    uint64_t Sdev[4] = { 0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL, 0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL };
    const uint64_t W = legacy_sdevice_fold(Sdev);
    const int64_t p = 3, q = 5;
    std::printf("  Tag = MCL_T2( hash_tx(tx) XOR nonce(ctr) XOR W(S_device), p, q )      (variant)\n");
    std::printf("  A variant of the superseded input-composition form: the published mcl_txn_verify.cpp has no\n"
                "  word W; its device secret is the pair (p, q).\n");
    std::printf("  SCOPE: the LEGACY tag only. Paper 5 Eq. (3) carries the secret in the twelve weights and has\n"
                "         no seed-XOR whitening; nothing in this part applies to it.\n\n");
    std::printf("  S1 [INSPECTION] FX shape  Enc(u) = E_k(u XOR k1), k = (p,q), k1 = W: the whitening is additive and\n"
                "                  depends on the key only.\n");
    {   // demonstration, and the positive control of the period verifier on the real engine
        std::vector<uint64_t> us((size_t)M);
        for (uint64_t& u : us) u = rng.next();
        int good = 0, bad = 0;
        for (uint64_t u : us) {
            const uint64_t f1 = ch_legacy(p, q, W, u)     ^ legacy_E(p, q, u);
            const uint64_t f2 = ch_legacy(p, q, W, u ^ W) ^ legacy_E(p, q, u ^ W);
            if (f1 == f2) good++;
            const uint64_t h1 = ch_legacy(p, q, W, u)     ^ legacy_E(5, 7, u);
            const uint64_t h2 = ch_legacy(p, q, W, u ^ W) ^ legacy_E(5, 7, u ^ W);
            if (h1 == h2) bad++;
        }
        char d[200]; std::snprintf(d, sizeof(d), "f = Tag XOR E_k' has period W on %d/%d inputs for k' = k, on %d/%d for k' != k", good, M, bad, M);
        control("PC-4 FX period: present for the right key only", good == M && bad == 0, d);
        std::printf("     (forced by the FX shape -- a demonstration on the real engine, not a discovery.)\n");
    }
    std::printf("  S2 [INSPECTION] Leander-May Theorem 2 assumes g(k,.) is a random FUNCTION, not a permutation.\n"
                "                  MCL_T2 being a generator does not block the attack. \"E is a keyed permutation\"\n"
                "                  is NOT a precondition of the theorem.\n");
    {   // addressability through the counter
        static const char* TX = "TRANSFER 100 TO ACCOUNT 0123456789";
        const uint64_t htx = legacy_hash_tx(TX);
        int ok = 0;
        for (int i = 0; i < M; i++) {
            const uint64_t u = rng.next();
            const uint64_t ctr = fmix64_inv(u ^ htx);
            if ((htx ^ legacy_nonce(ctr)) == u) ok++;
        }
        bool bij = true;
        for (int i = 0; i < 100000; i++) { const uint64_t v = rng.next(); if (fmix64_inv(fmix64(v)) != v) { bij = false; break; } }
        const bool consts = (0xBF58476D1CE4E5B9ULL * 0x96DE1B173F119089ULL == 1ULL) &&
                            (0x94D049BB133111EBULL * 0x319642B2D24D8EC3ULL == 1ULL);
        std::printf("  S3 [INSPECTION] nonce(ctr) = fmix64(ctr) is a composition of bijections, so for any fixed tx\n"
                    "                  ctr -> hash_tx(tx) XOR nonce(ctr) is a bijection onto the 64-bit words.\n");
        std::printf("     [MEASURED] target word reached through the counter on %d/%d random targets;\n"
                    "                fmix64 inverse: constants %s, round trip %s\n", ok, M,
                    consts ? "multiply to 1" : "WRONG", bij ? "100000/100000" : "FAILED");
        consistency(ok == M && bij && consts, "Part 3: addressability through the counter");
        std::printf("     => every engine-input word is addressable, PROVIDED the attacker chooses the counter.\n");
    }
    std::printf("  S4 [NOT MEASURABLE HERE] the access model. Theorem 2 needs superposition queries to the tag\n"
                "                  oracle (Q2). The counter is held by the device and only moves forward, so a\n"
                "                  deployed token answers neither chosen counters nor superpositions. THIS is the\n"
                "                  open assumption -- a property of the protocol, not of the map.\n");
    {
        const double m = std::log2((6.0 / (MCL_PI * MCL_PI)) * 1e9 * 1e9), n = 64.0;
        std::printf("  complexities [DERIVED from the cited theorems; m = log2(coprime pairs in [2,1e9]^2) = %.2f, n = 64]\n", m);
        std::printf("     Grover on (p,q,W), no structure used        : 2^%.1f\n", (m + n) / 2.0);
        std::printf("     Q2, Leander-May Theorem 2                   : 2^%.1f x O(m+n) queries  -- W adds nothing\n", m / 2.0);
        std::printf("     Q1 (classical queries), offline Simon T^2.D = 2^(n+m):\n");
        std::printf("         D = 2^16 -> T = 2^%.1f ;  D = 2^32 -> T = 2^%.1f ;  balanced T = D = 2^%.1f\n",
                    (n + m - 16.0) / 2.0, (n + m - 32.0) / 2.0, (n + m) / 3.0);
        std::printf("     Q1 needs the queried words to fill an affine subspace, i.e. chosen inputs.\n");
    }
    {   // whitening image
        const size_t N = (size_t)1 << o.whiten_log2;
        std::vector<uint64_t> ws; ws.reserve(N);
        for (size_t i = 0; i < N; i++) { uint64_t S[4] = { rng.next(), rng.next(), rng.next(), rng.next() }; ws.push_back(legacy_sdevice_fold(S)); }
        std::sort(ws.begin(), ws.end());
        size_t dup = 0; for (size_t i = 1; i < ws.size(); i++) if (ws[i] == ws[i - 1]) dup++;
        const double n2 = (double)N * (double)N;
        std::printf("  whitening word W = sdevice_fold(S_device)\n");
        std::printf("     [INSPECTION] W is one 64-bit word: S_device contributes at most 64 bits whatever its length.\n");
        if (dup == 0)
            std::printf("     [MEASURED] 2^%ld random S_device -> 0 equal W: effective image size at least 2^%.1f words\n"
                        "                (95%% confidence; 2^%.1f at 99%%). A LOWER bound on the image, nothing more.\n",
                        o.whiten_log2, std::log2(n2 / (2.0 * std::log(20.0))), std::log2(n2 / (2.0 * std::log(100.0))));
        else
            std::printf("     [MEASURED] 2^%ld random S_device -> %zu equal W: image size about 2^%.1f\n",
                        o.whiten_log2, dup, std::log2(n2 / (2.0 * (double)dup)));
    }
    std::printf("\n  VERDICT for the legacy tag: FX-shaped. In the chosen-input superposition model the whitening\n"
                "  word adds no quantum security over Grover on (p,q). What stands between that statement and a\n"
                "  deployed token is the access model (S4), not any property of the map. Paper 5's 46-56 bit\n"
                "  figure for a seed-borne secret is an UPPER bound and must not be read as a floor.\n");
    } // part 3

    // =====================================================================
    head("F4 -- generic collision search  [GENERIC: holds for any function of that size]");
    // =====================================================================
    std::printf("  %-5s %-36s %-18s %-14s %s\n", "n", "what has that width", "classical 2^(n/2)", "BHT 2^(n/3)", "CNS 2^(2n/5)");
    static const struct { int n; const char* what; } gen[3] = {
        {  64, "cascade state; legacy input word" }, { 128, "T4-Q30 / VDF128-T4 state" }, { 256, "tag; SHA-256 commitment" } };
    for (int i = 0; i < 3; i++)
        std::printf("  %-5d %-36s 2^%-16.1f 2^%-12.1f 2^%.1f\n", gen[i].n, gen[i].what,
                    gen[i].n / 2.0, gen[i].n / 3.0, 2.0 * gen[i].n / 5.0);
    std::printf("  BHT needs 2^(n/3) quantum-accessible memory; CNS needs O(n) qubits and 2^(n/5) classical memory.\n"
                "  Nothing was measured here. \"No collisions\" cannot be claimed for any finite-state function.\n");

    // =====================================================================
    head("SUMMARY");
    // =====================================================================
    const double total = std::chrono::duration<double>(std::chrono::steady_clock::now() - t_start).count();
    std::printf("  controls passed                 : %d / %d\n", g_ctrl_pass, g_ctrl_total);
    std::printf("  internal consistency checks     : %d run, %d failed\n", g_cons_total, g_cons_fail);
    std::printf("  pre-registered expectations     : %d compared, %d differ\n", g_prereg_total, g_prereg_diff);
    std::printf("  [time] total %.1f s\n", total);
    const bool ok = (g_ctrl_pass == g_ctrl_total) && (g_cons_fail == 0);
    if (!ok) std::printf("  !! A control or a consistency check FAILED: do not quote this run.\n");
    if (g_prereg_diff) std::printf("  !! %d result(s) differ from the pre-registered expectation: read those rows.\n", g_prereg_diff);
    std::printf("  This is a map of four attack surfaces. It is not a security proof (Paper 4 OP2 stays open).\n");
    if (o.selftest) return (ok && g_prereg_diff == 0) ? 0 : 1;
    return ok ? 0 : 1;
}
