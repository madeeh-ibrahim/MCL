/*
 * ============================================================================
 * MCL Lattice Coupled Oscillator -- Hex7 Multiplex Prototype
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-HEX7-2026-0526-001
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
 *   Research prototype for lattice-coupled multi-oscillator topologies.
 *   Demonstrates that a SINGLE (seed, p, q) instance can generate up to
 *   C(N, 2) statistically independent channels by extracting bits from
 *   XOR pairs of phase variables, where N is the number of nodes in the
 *   coupling lattice. Tests two topologies: Hex7 (hub + 6-ring) and
 *   Ring(N) for N in {3, 5, 7, 9, 13}.
 *
 * COUPLING:
 *   Kuramoto-style with K/degree normalization:
 *     theta_i += omega_i + (K / degree_i) * SUM_{j in N(i)} sin(p*theta_j - q*theta_i)
 *   This ensures each node receives effective coupling K regardless of
 *   degree (Kuramoto 1984, Strogatz 2000).
 *
 * UPDATE ORDER:
 *   Gauss-Seidel, sequential by node index 0,1,...,N-1.
 *   Node 0 updates first using stale theta_[1..N-1].
 *   Node i uses UPDATED theta_[0..i-1] + stale theta_[i+1..N-1].
 *   This sequential dependency makes the dynamics non-parallelizable
 *   (same principle as MCL_T2). The ordering is FIXED and DETERMINISTIC.
 *
 * EXTRACTION:
 *   Goldilocks dual-zone bit extraction (Paper 1 §III.E):
 *     byte = (uint8_t)(x >> 20) ^ (uint8_t)(x >> 36)
 *   where x = b_i XOR b_j and b_k is the IEEE 754 bit pattern of theta_k.
 *
 * TESTS:
 *   0. NEGATIVE CONTROL (4 checks): determinism, channel independence,
 *      bad-generator detection, weak-correlation detection.
 *   1. OUTPUT QUALITY: per-channel entropy > 7.998, chi-square < 330.
 *   2. HEX7 INDEPENDENCE: 21 pairs, Bonferroni-corrected, 3 seeds.
 *   3. RING(7) INDEPENDENCE: 21 pairs, Bonferroni-corrected, 3 seeds.
 *   4. MULTIPLE (p,q): 5 coprime pairs, quality + independence each.
 *   5. THROUGHPUT [INFO]: T2 vs Ring(7) vs Hex7, MB/s + sin/ch-byte.
 *   6. SATURATION [INFO]: Ring(N) for N in {3,5,7,9,13} + Hex7.
 *   7. MEMORY [INFO]: state size projections at 1M / 100M user scale.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -o mcl_hex7_proto mcl_hex7_proto.cpp -lm && ./mcl_hex7_proto
 *
 * EXPECTED RESULTS: PASS - all 5 numbered tests (0-4) pass; tests 5-7
 *                          are informational [INFO] only.
 *
 * REFERENCES:
 *   - Paper 2 §VI    Multi-Receiver Communication (multiplex construction)
 *   - Paper 2 §VI.A  Multiplex Construction (this file's experimental basis)
 *   - Paper 1 §III.E Goldilocks Dual-Zone Extraction (bit positions 20, 36)
 *   - Paper 3 §III.A Resonance Mapping (multi-coupling resonance elimination)
 *
 * LIMITATIONS (printed in summary; resolve before patent claims):
 *   1. BigCrush not yet run on any lattice engine
 *   2. Goldilocks [20, 36] Safe Zone unvalidated for lattice XOR
 *   3. Frequency linear independence assumed, not proven
 *   4. Maximum useful N not established (tested only N <= 13)
 *   5. Lyapunov exponent not computed for lattice topologies
 *   6. Kuramoto K/degree normalization chosen, not optimized
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

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

// ============================================================================
// Document version constants (mirror header).
// Use 'constexpr const char* const' to make BOTH the pointer AND the
// pointed-to data immutable. Plain 'const char*' allows the pointer to
// be reassigned (only the chars are const) -- a subtle correctness gap.
// ============================================================================
static constexpr const char* const DOC_VERSION = "6.0.0";
static constexpr const char* const DOC_ID      = "MCL-HEX7-2026-0526-001";

// ============================================================================
// Engine constants
// ============================================================================
static constexpr double TWO_PI            = 6.283185307179586476925286766559;
static constexpr int    BURNIN            = 10000;
static constexpr int    DECIMATION        = 2;
static constexpr int    GOLD_S1           = 20;     // Paper 1 §III.E lower zone
static constexpr int    GOLD_S2           = 36;     // Paper 1 §III.E upper zone
static constexpr double BONFERRONI_ALPHA  = 0.001;  // 99.9% family-wise

// Numerical-equivalence assertions: these constants must match
// mcl_core.hpp v5.0.0 exactly. If mcl_core changes, update here.
static_assert(BURNIN == 10000,
    "BURNIN must match mcl_core.hpp v5.0.0 (10000)");
static_assert(DECIMATION == 2,
    "DECIMATION must match mcl_core.hpp v5.0.0 (2)");
static_assert(GOLD_S1 == 20 && GOLD_S2 == 36,
    "Goldilocks zones must match Paper 1 III.E (20, 36)");

// ============================================================================
// Unified quality thresholds (calibrated per N).
// Derivation:
//   For uniform random over 256 symbols, entropy SD scales as ~1/(N*ln(2)).
//   At N=500000: SD ~ 7.4e-4   -> MIN_ENTROPY 7.998 = ~22 sigma below 8.0.
//   At N=100000: SD ~ 3.7e-3   -> MIN_ENTROPY 7.99  = ~2.7 sigma (quick smoke).
//   chi-square df=255 at alpha=0.001: critical = 330.52 (mode-independent).
// MAX_CHI2 is N-independent because chi-square is normalized by expected count.
// MIN_ENTROPY scales with N because finite-sample entropy underestimates 8.0.
// ============================================================================
static constexpr double MIN_ENTROPY_FULL  = 7.998;   // N >= 500K
static constexpr double MIN_ENTROPY_QUICK = 7.990;   // N >= 40K (smoke only)
static constexpr double MAX_CHI2          = 330.0;   // N-independent

// Negative-control (Test 0) thresholds.
static constexpr double T0_R_IDENTICAL_MIN = 0.999;   // same engine -> r ~ 1
static constexpr double T0_R_INDEP_MAX     = 0.02;    // independent -> |r| < 0.02
static constexpr double T0_CHI_BAD_MIN     = 1000.0;  // constant output -> huge chi2
static constexpr double T0_R_SIMILAR_MIN   = 0.80;    // 90% identical -> r > 0.80

// ============================================================================
// Sample sizes (default = full mode = Paper canonical).
// Quick mode uses 1/5 of these for smoke testing (preserves scientific
// validity since Bonferroni threshold scales correctly with N).
// ============================================================================
static constexpr int64_t T0_N_FULL       =  50000;
static constexpr int64_t T1_N_FULL       = 500000;
static constexpr int64_t T2_T3_N_FULL    = 500000;
static constexpr int64_t T4_N_FULL       = 200000;
static constexpr int64_t T5_T6_N_FULL    = 200000;   // Tests 5+6 throughput/saturation
static constexpr int64_t T6_SAT_N_FULL   = 100000;   // Test 6 saturation (smaller for breadth)

static constexpr int    QUICK_DIVISOR = 5;

// ============================================================================
// Test parameters
// ============================================================================
static constexpr int N_SEEDS_INDEP = 3;   // Tests 2/3 multi-seed count

// Test 4 (p,q) coprime pairs -- all within MCL operational range [2, 2^62].
struct PQPair { int64_t p, q; };
static constexpr PQPair T4_PAIRS[] = {
    {3, 5}, {7, 11}, {13, 17}, {97, 101}, {997, 1009}
};
static constexpr int T4_N_PAIRS = static_cast<int>(
    sizeof(T4_PAIRS) / sizeof(T4_PAIRS[0]));

// Test 6 saturation: ring sizes to sweep.
static constexpr int T6_RING_SIZES[] = {3, 5, 7, 9, 13};
static constexpr int T6_N_RING_SIZES = static_cast<int>(
    sizeof(T6_RING_SIZES) / sizeof(T6_RING_SIZES[0]));

// Test 7 memory: scale projections.
static constexpr int T7_SCALES[] = {1000000, 100000000};
static constexpr int T7_N_SCALES = 2;

// ============================================================================
// Frequencies: irrational constants. Linear independence over Q is
// ASSUMED, not proven. Empirically the system is strongly chaotic for
// all tested configurations. Rigorous proof would require showing no
// rational linear relation a0*w0 + a1*w1 + ... = 0.
// ============================================================================
static constexpr double OMEGA_TABLE[] = {
    0.6180339887498949,  // phi - 1
    1.3247179572447460,  // plastic constant
    0.4142135623730950,  // sqrt(2) - 1
    1.8392867552141612,  // tribonacci constant
    0.7071067811865476,  // 1 / sqrt(2)
    1.0594630943592953,  // 2^(1/12)
    0.5772156649015329,  // Euler-Mascheroni gamma
    0.3678794411714423,  // 1 / e
    0.6931471805599453,  // ln(2)
    0.4812118250596035,  // 1 / ln(pi)
    0.5671432904097838,  // Omega constant
    0.8346268416740732,  // sqrt(ln(2))
    0.6366197723675814,  // 2 / pi
};
static constexpr int N_OMEGA = static_cast<int>(
    sizeof(OMEGA_TABLE) / sizeof(double));

// ============================================================================
// Test seeds (named to avoid magic numbers).
// DEFAULT_SEED matches mcl_core.hpp v5.0.0 -- used in Tests 1, 4, 5, 6.
// TEST_SEED_2 / TEST_SEED_3 used alongside DEFAULT_SEED in Tests 2, 3
// (multi-seed independence).
// T0_SMALL_SEED is the deliberately compact seed for Test 0 negative
// control (N=50K is small, so a small seed suffices and exercises the
// hash_seed equivalent input distribution).
//
// CRITICAL — seed bound for MCL_T2_Ref / mcl_core MCL_T2 numerical
// equivalence: mcl_core's hash_seed() applies MurmurHash3 fmix64 ONLY
// when seed > 2^52. For seeds <= 2^52 (4.5e15), hash_seed(s) == s and
// the two engines produce identical output. All four named seeds below
// are well below 2^52 -- verified by static_assert. If you add new
// seeds above 2^52, MCL_T2_Ref output will DIVERGE from mcl_core
// MCL_T2 output (different initial conditions after hashing).
// ============================================================================
static constexpr uint64_t DEFAULT_SEED   = 12345678901234ULL;
static constexpr uint64_t TEST_SEED_2    = 98765432109876ULL;
static constexpr uint64_t TEST_SEED_3    = 55555555555555ULL;
static constexpr uint64_t T0_SMALL_SEED  = 12345ULL;

static constexpr uint64_t MCL_HASH_SEED_THRESHOLD = (1ULL << 52);
static_assert(DEFAULT_SEED   <= MCL_HASH_SEED_THRESHOLD,
    "DEFAULT_SEED above 2^52 would diverge from mcl_core MCL_T2");
static_assert(TEST_SEED_2    <= MCL_HASH_SEED_THRESHOLD,
    "TEST_SEED_2 above 2^52 would diverge from mcl_core MCL_T2");
static_assert(TEST_SEED_3    <= MCL_HASH_SEED_THRESHOLD,
    "TEST_SEED_3 above 2^52 would diverge from mcl_core MCL_T2");
static_assert(T0_SMALL_SEED  <= MCL_HASH_SEED_THRESHOLD,
    "T0_SMALL_SEED above 2^52 would diverge from mcl_core MCL_T2");

// ============================================================================
// CLI mode selection
// ============================================================================
enum class Mode { FULL, QUICK };

// Sample-size resolver based on mode.
static int64_t scale_n(int64_t n_full, Mode mode) {
    return (mode == Mode::QUICK) ? n_full / QUICK_DIVISOR : n_full;
}

// ============================================================================
// Topology
// ============================================================================
struct Topology {
    int n_nodes;
    std::vector<std::vector<int>> adj;

    int degree(int i) const {
        return static_cast<int>(adj[static_cast<size_t>(i)].size());
    }

    // Returns ALL node pairs C(N,2), not just graph edges.
    // A "channel" extracts bits from XOR(theta_i, theta_j) for any
    // pair (i,j), regardless of direct connectivity in the topology.
    // The topology determines coupling structure, not extraction.
    int n_channels() const { return n_nodes * (n_nodes - 1) / 2; }

    // Logical state size: N doubles + p(int64) + q(int64) + K(double).
    int logical_state_bytes() const { return n_nodes * 8 + 8 + 8 + 8; }

    // Total sin() calls per single iterate() invocation.
    int sin_per_iterate() const {
        int s = 0;
        for (int i = 0; i < n_nodes; i++) s += degree(i);
        return s;
    }
};

static Topology make_hex7() {
    // Hub-and-spoke with hexagonal ring.
    // Node 0 = center (degree 6), Nodes 1-6 = ring (degree 3 each).
    // Ring order: 1-2-3-4-5-6-1.
    // Adjacency is symmetric (undirected graph).
    Topology t;
    t.n_nodes = 7;
    t.adj.resize(7);
    t.adj[0] = {1, 2, 3, 4, 5, 6};
    t.adj[1] = {0, 2, 6};
    t.adj[2] = {0, 1, 3};
    t.adj[3] = {0, 2, 4};
    t.adj[4] = {0, 3, 5};
    t.adj[5] = {0, 4, 6};
    t.adj[6] = {0, 5, 1};
    return t;
}

// Ring topology: n >= 3 required to avoid duplicate neighbors.
static Topology make_ring(int n) {
    if (n < 3) {
        std::fprintf(stderr,
            "ERROR: make_ring requires n >= 3 (got %d)\n", n);
        std::exit(1);
    }
    Topology t;
    t.n_nodes = n;
    t.adj.resize(static_cast<size_t>(n));
    for (int i = 0; i < n; i++)
        t.adj[static_cast<size_t>(i)] = {(i - 1 + n) % n, (i + 1) % n};
    return t;
}

// ============================================================================
// Generic Lattice Engine
// ============================================================================
class MCL_Lattice {
    std::vector<double> theta_;
    Topology topo_;
    int64_t p_, q_;
    double K_;
public:
    MCL_Lattice(uint64_t seed, int64_t p, int64_t q,
                const Topology& topo, double K = 12.0)
        : theta_(static_cast<size_t>(topo.n_nodes)),
          topo_(topo), p_(p), q_(q), K_(K)
    {
        // Initialize each node with DIFFERENT irrational multiplier
        // (per-node OMEGA_TABLE[i % N_OMEGA] avoids identical seed
        // hashes across nodes that would cause initial-condition
        // synchronization).
        for (int i = 0; i < topo_.n_nodes; i++) {
            const uint64_t s = seed ^
                (static_cast<uint64_t>(static_cast<unsigned>(i + 1))
                 * 0x9E3779B97F4A7C15ULL);
            theta_[static_cast<size_t>(i)] =
                std::fmod(static_cast<double>(s)
                          * OMEGA_TABLE[i % N_OMEGA], TWO_PI);
            if (theta_[static_cast<size_t>(i)] < 0)
                theta_[static_cast<size_t>(i)] += TWO_PI;
        }
        for (int i = 0; i < BURNIN; i++) iterate();
    }

    void iterate() {
        for (int i = 0; i < topo_.n_nodes; i++) {
            double sum_sin = 0.0;
            const int deg = topo_.degree(i);
            for (int n = 0; n < deg; n++) {
                const int j = topo_.adj[static_cast<size_t>(i)]
                                       [static_cast<size_t>(n)];
                sum_sin += std::sin(static_cast<double>(p_)
                    * theta_[static_cast<size_t>(j)]
                    - static_cast<double>(q_)
                    * theta_[static_cast<size_t>(i)]);
            }
            const int oi = i % N_OMEGA;
            theta_[static_cast<size_t>(i)] +=
                OMEGA_TABLE[oi]
                + (K_ / static_cast<double>(deg)) * sum_sin;
            theta_[static_cast<size_t>(i)] =
                std::fmod(theta_[static_cast<size_t>(i)], TWO_PI);
            if (theta_[static_cast<size_t>(i)] < 0)
                theta_[static_cast<size_t>(i)] += TWO_PI;
        }
    }

    // Extract byte from pair (i,j).
    // CAVEAT: Goldilocks bit positions [20, 36] were validated as
    // Safe Zone for T2 (Paper 1, mcl_reference EXP 1). They have
    // NOT been validated for lattice XOR(theta_i, theta_j) where
    // i,j may not be directly coupled. BigCrush is required.
    uint8_t extract_pair(int i, int j) const {
        assert(i >= 0 && i < topo_.n_nodes);
        assert(j >= 0 && j < topo_.n_nodes);
        assert(i != j);
        uint64_t bi, bj;
        std::memcpy(&bi, &theta_[static_cast<size_t>(i)], sizeof(double));
        std::memcpy(&bj, &theta_[static_cast<size_t>(j)], sizeof(double));
        const uint64_t x = bi ^ bj;
        return static_cast<uint8_t>(
            (static_cast<uint8_t>(x >> GOLD_S1))
            ^ (static_cast<uint8_t>(x >> GOLD_S2)));
    }

    void gen_bytes_pair(uint8_t* buf, int64_t len, int pi, int pj) {
        for (int64_t k = 0; k < len; k++) {
            for (int d = 0; d < DECIMATION; d++) iterate();
            buf[k] = extract_pair(pi, pj);
        }
    }

    // Simultaneous extraction of ALL C(N,2) channels from ONE instance.
    // One iterate() advances all N oscillators, then we extract one byte
    // per pair -- yielding n_channels bytes per DECIMATION iterates.
    void gen_all_channels(std::vector<std::vector<uint8_t>>& streams,
                          int64_t len)
    {
        const int nc = topo_.n_channels();
        streams.resize(static_cast<size_t>(nc));
        for (int c = 0; c < nc; c++)
            streams[static_cast<size_t>(c)].resize(static_cast<size_t>(len));
        for (int64_t k = 0; k < len; k++) {
            for (int d = 0; d < DECIMATION; d++) iterate();
            int idx = 0;
            for (int i = 0; i < topo_.n_nodes; i++)
                for (int j = i + 1; j < topo_.n_nodes; j++)
                    streams[static_cast<size_t>(idx++)]
                           [static_cast<size_t>(k)] = extract_pair(i, j);
        }
    }

    const Topology& topology() const { return topo_; }
};

// ============================================================================
// MCL_T2_Ref -- ground-truth baseline matching mcl_core.hpp v5.0.0 MCL_T2.
// Self-contained to keep this prototype independent of the core engine.
// The compile-time assertions above verify the four engine constants
// (BURNIN, DECIMATION, GOLD_S1, GOLD_S2) match mcl_core.hpp; output
// equivalence with the official MCL_T2 must be re-verified empirically
// when mcl_core.hpp changes (recommended: run mcl_reference KAT vectors).
// ============================================================================
class MCL_T2_Ref {
    double theta1_, theta2_;
    int64_t p_, q_;
    double K_;
public:
    static constexpr int    SIN_PER_ITER = 2;
    static constexpr int    CHANNELS     = 1;
    static constexpr int    STATE_BYTES  = 40;
    // 2 sin/iter * DECIMATION iters/byte / 1 channel = 4.0
    static constexpr double SIN_PER_CH_BYTE =
        static_cast<double>(SIN_PER_ITER * DECIMATION) / CHANNELS;

    MCL_T2_Ref(uint64_t seed, int64_t p, int64_t q, double K = 12.0)
        : p_(p), q_(q), K_(K)
    {
        theta1_ = std::fmod(static_cast<double>(seed)
                            * 0.6180339887498949, TWO_PI);
        theta2_ = std::fmod(static_cast<double>(seed)
                            * 1.3247179572447460, TWO_PI);
        if (theta1_ < 0) theta1_ += TWO_PI;
        if (theta2_ < 0) theta2_ += TWO_PI;
        for (int i = 0; i < BURNIN; i++) iterate();
    }
    void iterate() {
        const double a1 = static_cast<double>(p_) * theta2_
                          - static_cast<double>(q_) * theta1_;
        theta1_ = std::fmod(theta1_ + 0.6180339887498949
                            + K_ * std::sin(a1), TWO_PI);
        if (theta1_ < 0) theta1_ += TWO_PI;
        const double a2 = static_cast<double>(p_) * theta1_
                          - static_cast<double>(q_) * theta2_;
        theta2_ = std::fmod(theta2_ + 1.3247179572447460
                            + K_ * std::sin(a2), TWO_PI);
        if (theta2_ < 0) theta2_ += TWO_PI;
    }
    void gen_bytes(uint8_t* buf, int64_t len) {
        for (int64_t i = 0; i < len; i++) {
            for (int d = 0; d < DECIMATION; d++) iterate();
            uint64_t b1, b2;
            std::memcpy(&b1, &theta1_, sizeof(double));
            std::memcpy(&b2, &theta2_, sizeof(double));
            const uint64_t x = b1 ^ b2;
            buf[i] = static_cast<uint8_t>(
                (static_cast<uint8_t>(x >> GOLD_S1))
                ^ (static_cast<uint8_t>(x >> GOLD_S2)));
        }
    }
};

// ============================================================================
// Statistical Tools
// ============================================================================
static double pearson_r(const uint8_t* a, const uint8_t* b, int64_t n) {
    double sa = 0, sb = 0, sa2 = 0, sb2 = 0, sab = 0;
    for (int64_t i = 0; i < n; i++) {
        const double da = a[i], db = b[i];
        sa += da; sb += db; sa2 += da * da; sb2 += db * db; sab += da * db;
    }
    const double dn = static_cast<double>(n);
    const double num = dn * sab - sa * sb;
    const double den = std::sqrt((dn * sa2 - sa * sa) * (dn * sb2 - sb * sb));
    return (den < 1e-15) ? 0.0 : num / den;
}

// p-value from Pearson r using normal approximation (valid for large N).
// For N > 30, z = r * sqrt(N) is approximately N(0,1) under H0.
// Uses erfc -- no tgamma overflow risk.
static double pvalue_from_r(double r, int64_t n) {
    if (n < 3) return 1.0;
    const double z = std::abs(r) * std::sqrt(static_cast<double>(n));
    return std::erfc(z / std::sqrt(2.0));
}

static double shannon_entropy(const uint8_t* data, int64_t n) {
    int64_t freq[256] = {};
    for (int64_t i = 0; i < n; i++) freq[data[i]]++;
    double ent = 0;
    for (int i = 0; i < 256; i++) if (freq[i] > 0) {
        const double p = static_cast<double>(freq[i])
                         / static_cast<double>(n);
        ent -= p * std::log2(p);
    }
    return ent;
}

static double chi_square(const uint8_t* data, int64_t n) {
    int64_t freq[256] = {};
    for (int64_t i = 0; i < n; i++) freq[data[i]]++;
    const double expected = static_cast<double>(n) / 256.0;
    double chi2 = 0;
    for (int i = 0; i < 256; i++) {
        const double d = static_cast<double>(freq[i]) - expected;
        chi2 += d * d / expected;
    }
    return chi2;
}

// Quality check: min entropy and max chi2 across ALL channels.
struct QualityResult { double min_ent; double max_chi; int failures; };

static QualityResult check_all_quality(
    const std::vector<std::vector<uint8_t>>& streams, int64_t N, Mode mode)
{
    const double min_ent_thr = (mode == Mode::QUICK)
        ? MIN_ENTROPY_QUICK : MIN_ENTROPY_FULL;
    double min_ent = 8.0, max_chi = 0;
    int fails = 0;
    for (size_t c = 0; c < streams.size(); c++) {
        const double e = shannon_entropy(streams[c].data(), N);
        const double x = chi_square(streams[c].data(), N);
        if (e < min_ent) min_ent = e;
        if (x > max_chi) max_chi = x;
        if (e < min_ent_thr || x > MAX_CHI2) fails++;
    }
    return {min_ent, max_chi, fails};
}

// Bonferroni independence test using erfc-based p-values.
struct IndepResult { bool pass; int n_pairs; double max_r; int rejections; };

static IndepResult test_independence(
    const std::vector<std::vector<uint8_t>>& streams, int64_t N)
{
    const int nc = static_cast<int>(streams.size());
    const int n_pairs = nc * (nc - 1) / 2;
    const double bonf_thr = BONFERRONI_ALPHA
        / static_cast<double>(std::max(n_pairs, 1));
    double max_r = 0;
    int rej = 0;

    for (int a = 0; a < nc; a++) {
        for (int b = a + 1; b < nc; b++) {
            const double r = std::abs(pearson_r(
                streams[static_cast<size_t>(a)].data(),
                streams[static_cast<size_t>(b)].data(), N));
            if (r > max_r) max_r = r;
            const double pv = pvalue_from_r(r, N);
            if (pv < bonf_thr) rej++;
        }
    }
    return {rej == 0, n_pairs, max_r, rej};
}

// ============================================================================
// Banner / sep helpers
// ============================================================================
static void sep(const char* title) {
    std::printf("\n=========================================="
                "====================================\n");
    std::printf("  %s\n", title);
    std::printf("=========================================="
                "====================================\n\n");
}

// ============================================================================
// TEST 0: NEGATIVE CONTROL
// ============================================================================
static bool test_00_negative_control(Mode mode) {
    sep("TEST 0: NEGATIVE CONTROL");
    const int64_t N = scale_n(T0_N_FULL, mode);
    bool all_ok = true;

    // Check 1: identical engine + pair -> r = 1.0
    {
        const Topology topo = make_hex7();
        MCL_Lattice e1(T0_SMALL_SEED, 3, 5, topo);
        MCL_Lattice e2(T0_SMALL_SEED, 3, 5, topo);
        std::vector<uint8_t> b1(static_cast<size_t>(N));
        std::vector<uint8_t> b2(static_cast<size_t>(N));
        e1.gen_bytes_pair(b1.data(), N, 0, 1);
        e2.gen_bytes_pair(b2.data(), N, 0, 1);
        const double r = pearson_r(b1.data(), b2.data(), N);
        const bool ok = (r > T0_R_IDENTICAL_MIN);
        std::printf("  Same engine+pair:    r=%.6f  %s\n",
            r, ok ? "OK" : "ERROR");
        if (!ok) all_ok = false;
    }

    // Check 2: SAME instance, different channels -> |r| near 0
    // (using the same engine instance, not separate -- this isolates
    // channel independence rather than initialization independence)
    {
        const Topology topo = make_hex7();
        MCL_Lattice eng(T0_SMALL_SEED, 3, 5, topo);
        std::vector<std::vector<uint8_t>> streams;
        eng.gen_all_channels(streams, N);
        const double r = std::abs(pearson_r(
            streams[0].data(), streams[10].data(), N));
        const bool ok = (r < T0_R_INDEP_MAX);
        std::printf("  Same instance ch0/10:|r|=%.6f  %s\n",
            r, ok ? "OK" : "ERROR");
        if (!ok) all_ok = false;
    }

    // Check 3: constant output -> chi2 massive (detects bad generator)
    {
        std::vector<uint8_t> bad(static_cast<size_t>(N), 42);
        const double chi = chi_square(bad.data(), N);
        const bool ok = (chi > T0_CHI_BAD_MIN);
        std::printf("  Constant output chi2:%.0f  %s\n",
            chi, ok ? "OK" : "ERROR");
        if (!ok) all_ok = false;
    }

    // Check 4: 90% byte-identical stream -> r > 0.80 (detects correlation)
    {
        const Topology topo = make_hex7();
        MCL_Lattice eng(T0_SMALL_SEED, 3, 5, topo);
        std::vector<uint8_t> b1(static_cast<size_t>(N));
        eng.gen_bytes_pair(b1.data(), N, 0, 1);
        std::vector<uint8_t> b2 = b1;
        // Perturb 10% of bytes (b2[i] += 128 mod 256, stronger
        // than XOR 0x01). Result: ~90% byte-identical, r ~ 0.81-0.84.
        for (int64_t i = 0; i < N / 10; i++)
            b2[static_cast<size_t>(i)] = static_cast<uint8_t>(
                b2[static_cast<size_t>(i)] + 128);
        const double r = pearson_r(b1.data(), b2.data(), N);
        const bool ok = (r > T0_R_SIMILAR_MIN);
        std::printf("  90%% similar stream:  r=%.6f  %s\n",
            r, ok ? "OK" : "ERROR");
        if (!ok) all_ok = false;
    }

    std::printf("\n  [%s] Test 0\n", all_ok ? "PASS" : "FAIL");
    return all_ok;
}

// ============================================================================
// TEST 1: Output Quality - ALL channels, unified thresholds
// ============================================================================
static bool test_01_quality(Mode mode) {
    const double min_ent_thr = (mode == Mode::QUICK)
        ? MIN_ENTROPY_QUICK : MIN_ENTROPY_FULL;
    char title[80];
    std::snprintf(title, sizeof(title),
        "TEST 1: OUTPUT QUALITY (ent>%.3f, chi2<%.0f)",
        min_ent_thr, MAX_CHI2);
    sep(title);
    const int64_t N = scale_n(T1_N_FULL, mode);
    const uint64_t seed = DEFAULT_SEED;
    const Topology topo = make_hex7();

    MCL_T2_Ref t2(seed, 3, 5);
    std::vector<uint8_t> t2_buf(static_cast<size_t>(N));
    t2.gen_bytes(t2_buf.data(), N);
    const double t2_ent = shannon_entropy(t2_buf.data(), N);
    const double t2_chi = chi_square(t2_buf.data(), N);
    const bool t2_ok = t2_ent > min_ent_thr && t2_chi < MAX_CHI2;

    MCL_Lattice hex(seed, 3, 5, topo);
    std::vector<std::vector<uint8_t>> streams;
    hex.gen_all_channels(streams, N);
    const QualityResult qr = check_all_quality(streams, N, mode);

    std::printf("  T2 baseline:    ent=%.6f chi2=%.2f %s\n",
        t2_ent, t2_chi, t2_ok ? "PASS" : "FAIL");
    std::printf("  Hex7 %d ch:     min_ent=%.6f max_chi2=%.2f "
                "fails=%d %s\n",
        topo.n_channels(), qr.min_ent, qr.max_chi, qr.failures,
        qr.failures == 0 ? "PASS" : "FAIL");

    std::printf("\n  NOTE: Entropy+Chi2 necessary but NOT sufficient.\n");
    std::printf("        BigCrush required before claiming crypto quality.\n");
    const bool pass = t2_ok && (qr.failures == 0);
    std::printf("\n  [%s] Test 1\n", pass ? "PASS" : "FAIL");
    return pass;
}

// ============================================================================
// TEST 2: Hex7 Independence (3 seeds)
// ============================================================================
static bool test_02_hex7_independence(Mode mode) {
    sep("TEST 2: HEX7 INDEPENDENCE (Bonferroni, 3 seeds)");
    const int64_t N = scale_n(T2_T3_N_FULL, mode);
    const uint64_t seeds[N_SEEDS_INDEP] = {
        DEFAULT_SEED, TEST_SEED_2, TEST_SEED_3
    };
    const Topology topo = make_hex7();
    bool all_pass = true;

    for (int s = 0; s < N_SEEDS_INDEP; s++) {
        MCL_Lattice eng(seeds[s], 3, 5, topo);
        std::vector<std::vector<uint8_t>> streams;
        eng.gen_all_channels(streams, N);
        const IndepResult res = test_independence(streams, N);

        std::printf("  seed=%llu: %d pairs, max|r|=%.6f, rej=%d %s\n",
            static_cast<unsigned long long>(seeds[s]),
            res.n_pairs, res.max_r, res.rejections,
            res.pass ? "PASS" : "FAIL");
        if (!res.pass) all_pass = false;
    }
    std::printf("\n  [%s] Test 2 -- Hex7, 3 seeds\n",
        all_pass ? "PASS" : "FAIL");
    return all_pass;
}

// ============================================================================
// TEST 3: Ring(7) Independence (3 seeds)
// ============================================================================
static bool test_03_ring7_independence(Mode mode) {
    sep("TEST 3: RING(7) INDEPENDENCE (Bonferroni, 3 seeds)");
    const int64_t N = scale_n(T2_T3_N_FULL, mode);
    const uint64_t seeds[N_SEEDS_INDEP] = {
        DEFAULT_SEED, TEST_SEED_2, TEST_SEED_3
    };
    const Topology topo = make_ring(7);
    bool all_pass = true;

    for (int s = 0; s < N_SEEDS_INDEP; s++) {
        MCL_Lattice eng(seeds[s], 3, 5, topo);
        std::vector<std::vector<uint8_t>> streams;
        eng.gen_all_channels(streams, N);
        const IndepResult res = test_independence(streams, N);

        std::printf("  seed=%llu: %d pairs, max|r|=%.6f, rej=%d %s\n",
            static_cast<unsigned long long>(seeds[s]),
            res.n_pairs, res.max_r, res.rejections,
            res.pass ? "PASS" : "FAIL");
        if (!res.pass) all_pass = false;
    }
    std::printf("\n  [%s] Test 3 -- Ring(7), 3 seeds\n",
        all_pass ? "PASS" : "FAIL");
    return all_pass;
}

// ============================================================================
// TEST 4: Multiple (p,q) -- quality + independence
// ============================================================================
static bool test_04_multi_params(Mode mode) {
    sep("TEST 4: MULTIPLE (p,q)");
    const int64_t N = scale_n(T4_N_FULL, mode);
    const uint64_t seed = DEFAULT_SEED;
    const Topology topo = make_hex7();

    std::printf("  %-12s %-10s %-10s %-10s %-6s %-6s\n",
        "(p,q)", "min_ent", "max_chi", "max|r|", "rej", "ok");
    std::printf("  %-12s %-10s %-10s %-10s %-6s %-6s\n",
        "------", "-------", "-------", "------", "---", "--");

    bool all_pass = true;
    for (int t = 0; t < T4_N_PAIRS; t++) {
        MCL_Lattice eng(seed, T4_PAIRS[t].p, T4_PAIRS[t].q, topo);
        std::vector<std::vector<uint8_t>> streams;
        eng.gen_all_channels(streams, N);

        const QualityResult qr = check_all_quality(streams, N, mode);
        const IndepResult ir = test_independence(streams, N);

        const bool ok = (qr.failures == 0) && ir.pass;
        if (!ok) all_pass = false;

        char s[32];
        std::snprintf(s, sizeof(s), "(%lld,%lld)",
            static_cast<long long>(T4_PAIRS[t].p),
            static_cast<long long>(T4_PAIRS[t].q));
        std::printf("  %-12s %-10.6f %-10.2f %-10.6f %-6d %s\n",
            s, qr.min_ent, qr.max_chi, ir.max_r, ir.rejections,
            ok ? "PASS" : "FAIL");
    }
    std::printf("\n  [%s] Test 4 -- %d pairs\n",
        all_pass ? "PASS" : "FAIL", T4_N_PAIRS);
    return all_pass;
}

// ============================================================================
// TEST 5: Throughput [INFO]
//
// Throughput measurement uses multi-rep timing: the engine generates N bytes
// REP times, and we average. This is necessary because on fast hardware
// (e.g. macOS Apple Silicon) a single 200K-byte run for T2 may complete
// in <1us, making division by 'sec' produce 'inf' or absurd MB/s values.
// Multi-rep ensures total measured time is well above timer resolution.
//
// Dead-code elimination defense: clang/LLVM (especially on Apple Silicon)
// is aggressive about deleting work whose output is never consumed. Without
// a forced read of the generated bytes, the optimizer can elide most of
// gen_bytes() and report unrealistic throughput (e.g. 1.9 PB/s on macOS,
// while the same code runs at 5 MB/s on Linux/gcc -- a 4e8x discrepancy
// caused entirely by DCE). The 'volatile uint8_t sink' below forces a read
// of the last generated byte, which prevents the optimizer from treating
// gen_bytes()/gen_all_channels() as dead. The XOR accumulator pattern is
// the standard idiom for this purpose (see Google Benchmark's
// DoNotOptimize for the same approach).
//
// Scientific note: this is not a precision benchmark -- for that see
// mcl_benchmark.cpp / mcl_bench_internal.cpp. Test 5 is a relative
// comparison T2 vs lattice variants under identical conditions.
// ============================================================================
static constexpr int    T5_REPS    = 10;     // repetitions per engine
static constexpr double T5_MIN_SEC = 1e-6;   // floor to prevent div-by-near-zero

static void test_05_throughput(Mode mode) {
    sep("TEST 5: THROUGHPUT");
    const int64_t N = scale_n(T5_T6_N_FULL, mode);
    const uint64_t seed = DEFAULT_SEED;

    // T2 (ground truth -- not Ring(2) which is degenerate)
    // Warmup pass: discard first measurement to neutralize cold-cache bias.
    // Without this, T2 (measured first) would be unfairly slow vs the
    // lattice variants (measured second/third with warm cache).
    {
        MCL_T2_Ref warmup_eng(seed, 3, 5);
        std::vector<uint8_t> warmup_buf(static_cast<size_t>(N / 10));
        warmup_eng.gen_bytes(warmup_buf.data(), N / 10);  // discard
    }
    {
        MCL_T2_Ref eng(seed, 3, 5);
        std::vector<uint8_t> buf(static_cast<size_t>(N));
        volatile uint8_t sink = 0;  // DCE guard (see comment block above)
        const auto t0 = std::chrono::steady_clock::now();
        for (int r = 0; r < T5_REPS; r++) {
            eng.gen_bytes(buf.data(), N);
            sink = static_cast<uint8_t>(sink
                ^ buf[static_cast<size_t>(N - 1)]);
        }
        const auto t1 = std::chrono::steady_clock::now();
        (void)sink;  // silence "set but not read" if any
        double sec = std::chrono::duration<double>(t1 - t0).count();
        if (sec < T5_MIN_SEC) sec = T5_MIN_SEC;
        const double total_bytes = static_cast<double>(N)
            * static_cast<double>(T5_REPS);
        const double mbps = (total_bytes / (1024.0 * 1024.0)) / sec;
        std::printf("  T2 (mcl_core):  %8.2f MB/s | %d sin/iter | %d ch | "
                    "%d B | %.1f sin/ch-byte\n",
            mbps, MCL_T2_Ref::SIN_PER_ITER, MCL_T2_Ref::CHANNELS,
            MCL_T2_Ref::STATE_BYTES, MCL_T2_Ref::SIN_PER_CH_BYTE);
    }

    // Ring(7)
    {
        const Topology topo = make_ring(7);
        MCL_Lattice eng(seed, 3, 5, topo);
        std::vector<std::vector<uint8_t>> streams;
        volatile uint8_t sink = 0;
        const auto t0 = std::chrono::steady_clock::now();
        for (int r = 0; r < T5_REPS; r++) {
            eng.gen_all_channels(streams, N);
            sink = static_cast<uint8_t>(sink
                ^ streams[0][static_cast<size_t>(N - 1)]);
        }
        const auto t1 = std::chrono::steady_clock::now();
        (void)sink;
        double sec = std::chrono::duration<double>(t1 - t0).count();
        if (sec < T5_MIN_SEC) sec = T5_MIN_SEC;
        const int nc = topo.n_channels();
        const int spi = topo.sin_per_iterate();
        const double total_mb = static_cast<double>(N)
            * static_cast<double>(nc)
            * static_cast<double>(T5_REPS) / (1024.0 * 1024.0);
        const double scb = static_cast<double>(spi * DECIMATION)
            / static_cast<double>(nc);
        std::printf("  Ring(7):        %8.2f MB/s | %d sin/iter | %d ch | "
                    "%d B | %.2f sin/ch-byte\n",
            total_mb / sec, spi, nc, topo.logical_state_bytes(), scb);
    }

    // Hex7
    {
        const Topology topo = make_hex7();
        MCL_Lattice eng(seed, 3, 5, topo);
        std::vector<std::vector<uint8_t>> streams;
        volatile uint8_t sink = 0;
        const auto t0 = std::chrono::steady_clock::now();
        for (int r = 0; r < T5_REPS; r++) {
            eng.gen_all_channels(streams, N);
            sink = static_cast<uint8_t>(sink
                ^ streams[0][static_cast<size_t>(N - 1)]);
        }
        const auto t1 = std::chrono::steady_clock::now();
        (void)sink;
        double sec = std::chrono::duration<double>(t1 - t0).count();
        if (sec < T5_MIN_SEC) sec = T5_MIN_SEC;
        const int nc = topo.n_channels();
        const int spi = topo.sin_per_iterate();
        const double total_mb = static_cast<double>(N)
            * static_cast<double>(nc)
            * static_cast<double>(T5_REPS) / (1024.0 * 1024.0);
        const double scb = static_cast<double>(spi * DECIMATION)
            / static_cast<double>(nc);
        std::printf("  Hex7:           %8.2f MB/s | %d sin/iter | %d ch | "
                    "%d B | %.2f sin/ch-byte\n",
            total_mb / sec, spi, nc, topo.logical_state_bytes(), scb);
    }

    std::printf("\n  [INFO] Test 5\n");
}

// ============================================================================
// TEST 6: Saturation [INFO]
// ============================================================================
static void test_06_saturation(Mode mode) {
    sep("TEST 6: SATURATION");
    const int64_t N = scale_n(T6_SAT_N_FULL, mode);
    const uint64_t seed = DEFAULT_SEED;

    std::printf("  Coupling: (K/degree)*SUM sin(p*tj - q*ti)  "
                "|  DECIMATION=%d\n", DECIMATION);
    std::printf("  T2 baseline: %.1f sin/ch-byte\n\n",
        MCL_T2_Ref::SIN_PER_CH_BYTE);

    std::printf("  %-10s %-6s %-8s %-8s %-12s %-10s\n",
        "Topology", "Nodes", "sin/i", "Chans", "sin/ch-byte", "min_ent");
    std::printf("  %-10s %-6s %-8s %-8s %-12s %-10s\n",
        "--------", "-----", "-----", "-----", "-----------", "-------");

    for (int ri = 0; ri < T6_N_RING_SIZES; ri++) {
        const int n = T6_RING_SIZES[ri];
        const Topology topo = make_ring(n);
        MCL_Lattice eng(seed, 3, 5, topo);
        std::vector<std::vector<uint8_t>> st;
        eng.gen_all_channels(st, N);
        const int spi = topo.sin_per_iterate();
        const int nc = topo.n_channels();
        const double scb = static_cast<double>(spi * DECIMATION)
            / static_cast<double>(nc);
        const QualityResult qr = check_all_quality(st, N, mode);

        char name[16];
        std::snprintf(name, sizeof(name), "Ring(%d)", n);
        std::printf("  %-10s %-6d %-8d %-8d %-12.2f %-10.6f\n",
            name, n, spi, nc, scb, qr.min_ent);
    }

    // Hex7
    {
        const Topology topo = make_hex7();
        MCL_Lattice eng(seed, 3, 5, topo);
        std::vector<std::vector<uint8_t>> st;
        eng.gen_all_channels(st, N);
        const int spi = topo.sin_per_iterate();
        const int nc = topo.n_channels();
        const double scb = static_cast<double>(spi * DECIMATION)
            / static_cast<double>(nc);
        const QualityResult qr = check_all_quality(st, N, mode);
        std::printf("  %-10s %-6d %-8d %-8d %-12.2f %-10.6f\n",
            "Hex7", 7, spi, nc, scb, qr.min_ent);
    }

    // Formula explanation
    std::printf("\n  Formula: sin/ch-byte = sin_per_iter * DECIMATION / "
                "n_channels\n");
    std::printf("  Ring(N): sin/iter=2N, channels=N(N-1)/2\n");
    std::printf("  => sin/ch-byte = 2N * %d / (N(N-1)/2) = %d/(N-1)\n",
        DECIMATION, 4 * DECIMATION);
    std::printf("  This scaling is combinatorial (C(N,2) grows as N^2).\n");
    std::printf("  The real question: do ALL channels remain independent?\n");
    std::printf("  (Verified for N=7 in Tests 2+3, unverified for N>7)\n");

    std::printf("\n  [INFO] Test 6\n");
}

// ============================================================================
// TEST 7: Memory [INFO]
// ============================================================================
static void test_07_memory() {
    sep("TEST 7: MEMORY");

    const Topology hex = make_hex7();
    const Topology ring = make_ring(7);

    struct Cfg { const char* name; int nc; int state; };
    const Cfg cfgs[] = {
        {"T2 (21 instances)", 21,
            21 * MCL_T2_Ref::STATE_BYTES},
        {"Ring(7)", ring.n_channels(),
            ring.logical_state_bytes()},
        {"Hex7", hex.n_channels(),
            hex.logical_state_bytes()},
    };
    const int n_cfgs = static_cast<int>(sizeof(cfgs) / sizeof(cfgs[0]));

    std::printf("  For 21 independent channels:\n\n");
    for (int i = 0; i < n_cfgs; i++)
        std::printf("    %-22s %3d ch  %4d bytes (logical)\n",
            cfgs[i].name, cfgs[i].nc, cfgs[i].state);

    std::printf("\n  At scale:\n");
    const char* labels[T7_N_SCALES] = {"1M users", "100M users"};
    for (int s = 0; s < T7_N_SCALES; s++) {
        std::printf("    %s:\n", labels[s]);
        for (int i = 0; i < n_cfgs; i++) {
            const double gb = static_cast<double>(T7_SCALES[s])
                * static_cast<double>(cfgs[i].state)
                / (1024.0 * 1024.0 * 1024.0);
            std::printf("      %-22s %8.2f GB\n", cfgs[i].name, gb);
        }
    }

    std::printf("\n  CAVEAT: T2 with different (p,q) also gives "
                "unlimited channels.\n");
    std::printf("  Lattice advantage = N(N-1)/2 channels from SINGLE "
                "(p,q)+seed.\n");
    std::printf("\n  [INFO] Test 7\n");
}

// ============================================================================
// CLI helpers
// ============================================================================
static void print_help(const char* prog) {
    std::printf("Usage: %s [OPTIONS]\n\n", prog);
    std::printf("MCL Lattice Coupled Oscillator -- Hex7 Multiplex Prototype "
                "v%s.\n\n", DOC_VERSION);
    std::printf("OPTIONS:\n");
    std::printf("  --full       Canonical sample sizes (default).\n");
    std::printf("  --quick      1/%d sample sizes for smoke testing.\n",
        QUICK_DIVISOR);
    std::printf("  --help       Show this help and exit.\n");
    std::printf("  --version    Show version and exit.\n\n");
    std::printf("EXIT CODES:\n");
    std::printf("  0  PASS (all 5 numbered tests pass)\n");
    std::printf("  1  FAIL (one or more numbered tests fail)\n");
    std::printf("  2  Bad CLI arguments\n\n");
    std::printf("Doc ID: %s v%s\n", DOC_ID, DOC_VERSION);
}

// UTC timestamp formatter (defensive: empty string on failure).
static void format_utc_now(char* buf, size_t buflen) {
    if (buflen == 0) return;
    buf[0] = '\0';
    const std::time_t now = std::time(nullptr);
    std::tm tm_utc;
#ifdef _WIN32
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    if (std::strftime(buf, buflen, "%Y-%m-%d %H:%M:%S UTC", &tm_utc) == 0) {
        buf[0] = '\0';
    }
}

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char** argv) {
    setbuf(stdout, nullptr);  // realtime output, no buffering

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
        if (a == "--quick") { saw_quick = true; mode = Mode::QUICK; continue; }
        if (a == "--full")  { saw_full  = true; mode = Mode::FULL;  continue; }
        std::fprintf(stderr, "Unknown argument: %s\n", argv[i]);
        std::fprintf(stderr, "Try '%s --help' for usage.\n", argv[0]);
        return 2;
    }
    if (saw_quick && saw_full) {
        std::fprintf(stderr,
            "Error: --quick and --full are mutually exclusive.\n");
        return 2;
    }

    char ts[32];
    format_utc_now(ts, sizeof(ts));

    const auto t_start = std::chrono::steady_clock::now();
    std::printf(
        "\n==============================================================================\n");
    std::printf("  MCL LATTICE COUPLED OSCILLATOR v%s\n", DOC_VERSION);
    std::printf("  %s\n", DOC_ID);
    std::printf("  Mode: %s\n", (mode == Mode::QUICK) ? "QUICK" : "FULL");
    std::printf("  Started: %s\n", ts);
    std::printf("  Coupling: Kuramoto (K/degree * SUM sin, separate per "
                "neighbor)\n");
    std::printf("  Update:   Gauss-Seidel, sequential node order 0..N-1\n");
    std::printf("  Extract:  simultaneous C(N,2) channels from single "
                "instance\n");
    std::printf(
        "==============================================================================\n");

    int passed = 0, total = 0;
    total++; if (test_00_negative_control(mode))   passed++;
    total++; if (test_01_quality(mode))            passed++;
    total++; if (test_02_hex7_independence(mode))  passed++;
    total++; if (test_03_ring7_independence(mode)) passed++;
    total++; if (test_04_multi_params(mode))       passed++;
    test_05_throughput(mode);
    test_06_saturation(mode);
    test_07_memory();

    const auto t_end = std::chrono::steady_clock::now();
    const double el = std::chrono::duration<double>(
        t_end - t_start).count();

    std::printf(
        "\n==============================================================================\n");
    std::printf("  RESULTS: %d/%d PASS | %.1f sec\n\n",
        passed, total, el);
    std::printf("  LIMITATIONS (resolve before patent claims):\n");
    std::printf("    1. BigCrush not yet run on any lattice engine\n");
    std::printf("    2. Goldilocks [20,36] Safe Zone unvalidated for "
                "lattice XOR\n");
    std::printf("    3. Frequency linear independence assumed, not proven\n");
    std::printf("    4. Maximum useful N not established (tested only N "
                "<= 13)\n");
    std::printf("    5. Lyapunov exponent not computed for lattice "
                "topologies\n");
    std::printf("    6. Kuramoto K/degree normalization chosen, not "
                "optimized\n");
    std::printf("\n  Doc ID:  %s v%s\n", DOC_ID, DOC_VERSION);
    std::printf("  Author:  Madeeh Ibrahim, Cairo, Egypt\n");
    std::printf("  Patent Pending: PCT/IB2026/052737, "
                "PCT/IB2026/053253, PCT/IB2026/053673\n");
    std::printf(
        "==============================================================================\n\n");

    return (passed == total) ? 0 : 1;
}
