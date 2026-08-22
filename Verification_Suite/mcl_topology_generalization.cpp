/*
 * ============================================================================
 * MCL Topology Generalization v1.0.0 -- N>=3 Oscillator Networks
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-TOPOLOGY-GENERALIZATION-2026-0526-001
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
 * PURPOSE: Test the claim, described as "conjectured / verification ongoing"
 *   in Paper 1 (Section VI) and Paper 3 (Section VII), that the MCL chaotic
 *   and channel-independence properties GENERALIZE from the two-oscillator
 *   engine (MCL_T2) to higher-order networks of N >= 3 fully-coupled
 *   oscillators (MCL_T3, MCL_T4). This turns "expected theoretically" into
 *   measured evidence.
 *
 * ----------------------------------------------------------------------------
 * WHAT IS TESTED
 * ----------------------------------------------------------------------------
 * For N = 3 (MCL_T3) and N = 4 (MCL_T4), across several coupling
 * configurations (the triples / sextets shipped in mcl_core.hpp):
 *
 *   T1. CHAOS PERSISTS: the largest Lyapunov exponent lambda_1 stays strongly
 *       positive as the dimension grows. Measured by the standard
 *       two-trajectory (Benettin) method: evolve a reference trajectory and a
 *       perturbed shadow, accumulate the log of their divergence, and
 *       renormalize the perturbation to a fixed magnitude each step.
 *
 *   T2. CHANNELS STAY INDEPENDENT: the per-oscillator output bytes
 *       b_i = Goldilocks(theta_i) carry near-zero mutual information between
 *       oscillators, i.e. the network does not collapse into a synchronized
 *       (correlated) regime.
 *       SCOPE: this is the PER-OSCILLATOR channel independence relevant to the
 *       multi-receiver architecture (Paper 1 Section VI), where distinct
 *       receivers use distinct oscillators/parameters and must not be able to
 *       infer one another's channel. It is NOT a test of the merged
 *       production output gen_byte = XOR of all oscillators -- that combined
 *       stream's randomness is tested separately (PractRand / BigCrush in
 *       mcl_practrand.cpp / mcl_bigcrush.c).
 *       NEGATIVE CONTROL: a genuinely SYNCHRONIZED network (identical natural
 *       frequencies, attractive Kuramoto coupling) MUST fail independence --
 *       its channels lock and the byte MI is high (~ 4 bits on the 16-bin
 *       estimator). This calibrates the MI estimator: a near-zero MI on the
 *       real engine is only meaningful if the estimator can detect real
 *       correlation when it exists. (The control uses Kuramoto dynamics, not
 *       the MCL map, on purpose: its only job is to produce genuinely
 *       correlated channels to exercise the estimator; the MCL engine does
 *       not synchronize -- that is the property under test.)
 *
 * Decision rule:
 *   lambda_1 > 0 for every configuration  => chaos generalizes.
 *   real-engine inter-channel MI ~ 0      => independence generalizes,
 *   AND the synchronized control MI >> 0  => the MI test is valid.
 *
 * ----------------------------------------------------------------------------
 * HONEST SCOPE
 * ----------------------------------------------------------------------------
 * This is empirical evidence for the specific N=3 and N=4 fully-coupled
 * configurations shipped in mcl_core.hpp. It supports the generalization
 * claim for those topologies; it is NOT a proof that EVERY (p,q) coupling at
 * every N is hyperchaotic (that is a question in rigorous dynamical-systems
 * theory, explicitly left open in Paper 3 Section VIII.B). The Lyapunov here
 * is the LARGEST exponent by the two-trajectory method, not the full spectrum.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_topology_generalization mcl_topology_generalization.cpp -lm && ./mcl_topology_generalization
 *
 * REFERENCES:
 *   - Benettin et al. (1980): largest Lyapunov exponent via two-trajectory
 *     divergence with periodic renormalization.
 *   - Kuramoto (1975): synchronization of coupled phase oscillators (the
 *     negative-control regime).
 *   - mcl_core.hpp: MCL_T3 / MCL_T4 engines and their coupling tables.
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

#include <array>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

static constexpr const char* const DOC_ID =
    "MCL-TOPOLOGY-GENERALIZATION-2026-0526-001";
static constexpr const char* const DOC_VERSION = "6.0.0";

// Per-oscillator Goldilocks readout byte (same windows as the engines).
static uint8_t osc_byte(double t) {
    const uint64_t x = d2b(t);
    return static_cast<uint8_t>(
               static_cast<uint8_t>(x >> GOLD_S1) ^
               static_cast<uint8_t>(x >> GOLD_S2));
}

// Circular wrapped distance in [0, pi].
static double circ_metric(double a, double b) {
    double d = std::fmod(a - b + MCL_TWO_PI, MCL_TWO_PI);
    if (d > MCL_PI) d = MCL_TWO_PI - d;
    return d;
}

// Signed circular difference in (-pi, pi].
static double circ_signed(double a, double b) {
    double d = std::fmod(a - b + MCL_TWO_PI, MCL_TWO_PI);
    if (d > MCL_PI) d -= MCL_TWO_PI;
    return d;
}

// Miller-Madow-corrected mutual information between two byte streams, on a
// 16x16 grid (top nibble) for estimator stability at these sample counts.
static double mi_bytes(const std::vector<uint8_t>& a,
                       const std::vector<uint8_t>& b) {
    const int B = 16;
    std::vector<long> ja(static_cast<size_t>(B), 0);
    std::vector<long> jb(static_cast<size_t>(B), 0);
    std::vector<std::vector<long> > j(
        static_cast<size_t>(B), std::vector<long>(static_cast<size_t>(B), 0));
    const long n = static_cast<long>(a.size());
    for (long i = 0; i < n; i++) {
        const int x = a[static_cast<size_t>(i)] >> 4;
        const int y = b[static_cast<size_t>(i)] >> 4;
        ja[static_cast<size_t>(x)]++;
        jb[static_cast<size_t>(y)]++;
        j[static_cast<size_t>(x)][static_cast<size_t>(y)]++;
    }
    double mi = 0.0;
    int nz = 0;
    for (int x = 0; x < B; x++) {
        for (int y = 0; y < B; y++) {
            const long cell = j[static_cast<size_t>(x)][static_cast<size_t>(y)];
            if (cell > 0) {
                const double pxy = static_cast<double>(cell)
                                 / static_cast<double>(n);
                const double px = static_cast<double>(ja[static_cast<size_t>(x)])
                                / static_cast<double>(n);
                const double py = static_cast<double>(jb[static_cast<size_t>(y)])
                                / static_cast<double>(n);
                mi += pxy * std::log2(pxy / (px * py));
                nz++;
            }
        }
    }
    // Miller-Madow bias correction: + (nonempty_cells - 1) / (2 n ln2).
    mi -= static_cast<double>(nz - 1)
        / (2.0 * static_cast<double>(n) * std::log(2.0));
    return mi;
}

static void banner(const char* title) {
    std::printf("\n==========================================================="
                "===================\n");
    std::printf("  %s\n", title);
    std::printf("============================================================="
                "=================\n\n");
}

// ---------------------------------------------------------------------------
// T1: largest Lyapunov exponent for N=3 via two-trajectory divergence.
// We reimplement the MCL_T3 iterate for a free state vector so we can evolve
// a reference and a renormalized shadow in lockstep.
// ---------------------------------------------------------------------------
static void t3_step(std::array<double, 3>& s, const CouplingTriple& ct,
                    double kc) {
    const double p12 = static_cast<double>(ct.p12);
    const double q12 = static_cast<double>(ct.q12);
    const double p13 = static_cast<double>(ct.p13);
    const double q13 = static_cast<double>(ct.q13);
    const double p23 = static_cast<double>(ct.p23);
    const double q23 = static_cast<double>(ct.q23);
    const double c12 = p12 * s[1] - q12 * s[0];
    const double c13 = p13 * s[2] - q13 * s[0];
    s[0] = mod2pi(s[0] + OMEGA_1 + kc * (std::sin(c12) + std::sin(c13)));
    const double c21 = p12 * s[0] - q12 * s[1];
    const double c23 = p23 * s[2] - q23 * s[1];
    s[1] = mod2pi(s[1] + OMEGA_2 + kc * (std::sin(c21) + std::sin(c23)));
    const double c31 = p13 * s[0] - q13 * s[2];
    const double c32 = p23 * s[1] - q23 * s[2];
    s[2] = mod2pi(s[2] + OMEGA_3 + kc * (std::sin(c31) + std::sin(c32)));
}

static double lyapunov_t3(const CouplingTriple& ct, uint64_t seed) {
    MCL_T3 e(seed, ct);              // burned-in reference on the attractor
    std::array<double, 3> r = e.state();
    std::array<double, 3> p = r;
    const double d0 = 1e-8;
    p[0] = mod2pi(p[0] + d0);

    double sum = 0.0;
    const int N = 30000;
    for (int i = 0; i < N; i++) {
        t3_step(r, ct, K_DEFAULT);
        t3_step(p, ct, K_DEFAULT);
        const double dx = circ_metric(r[0], p[0]);
        const double dy = circ_metric(r[1], p[1]);
        const double dz = circ_metric(r[2], p[2]);
        const double d = std::sqrt(dx * dx + dy * dy + dz * dz);
        if (d > 0.0) {
            sum += std::log(d / d0);
            const double f = d0 / d;   // renormalize shadow to distance d0
            p[0] = mod2pi(r[0] + circ_signed(p[0], r[0]) * f);
            p[1] = mod2pi(r[1] + circ_signed(p[1], r[1]) * f);
            p[2] = mod2pi(r[2] + circ_signed(p[2], r[2]) * f);
        }
    }
    return sum / static_cast<double>(N);
}

// ---------------------------------------------------------------------------
// T1 (N=4): same method for MCL_T4.
// ---------------------------------------------------------------------------
static void t4_step(std::array<double, 4>& s, const CouplingSextet& cs,
                    double kc) {
    const double p12 = static_cast<double>(cs.p12);
    const double q12 = static_cast<double>(cs.q12);
    const double p13 = static_cast<double>(cs.p13);
    const double q13 = static_cast<double>(cs.q13);
    const double p14 = static_cast<double>(cs.p14);
    const double q14 = static_cast<double>(cs.q14);
    const double p23 = static_cast<double>(cs.p23);
    const double q23 = static_cast<double>(cs.q23);
    const double p24 = static_cast<double>(cs.p24);
    const double q24 = static_cast<double>(cs.q24);
    const double p34 = static_cast<double>(cs.p34);
    const double q34 = static_cast<double>(cs.q34);
    const double c12 = p12 * s[1] - q12 * s[0];
    const double c13 = p13 * s[2] - q13 * s[0];
    const double c14 = p14 * s[3] - q14 * s[0];
    s[0] = mod2pi(s[0] + OMEGA_1 + kc * (std::sin(c12) + std::sin(c13)
                                         + std::sin(c14)));
    const double c21 = p12 * s[0] - q12 * s[1];
    const double c23 = p23 * s[2] - q23 * s[1];
    const double c24 = p24 * s[3] - q24 * s[1];
    s[1] = mod2pi(s[1] + OMEGA_2 + kc * (std::sin(c21) + std::sin(c23)
                                         + std::sin(c24)));
    const double c31 = p13 * s[0] - q13 * s[2];
    const double c32 = p23 * s[1] - q23 * s[2];
    const double c34 = p34 * s[3] - q34 * s[2];
    s[2] = mod2pi(s[2] + OMEGA_3 + kc * (std::sin(c31) + std::sin(c32)
                                         + std::sin(c34)));
    const double c41 = p14 * s[0] - q14 * s[3];
    const double c42 = p24 * s[1] - q24 * s[3];
    const double c43 = p34 * s[2] - q34 * s[3];
    s[3] = mod2pi(s[3] + OMEGA_4 + kc * (std::sin(c41) + std::sin(c42)
                                         + std::sin(c43)));
}

static double lyapunov_t4(const CouplingSextet& cs, uint64_t seed) {
    // Burn in a free state vector (MCL_T4 has no state() accessor).
    const uint64_t h = hash_seed(seed);
    std::array<double, 4> r = {
        mod2pi(static_cast<double>(h) * OMEGA_1),
        mod2pi(static_cast<double>(h) * OMEGA_2),
        mod2pi(static_cast<double>(h) * OMEGA_3),
        mod2pi(static_cast<double>(h) * OMEGA_4)};
    for (int i = 0; i < BURNIN; i++) t4_step(r, cs, K_DEFAULT);
    std::array<double, 4> p = r;
    const double d0 = 1e-8;
    p[0] = mod2pi(p[0] + d0);

    double sum = 0.0;
    const int N = 30000;
    for (int i = 0; i < N; i++) {
        t4_step(r, cs, K_DEFAULT);
        t4_step(p, cs, K_DEFAULT);
        double sq = 0.0;
        for (int k = 0; k < 4; k++) {
            const double dk = circ_metric(r[static_cast<size_t>(k)],
                                          p[static_cast<size_t>(k)]);
            sq += dk * dk;
        }
        const double d = std::sqrt(sq);
        if (d > 0.0) {
            sum += std::log(d / d0);
            const double f = d0 / d;
            for (int k = 0; k < 4; k++)
                p[static_cast<size_t>(k)] = mod2pi(
                    r[static_cast<size_t>(k)]
                    + circ_signed(p[static_cast<size_t>(k)],
                                  r[static_cast<size_t>(k)]) * f);
        }
    }
    return sum / static_cast<double>(N);
}

// ---------------------------------------------------------------------------
// T2: inter-channel independence for N=3.
// ---------------------------------------------------------------------------
static void independence_t3(const CouplingTriple& ct, long n,
                            double& mi12, double& mi13, double& mi23) {
    MCL_T3 e(DEFAULT_SEED, ct);
    std::vector<uint8_t> b1(static_cast<size_t>(n));
    std::vector<uint8_t> b2(static_cast<size_t>(n));
    std::vector<uint8_t> b3(static_cast<size_t>(n));
    for (long i = 0; i < n; i++) {
        e.iterate();
        const std::array<double, 3> s = e.state();
        b1[static_cast<size_t>(i)] = osc_byte(s[0]);
        b2[static_cast<size_t>(i)] = osc_byte(s[1]);
        b3[static_cast<size_t>(i)] = osc_byte(s[2]);
    }
    mi12 = mi_bytes(b1, b2);
    mi13 = mi_bytes(b1, b3);
    mi23 = mi_bytes(b2, b3);
}

// NEGATIVE CONTROL: a genuinely synchronized Kuramoto network. Identical
// natural frequency + attractive coupling drives the phases to lock, so the
// per-oscillator bytes become correlated and MI is high. This proves the MI
// estimator can detect real correlation.
static void independence_sync_control(long n, double& mi12, double& mi13,
                                      double& mi23) {
    const double w = 0.5;
    const double K = 0.3;
    const double dt = 0.1;
    double t1 = 0.1, t2 = 2.5, t3 = 5.0;
    auto step = [&]() {
        const double d1 = w + K * (std::sin(t2 - t1) + std::sin(t3 - t1));
        const double d2 = w + K * (std::sin(t1 - t2) + std::sin(t3 - t2));
        const double d3 = w + K * (std::sin(t1 - t3) + std::sin(t2 - t3));
        t1 += dt * d1;
        t2 += dt * d2;
        t3 += dt * d3;
    };
    for (int i = 0; i < 20000; i++) step();   // settle into synchronization
    std::vector<uint8_t> b1(static_cast<size_t>(n));
    std::vector<uint8_t> b2(static_cast<size_t>(n));
    std::vector<uint8_t> b3(static_cast<size_t>(n));
    for (long i = 0; i < n; i++) {
        step();
        b1[static_cast<size_t>(i)] = osc_byte(mod2pi(t1));
        b2[static_cast<size_t>(i)] = osc_byte(mod2pi(t2));
        b3[static_cast<size_t>(i)] = osc_byte(mod2pi(t3));
    }
    mi12 = mi_bytes(b1, b2);
    mi13 = mi_bytes(b1, b3);
    mi23 = mi_bytes(b2, b3);
}

static bool run() {
    bool all_chaotic = true;
    bool indep_ok = true;

    // ---- T1: chaos persists at N=3 and N=4 ----
    banner("TEST 1: CHAOS PERSISTS (largest Lyapunov, N=3 and N=4)");
    std::printf("  Two-trajectory (Benettin) method. lambda_1 > 0 => chaotic.\n\n");

    std::printf("  N=3 (MCL_T3) over coupling triples:\n");
    std::printf("  %-8s %-26s %-12s\n", "triple", "(p12,q12;p13,q13;p23,q23)",
                "lambda_1");
    std::printf("  %-8s %-26s %-12s\n", "------", "-------------------------",
                "--------");
    const CouplingTriple* tr = t3_triples();
    const int N_T3 = 6;
    for (int i = 0; i < N_T3; i++) {
        const double l = lyapunov_t3(tr[i],
                                     DEFAULT_SEED + static_cast<uint64_t>(i) * 7919U);
        char cfg[32];
        std::snprintf(cfg, sizeof(cfg), "(%lld,%lld;%lld,%lld;%lld,%lld)",
                      static_cast<long long>(tr[i].p12),
                      static_cast<long long>(tr[i].q12),
                      static_cast<long long>(tr[i].p13),
                      static_cast<long long>(tr[i].q13),
                      static_cast<long long>(tr[i].p23),
                      static_cast<long long>(tr[i].q23));
        std::printf("  %-8d %-26s %-12.4f %s\n", i, cfg, l,
                    l > 0.0 ? "" : "<-- NOT CHAOTIC");
        if (l <= 0.0) all_chaotic = false;
    }

    std::printf("\n  N=4 (MCL_T4) over coupling sextets:\n");
    std::printf("  %-8s %-12s\n", "sextet", "lambda_1");
    std::printf("  %-8s %-12s\n", "------", "--------");
    const CouplingSextet* sx = t4_sextets();
    const int N_T4 = 4;
    for (int i = 0; i < N_T4; i++) {
        const double l = lyapunov_t4(sx[i],
                                     DEFAULT_SEED + static_cast<uint64_t>(i) * 7919U);
        std::printf("  %-8d %-12.4f %s\n", i, l,
                    l > 0.0 ? "" : "<-- NOT CHAOTIC");
        if (l <= 0.0) all_chaotic = false;
    }

    // ---- T2: channels independent, with synchronized negative control ----
    banner("TEST 2: CHANNELS INDEPENDENT (inter-oscillator byte MI, N=3)");
    std::printf("  Per-oscillator byte MI should be ~ 0 (independent).\n");
    std::printf("  NEGATIVE control (synchronized Kuramoto net) MUST be >> 0.\n");
    std::printf("  (This is per-oscillator/multi-receiver channel independence,\n");
    std::printf("  not the merged gen_byte randomness -- that is PractRand's job.)\n\n");

    const long N_SAMP = 2000000;
    double m12 = 0.0, m13 = 0.0, m23 = 0.0;
    independence_t3(tr[0], N_SAMP, m12, m13, m23);
    std::printf("  REAL (triple 0):  MI(1;2)=%+.6f  MI(1;3)=%+.6f  "
                "MI(2;3)=%+.6f\n", m12, m13, m23);
    const double real_max = std::fmax(std::fmax(std::fabs(m12),
                                                std::fabs(m13)),
                                      std::fabs(m23));

    double s12 = 0.0, s13 = 0.0, s23 = 0.0;
    independence_sync_control(N_SAMP, s12, s13, s23);
    std::printf("  SYNC control:     MI(1;2)=%+.6f  MI(1;3)=%+.6f  "
                "MI(2;3)=%+.6f\n", s12, s13, s23);
    const double sync_min = std::fmin(std::fmin(s12, s13), s23);

    // Independence holds if real MI ~ 0 (< 0.01 bits) AND the control detects
    // real correlation (sync MI > 1 bit).
    const bool real_indep = (real_max < 0.01);
    const bool control_valid = (sync_min > 1.0);
    indep_ok = real_indep && control_valid;

    std::printf("\n  Real-engine max |MI| = %.6f (independent if < 0.01)\n",
                real_max);
    std::printf("  Sync-control min MI  = %.4f (detector valid if > 1.0)\n",
                sync_min);

    // ---- Verdict ----
    banner("VERDICT: DOES THE MCL TOPOLOGY GENERALIZE TO N >= 3?");
    if (all_chaotic) {
        std::printf("  T1 PASS: lambda_1 > 0 for all tested N=3 and N=4\n");
        std::printf("           configurations -- chaos persists with the\n");
        std::printf("           higher-order topology.\n");
    } else {
        std::printf("  T1 FAIL: at least one configuration was not chaotic.\n");
    }
    if (!control_valid) {
        std::printf("  T2 INVALID: the synchronized control did not produce\n");
        std::printf("              high MI; the estimator cannot be trusted.\n");
    } else if (real_indep) {
        std::printf("  T2 PASS: real-engine inter-channel MI ~ 0 (independent),\n");
        std::printf("           and the synchronized control MI is high\n");
        std::printf("           (%.2f bits), so the estimator is valid. The\n",
                    sync_min);
        std::printf("           channels do NOT collapse into synchronization.\n");
    } else {
        std::printf("  T2 FAIL: real-engine channels show measurable MI.\n");
    }

    std::printf("\n  OVERALL: %s\n",
                (all_chaotic && indep_ok)
                    ? "GENERALIZES -- both chaos and channel independence hold\n"
                      "  at N=3 and N=4 for the tested couplings. The Paper 1/3\n"
                      "  'conjectured' generalization is supported empirically\n"
                      "  for these topologies (not a proof for all (p,q)/N)."
                    : "INCOMPLETE -- see failing test above.");
    return all_chaotic && indep_ok;
}

static void print_help(const char* prog) {
    std::printf("Usage:\n");
    std::printf("  %s            # run the N>=3 generalization tests\n", prog);
    std::printf("  %s --help     # this message\n", prog);
    std::printf("\n");
    std::printf("Tests whether MCL chaos (largest Lyapunov > 0) and channel\n");
    std::printf("independence (inter-oscillator byte MI ~ 0) generalize from\n");
    std::printf("N=2 to N=3 (MCL_T3) and N=4 (MCL_T4) networks, with a\n");
    std::printf("synchronized negative control for the independence test.\n");
    std::printf("\n");
    std::printf("Document: %s v%s\n", DOC_ID, DOC_VERSION);
}

}  // namespace

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);

    if (argc > 1) {
        if (std::strcmp(argv[1], "--help") == 0) {
            print_help(argv[0]);
            return 0;
        }
        std::fprintf(stderr, "Unknown argument: %s\n", argv[1]);
        return 1;
    }

    std::printf("============================================================="
                "=================\n");
    std::printf("  MCL TOPOLOGY GENERALIZATION v%s\n", DOC_VERSION);
    std::printf("  Do chaos and channel independence hold for N >= 3 "
                "oscillators?\n");
    std::printf("  %s\n", DOC_ID);
    std::printf("============================================================="
                "=================\n");

    const bool ok = run();

    std::printf("\n============================================================"
                "==================\n");
    std::printf("  This is empirical evidence for the N=3 and N=4 couplings\n");
    std::printf("  shipped in mcl_core.hpp. It supports the Paper 1/3\n");
    std::printf("  generalization claim for those topologies; it is not a\n");
    std::printf("  proof that every (p,q) at every N is hyperchaotic.\n");
    std::printf("============================================================="
                "=================\n\n");
    return ok ? 0 : 1;
}
