/* ============================================================================
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ----------------------------------------------------------------------------
 * Lag Autocorrelation Decay Test  (Paper 3 v3, Experiment 3 / Phase 1)
 *
 * Measures the within-channel autocorrelation function rho(tau) for a single
 * MCL byte stream, identifies the decorrelation time tau_dec, and computes the
 * effective sample size N_eff = N / (1 + 2 * sum_{tau=1}^{tau_dec} rho(tau)).
 * This corrects the noise floor used in Paper 3 Eq. (8).
 *
 * Acceptance (per spec): rho(1) < 0.01, tau_dec <= 3, N_eff > 0.95 N.
 *
 * Positive control: run with a low K (e.g. K=0.5, Arnold-tongue / quasi-
 * periodic) which is NOT mixing and MUST show large rho(1) -- this proves the
 * apparatus detects temporal dependence when present.
 *
 * Document ID:  MCL-LAGAUTOCORR-2026-0526-v6-0-0
 * Version:      6.0.0
 * Date:         June 3, 2026
 * Author:       Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:      madeeh.chaotic.lock@gmail.com
 * ORCID:        https://orcid.org/0009-0002-8562-8325
 * Engine:       mcl_core.hpp (frozen, MD5 241db79ecf8a42897eb9a8399cf37929).
 * Build:  g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
 *             -Wsign-conversion -Werror -DMCL_UNSAFE_ALLOW_INVALID \
 *             mcl_lag_autocorrelation_test.cpp -o mcl_lag_autocorrelation_test
 *
 * License:      PolyForm Noncommercial 1.0.0.  Patent Pending.
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 *
 * NO WARRANTY: THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED. THE AUTHOR IS NOT LIABLE FOR ANY CLAIM OR DAMAGES.
 * ============================================================================
 */
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <vector>
#include <string>
#include "mcl_core.hpp"

namespace {
constexpr const char* DOC_ID  = "MCL-LAGAUTOCORR-2026-0526-v6-0-0";
constexpr const char* DOC_VER = "6.0.0";

void print_help() {
    std::printf("MCL (Madeeh Chaotic Lock) - Lag Autocorrelation Decay Test\n");
    std::printf("DOC_ID %s  DOC_VER %s\n", DOC_ID, DOC_VER);
    std::printf("Usage: mcl_lag_autocorrelation_test "
                "[--p P] [--q Q] [--K K] [--N N] [--maxlag L] [--seed S]\n");
    std::printf("Defaults: p=3 q=5 K=12 N=10000000 maxlag=100 seed=12345678901234\n");
    std::printf("Output: rho(1..5), tau_dec, N_eff, N_eff/N, PASS/FAIL.\n");
}
}  // namespace

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);

    int64_t  p      = 3;
    int64_t  q      = 5;
    double   K      = 12.0;
    int64_t  N      = 10000000;
    int64_t  maxlag = 100;
    uint64_t seed   = 12345678901234ULL;
    int64_t  synth_period = 0;  // >0 => synthetic sine control (validates estimator)

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--help" || a == "-h") { print_help(); return 0; }
        else if (a == "--p"      && i + 1 < argc) { p      = std::atoll(argv[++i]); }
        else if (a == "--q"      && i + 1 < argc) { q      = std::atoll(argv[++i]); }
        else if (a == "--K"      && i + 1 < argc) { K      = std::atof (argv[++i]); }
        else if (a == "--N"      && i + 1 < argc) { N      = std::atoll(argv[++i]); }
        else if (a == "--maxlag" && i + 1 < argc) { maxlag = std::atoll(argv[++i]); }
        else if (a == "--seed"   && i + 1 < argc) { seed   = static_cast<uint64_t>(std::strtoull(argv[++i], nullptr, 10)); }
        else if (a == "--synth-period" && i + 1 < argc) { synth_period = std::atoll(argv[++i]); }
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 1; }
    }
    if (N < 2 || maxlag < 1 || maxlag >= N) {
        std::fprintf(stderr, "FATAL: need N>=2, 1<=maxlag<N\n"); return 1;
    }

    // --- generate the byte stream ---
    std::vector<uint8_t> x(static_cast<size_t>(N));
    if (synth_period > 0) {
        // POSITIVE CONTROL: quantized sine of known period. The autocorrelation
        // estimator MUST recover rho(1) ~ cos(2*pi/period). This validates the
        // measurement apparatus independently of MCL.
        const double tp = 6.283185307179586 / static_cast<double>(synth_period);
        for (int64_t t = 0; t < N; ++t) {
            const double v = 127.5 + 127.5 * std::sin(tp * static_cast<double>(t));
            long ri = std::lround(v);
            if (ri < 0)   ri = 0;
            if (ri > 255) ri = 255;
            x[static_cast<size_t>(t)] = static_cast<uint8_t>(ri);
        }
    } else {
        MCL_T2 eng(seed, p, q, K);
        eng.gen_bytes(x.data(), N);
        eng.erase();
    }

    // --- mean ---
    long double s = 0.0L;
    for (int64_t t = 0; t < N; ++t) s += static_cast<long double>(x[static_cast<size_t>(t)]);
    const long double mu = s / static_cast<long double>(N);

    // --- c0 = variance ---
    long double c0 = 0.0L;
    for (int64_t t = 0; t < N; ++t) {
        const long double d = static_cast<long double>(x[static_cast<size_t>(t)]) - mu;
        c0 += d * d;
    }
    c0 /= static_cast<long double>(N);
    if (c0 <= 0.0L) { std::fprintf(stderr, "FATAL: zero variance\n"); return 1; }

    // --- rho(tau) for tau in [1, maxlag] ---
    std::vector<double> rho(static_cast<size_t>(maxlag) + 1U, 0.0);
    for (int64_t tau = 1; tau <= maxlag; ++tau) {
        const int64_t M = N - tau;
        long double c = 0.0L;
        for (int64_t t = 0; t < M; ++t) {
            const long double d1 = static_cast<long double>(x[static_cast<size_t>(t)])       - mu;
            const long double d2 = static_cast<long double>(x[static_cast<size_t>(t + tau)]) - mu;
            c += d1 * d2;
        }
        c /= static_cast<long double>(M);
        rho[static_cast<size_t>(tau)] = static_cast<double>(c / c0);
    }

    // --- noise floor, tau_dec, N_eff ---
    const double noise_floor = 1.0 / std::sqrt(static_cast<double>(N));
    int64_t    tau_dec = maxlag;
    long double sum_rho = 0.0L;
    for (int64_t tau = 1; tau <= maxlag; ++tau) {
        sum_rho += static_cast<long double>(rho[static_cast<size_t>(tau)]);
        if (std::fabs(rho[static_cast<size_t>(tau)]) < noise_floor) { tau_dec = tau; break; }
    }
    long double denom = 1.0L + 2.0L * sum_rho;
    if (denom < 0.01L) denom = 0.01L;  // guard against pathological controls
    const double n_eff   = static_cast<double>(static_cast<long double>(N) / denom);
    const double n_ratio = n_eff / static_cast<double>(N);

    const double rho1 = rho[static_cast<size_t>(1)];
    const bool pass = (std::fabs(rho1) < 0.01) && (tau_dec <= 3) && (n_ratio > 0.95);

    // --- report ---
    std::printf("# MCL lag-autocorrelation  DOC_ID %s\n", DOC_ID);
    std::printf("p=%lld q=%lld K=%.6f N=%lld maxlag=%lld seed=%llu\n",
                static_cast<long long>(p), static_cast<long long>(q), K,
                static_cast<long long>(N), static_cast<long long>(maxlag),
                static_cast<unsigned long long>(seed));
    std::printf("noise_floor(1/sqrtN) = %.6e\n", noise_floor);
    for (int64_t tau = 1; tau <= 5 && tau <= maxlag; ++tau)
        std::printf("rho(%lld) = % .6e\n", static_cast<long long>(tau),
                    rho[static_cast<size_t>(tau)]);
    std::printf("tau_dec = %lld\n", static_cast<long long>(tau_dec));
    std::printf("N_eff = %.4e   N_eff/N = %.6f\n", n_eff, n_ratio);
    std::printf("VERDICT: %s  (rho1<0.01 & tau_dec<=3 & N_eff>0.95N)\n",
                pass ? "PASS" : "FAIL");
    return 0;
}
