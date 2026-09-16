// mcl_p1_init_convention_scan.cpp — Doc ID MCL-P1-INITCONV-2026-0909-001
//
// PURPOSE (Paper 1, Supplementary S3 note "initialization sensitivity"): the
// Supplement compared the window-start-0 byte-level chi-square under two
// initial-state derivations ("simple decimal multipliers (0.1, 0.2)" vs the
// production derivation of mcl_core.hpp) and stated that the Safe Zone
// boundary [6, 39] is identical under both. Neither value had a log. This tool
// measures the full single-extractor scan of Paper 1 §3.3 / Table 6 (Doc ID
// MCL-SAFEZONE-HOLDOUT-2026-0719-001: one iterate per sample, N = 1e8,
// byte = (mantissa >> P) & 0xFF, P in [0, 44], three streams theta1 / theta2 /
// XOR, chi-square df = 255, critical 310.46) under FOUR initial-state
// conventions, all on the same map, (p,q), K and burn-in:
//
//   A  PRODUCTION      : MCL_T2(seed) of the engine of record (hash_seed for
//                        seeds > 2^52; theta_i(0) = (s * OMEGA_i) mod 2pi;
//                        burn-in 10000). Positive control: must reproduce the
//                        archived Table 6 scan row for row.
//   A' PRODUCTION-LOCAL: the same initial state and burn-in, iterated by a
//                        local copy of MCL_T2::iterate (Eqs. 1-2). Self-check:
//                        must equal A bit for bit (validates the local stepper
//                        used for B and C).
//   B  DECIMAL-MULT    : theta_1(0) = (seed * 0.1) mod 2pi, theta_2(0) =
//                        (seed * 0.2) mod 2pi — the "decimal multipliers"
//                        convention of the historical reference code.
//   C  FIXED-ANGLES    : theta_1(0) = 0.1, theta_2(0) = 0.2 (seed-independent
//                        prototype reading of the same phrase).
//
// Engine of record mcl_core.hpp v6.0.0 (MD5 241db79ecf8a42897eb9a8399cf37929);
// (p,q) = (3,5), K = 12.0, burn-in 10000, seed 12345678901234, N = 1e8.
// BUILD: c++ -O3 -std=c++17 -ffp-contract=off \
//            -o mcl_p1_init_convention_scan mcl_p1_init_convention_scan.cpp -lm
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>

static const double CRIT255 = 310.46;
static const int PMAX = 44;
static const uint64_t MANT = 0x000FFFFFFFFFFFFFULL;

static inline void step_f64(double &t1, double &t2, double p, double q, double kc) {
    double a1 = p * t2 - q * t1;
    t1 = mod2pi(t1 + OMEGA_1 + kc * std::sin(a1));
    double a2 = p * t1 - q * t2;
    t2 = mod2pi(t2 + OMEGA_2 + kc * std::sin(a2));
}

struct Scan {
    std::vector<std::vector<std::vector<int64_t>>> H; // [stream][P][byte]
    double chi2[3][PMAX + 1];
    Scan() : H(3, std::vector<std::vector<int64_t>>(PMAX + 1, std::vector<int64_t>(256, 0))) {}
    inline void add(uint64_t m1, uint64_t m2) {
        uint64_t mx = m1 ^ m2;
        for (int p = 0; p <= PMAX; p++) {
            H[0][p][(m1 >> p) & 0xFF]++;
            H[1][p][(m2 >> p) & 0xFF]++;
            H[2][p][(mx >> p) & 0xFF]++;
        }
    }
    void finish(int64_t N) {
        double E = (double)N / 256.0;
        for (int s = 0; s < 3; s++)
            for (int p = 0; p <= PMAX; p++) {
                double c = 0.0;
                for (int b = 0; b < 256; b++) { double d = (double)H[s][p][b] - E; c += d * d / E; }
                chi2[s][p] = c;
            }
    }
};

static int zone(const double* c, int& lo, int& hi) {
    int best_lo = -1, best_len = 0, cur_lo = -1, cur_len = 0;
    for (int p = 0; p <= PMAX; p++) {
        if (c[p] < CRIT255) { if (cur_lo < 0) cur_lo = p; cur_len++; if (cur_len > best_len) { best_len = cur_len; best_lo = cur_lo; } }
        else { cur_lo = -1; cur_len = 0; }
    }
    lo = best_lo; hi = best_lo + best_len - 1; return best_len;
}

static void report(const char* name, const Scan& S) {
    std::printf("%s\n", name);
    std::printf("  P  |     theta1      |     theta2      |       XOR       | XOR verdict\n");
    std::printf("-----|-----------------|-----------------|-----------------|------------\n");
    for (int p = 0; p <= PMAX; p++)
        std::printf(" %3d | %15.2f | %15.2f | %15.2f | %s\n", p, S.chi2[0][p], S.chi2[1][p], S.chi2[2][p],
                    S.chi2[2][p] < CRIT255 ? "PASS" : "FAIL");
    int lo, hi, w = zone(S.chi2[2], lo, hi), lo1, hi1, w1 = zone(S.chi2[0], lo1, hi1), lo2, hi2, w2 = zone(S.chi2[1], lo2, hi2);
    std::printf("  XOR Safe Zone (byte-window start positions): [%d, %d] = %d positions\n", lo, hi, w);
    std::printf("  theta1 zone: [%d, %d] = %d   theta2 zone: [%d, %d] = %d\n", lo1, hi1, w1, lo2, hi2, w2);
    std::string fails;
    for (int p = 0; p <= PMAX; p++) if (S.chi2[2][p] >= CRIT255) fails += " " + std::to_string(p);
    std::printf("  XOR failing starts:%s\n\n", fails.c_str());
}

int main(int argc, char** argv) {
    uint64_t seed = (argc > 1) ? strtoull(argv[1], nullptr, 10) : 12345678901234ULL;
    int64_t N = (argc > 2) ? strtoll(argv[2], nullptr, 10) : 100000000LL;
    const int64_t p = 3, q = 5; const double K = 12.0;
    std::printf("==============================================================\n");
    std::printf(" MCL PAPER 1 — SINGLE-EXTRACTOR SCAN UNDER FOUR INITIAL-STATE CONVENTIONS\n");
    std::printf(" Doc ID: MCL-P1-INITCONV-2026-0909-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen), (p,q)=(3,5), K=12, burn-in %d, seed %llu, N = %lld\n", BURNIN, (unsigned long long)seed, (long long)N);
    std::printf(" Protocol: one iterate per sample; byte = (mantissa >> P) & 0xFF, P in [0,44]; chi2 df=255, crit %.2f\n\n", CRIT255);

    Scan SA, SA2, SB, SC;
    { // A: production engine
        MCL_T2 eng(seed, p, q, K);
        for (int64_t i = 0; i < N; i++) { eng.iterate(); SA.add(d2b(eng.theta1()) & MANT, d2b(eng.theta2()) & MANT); }
        SA.finish(N);
    }
    { // A': production initial state, local stepper (self-check of the stepper)
        uint64_t s = hash_seed(seed);
        double t1 = mod2pi((double)s * OMEGA_1), t2 = mod2pi((double)s * OMEGA_2);
        for (int i = 0; i < BURNIN; i++) step_f64(t1, t2, (double)p, (double)q, K);
        for (int64_t i = 0; i < N; i++) { step_f64(t1, t2, (double)p, (double)q, K); SA2.add(d2b(t1) & MANT, d2b(t2) & MANT); }
        SA2.finish(N);
    }
    { // B: decimal multipliers
        double t1 = mod2pi((double)seed * 0.1), t2 = mod2pi((double)seed * 0.2);
        std::printf(" B initial state: theta1(0) = %.17g  theta2(0) = %.17g\n", t1, t2);
        for (int i = 0; i < BURNIN; i++) step_f64(t1, t2, (double)p, (double)q, K);
        for (int64_t i = 0; i < N; i++) { step_f64(t1, t2, (double)p, (double)q, K); SB.add(d2b(t1) & MANT, d2b(t2) & MANT); }
        SB.finish(N);
    }
    { // C: fixed decimal angles
        double t1 = 0.1, t2 = 0.2;
        std::printf(" C initial state: theta1(0) = %.17g  theta2(0) = %.17g\n\n", t1, t2);
        for (int i = 0; i < BURNIN; i++) step_f64(t1, t2, (double)p, (double)q, K);
        for (int64_t i = 0; i < N; i++) { step_f64(t1, t2, (double)p, (double)q, K); SC.add(d2b(t1) & MANT, d2b(t2) & MANT); }
        SC.finish(N);
    }
    report("A. PRODUCTION (MCL_T2 of the engine of record) — positive control vs Table 6 / MCL-SAFEZONE-HOLDOUT-2026-0719-001", SA);
    int ndiff = 0;
    for (int s = 0; s < 3; s++) for (int pp = 0; pp <= PMAX; pp++) if (SA.chi2[s][pp] != SA2.chi2[s][pp]) ndiff++;
    std::printf("A'. PRODUCTION-LOCAL stepper self-check: %d of %d chi2 values differ from A (%s)\n\n", ndiff, 3 * (PMAX + 1), ndiff == 0 ? "IDENTICAL" : "MISMATCH");
    report("B. DECIMAL MULTIPLIERS theta_i(0) = (seed * {0.1, 0.2}) mod 2pi", SB);
    report("C. FIXED DECIMAL ANGLES theta(0) = (0.1, 0.2)", SC);
    std::printf("SUMMARY (window start 0, byte-level chi2):\n");
    std::printf("  convention |     theta1      |     theta2      |       XOR\n");
    std::printf("  A          | %15.2f | %15.2f | %15.2f\n", SA.chi2[0][0], SA.chi2[1][0], SA.chi2[2][0]);
    std::printf("  B          | %15.2f | %15.2f | %15.2f\n", SB.chi2[0][0], SB.chi2[1][0], SB.chi2[2][0]);
    std::printf("  C          | %15.2f | %15.2f | %15.2f\n", SC.chi2[0][0], SC.chi2[1][0], SC.chi2[2][0]);
    int same = 0;
    for (int pp = 0; pp <= PMAX; pp++) {
        bool a = SA.chi2[2][pp] < CRIT255, b = SB.chi2[2][pp] < CRIT255, c = SC.chi2[2][pp] < CRIT255;
        if (a == b && b == c) same++;
    }
    std::printf("  XOR pass/fail classification identical across A, B, C at %d of %d start positions\n", same, PMAX + 1);
    return 0;
}
