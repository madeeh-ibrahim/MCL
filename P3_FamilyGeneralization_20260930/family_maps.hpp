// Paper 3, ت-309 (2026-09-30): the three additional coupled families of Sec. VII (Henon, logistic,
// tent) with the map parameter (a, r, mu) exposed, so that a PARAMETER change can be applied to one of
// two same-seed trajectories.  The step below reproduces CoupledHenon::iterate / CoupledLogistic::iterate /
// CoupledTent::iterate of mcl_core.hpp operation for operation (same expression order, same fmod+clamp
// confinement, same Gauss-Seidel substitution); at the engine's default parameters (a=1.4, b=0.3, r=4.0,
// tent slope 2 written as 0.5*mu with mu=2 so that the multiplier is exactly 1.0) the byte stream produced
// through the engine's own extraction (d2b, GOLD_S1/S2, DECIMATION) is asserted bit-identical to the
// engine class over 1e5 bytes at start-up (identity_check()).  Initial states and seed map are the engine's.
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>
#include "../mcl_core.hpp"

enum Family { HENON = 0, LOGISTIC = 1, TENT = 2 };
static const char* FAMILY_NAME[3] = {"henon", "logistic", "tent"};
static inline Family parse_family(const std::string& s) {
    if (s == "henon") return HENON; if (s == "logistic") return LOGISTIC; if (s == "tent") return TENT;
    std::fprintf(stderr, "unknown family '%s'\n", s.c_str()); std::exit(2);
}
struct FParams { int64_t p, q; double K; double a, b; double r; double mu; };
struct FState { double x1, y1, x2, y2; };

static inline FParams default_params(Family f, int64_t p, int64_t q) {
    FParams P{p, q, 0.0, HENON_A, HENON_B, LOGISTIC_R, 2.0};
    P.K = (f == HENON) ? HENON_K : (f == LOGISTIC ? LOGISTIC_K : TENT_K);
    return P;
}
static inline double get_param(const FParams& P, Family f) { return f == HENON ? P.a : (f == LOGISTIC ? P.r : P.mu); }
static inline void set_param(FParams& P, Family f, double v) { if (f == HENON) P.a = v; else if (f == LOGISTIC) P.r = v; else P.mu = v; }
static inline const char* param_name(Family f) { return f == HENON ? "a" : (f == LOGISTIC ? "r" : "mu"); }

static inline double confine01(double x) {           // engine: fmod + clamp, verbatim order
    x = std::fmod(x, 1.0);
    if (x <= 0.0) x += 1.0;
    if (x < 1e-10) x = 1e-10;
    if (x > 1.0 - 1e-10) x = 1.0 - 1e-10;
    return x;
}
static inline void fstep(FState& s, const FParams& P, Family f) {
    if (f == HENON) {
        double a1 = (double)P.p * s.x2 - (double)P.q * s.x1;
        double nx1 = 1.0 - P.a * s.x1 * s.x1 + s.y1 + P.K * std::sin(a1);
        double ny1 = P.b * s.x1;
        s.x1 = nx1; s.y1 = ny1;
        double a2 = (double)P.p * s.x1 - (double)P.q * s.x2;
        double nx2 = 1.0 - P.a * s.x2 * s.x2 + s.y2 + P.K * std::sin(a2);
        double ny2 = P.b * s.x2;
        s.x2 = nx2; s.y2 = ny2;
    } else if (f == LOGISTIC) {
        double a1 = (double)P.p * s.x2 - (double)P.q * s.x1;
        s.x1 = confine01(P.r * s.x1 * (1.0 - s.x1) + P.K * std::sin(a1));
        double a2 = (double)P.p * s.x1 - (double)P.q * s.x2;
        s.x2 = confine01(P.r * s.x2 * (1.0 - s.x2) + P.K * std::sin(a2));
    } else {
        double h = 0.5 * P.mu;                        // == 1.0 exactly at mu = 2 (engine: 1 - |2u - 1|)
        double a1 = (double)P.p * s.x2 - (double)P.q * s.x1;
        s.x1 = confine01(h * (1.0 - std::abs(2.0 * s.x1 - 1.0)) + P.K * std::sin(a1));
        double a2 = (double)P.p * s.x1 - (double)P.q * s.x2;
        s.x2 = confine01(h * (1.0 - std::abs(2.0 * s.x2 - 1.0)) + P.K * std::sin(a2));
    }
}
static inline FState init_state(uint64_t seed, Family f) {   // engine constructors, verbatim
    uint64_t s = hash_seed(seed); FState st{0, 0, 0, 0};
    if (f == HENON) { st.x1 = std::fmod((double)s * OMEGA_1, 1.0) * 0.5; st.y1 = 0.0; st.x2 = std::fmod((double)s * OMEGA_2, 1.0) * 0.5; st.y2 = 0.0; }
    else { st.x1 = std::fmod((double)s * OMEGA_1, 1.0) * 0.8 + 0.1; st.x2 = std::fmod((double)s * OMEGA_2, 1.0) * 0.8 + 0.1; }
    return st;
}
static inline bool escaped(const FState& s) { return !std::isfinite(s.x1) || !std::isfinite(s.x2) || std::fabs(s.x1) > 100.0 || std::fabs(s.x2) > 100.0; }
static inline double fdist(const FState& a, const FState& b, Family f) {
    double d1 = a.x1 - b.x1, d2 = a.x2 - b.x2;
    if (f == HENON) { double e1 = a.y1 - b.y1, e2 = a.y2 - b.y2; return std::sqrt(d1 * d1 + d2 * d2 + e1 * e1 + e2 * e2); }
    return std::sqrt(d1 * d1 + d2 * d2);
}
static inline uint8_t fbyte(FState& s, const FParams& P, Family f) {   // engine gen_byte(): DECIMATION steps + extraction
    for (int d = 0; d < DECIMATION; d++) fstep(s, P, f);
    uint64_t x = d2b(s.x1) ^ d2b(s.x2);
    return (uint8_t)(x >> GOLD_S1) ^ (uint8_t)(x >> GOLD_S2);
}
// Bit-identity with the engine class at default parameters: same seed, engine constructor burn-in (BURNIN
// steps) versus init_state + BURNIN fstep, then 1e5 bytes compared.
static inline void identity_check(Family f, int64_t p, int64_t q, long nbytes = 100000) {
    const uint64_t seed = 12345678901234ULL; FParams P = default_params(f, p, q);
    FState s = init_state(seed, f); for (int i = 0; i < BURNIN; i++) fstep(s, P, f);
    long bad = -1;
    if (f == HENON) { CoupledHenon g(seed, p, q); if (!g.ok()) { std::fprintf(stderr, "FATAL: engine CoupledHenon diverged in identity check\n"); std::exit(3); }
        for (long i = 0; i < nbytes; i++) if (g.gen_byte() != fbyte(s, P, f)) { bad = i; break; } }
    else if (f == LOGISTIC) { CoupledLogistic g(seed, p, q); for (long i = 0; i < nbytes; i++) if (g.gen_byte() != fbyte(s, P, f)) { bad = i; break; } }
    else { CoupledTent g(seed, p, q); for (long i = 0; i < nbytes; i++) if (g.gen_byte() != fbyte(s, P, f)) { bad = i; break; } }
    if (bad >= 0) { std::fprintf(stderr, "FATAL: fstep(%s) deviates from the engine class at byte %ld\n", FAMILY_NAME[f], bad); std::exit(3); }
    std::fprintf(stderr, "[ok] fstep(%s,(%lld,%lld)) byte stream bit-identical to the engine class over %ld bytes (%ld iterations)\n", FAMILY_NAME[f], (long long)p, (long long)q, nbytes, nbytes * (long)DECIMATION);
}
// Maximal Lyapunov exponent by Benettin renormalisation of a shadow trajectory (d0 = 1e-9 along x1), after
// `burn` common steps from the engine seed state; returns mean ln(d/d0) per step over `steps` steps.
// Cross-checks: coupled tent at mu=2 -> ln 2 within coupling corrections; logistic r=4 -> ln 2.
static inline double lyap_benettin(const FParams& P, Family f, uint64_t seed, int burn, long steps, bool* esc = nullptr, int* period = nullptr) {
    const double d0 = 1e-9; FState a = init_state(seed, f);
    for (int i = 0; i < burn; i++) fstep(a, P, f);
    if (period) { *period = 0; FState s0 = a, t = a; for (int i = 1; i <= 256; i++) { fstep(t, P, f);
            if (std::fabs(t.x1 - s0.x1) < 1e-9 && std::fabs(t.x2 - s0.x2) < 1e-9 && std::fabs(t.y1 - s0.y1) < 1e-9 && std::fabs(t.y2 - s0.y2) < 1e-9) { *period = i; break; } } }
    FState b = a; b.x1 += d0; double sum = 0; long n = 0; bool e = false;
    for (long i = 0; i < steps; i++) {
        fstep(a, P, f); fstep(b, P, f);
        if (escaped(a) || escaped(b)) { e = true; break; }
        double d = fdist(a, b, f); if (d < 1e-300) d = 1e-300;
        sum += std::log(d / d0); n++;
        double sc = d0 / d; b.x1 = a.x1 + (b.x1 - a.x1) * sc; b.x2 = a.x2 + (b.x2 - a.x2) * sc; b.y1 = a.y1 + (b.y1 - a.y1) * sc; b.y2 = a.y2 + (b.y2 - a.y2) * sc;
    }
    if (esc) *esc = e; return n ? sum / n : NAN;
}
