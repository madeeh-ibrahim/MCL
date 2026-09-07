// mcl_thirdmap_safezone.cpp — Paper 1 (CS&F revision, 2026-09-05), item د-9:
// apply the §3.3 byte-level Safe-Zone protocol, UNCHANGED, to reference maps
// other than MCL, so the tripartite mantissa structure is shown on more than
// two systems. No MCL engine is involved: each map is iterated in IEEE 754
// binary64, one sample per iteration after a 10,000-step burn-in, and for every
// window start position P in [0,44] the byte (mantissa >> P) & 0xFF is
// histogrammed; chi2 (df=255) vs crit(alpha=0.01)=310.46; the Safe Zone is the
// longest contiguous run of passing start positions (same rule as
// mcl_safezone_holdout.cpp, Doc ID MCL-SAFEZONE-HOLDOUT-2026-0719-001).
//
// Maps:  0 = logistic x' = 4x(1-x)            (POSITIVE CONTROL: paper reports [19,31] = 13)
//        1 = Chirikov standard map, K = 12:   p' = p + K sin(theta) mod 2pi ; theta' = theta + p' mod 2pi
//            (streams: theta, p)   — a torus map like MCL, but uncoupled and single-degree-of-freedom
//        2 = Henon a=1.4, b=0.3:   x' = 1 - a x^2 + y ; y' = b x   (streams: x, y)
//        3 = logistic x' = 3.99x(1-x)   (the r used by mcl_generality.cpp)
// Initial conditions derive from the seed exactly as MCL does: (seed * omega) mod range,
// omega_1 = phi-1, omega_2 = plastic constant (mcl_core.hpp constants).
//
// Doc ID: MCL-THIRDMAP-SAFEZONE-2026-0905-001
// Build: c++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -o mcl_thirdmap_safezone mcl_thirdmap_safezone.cpp -lm
// Usage: mcl_thirdmap_safezone <map 0|1|2> <seed> [N=1e8]
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include "mcl_core.hpp"   // map 4 positive control only

static const double CRIT255 = 310.46;
static const int PMAX = 44;
static const int BURN = 10000;
static const uint64_t MANT = 0x000FFFFFFFFFFFFFULL;
static const double OMEGA1 = 0.6180339887498949;   // phi - 1
static const double OMEGA2 = 1.3247179572447460;   // plastic constant
static const double TWO_PI = 6.283185307179586;

static inline uint64_t bits_of(double x) { uint64_t u; std::memcpy(&u, &x, 8); return u; }
static inline double m2pi(double x) { x = std::fmod(x, TWO_PI); if (x < 0) x += TWO_PI; return x; }
static inline double mod1(double x)   { x = std::fmod(x, 1.0);    if (x < 0) x += 1.0;    return x; }

static int zone(const std::vector<double>& chi2, int& lo, int& hi) {
    int best_lo = -1, best_len = 0, cur_lo = -1, cur_len = 0;
    for (int p = 0; p <= PMAX; p++) {
        if (chi2[(size_t)p] < CRIT255) { if (cur_lo < 0) cur_lo = p; cur_len++;
            if (cur_len > best_len) { best_len = cur_len; best_lo = cur_lo; } }
        else { cur_lo = -1; cur_len = 0; }
    }
    lo = best_lo; hi = best_lo + best_len - 1; return best_len;
}

int main(int argc, char** argv) {
    int map = (argc > 1) ? std::atoi(argv[1]) : 0;
    uint64_t seed = (argc > 2) ? std::strtoull(argv[2], nullptr, 10) : 12345678901234ULL;
    int64_t N = (argc > 3) ? std::strtoll(argv[3], nullptr, 10) : 100000000LL;
    double x0_explicit = (argc > 4) ? std::atof(argv[4]) : -1.0;   // logistic maps only
    const char* names[5] = {"logistic r=4 (control)", "Chirikov standard map K=12", "Henon a=1.4 b=0.3", "logistic r=3.99", "MCL (3,5,12) theta1/theta2 via engine v6.0.0 (positive control)"};
    const char* streams[5][2] = {{"x", ""}, {"theta", "p"}, {"x", "y"}, {"x", ""}, {"theta1", "theta2"}};
    int ns = (map == 0 || map == 3) ? 1 : 2;

    std::printf("==============================================================\n");
    std::printf(" THIRD-MAP SAFE-ZONE SCAN (Paper 1 §3.3 byte-level protocol, unchanged)\n");
    std::printf(" Doc ID: MCL-THIRDMAP-SAFEZONE-2026-0905-001\n");
    std::printf(" Map: %s | seed %llu | N = %lld | burn-in %d | binary64, Apple libm | x0 %s\n",
                names[map], (unsigned long long)seed, (long long)N, BURN, x0_explicit > 0 ? argv[4] : "from seed");
    std::printf(" Byte = (mantissa >> P) & 0xFF, P in [0,%d]; chi2 df=255, crit(0.01)=%.2f\n", PMAX, CRIT255);
    std::printf("==============================================================\n\n");

    std::vector<std::vector<std::vector<int64_t>>> H(
        (size_t)ns, std::vector<std::vector<int64_t>>((size_t)PMAX + 1, std::vector<int64_t>(256, 0)));

    double a = 0, b = 0;
    if (map == 0 || map == 3) { a = (x0_explicit > 0) ? x0_explicit : 0.05 + 0.9 * mod1((double)seed * OMEGA1); }
    else if (map == 1) { a = m2pi((double)seed * OMEGA1); b = m2pi((double)seed * OMEGA2); }
    else { a = 0.5 * mod1((double)seed * OMEGA1) - 0.25; b = 0.2 * mod1((double)seed * OMEGA2) - 0.1; }

    auto step = [&](void) {
        if (map == 0) { a = 4.0 * a * (1.0 - a); }
        else if (map == 3) { a = 3.99 * a * (1.0 - a); }
        else if (map == 1) { b = m2pi(b + 12.0 * std::sin(a)); a = m2pi(a + b); }
        else { double x = 1.0 - 1.4 * a * a + b; b = 0.3 * a; a = x; }
    };
    MCL_T2* eng = (map == 4) ? new MCL_T2(seed, 3, 5, 12.0) : nullptr;   // engine applies its own BURNIN
    if (map != 4) for (int i = 0; i < BURN; i++) step();
    for (int64_t i = 0; i < N; i++) {
        if (map == 4) { eng->iterate(); a = eng->theta1(); b = eng->theta2(); } else step();
        uint64_t m0 = bits_of(a) & MANT;
        for (int p = 0; p <= PMAX; p++) H[0][(size_t)p][(m0 >> p) & 0xFF]++;
        if (ns == 2) { uint64_t m1 = bits_of(b) & MANT;
            for (int p = 0; p <= PMAX; p++) H[1][(size_t)p][(m1 >> p) & 0xFF]++; }
    }
    if (!std::isfinite(a)) { std::printf("DIVERGED\n"); return 1; }

    double E = (double)N / 256.0;
    for (int s = 0; s < ns; s++) {
        std::vector<double> chi2((size_t)PMAX + 1, 0.0);
        for (int p = 0; p <= PMAX; p++) { double c = 0;
            for (int k = 0; k < 256; k++) { double d = (double)H[(size_t)s][(size_t)p][(size_t)k] - E; c += d * d / E; }
            chi2[(size_t)p] = c; }
        std::printf("Stream %s:\n   P |          chi2 | verdict\n-----|---------------|--------\n", streams[map][s]);
        for (int p = 0; p <= PMAX; p++)
            std::printf(" %3d | %13.2f | %s\n", p, chi2[(size_t)p], chi2[(size_t)p] < CRIT255 ? "PASS" : "FAIL");
        int lo, hi, w = zone(chi2, lo, hi);
        std::printf("  => Safe Zone (byte-window start positions) for %s: [%d, %d] = %d positions\n\n",
                    streams[map][s], lo, hi, w);
    }
    return 0;
}
