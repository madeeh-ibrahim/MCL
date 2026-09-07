// mcl_xor_control.cpp — control for the XOR-healing step (Paper 1 §6.2, CS&F revision 2026-09-05):
// does XOR of ANY two binary64 streams widen the byte-level Safe Zone to ~34, or only MCL's coupled pair?
// Same §3.3 protocol: N samples after 10,000 burn-in, byte=(mantissa>>P)&0xFF, P in [0,44], chi2 df=255 vs 310.46.
// Cases: 0 = standard map K=12: theta XOR p (same orbit)
//        1 = two INDEPENDENT standard maps (seeds s and s^0x5DEECE66D...): theta_a XOR theta_b
//        2 = Henon: x XOR y (same orbit)
//        3 = two independent Henon orbits: x_a XOR x_b
//        4 = MCL (3,5,12) theta1 XOR theta2 — positive control, must give [6,39]=34 (uses engine v6.0.0)
// Doc ID: MCL-XOR-CONTROL-2026-0905-001
// Build: c++ -O3 -std=c++17 -o mcl_xor_control mcl_xor_control.cpp -lm
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
static const double CRIT255 = 310.46; static const int PMAX = 44; static const int BURN = 10000;
static const uint64_t MANT = 0x000FFFFFFFFFFFFFULL;
static const double OMEGA1 = 0.6180339887498949, OMEGA2 = 1.3247179572447460, TWO_PI = 6.283185307179586;
static inline uint64_t bits(double x) { uint64_t u; std::memcpy(&u, &x, 8); return u; }
static inline double m2pi(double x) { x = std::fmod(x, TWO_PI); if (x < 0) x += TWO_PI; return x; }
static inline double m1(double x) { x = std::fmod(x, 1.0); if (x < 0) x += 1.0; return x; }
static int zone(const std::vector<double>& c, int& lo, int& hi) { int bl=-1,bn=0,cl=-1,cn=0; for (int p=0;p<=PMAX;p++){ if(c[(size_t)p]<CRIT255){ if(cl<0)cl=p; cn++; if(cn>bn){bn=cn;bl=cl;} } else {cl=-1;cn=0;} } lo=bl; hi=bl+bn-1; return bn; }
struct SM { double th, p; void init(uint64_t s){ th=m2pi((double)s*OMEGA1); p=m2pi((double)s*OMEGA2);} void step(){ p=m2pi(p+12.0*std::sin(th)); th=m2pi(th+p);} };
struct HN { double x, y; void init(uint64_t s){ x=0.5*m1((double)s*OMEGA1)-0.25; y=0.2*m1((double)s*OMEGA2)-0.1;} void step(){ double nx=1.0-1.4*x*x+y; y=0.3*x; x=nx;} };
int main(int argc, char** argv) {
    int cs = (argc > 1) ? std::atoi(argv[1]) : 0;
    uint64_t seed = (argc > 2) ? std::strtoull(argv[2], nullptr, 10) : 12345678901234ULL;
    int64_t N = (argc > 3) ? std::strtoll(argv[3], nullptr, 10) : 100000000LL;
    uint64_t seed2 = seed ^ 0x5DEECE66DULL;
    const char* names[5] = {"standard map theta XOR p (same orbit)", "two independent standard maps theta_a XOR theta_b", "Henon x XOR y (same orbit)", "two independent Henon x_a XOR x_b", "MCL theta1 XOR theta2 (positive control, engine v6.0.0)"};
    std::printf("XOR CONTROL | Doc ID MCL-XOR-CONTROL-2026-0905-001 | case %d: %s | seed %llu (second seed %llu) | N=%lld\n", cs, names[cs], (unsigned long long)seed, (unsigned long long)seed2, (long long)N);
    std::vector<std::vector<int64_t>> H((size_t)PMAX + 1, std::vector<int64_t>(256, 0));
    SM a, b; HN ha, hb; a.init(seed); b.init(seed2); ha.init(seed); hb.init(seed2);
    for (int i = 0; i < BURN; i++) { a.step(); b.step(); ha.step(); hb.step(); }
    if (cs == 4) {
        MCL_T2 eng(seed, 3, 5, 12.0);
        for (int64_t i = 0; i < N; i++) { eng.iterate(); uint64_t m = (d2b(eng.theta1()) ^ d2b(eng.theta2())) & MANT; for (int p = 0; p <= PMAX; p++) H[(size_t)p][(m >> p) & 0xFF]++; }
    } else {
        for (int64_t i = 0; i < N; i++) {
            uint64_t m;
            if (cs == 0) { a.step(); m = (bits(a.th) ^ bits(a.p)) & MANT; }
            else if (cs == 1) { a.step(); b.step(); m = (bits(a.th) ^ bits(b.th)) & MANT; }
            else if (cs == 2) { ha.step(); m = (bits(ha.x) ^ bits(ha.y)) & MANT; }
            else { ha.step(); hb.step(); m = (bits(ha.x) ^ bits(hb.x)) & MANT; }
            for (int p = 0; p <= PMAX; p++) H[(size_t)p][(m >> p) & 0xFF]++;
        }
    }
    double E = (double)N / 256.0; std::vector<double> c((size_t)PMAX + 1, 0.0);
    std::printf("   P |          chi2 | verdict\n");
    for (int p = 0; p <= PMAX; p++) { double s = 0; for (int k = 0; k < 256; k++) { double d = (double)H[(size_t)p][(size_t)k] - E; s += d * d / E; } c[(size_t)p] = s; std::printf(" %3d | %13.2f | %s\n", p, s, s < CRIT255 ? "PASS" : "FAIL"); }
    int lo, hi, w = zone(c, lo, hi); std::printf("  => XOR Safe Zone: [%d, %d] = %d positions\n", lo, hi, w); return 0;
}
