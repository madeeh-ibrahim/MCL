// mcl_cycle_search.cpp — Brent cycle detection on the full binary64 state of (a) the MCL map
// (engine v6.0.0, raw iterate, (3,5,12)) and (b) the Chirikov standard map K=12, from the paper's
// seed rule, capped. Reports "no cycle within cap" or (mu, lambda). Doc ID: MCL-CYCLE-SEARCH-2026-0906-001
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
struct St { double a, b; bool operator==(const St& o) const { return a == o.a && b == o.b; } };
static const double OMEGA1 = 0.6180339887498949, OMEGA2 = 1.3247179572447460, TWO_PI = 6.283185307179586;
static inline double m2pi(double x) { x = std::fmod(x, TWO_PI); if (x < 0) x += TWO_PI; return x; }
int main(int argc, char** argv) {
    int which = (argc > 1) ? std::atoi(argv[1]) : 0;   // 0 = MCL, 1 = standard map
    uint64_t seed = (argc > 2) ? std::strtoull(argv[2], nullptr, 10) : 12345678901234ULL;
    uint64_t cap = (argc > 3) ? std::strtoull(argv[3], nullptr, 10) : 2000000000ULL;
    auto f = [which](St s) { if (which == 0) { mcl_iterate_raw(s.a, s.b, 3, 5, 12.0); } else { s.b = m2pi(s.b + 12.0 * std::sin(s.a)); s.a = m2pi(s.a + s.b); } return s; };
    St x0; if (which == 0) mcl_init_state(seed, x0.a, x0.b); else { x0.a = m2pi((double)seed * OMEGA1); x0.b = m2pi((double)seed * OMEGA2); }
    uint64_t power = 1, lam = 1; St tort = x0, hare = f(x0);
    while (!(tort == hare)) {
        if (power == lam) { tort = hare; power *= 2; lam = 0; }
        hare = f(hare); lam++;
        if (power + lam > cap) { std::printf("%s seed=%llu: NO CYCLE within %llu iterations (Brent)\n", which == 0 ? "MCL(3,5,12)" : "standard map K=12", (unsigned long long)seed, (unsigned long long)cap); return 0; }
    }
    uint64_t mu = 0; tort = hare = x0; for (uint64_t i = 0; i < lam; i++) hare = f(hare);
    while (!(tort == hare)) { tort = f(tort); hare = f(hare); mu++; }
    std::printf("%s seed=%llu: tail mu=%llu cycle lambda=%llu\n", which == 0 ? "MCL(3,5,12)" : "standard map K=12", (unsigned long long)seed, (unsigned long long)mu, (unsigned long long)lam);
    return 0;
}
