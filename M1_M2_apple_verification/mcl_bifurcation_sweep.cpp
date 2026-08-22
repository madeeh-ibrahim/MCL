// mcl_bifurcation_sweep.cpp — Bifurcation diagnostic data generator for
// Paper 1 Figure 2 (coarse step-0.25 panel + fine step-0.005 sub-6 sweep).
//
// Protocol (Paper 1 §3.2.4): for each K, iterate from the working seed for
// 5,000 burn-in steps; collect 200 theta1 samples (range + distinct phase
// buckets); independently measure lambda_max by the QR method at 1e5
// iterations (engine compute_lyapunov, which applies its own 10,000 burn-in).
// Classification: CHAOTIC (buckets>3 and lmax>0.05), QUASI-PERIODIC
// (buckets>3, lmax<=0.05), PERIODIC (buckets<=3), DIVERGED (non-finite).
//
// Usage: mcl_bifurcation_sweep coarse|fine
//   coarse: K = 0.50 .. 20.00 step 0.25   (79 values, main panels)
//   fine  : K = 0.50 ..  6.00 step 0.005  (1101 values, inset panels)
// Output: CSV to stdout — K,lmax,l2,th_min,th_max,buckets,class
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <set>

int main(int argc, char** argv) {
    const uint64_t SEED = 12345678901234ULL;
    const int64_t p = 3, q = 5;
    bool fine = (argc > 1 && std::strcmp(argv[1], "fine") == 0);
    double K0 = 0.50, K1 = fine ? 6.00 : 20.00, dK = fine ? 0.005 : 0.25;

    std::printf("# MCL bifurcation sweep (%s) — Doc ID MCL-BIFSWEEP-2026-0719-001\n",
                fine ? "fine step-0.005" : "coarse step-0.25");
    std::printf("# engine v6.0.0 frozen copy, seed %llu, (p,q)=(3,5), QR 1e5 iters\n",
                (unsigned long long)SEED);
    std::printf("K,lmax,l2,th_min,th_max,buckets,class\n");

    int steps = (int)std::llround((K1 - K0) / dK);
    for (int i = 0; i <= steps; i++) {
        double K = K0 + dK * i;
        double t1, t2;
        mcl_init_state(SEED, t1, t2);
        for (int n = 0; n < 5000; n++) mcl_iterate_raw(t1, t2, p, q, K);
        double thmin = 1e9, thmax = -1e9;
        std::set<long> buckets;
        bool finite = true;
        for (int n = 0; n < 200; n++) {
            mcl_iterate_raw(t1, t2, p, q, K);
            if (!std::isfinite(t1) || !std::isfinite(t2)) { finite = false; break; }
            if (t1 < thmin) thmin = t1;
            if (t1 > thmax) thmax = t1;
            buckets.insert(std::lround(t1 * 1000.0)); // 1e-3 phase buckets
        }
        if (!finite) { std::printf("%.3f,nan,nan,nan,nan,0,DIVERGED\n", K); continue; }
        LyapResult lr = compute_lyapunov(SEED, p, q, K, 100000);
        const char* cls = (buckets.size() <= 3) ? "PERIODIC"
                         : (lr.l1 > 0.05 ? "CHAOTIC" : "QUASI-PERIODIC");
        std::printf("%.3f,%.6f,%.6f,%.6f,%.6f,%zu,%s\n",
                    K, lr.l1, lr.l2, thmin, thmax, buckets.size(), cls);
    }
    return 0;
}
