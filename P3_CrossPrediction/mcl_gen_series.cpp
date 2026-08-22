/*
 * mcl_gen_series.cpp — series generator for the Paper-3 cross-prediction test
 * Doc ID: MCL-P3-XPRED-2026-0822-001
 * ---------------------------------------------------------------------------
 * Emits, for one (p,q,K) configuration, four aligned series so that a single
 * predictor can be applied to each and the R^2 values compared:
 *   internal : theta1 after each iteration (the dynamical state itself)
 *   raw      : the Safe-Zone byte extracted at each iteration (the output)
 *   coarse   : theta1 quantised to Q bits (precision-dependence probe)
 *   control  : a counter-based SHA-256 stream (deterministic but structureless)
 * The chaotic regime is selected by K; running below the sentinel yields a
 * non-chaotic series for contrast.
 *
 * Build: clang++ -std=c++17 -O2 -I.. mcl_gen_series.cpp -o mcl_gen_series
 * Usage: ./mcl_gen_series <p> <q> <K> <N> <Qbits> > series.tsv
 */
#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

int main(int argc, char** argv) {
    int64_t p = argc>1? atoll(argv[1]) : 3;
    int64_t q = argc>2? atoll(argv[2]) : 5;
    double  K = argc>3? atof (argv[3]) : 12.0;
    long    N = argc>4? atol (argv[4]) : 20000;
    int     Q = argc>5? atoi (argv[5]) : 8;

    MCL_T2 eng(12345678901234ULL, p, q, K);          // ctor performs the burn-in
    std::printf("# p=%lld q=%lld K=%.4f N=%ld Q=%d engine=v%s\n",
                (long long)p,(long long)q,K,N,Q,MCL_VERSION_STRING);
    std::printf("theta1\ttheta2\traw\tcoarse\tcontrol\n");
    const double TWO_PI = 6.283185307179586;
    for (long i = 0; i < N; i++) {
        double th = eng.theta1(), th2 = eng.theta2();  // full state BEFORE this output
        uint8_t b  = eng.gen_byte();                  // advances one iteration
        double frac = th / TWO_PI;                    // in [0,1)
        long   qq   = (long)(frac * (double)(1L << Q));
        uint8_t ctr[8], h[32];
        for (int k=0;k<8;k++) ctr[k]=(uint8_t)((unsigned long)i>>(8*k));
        CC_SHA256(ctr,8,h);
        std::printf("%.17g\t%.17g\t%u\t%ld\t%u\n", th, th2, (unsigned)b, qq, (unsigned)h[0]);
    }
    return 0;
}
