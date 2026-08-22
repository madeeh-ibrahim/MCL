// mcl_perbit_msb_flank.cpp — Per-bit chi-square (df=1) over the XOR-mixed
// mantissa stream, all 52 positions, with validation against the published
// Table-8 values of Paper 1 (which pins the extraction protocol).
//
// Protocol (Paper 1 §3.3 / Tech Ref §4.5-4.6):
//   engine  : mcl_core.hpp v6.0.0 (frozen Apple-verification copy)
//   config  : MCL_T2, seed 12345678901234, (p,q)=(3,5), K=12
//   sampling: one sample per production iterate() (no decimation),
//             constructor burn-in 10,000
//   sample  : x = (d2b(theta1) XOR d2b(theta2)) & 0xFFFFFFFFFFFFF  (52-bit)
//   N       : 1e8 samples
//   chi2    : df=1, (2*ones - N)^2 / N ; nominal crit 3.841 (alpha=0.05),
//             Bonferroni family-wise crit chi2_{0.05/52}(1) = 10.90
//
// Purpose: close the Table-8 gap (bits 42-46 unreported) demanded by the
// 2026-07-19 deep audit; validation = exact reproduction of the 16 published
// per-bit values before the new values are cited.
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstdlib>

int main(int argc, char** argv) {
    const int64_t N = 100000000LL;
    const uint64_t SEED = 12345678901234ULL;

    std::printf("==============================================================\n");
    std::printf(" MCL PER-BIT CHI-SQUARE — FULL 52-POSITION XOR TABLE\n");
    std::printf(" Doc ID: MCL-PERBIT-MSBFLANK-2026-0719-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen M1_M2_apple_verification copy)\n");
    std::printf(" Config: seed %llu, (p,q)=(3,5), K=12, burn-in 10000\n", (unsigned long long)SEED);
    std::printf(" N = %lld XOR-mixed mantissa samples (one per iterate())\n", (long long)N);
    std::printf("==============================================================\n\n");

    int stride = (argc > 1) ? std::atoi(argv[1]) : 1;
    std::printf(" stride (iterations per sample) = %d\n\n", stride);
    MCL_T2 eng(SEED, 3, 5, 12.0);
    static int64_t ones[52] = {0};

    for (int64_t i = 0; i < N; i++) {
        for (int d = 0; d < stride; d++) eng.iterate();
        uint64_t x = (d2b(eng.theta1()) ^ d2b(eng.theta2())) & 0x000FFFFFFFFFFFFFULL;
        for (int b = 0; b < 52; b++) ones[b] += (int64_t)((x >> b) & 1ULL);
    }

    // Published Table-8 / Tech-Ref values (bit -> chi2); -1 = unpublished
    double published[52];
    for (int b = 0; b < 52; b++) published[b] = -1.0;
    published[0]  = 37721027.0;  published[1]  = 11448581.0;
    published[5]  = 242.412;     published[6]  = 18.003;
    published[7]  = 0.149;       published[8]  = 0.053;
    published[17] = 0.486;       published[27] = 2.101;
    published[38] = 0.012;       published[39] = 0.010;
    published[40] = 0.358;       published[41] = 7.484;
    published[42] = 0.771;       published[43] = 0.395;
    published[46] = 0.000;       // Tech Ref v2.1.9 table only
    published[47] = 35.748;      published[51] = 584587.0;

    std::printf(" bit |        ones |  chi2(df=1) | vs published | match\n");
    std::printf("-----|-------------|-------------|--------------|------\n");
    int mismatches = 0, checked = 0;
    for (int b = 0; b < 52; b++) {
        double diff = 2.0 * (double)ones[b] - (double)N;
        double chi2 = diff * diff / (double)N;
        char verdict[16] = "   - ";
        if (published[b] >= 0.0) {
            checked++;
            double tol = (published[b] > 1000.0) ? 1.0 : 0.0006;
            bool ok = std::fabs(chi2 - published[b]) <= tol;
            if (!ok) mismatches++;
            std::snprintf(verdict, sizeof verdict, "%s", ok ? "MATCH" : "***DIFF***");
            std::printf(" %3d | %11lld | %11.3f | %12.3f | %s\n",
                        b, (long long)ones[b], chi2, published[b], verdict);
        } else {
            std::printf(" %3d | %11lld | %11.3f |            - | %s\n",
                        b, (long long)ones[b], chi2, verdict);
        }
    }
    std::printf("\n Validation: %d published values checked, %d mismatches.\n", checked, mismatches);
    std::printf(" Thresholds: nominal 3.841 (alpha=0.05, df=1); Bonferroni 10.90 (0.05/52).\n");
    std::printf(" %s\n", mismatches == 0 ?
        "PROTOCOL REPRODUCTION: EXACT — new values (bits 42-46) are citable." :
        "PROTOCOL REPRODUCTION FAILED — do NOT cite new values; investigate.");
    return mismatches == 0 ? 0 : 1;
}
