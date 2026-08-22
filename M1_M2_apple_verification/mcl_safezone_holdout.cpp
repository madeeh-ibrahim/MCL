// mcl_safezone_holdout.cpp — three deliverables for the 2026-07-19 dual-review
// finishing round on Paper 1, all against the frozen v6.0.0 engine of record:
//
//   (A) Table-7 rebuild with a SINGLE extractor: byte-level chi-square (df=255)
//       at every window start position P in [0,44] for THREE streams computed
//       identically — theta1 mantissa, theta2 mantissa, and the XOR mantissa.
//       (The published Table 7 mixed a one-oscillator LSB/MSB row with an
//       XOR Safe-Zone row; this produces all three curves under one protocol.)
//
//   (B) Source-bit joint independence: for each mantissa position P, the 2x2
//       contingency of (bit_P(theta1), bit_P(theta2)), the covariance
//       Cov = P11 - P1*P2, and the df=1 independence chi-square. This is the
//       quantity the XOR healing identity (Paper 1 Eq. 6) actually requires:
//       the two SOURCE bits at a given position must be independent for the
//       bias to suppress as 2*d1*d2. Never measured directly before.
//
//   (C) Holdout: (A) is run on SEEDS NOT USED to select the Safe-Zone
//       boundary (the boundary was chosen/validated on 12345678901234). Fresh
//       seeds test whether [6,39] is a seed-specific artifact or reproducible.
//
// Usage: mcl_safezone_holdout <seed> [N]   (default N = 1e8, one iterate/sample)
// Byte-level protocol matches Paper 1 §3.3: byte = (mantissa >> P) & 0xFF,
// chi2 = sum_b (H_b - E)^2 / E, E = N/256, crit(df=255,a=0.01) = 310.46.
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
#include <vector>

static const double CRIT255 = 310.46; // df=255, alpha=0.01
static const int PMAX = 44;            // window start positions [0,44]
static const uint64_t MANT = 0x000FFFFFFFFFFFFFULL;

static int safe_zone_lo_hi(const double* chi2, int& lo, int& hi) {
    // longest contiguous run of start positions with chi2 < CRIT255
    int best_lo = -1, best_len = 0, cur_lo = -1, cur_len = 0;
    for (int p = 0; p <= PMAX; p++) {
        if (chi2[p] < CRIT255) {
            if (cur_lo < 0) cur_lo = p;
            cur_len++;
            if (cur_len > best_len) { best_len = cur_len; best_lo = cur_lo; }
        } else { cur_lo = -1; cur_len = 0; }
    }
    lo = best_lo; hi = best_lo + best_len - 1; return best_len;
}

int main(int argc, char** argv) {
    uint64_t seed = (argc > 1) ? strtoull(argv[1], nullptr, 10) : 12345678901234ULL;
    int64_t N = (argc > 2) ? strtoll(argv[2], nullptr, 10) : 100000000LL;

    std::printf("==============================================================\n");
    std::printf(" MCL SAFE-ZONE: SINGLE-EXTRACTOR SCAN + JOINT INDEPENDENCE + HOLDOUT\n");
    std::printf(" Doc ID: MCL-SAFEZONE-HOLDOUT-2026-0719-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen M1_M2_apple_verification copy)\n");
    std::printf(" Seed: %llu   N: %lld   (p,q)=(3,5), K=12, burn-in 10000\n",
                (unsigned long long)seed, (long long)N);
    std::printf("==============================================================\n\n");

    // histograms[stream][P][byte]; stream 0=theta1, 1=theta2, 2=XOR
    std::vector<std::vector<std::vector<int64_t>>> H(
        3, std::vector<std::vector<int64_t>>(PMAX + 1, std::vector<int64_t>(256, 0)));
    // joint[P][2*b1+b2]
    std::vector<std::array<int64_t, 4>> J(52);
    for (auto& a : J) a = {0, 0, 0, 0};

    MCL_T2 eng(seed, 3, 5, 12.0);
    for (int64_t i = 0; i < N; i++) {
        eng.iterate();
        uint64_t m1 = d2b(eng.theta1()) & MANT;
        uint64_t m2 = d2b(eng.theta2()) & MANT;
        uint64_t mx = m1 ^ m2;
        for (int p = 0; p <= PMAX; p++) {
            H[0][p][(m1 >> p) & 0xFF]++;
            H[1][p][(m2 >> p) & 0xFF]++;
            H[2][p][(mx >> p) & 0xFF]++;
        }
        for (int p = 0; p < 52; p++) {
            int b1 = (int)((m1 >> p) & 1ULL);
            int b2 = (int)((m2 >> p) & 1ULL);
            J[p][2 * b1 + b2]++;
        }
    }

    double E = (double)N / 256.0;
    double chi2[3][PMAX + 1];
    for (int s = 0; s < 3; s++)
        for (int p = 0; p <= PMAX; p++) {
            double c = 0;
            for (int b = 0; b < 256; b++) { double d = (double)H[s][p][b] - E; c += d * d / E; }
            chi2[s][p] = c;
        }

    // (A) three-stream byte-level scan
    std::printf("(A) BYTE-LEVEL chi2 (df=255, crit=%.2f) — SINGLE EXTRACTOR, THREE STREAMS\n", CRIT255);
    std::printf("  P  |     theta1      |     theta2      |       XOR       | XOR verdict\n");
    std::printf("-----|-----------------|-----------------|-----------------|------------\n");
    for (int p = 0; p <= PMAX; p++)
        std::printf(" %3d | %15.2f | %15.2f | %15.2f | %s\n", p,
                    chi2[0][p], chi2[1][p], chi2[2][p],
                    chi2[2][p] < CRIT255 ? "PASS" : "FAIL");

    int lo, hi, w = safe_zone_lo_hi(chi2[2], lo, hi);
    int lo1, hi1, w1 = safe_zone_lo_hi(chi2[0], lo1, hi1);
    int lo2, hi2, w2 = safe_zone_lo_hi(chi2[1], lo2, hi2);
    std::printf("\n  XOR Safe Zone (byte-window start positions): [%d, %d] = %d positions\n", lo, hi, w);
    std::printf("  theta1 zone: [%d, %d] = %d   theta2 zone: [%d, %d] = %d\n", lo1, hi1, w1, lo2, hi2, w2);

    // (B) source-bit joint independence at representative positions
    std::printf("\n(B) SOURCE-BIT JOINT INDEPENDENCE  bit_P(theta1) vs bit_P(theta2)\n");
    std::printf("  P  |  P(b1=1)  |  P(b2=1)  |    Cov     | chi2_indep(df=1) | verdict\n");
    std::printf("-----|-----------|-----------|------------|------------------|--------\n");
    int probe[] = {5, 6, 7, 8, 20, 27, 36, 39, 40, 41};
    for (int idx = 0; idx < (int)(sizeof probe / sizeof probe[0]); idx++) {
        int p = probe[idx];
        double n00 = (double)J[p][0], n01 = (double)J[p][1], n10 = (double)J[p][2], n11 = (double)J[p][3];
        double tot = n00 + n01 + n10 + n11;
        double p1 = (n10 + n11) / tot, p2 = (n01 + n11) / tot, p11 = n11 / tot;
        double cov = p11 - p1 * p2;
        // df=1 chi-square of independence on the 2x2 table
        double chi = 0;
        double row1 = n10 + n11, row0 = n00 + n01, col1 = n01 + n11, col0 = n00 + n10;
        double exp[4] = {row0 * col0 / tot, row0 * col1 / tot, row1 * col0 / tot, row1 * col1 / tot};
        double obs[4] = {n00, n01, n10, n11};
        for (int k = 0; k < 4; k++) { double d = obs[k] - exp[k]; chi += d * d / exp[k]; }
        std::printf(" %3d | %9.6f | %9.6f | %+.6f | %16.4f | %s\n",
                    p, p1, p2, cov, chi, chi < 3.841 ? "indep" : "DEP");
    }
    std::printf("\n  (Independence of the two SOURCE bits is the premise of the XOR healing\n");
    std::printf("   identity P(out=1)=1/2 - 2*d1*d2 - 2*Cov; Cov ~ 0 => healing applies.)\n");
    return 0;
}
