// mcl_p1_singlewindow_bytes.cpp — Doc ID MCL-P1-SINGLEWIN-2026-0909-001
//
// PURPOSE (Paper 1, external review #5, item ت-49): the production extractor
// (Eq. 5, "Goldilocks") XORs two 8-bit windows of the XOR-mixed mantissa,
// bits [20,27] and [36,43], into one byte. A referee asked why two windows
// rather than one, since a single window starting at 36 already passes the
// byte-level test in the single-extractor scan (Table 6) and both forms emit
// eight bits per sample. This tool measures, on the SAME six seeds and at the
// SAME production decimation D = 2 as MCL-P1-GOLDBIT-2026-0907-001, the
// 256-bin byte-level chi-square (df = 255, critical 310.46 at alpha = 0.01) of
//   S20 : the single window bits [20,27]
//   S36 : the single window bits [36,43]
//   A   : the dual-window byte S20 XOR S36 (control; = Table 9 configuration A)
// and, for each, the worst emitted-bit chi2(df=1) over the 8 bits, so that the
// single-window and dual-window forms can be compared directly.
//
// Engine of record mcl_core.hpp v6.0.0 (MD5 241db79ecf8a42897eb9a8399cf37929),
// (p,q) = (3,5), K = 12, D = 2, burn-in 10000 (engine default), N = 1e8 per seed.
//
// BUILD: c++ -O3 -std=c++17 -ffp-contract=off \
//            -o mcl_p1_singlewindow_bytes mcl_p1_singlewindow_bytes.cpp -lm
#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <cstring>

static double chi2_byte(const long long *bins, long long n) {
    double e = (double)n / 256.0, s = 0.0;
    for (int i = 0; i < 256; i++) { double d = (double)bins[i] - e; s += d * d / e; }
    return s;
}

int main() {
    const long long N = 100000000LL;
    const uint64_t seeds[6] = {12345678901234ULL, 31415926535897ULL, 27182818284590ULL,
                               98765432109876ULL, 17320508075688ULL, 70466644885213ULL};
    std::printf("==============================================================\n");
    std::printf(" MCL PAPER 1 — SINGLE-WINDOW vs DUAL-WINDOW BYTE UNIFORMITY\n");
    std::printf(" Doc ID: MCL-P1-SINGLEWIN-2026-0909-001\n");
    std::printf(" Engine: mcl_core.hpp v6.0.0 (frozen), (p,q)=(3,5), K=12, D=2, burn-in %d\n", BURNIN);
    std::printf(" N = %lld output samples per seed; S20 = xm[20:27], S36 = xm[36:43], A = S20 XOR S36\n", N);
    std::printf(" byte-level chi2 df=255, critical 310.46 (alpha=0.01); worst-bit chi2 df=1, nominal 3.841\n");
    std::printf("==============================================================\n\n");
    std::printf(" seed             |  S20 chi2 | S20 worst bit |  S36 chi2 | S36 worst bit |   A chi2  | A worst bit\n");
    std::printf("------------------|-----------|---------------|-----------|---------------|-----------|------------\n");
    double mn[3]={1e9,1e9,1e9}, mx[3]={0,0,0}, sum[3]={0,0,0};
    for (int s = 0; s < 6; s++) {
        MCL_T2 eng(seeds[s], 3, 5, 12.0);
        long long b20[256], b36[256], bA[256]; std::memset(b20,0,sizeof b20); std::memset(b36,0,sizeof b36); std::memset(bA,0,sizeof bA);
        long long o20[8]={0}, o36[8]={0}, oA[8]={0};
        for (long long i = 0; i < N; i++) {
            eng.iterate(); eng.iterate();
            uint64_t x = d2b(eng.theta1()) ^ d2b(eng.theta2());
            uint64_t xm = x & ((1ULL << 52) - 1);
            int w20 = (int)((xm >> 20) & 0xFF), w36 = (int)((xm >> 36) & 0xFF), a = w20 ^ w36;
            b20[w20]++; b36[w36]++; bA[a]++;
            for (int k = 0; k < 8; k++) { o20[k] += (w20 >> k) & 1; o36[k] += (w36 >> k) & 1; oA[k] += (a >> k) & 1; }
        }
        double n = (double)N;
        auto worst = [&](long long *o){ double w=0; for (int k=0;k<8;k++){ double d=(double)o[k]/n-0.5; double c=n*4.0*d*d; if(c>w) w=c;} return w; };
        double c20 = chi2_byte(b20,N), c36 = chi2_byte(b36,N), cA = chi2_byte(bA,N);
        double cs[3]={c20,c36,cA};
        for (int j=0;j<3;j++){ if(cs[j]<mn[j]) mn[j]=cs[j]; if(cs[j]>mx[j]) mx[j]=cs[j]; sum[j]+=cs[j]; }
        std::printf(" %-16llu | %9.1f | %13.3f | %9.1f | %13.3f | %9.1f | %10.3f\n",
                    (unsigned long long)seeds[s], c20, worst(o20), c36, worst(o36), cA, worst(oA));
        std::fflush(stdout);
    }
    const char* nm[3]={"S20","S36","A  "};
    std::printf("\n Summary over 6 seeds (byte chi2): ");
    for (int j=0;j<3;j++) std::printf("%s mean %.1f (%.1f – %.1f)%s", nm[j], sum[j]/6.0, mn[j], mx[j], j<2?" · ":"\n");
    return 0;
}
