// mcl_table10_multiseed.cpp — Doc ID MCL-TABLE10-MULTISEED-2026-0817-001
// Re-measurement of Paper 1 Table 10 configurations A, B, C against the
// archived engine of record mcl_core.hpp v6.0.0 (MD5 241db79e...), plus the
// intra-mantissa window-pair independence premise of Eq. (5)
// (Doc ID MCL-GOLD-INTRAPAIR-2026-0817-001).
// Protocol: N = 1e8 output samples per seed, decimation D = 2 (production),
// byte-level chi^2 (df = 255, crit 310.46 at alpha = 0.01).
//   A: byte = (xm>>20 ^ xm>>36) & 0xFF          (deployed gen_byte)
//   B: byte = (xm>>6  ^ xm>>31) & 0xFF
//   C: word32 = (uint32)((xm>>6) ^ (xm>>20)), serialized to 4 LE bytes
//      (windows [6,37] and [20,51], overlap [20,37] = 18 bits)
// Intra-pair block: joint 2x2 independence of (bit 20+i, bit 36+i) of the
// XORed mantissa, i = 0..7 — the exact bit pairs combined by Eq. (5).
#include "mcl_core.hpp"
#include <cstdio>
#include <vector>
static double chi2(const std::vector<long long>&h,long long n){
  double E=(double)n/256.0,c=0; for(int i=0;i<256;i++){double d=h[i]-E;c+=d*d/E;} return c;}
int main(){
  const long long N=100000000LL;
  const uint64_t seeds[3]={12345678901234ULL,31415926535897ULL,27182818284590ULL};
  printf("engine v6.0.0 (frozen), N=1e8 samples/seed, D=2, df=255 crit=310.46\n\n");
  for(int s=0;s<3;s++){
    MCL_T2 eng(seeds[s],3,5,12.0);
    std::vector<long long> hA(256,0),hB(256,0),hC(256,0);
    long long n11[8]={0},n1a[8]={0},n1b[8]={0};
    for(long long i=0;i<N;i++){
      eng.iterate(); eng.iterate();
      uint64_t x=d2b(eng.theta1())^d2b(eng.theta2());
      uint64_t xm=x&((1ULL<<52)-1);
      hA[(uint8_t)((x>>20)^(x>>36))]++;
      hB[(uint8_t)((x>>6)^(x>>31))]++;
      uint32_t w=(uint32_t)((xm>>6)^(xm>>20));
      hC[w&0xFF]++; hC[(w>>8)&0xFF]++; hC[(w>>16)&0xFF]++; hC[(w>>24)&0xFF]++;
      for(int k=0;k<8;k++){
        int a=(int)((xm>>(20+k))&1), b=(int)((xm>>(36+k))&1);
        n1a[k]+=a; n1b[k]+=b; n11[k]+=(a&b);
      }
    }
    printf("seed %llu:\n", (unsigned long long)seeds[s]);
    printf("  A (8-bit, 20^36)  chi2 = %8.2f\n", chi2(hA,N));
    printf("  B (8-bit, 6^31)   chi2 = %8.2f\n", chi2(hB,N));
    printf("  C (32-bit, 6^20)  chi2 = %8.2f  (4N pooled bytes)\n", chi2(hC,4*N));
    printf("  intra-mantissa pairs (bit 20+i vs 36+i), i=0..7:\n");
    for(int k=0;k<8;k++){
      double pa=(double)n1a[k]/N, pb=(double)n1b[k]/N, pab=(double)n11[k]/N;
      double c=pab-pa*pb;
      double n=(double)N,o11=n11[k],o10=n1a[k]-n11[k],o01=n1b[k]-n11[k],o00=N-n1a[k]-n1b[k]+n11[k];
      double e11=(double)n1a[k]*n1b[k]/n, e10=(double)n1a[k]*(n-n1b[k])/n,
             e01=(n-n1a[k])*(double)n1b[k]/n, e00=(n-n1a[k])*(n-n1b[k])/n;
      double xx=(o11-e11)*(o11-e11)/e11+(o10-e10)*(o10-e10)/e10+(o01-e01)*(o01-e01)/e01+(o00-e00)*(o00-e00)/e00;
      printf("    i=%d cov=%+.3e chi2(1)=%7.3f %s\n",k,c,xx,xx<3.841?"indep":"CORR");
    }
    printf("\n");
  }
  return 0;
}
