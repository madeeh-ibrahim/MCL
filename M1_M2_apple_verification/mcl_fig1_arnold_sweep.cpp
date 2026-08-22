// mcl_fig1_arnold_sweep.cpp — Doc ID MCL-FIG1-ARNOLD-2026-0817-001
// Regeneration data for Paper 3 Figure 1 / Table I (Arnold tongue map).
// Protocol = paper §III.A + public tool mcl_k_sweep_unified.cpp (v6.0.0):
//   K = 0.30 .. 1.00 step 0.02 (36 values) x 4 topologies (2,3),(3,5),(5,7),(7,11)
//   500,000 bytes per (K, seed), 3 seeds worst-case chi^2 aggregation,
//   production gen_byte() extraction, chi^2 df=255.
//   Classification: chi2 > 1000 -> RESONANCE ; chi2 < 330 -> PASS (chaotic/quasi-periodic).
// Engine: frozen v6.0.0 (MD5 241db79e...), -DMCL_UNSAFE_ALLOW_INVALID (sub-K_min sweep).
#include "mcl_core.hpp"
#include <cstdio>
#include <vector>
static const uint64_t SEEDS[3]={12345678901234ULL,98765432109876ULL,31415926535897ULL};
static double chi2_bytes(const std::vector<uint8_t>&d){
  long long h[256]={0}; for(uint8_t b:d)h[b]++;
  double E=(double)d.size()/256.0,c=0;
  for(int i=0;i<256;i++){double x=h[i]-E;c+=x*x/E;} return c;}
int main(){
  const int64_t NB=500000;
  const int64_t P[4]={2,3,5,7}, Q[4]={3,5,7,11};
  printf("# topology,K,chi2_worst,class\n");
  for(int t=0;t<4;t++){
    int res=0; double rlo=99,rhi=-1;
    for(int ki=0;ki<36;ki++){
      double K=0.30+0.02*ki;
      double worst=0;
      for(int s=0;s<3;s++){
        MCL_T2 eng(SEEDS[s],P[t],Q[t],K);
        std::vector<uint8_t> d((size_t)NB);
        eng.gen_bytes(d.data(),NB);
        double c=chi2_bytes(d); if(c>worst)worst=c;
      }
      const char* cls = worst>1000.0 ? "RESON" : (worst<330.0 ? "PASS" : "MARGN");
      if(worst>1000.0){res++; if(K<rlo)rlo=K; if(K>rhi)rhi=K;}
      printf("(%lld,%lld),%.2f,%.2f,%s\n",(long long)P[t],(long long)Q[t],K,worst,cls);
    }
    fprintf(stderr,"(%lld,%lld): resonant %d/36  range [%.2f, %.2f]\n",
      (long long)P[t],(long long)Q[t],res,rlo,rhi);
  }
  return 0;
}
