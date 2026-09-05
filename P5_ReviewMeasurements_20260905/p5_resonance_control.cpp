// Positive control for the Step-4 resonance screen (Paper 5 §III.A / §IV.F): does the byte chi-square over
// 100,000 dual-zone-XOR bytes detect the narrow (3,5) window near K ≈ 1.22 reported in the companion physics paper?
// Sweeps K in [1.200, 1.240] step 0.001 (plus the baselines K = 1.0 and K = 12.0).  Doc ID: MCL-P5-RESCTRL-2026-0905-001
#include "mcl_core.hpp"
#include <cstdio>
#include <vector>
static double chi2(const uint8_t* b, size_t n){ double c[256]={0}; for(size_t i=0;i<n;i++) c[b[i]]++; double e=n/256.0,s=0; for(int i=0;i<256;i++){double d=c[i]-e; s+=d*d/e;} return s; }
int main(){ std::vector<uint8_t> buf(100000); double mx=0; double kmx=0;
  for(int i=0;i<=40;i++){ double K=1.200+0.001*i; MCL_T2 e(12345678901234ULL,3,5,K); e.gen_bytes(buf.data(),buf.size()); double c=chi2(buf.data(),buf.size()); if(c>mx){mx=c;kmx=K;} std::printf("K=%.3f chi2=%.1f %s\n",K,c,c>330.52?"  <-- FLAGGED":""); }
  for(double K: {1.0, 12.0}){ MCL_T2 e(12345678901234ULL,3,5,K); e.gen_bytes(buf.data(),buf.size()); std::printf("baseline K=%.1f chi2=%.1f\n",K,chi2(buf.data(),buf.size())); }
  std::printf("max chi2 in [1.200,1.240] = %.1f at K=%.3f (threshold 330.52)\n",mx,kmx); return 0; }
