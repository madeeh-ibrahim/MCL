#include "mcl_keyed_q30.hpp"
#include <cstdio>
#include <cstdint>
#include <cstdlib>
static void fill_key(uint8_t kx[32], uint64_t idx){
  uint64_t z=0x9E3779B97F4A7C15ULL*(idx+1);
  for(int i=0;i<32;i++){z+=0x9E3779B97F4A7C15ULL;uint64_t x=z;x^=x>>30;x*=0xBF58476D1CE4E5B9ULL;x^=x>>27;x*=0x94D049BB133111EBULL;x^=x>>31;kx[i]=(uint8_t)x;}
}
int main(int argc,char**argv){
  uint64_t idx = argc>1? strtoull(argv[1],0,10):0;
  uint8_t kx[32]; fill_key(kx,idx);
  MCL_Q30_Sextet s=mcl_t4_q30_params_from_key(kx);
  printf("KEY %llu P=%u,%u,%u,%u,%u,%u Q=%u,%u,%u,%u,%u,%u\n",
    (unsigned long long)idx, s.p12,s.p13,s.p14,s.p23,s.p24,s.p34, s.q12,s.q13,s.q14,s.q23,s.q24,s.q34);
  return 0;
}
