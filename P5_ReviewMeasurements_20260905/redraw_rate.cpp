// Empirical rate of the weak-key re-draw in params(K_tx) for random 256-bit K_tx (Q30 sidecar v1.0.6).
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <cstdio>
#include <cstring>
int main(){
  const int N=200000; int raw_sym=0, final_sym=0;
  for (int i=0;i<N;i++){
    uint8_t key[32], buf[40]={0}; std::memcpy(buf,"MCL-P5-REDRAW",13); for(int k=0;k<8;k++) buf[32+k]=(uint8_t)((uint64_t)i>>(8*k)); CC_SHA256(buf,40,key);
    // raw mapping = KDF lanes -> weights, before the re-draw loop (mirrors the sidecar's first probe)
    uint8_t info[8]={0}; uint8_t kd[96]; mcl_kdf256(key,"MCL-T4-Q30-v1",info,8,kd,96);
    MCL_Q30_Sextet raw{}; int32_t* w=reinterpret_cast<int32_t*>(&raw);
    for(int l=0;l<12;l++){ uint64_t v=0; std::memcpy(&v,kd+8*l,8); w[l]=(int32_t)(2+(v%((1u<<30)-2))); }
    if (mcl_t4_q30_has_reachable_symmetry(raw)) raw_sym++;
    MCL_Q30_Sextet fin=mcl_t4_q30_params_from_key(key,0);
    if (mcl_t4_q30_has_reachable_symmetry(fin)) final_sym++;
  }
  printf("random K_tx: %d | raw weight sets with reachable symmetry: %d (%.3f%%, expected ~%.3f%%) | after deterministic re-draw: %d\n", N, raw_sym, 100.0*raw_sym/N, 100.0*114/65536, final_sym);
  return 0; }
