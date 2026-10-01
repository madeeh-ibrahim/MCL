/*
 * p5_bip32_cost.cpp — Paper 5 §IV.H / §IX / Table 7: measured cost of one BIP-32 child derivation.
 * BIP-32 private child derivation (hardened, or non-hardened with the parent public key cached):
 *   I = HMAC-SHA512(c_par, 0x00 || ser256(k_par) || ser32(i)),  k_i = parse256(I_L) + k_par mod n,  c_i = I_R
 * n = order of secp256k1. The elliptic-curve multiplication that a non-hardened derivation needs when the
 * parent public key is NOT cached is out of scope (it is not part of a private->private derivation).
 * HMAC-SHA512 from Apple CommonCrypto (macOS only; the MCL side of the comparison is the record
 * hd_throughput_v2_quiet_20260905.log, 0.82 ms per derive_child_v2 without the Step-4 screen).
 * Timing: 200 batches of 10,000 derivations, single thread; min and median per-derivation time are
 * reported, because the host may be loaded (load average printed by the wrapper).
 * Correctness: BIP-32 test vector 1 (seed 000102030405060708090a0b0c0d0e0f), chain m/0H, checked below.
 * Build: clang++ -std=c++17 -O3 -DNDEBUG p5_bip32_cost.cpp -o p5_bip32_cost
 * Doc ID: MCL-P5-PREUPLOAD-2026-1001-005
 */
#include <CommonCrypto/CommonHMAC.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
static const uint8_t N[32]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41};
static bool geq(const uint8_t a[32],const uint8_t b[32]){for(int i=0;i<32;i++){if(a[i]!=b[i])return a[i]>b[i];}return true;}
static void sub(uint8_t a[32],const uint8_t b[32]){int br=0;for(int i=31;i>=0;i--){int d=a[i]-b[i]-br;br=d<0;a[i]=(uint8_t)(d+(br?256:0));}}
static void addmod(uint8_t r[32],const uint8_t a[32],const uint8_t b[32]){int c=0;for(int i=31;i>=0;i--){int s=a[i]+b[i]+c;r[i]=(uint8_t)s;c=s>>8;} if(c||geq(r,N)) sub(r,N);}
static void ckd_priv(const uint8_t k[32],const uint8_t c[32],uint32_t i,uint8_t ko[32],uint8_t co[32]){
  uint8_t data[37]; data[0]=0; std::memcpy(data+1,k,32); data[33]=(uint8_t)(i>>24);data[34]=(uint8_t)(i>>16);data[35]=(uint8_t)(i>>8);data[36]=(uint8_t)i;
  uint8_t I[64]; CCHmac(kCCHmacAlgSHA512,c,32,data,37,I); addmod(ko,I,k); std::memcpy(co,I+32,32); }
static void hex(const char*s,uint8_t*o,int n){for(int i=0;i<n;i++){unsigned v;std::sscanf(s+2*i,"%2x",&v);o[i]=(uint8_t)v;}}
int main(){
  // BIP-32 test vector 1: master from seed via HMAC-SHA512("Bitcoin seed", seed); then m/0H
  uint8_t seed[16]; hex("000102030405060708090a0b0c0d0e0f",seed,16); uint8_t I[64];
  CCHmac(kCCHmacAlgSHA512,"Bitcoin seed",12,seed,16,I); uint8_t k[32],c[32]; std::memcpy(k,I,32); std::memcpy(c,I+32,32);
  uint8_t k1[32],c1[32]; ckd_priv(k,c,0x80000000u,k1,c1);
  uint8_t ek[32]; hex("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",ek,32);
  uint8_t ec[32]; hex("47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141",ec,32);
  bool ok=!std::memcmp(k1,ek,32)&&!std::memcmp(c1,ec,32);
  std::printf("BIP-32 test vector 1, m/0H private key and chain code: %s\n",ok?"MATCH":"MISMATCH");
  if(!ok) return 1;
  std::vector<double> per; per.reserve(200); uint8_t kk[32],cc[32]; std::memcpy(kk,k1,32); std::memcpy(cc,c1,32); volatile uint8_t sink=0;
  for(int b=0;b<200;b++){ auto t0=std::chrono::steady_clock::now();
    for(int j=0;j<10000;j++){ uint8_t ko[32],co[32]; ckd_priv(kk,cc,0x80000000u+(uint32_t)j,ko,co); sink^=ko[0]^co[0]; }
    per.push_back(std::chrono::duration<double,std::micro>(std::chrono::steady_clock::now()-t0).count()/10000.0); }
  std::sort(per.begin(),per.end());
  std::printf("BIP-32 child derivation (HMAC-SHA512 + addition mod n), 200 x 10,000: min %.3f us, median %.3f us, max %.3f us per derivation (sink %u)\n",
    per.front(),per[100],per.back(),(unsigned)sink);
  std::printf("against derive_child_v2 0.82 ms (record hd_throughput_v2_quiet_20260905.log): %.0fx (min) / %.0fx (median)\n",820.0/per.front(),820.0/per[100]);
  return 0; }
