/*
 * p5_crosssystem_v2.cpp — Paper 5 §IV.G (Table 1, Figure 2): the cross-system check re-run with the
 * VERSION-2 derivation. Test 9 of hd_v2/mcl_hd_verify_v2.cpp (record of 2026-09-05) derives the
 * logistic and tent children with a local helper that applies the version-1 XOR index mask and no
 * coprimality step (range 1,000), which is why its tent child (442, 13) is not coprime. Here the
 * child is derived from the same 32 raw parent bytes by Steps 2-3 of derive_child_v2 (mcl_hd_v2.hpp)
 * verbatim — d = SHA-256("MCL-HD-v2" || raw[0:32] || LE64(i)), p, q in [2, max_val-1], p != q,
 * coprimality loop — with max_val = 1,000 as in Test 9; then the parent and child byte streams
 * (10^6 bytes each, same seed) are correlated exactly as in Test 9. Hénon stays excluded (Test 9).
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. -I../hd_v2 p5_crosssystem_v2.cpp -o p5_crosssystem_v2
 * Doc ID: MCL-P5-PREUPLOAD-2026-1001-004
 */
#include "mcl_core.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>
static const uint64_t SEED = 12345678901234ULL;     // DEFAULT_SEED of mcl_hd_verify_v2.cpp
static const int64_t NB = 1000000, RANGE = 1000;
static std::pair<int64_t,int64_t> derive_v2_from_raw(const uint8_t raw[32], int64_t max_val, int64_t index){
  uint8_t msg[9+32+8]; std::memcpy(msg,"MCL-HD-v2",9); std::memcpy(msg+9,raw,32);
  for(int b=0;b<8;b++) msg[41+b]=(uint8_t)(((uint64_t)index)>>(8*b));
  uint8_t d[32]; mcl_sha256(msg,sizeof(msg),d);
  uint64_t c1=0,c2=0; for(int b=0;b<8;b++){c1|=((uint64_t)d[b])<<(8*b); c2|=((uint64_t)d[8+b])<<(8*b);}
  int64_t pc=2+(int64_t)(c1%(uint64_t)(max_val-2)), qc=2+(int64_t)(c2%(uint64_t)(max_val-2));
  if(pc==qc) qc=2+((qc-2+1)%(max_val-2));
  for(;;){ int64_t a=pc>qc?pc:qc, bb=pc>qc?qc:pc; while(bb){int64_t t=bb; bb=a%bb; a=t;} if(a==1) break;
    qc=2+((qc-2+1)%(max_val-2)); if(qc==pc) qc=2+((qc-2+1)%(max_val-2)); }
  return {pc,qc}; }
// Test 9's local helper of 2026-09-05, verbatim in effect (version-1 XOR mask, no coprimality) — used ONLY to
// reproduce the record's two rows, which validates the correlation code of this program.
static std::pair<int64_t,int64_t> derive_test9_v1mask(uint8_t raw[32], int64_t max_v, int64_t idx){
  uint64_t iv=(uint64_t)idx; iv^=iv>>30; iv*=0xBF58476D1CE4E5B9ULL; iv^=iv>>27; iv*=0x94D049BB133111EBULL; iv^=iv>>31;
  uint64_t im=iv*0x9E3779B97F4A7C15ULL;
  for(int b=0;b<8;b++){ raw[b]^=(uint8_t)(iv>>(b*8)); raw[8+b]^=(uint8_t)(im>>(b*8)); }
  uint64_t c1=0,c2=0; std::memcpy(&c1,raw,8); std::memcpy(&c2,raw+8,8);
  int64_t p=2+(int64_t)(c1%(uint64_t)(max_v-2)), q=2+(int64_t)(c2%(uint64_t)(max_v-2)); if(p==q) q++;
  return {p,q}; }
static double pearson(const std::vector<uint8_t>&x,const std::vector<uint8_t>&y){
  double n=(double)x.size(),sx=0,sy=0,sxx=0,syy=0,sxy=0;
  for(size_t i=0;i<x.size();i++){double a=x[i],b=y[i];sx+=a;sy+=b;sxx+=a*a;syy+=b*b;sxy+=a*b;}
  return (n*sxy-sx*sy)/std::sqrt((n*sxx-sx*sx)*(n*syy-sy*sy)); }
template<class E> static void one(const char* name, bool v1mask=false){
  E par(SEED,3,5); uint8_t raw[32]; par.gen_bytes(raw,32);
  auto pq=v1mask?derive_test9_v1mask(raw,RANGE,0):derive_v2_from_raw(raw,RANGE,0);
  E child(SEED,pq.first,pq.second), par2(SEED,3,5);
  std::vector<uint8_t> a((size_t)NB), b((size_t)NB); par2.gen_bytes(a.data(),NB); child.gen_bytes(b.data(),NB);
  double r=std::fabs(pearson(a,b)), z=r*std::sqrt((double)NB), p=std::erfc(z/std::sqrt(2.0));
  int64_t g=pq.first, h=pq.second; while(h){int64_t t=h; h=g%h; g=t;}
  std::printf("  %-9s parent(3,5) -> child (%lld,%lld) gcd %lld | |r| = %.6f  p = %.4f  (Bonferroni alpha/135 = 7.41e-06: %s)\n",
    name,(long long)pq.first,(long long)pq.second,(long long)g,r,p,p<0.001/135?"REJECT":"no rejection"); }
int main(){
  std::printf("cross-system check, version-2 derivation, max_val = %lld, %lld bytes per stream, seed %llu\n",
    (long long)RANGE,(long long)NB,(unsigned long long)SEED);
  std::printf("(a) reproduction of the 2026-09-05 Test 9 rows (version-1 mask helper):\n");
  one<CoupledLogistic>("Logistic",true);
  one<CoupledTent>("Tent",true);
  std::printf("(b) version-2 derivation:\n");
  one<CoupledLogistic>("Logistic");
  one<CoupledTent>("Tent");
  std::printf("  Henon     excluded (narrow attractor basin; as in Test 9)\n");
  return 0; }
