/*
 * p5_burnin_curve.cpp — Paper 5 referee question Q3 (2026-09-05):
 *   "Why a 10,000-iteration burn-in per transaction when, under Eq. (3), the seed is a public
 *    constant and the secret lives in the twelve derived weights?"
 * Measures, on the Q30 realization of the SS-VI protocol, how the tag statistics depend on the
 * burn-in length B. Built once per B against a SCRATCH copy of the engine whose BURNIN constant
 * is made overridable (see header_patch.diff); the engine of record is untouched.
 * Per B: T2 avalanche (5,000 single-bit TX flips), T3 byte chi2 (20,000 tags), T4 device binding
 * (10 devices, 45 pairs), T5 128 stride-4 single-bit neighbours of (K,S) incl. near-misses,
 * mini-FAR (10,000 random wrong devices), latency per tag.
 * Doc ID: MCL-P5-BURNIN-2026-0905-002 (v2: same random-bit avalanche as battery v3.2; portable SHA-256)
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -DMCL_BURNIN_OVERRIDE=<B> -I. p5_burnin_curve.cpp -o burnin_<B>
 */
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <set>
#include <vector>
using Bytes=std::vector<uint8_t>; using Key256=std::array<uint8_t,32>; using Tag=std::array<uint8_t,32>;
using clk=std::chrono::high_resolution_clock;
static Bytes sha256v(const Bytes& m){Bytes d(32);mcl_sha256(m.data(),m.size(),d.data());return d;}
static void put_u64(Bytes& v,uint64_t x){for(int i=0;i<8;i++)v.push_back((uint8_t)(x>>(8*i)));}
static int ham(const Tag&a,const Tag&b){int h=0;for(int i=0;i<32;i++)h+=__builtin_popcount((unsigned)(a[i]^b[i]));return h;}
struct Tx{uint64_t chain_id,nonce,to,value;Bytes calldata;};
static Bytes canon(const Tx&t){Bytes c;put_u64(c,t.chain_id);put_u64(c,t.nonce);put_u64(c,t.to);put_u64(c,t.value);put_u64(c,(uint64_t)t.calldata.size());c.insert(c.end(),t.calldata.begin(),t.calldata.end());return c;}
struct Device{Key256 K,S;uint64_t account;};
static const uint64_t PUBLIC_SEED=12345678901234ULL;
static Tag tag_v3(const Device&d,const Tx&tx,uint64_t verifier){
  Bytes pre=canon(tx);put_u64(pre,tx.nonce);put_u64(pre,d.account);put_u64(pre,verifier);
  Bytes ctx=sha256v(pre); uint8_t keff[32],ktx[32];
  mcl_keff_from_key_device(d.K.data(),d.S.data(),keff);
  mcl_kdf256(keff,"MCL-TxChallenge-v1",ctx.data(),ctx.size(),ktx,32);
  Tag out{}; { MCL_T4_Q30 eng(ktx,0,PUBLIC_SEED,K_DEFAULT); eng.gen_bytes(out.data(),32); }
  secure_zero(keff,32);secure_zero(ktx,32); return out;
}
static void trial_bytes(const char*tag,uint64_t i,uint8_t out[32]){uint8_t buf[40];std::memset(buf,0,32);std::strncpy((char*)buf,tag,31);for(int k=0;k<8;k++)buf[32+k]=(uint8_t)(i>>(k*8));mcl_sha256(buf,sizeof(buf),out);}
static Tx tx_of(uint64_t i){uint8_t h[32];trial_bytes("MCL-P5-V3-TX",i,h);Tx t;t.chain_id=1;t.nonce=i;std::memcpy(&t.to,h,8);std::memcpy(&t.value,h+8,8);t.value%=1000000;t.calldata.assign(h+16,h+32);return t;}
static Device dev_of(uint64_t i){Device d{};uint8_t h[32];trial_bytes("MCL-P5-V3-KEY",i,h);std::memcpy(d.K.data(),h,32);trial_bytes("MCL-P5-V3-SDV",i,h);std::memcpy(d.S.data(),h,32);d.account=0xA0+i;return d;}
int main(){
  const int B=BURNIN; Device A=dev_of(1); const uint64_t V1=0x5601;
  // T2 avalanche
  double s2=0;int mn2=256,mx2=0; for(int i=0;i<5000;i++){Tx t=tx_of(2000000+i);Tag a=tag_v3(A,t,V1);uint8_t hh[32];trial_bytes("MCL-P5-T2BIT",(uint64_t)i,hh);uint64_t r=0;std::memcpy(&r,hh,8);unsigned bit=(unsigned)(r%384u);Tx t2=t;
    if(bit<64)t2.chain_id^=(1ULL<<bit);else if(bit<128)t2.nonce^=(1ULL<<(bit-64));else if(bit<192)t2.to^=(1ULL<<(bit-128));else if(bit<256)t2.value^=(1ULL<<(bit-192));else t2.calldata[(bit-256)/8]^=(uint8_t)(1u<<((bit-256)%8));
    Tag b=tag_v3(A,t2,V1);int h=ham(a,b);s2+=h;mn2=std::min(mn2,h);mx2=std::max(mx2,h);}
  // T3 byte chi2 over 20,000 tags
  std::vector<uint64_t> cnt(256,0); for(int i=0;i<20000;i++){Tag g=tag_v3(A,tx_of(3000000+i),V1);for(uint8_t x:g)cnt[x]++;}
  double e=20000.0*32/256,chi=0;for(int i=0;i<256;i++){double d=cnt[i]-e;chi+=d*d/e;}
  // T4 device binding: 10 devices x fixed tx, 45 pairs
  Tx t4=tx_of(4000001); std::vector<Tag> tg; for(int i=0;i<10;i++){Device d=dev_of(100+i);d.account=A.account;tg.push_back(tag_v3(d,t4,V1));}
  double s4=0;int n4=0,mn4=256,mx4=0;for(int i=0;i<10;i++)for(int j=i+1;j<10;j++){int h=ham(tg[i],tg[j]);s4+=h;n4++;mn4=std::min(mn4,h);mx4=std::max(mx4,h);}
  // T5 neighbours
  Tx t5=tx_of(5000001);Tag ref=tag_v3(A,t5,V1);double s5=0;int n5=0,mn5=256,mx5=0,near5=0;
  for(int w=0;w<2;w++)for(int bit=0;bit<256;bit+=4){Device d=A;if(w==0)d.K[bit/8]^=(uint8_t)(1u<<(bit%8));else d.S[bit/8]^=(uint8_t)(1u<<(bit%8));int h=ham(ref,tag_v3(d,t5,V1));s5+=h;n5++;mn5=std::min(mn5,h);mx5=std::max(mx5,h);if(h<=32)near5++;}
  // mini-FAR 10,000
  Tx tf=tx_of(7000001);Tag truth=tag_v3(A,tf,V1);int acc=0,nearf=0;double sf=0;
  for(int i=0;i<10000;i++){Device g=dev_of(10000000+i);g.account=A.account;Tag gt=tag_v3(g,tf,V1);if(gt==truth)acc++;int h=ham(gt,truth);sf+=h;if(h<=32)nearf++;}
  // latency
  Tx t8=tx_of(8000001);auto t0=clk::now();for(int i=0;i<300;i++){t8.nonce=1+i;Tag g=tag_v3(A,t8,V1);(void)g;}double ms=std::chrono::duration<double,std::milli>(clk::now()-t0).count()/300;
  std::printf("B=%5d | T2 avalanche mean %.3f/256 min %d max %d | T3 chi2 %.1f | T4 binding mean %.2f min %d max %d | T5 nbr mean %.2f min %d max %d near %d | FAR 1e4: acc %d near %d meanHD %.3f | %.3f ms/tag\n",
    B,s2/5000,mn2,mx2,chi,s4/n4,mn4,mx4,s5/n5,mn5,mx5,near5,acc,nearf,sf/10000,ms);
  return 0;
}
