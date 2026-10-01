/*
 * p5_burnin_avalanche_large.cpp — Paper 5, §VI.C (Table 4): larger-sample avalanche at short burn-in.
 * Question: Table 4 (5,000 flips per row, one input set shared by all rows) puts the avalanche mean
 * 2.1–2.7 null SE above 128 at B = 0, 2, 4, 8, 16. Is that a property of the short transient or a
 * draw of the shared input set? This program repeats T2 of p5_burnin_curve_v2.cpp unchanged in
 * definition, (a) on the ORIGINAL 5,000 inputs (sanity check: must reproduce Table 4 exactly) and
 * (b) on 100,000 FRESH inputs (transactions tx_of(20,000,000 + i), bit positions from the label
 * "MCL-P5-T2BIT-L"), disjoint from every input of the 2026-09-05 records.
 * The fresh inputs are shared across B (as in Table 4), so rows are not independent of each other;
 * each row is a valid estimate of its own B.
 * Built once per B against a SCRATCH copy of engine 8.1.3 (416ad145e79c095b) patched with
 * ../P5_ReviewMeasurements_20260905/header_patch.diff, and keyed sidecar v1.0.7 (05c01cf8a156…).
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -DMCL_BURNIN_OVERRIDE=<B> -I_scratch p5_burnin_avalanche_large.cpp -o av_<B>
 * Doc ID: MCL-P5-PREUPLOAD-2026-1001-002
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
#include <cmath>
static void flip(Tx& t2, unsigned bit){
  if(bit<64)t2.chain_id^=(1ULL<<bit);else if(bit<128)t2.nonce^=(1ULL<<(bit-64));else if(bit<192)t2.to^=(1ULL<<(bit-128));
  else if(bit<256)t2.value^=(1ULL<<(bit-192));else t2.calldata[(bit-256)/8]^=(uint8_t)(1u<<((bit-256)%8));}
struct Stat{double s=0,s2=0;long n=0;int mn=256,mx=0;void add(int h){s+=h;s2+=(double)h*h;n++;mn=std::min(mn,h);mx=std::max(mx,h);}};
static Stat run(const Device&A,uint64_t V1,uint64_t tx0,const char*bitlabel,long n){
  Stat st; for(long i=0;i<n;i++){Tx t=tx_of(tx0+(uint64_t)i);Tag a=tag_v3(A,t,V1);uint8_t hh[32];trial_bytes(bitlabel,(uint64_t)i,hh);
    uint64_t r=0;std::memcpy(&r,hh,8);unsigned bit=(unsigned)(r%384u);Tx t2=t;flip(t2,bit);Tag b=tag_v3(A,t2,V1);st.add(ham(a,b));}
  return st;}
int main(){
  const int B=BURNIN; Device A=dev_of(1); const uint64_t V1=0x5601;
  Stat o=run(A,V1,2000000,"MCL-P5-T2BIT",5000);
  auto t0=clk::now();
  Stat f=run(A,V1,20000000,"MCL-P5-T2BIT-L",100000);
  double sec=std::chrono::duration<double>(clk::now()-t0).count();
  double m=f.s/f.n, sd=std::sqrt(f.s2/f.n-m*m), se0=8.0/std::sqrt((double)f.n), z=(m-128.0)/se0;
  std::printf("B=%5d | original 5,000 inputs: mean %.3f/256 min %d max %d | fresh 100,000 inputs: mean %.4f/256 sd %.3f min %d max %d | null SE %.4f | z %+.2f | %.1f s\n",
    B,o.s/o.n,o.mn,o.mx,m,sd,f.mn,f.mx,se0,z,sec);
  return 0;}
