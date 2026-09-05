/*
 * p5_adversarial.cpp — Paper 5 §VI.E: two ATTEMPTED attacks on the Eq. (3) tag (Q30), with
 * their (negative) results. Scratch engine copy with MCL_BURNIN_OVERRIDE; engine of record untouched.
 *
 * A1  Per-field context sensitivity. ctx = H(canon(TX) || LE64(c) || LE64(account) || LE64(verifier)).
 *     For each ctx-bearing FIELD separately, flip one uniformly random bit of that field only and
 *     measure the tag Hamming distance. A field that failed to reach the 128/256 null mean would be a
 *     field the tag does not bind at full width (the §V.B "transaction-bound" claim, per field).
 *
 * A2  First-order weight-leak test (the §X.12 concern). For N random keys: derive the twelve Q30
 *     weights and the tag, then correlate EVERY weight bit (12 x 30 = 360) with EVERY tag bit (256)
 *     across the N samples -- 92,160 point-biserial correlations. Under the null each |r| ~ N(0,1/sqrt(N));
 *     a weight bit readable from the tag at first order would show |r| far above the noise floor.
 *     Run at the normative burn-in and at B = 0, where a short transient would leak most.
 * Doc ID: MCL-P5-ADVERSARIAL-2026-0905-001
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -DMCL_BURNIN_OVERRIDE=<B> -I. p5_adversarial.cpp -o adv_<B>
 */
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
#include <cmath>
#include <cstdio>
#include <cstring>
#include <vector>
static const uint64_t PUBLIC_SEED = 12345678901234ULL;
typedef std::vector<uint8_t> Bytes;
static void put_u64(Bytes& b, uint64_t v){ for(int k=0;k<8;k++) b.push_back((uint8_t)(v>>(8*k))); }
static void trial_bytes(const char* tag, uint64_t i, uint8_t out[32]) {
    uint8_t buf[40]; std::memset(buf,0,32); std::strncpy((char*)buf,tag,31);
    for(int k=0;k<8;k++) buf[32+k]=(uint8_t)(i>>(8*k)); mcl_sha256(buf,sizeof(buf),out);
}
struct Tx { uint64_t chain_id, nonce, to, value; Bytes calldata; };
static Bytes canon(const Tx& t){ Bytes c; put_u64(c,t.chain_id); put_u64(c,t.nonce); put_u64(c,t.to); put_u64(c,t.value);
    put_u64(c,(uint64_t)t.calldata.size()); c.insert(c.end(),t.calldata.begin(),t.calldata.end()); return c; }
static void tag_of(const uint8_t K[32], const uint8_t S[32], const Tx& tx, uint64_t acct, uint64_t ver, uint8_t out[32]) {
    Bytes pre=canon(tx); put_u64(pre,tx.nonce); put_u64(pre,acct); put_u64(pre,ver);
    uint8_t ctx[32]; mcl_sha256(pre.data(),pre.size(),ctx);
    uint8_t keff[32],ktx[32]; mcl_keff_from_key_device(K,S,keff);
    mcl_kdf256(keff,"MCL-TxChallenge-v1",ctx,32,ktx,32);
    MCL_T4_Q30 e(ktx,0,PUBLIC_SEED,K_DEFAULT); e.gen_bytes(out,32);
}
static int ham(const uint8_t a[32], const uint8_t b[32]){ int h=0; for(int i=0;i<32;i++) h+=__builtin_popcount((unsigned)(a[i]^b[i])); return h; }
int main(int argc,char**argv){
    const int N   = argc>1? atoi(argv[1]) : 20000;   // A2 samples
    const int NF  = argc>2? atoi(argv[2]) : 2000;    // A1 trials per field
    std::printf("=== Paper-5 SS-VI.E adversarial evaluation (MCL-P5-ADVERSARIAL-2026-0905-001) ===\n");
    std::printf("engine v%s, BURNIN=%d, MCL_T4_Q30\n\n", MCL_VERSION_STRING, BURNIN);
    uint8_t K[32],S[32]; trial_bytes("MCL-P5-V3-KEY",0,K); trial_bytes("MCL-P5-V3-SDV",0,S);

    // ---- A1 per-field context sensitivity ----
    const char* fname[6]={"chain_id","nonce(counter)","to","value","calldata(16 B)","account_id/verifier_id"};
    std::printf("A1 per-field context sensitivity (one random bit flipped in that field only, n=%d each)\n",NF);
    std::printf("   field                    mean HD/256    min   max   verdict\n");
    bool a1ok=true;
    for(int f=0; f<6; f++){
        double s=0; int mn=256,mx=0;
        for(int i=0;i<NF;i++){
            uint8_t h[32]; trial_bytes("MCL-P5-V3-TX",(uint64_t)i,h);
            Tx t; t.chain_id=1; t.nonce=(uint64_t)i; std::memcpy(&t.to,h,8); std::memcpy(&t.value,h+8,8); t.value%=1000000;
            t.calldata.assign(h+16,h+16+16);
            uint64_t acct=1000, ver=1;
            uint8_t A[32]; tag_of(K,S,t,acct,ver,A);
            uint8_t hb[32]; trial_bytes("MCL-P5-A1BIT",(uint64_t)(f*1000000+i),hb);
            uint64_t r=0; std::memcpy(&r,hb,8);
            Tx t2=t; uint64_t acct2=acct, ver2=ver;
            switch(f){
              case 0: t2.chain_id ^= (1ULL<<(r%64)); break;
              case 1: t2.nonce    ^= (1ULL<<(r%64)); break;
              case 2: t2.to       ^= (1ULL<<(r%64)); break;
              case 3: t2.value    ^= (1ULL<<(r%64)); break;
              case 4: t2.calldata[(r%128)/8] ^= (uint8_t)(1u<<((r%128)%8)); break;
              case 5: if(r&1) acct2 ^= (1ULL<<(r%64)); else ver2 ^= (1ULL<<(r%64)); break;
            }
            uint8_t B[32]; tag_of(K,S,t2,acct2,ver2,B);
            int hd=ham(A,B); s+=hd; if(hd<mn)mn=hd; if(hd>mx)mx=hd;
        }
        double mean=s/NF, se=8.0/std::sqrt((double)NF), z=(mean-128.0)/se;
        bool ok = std::fabs(z)<4.0; a1ok = a1ok && ok;
        std::printf("   %-24s %8.3f    %4d  %4d   %s (z=%+.2f)\n", fname[f], mean, mn, mx, ok?"binds at full width":"ANOMALY", z);
    }
    std::printf("   A1 verdict: %s\n\n", a1ok?"every ctx field binds the tag at the null-model mean":"AT LEAST ONE FIELD ANOMALOUS");

    // ---- A2 first-order weight-leak ----
    std::printf("A2 first-order weight-leak test: %d keys x (360 weight bits) x (256 tag bits) = 92,160 correlations\n",N);
    const int WB=360, TB=256;
    std::vector<double> sw(WB,0), st(TB,0); std::vector<double> swt((size_t)WB*TB,0.0);
    std::vector<uint8_t> wbit(WB), tbit(TB);
    for(int i=0;i<N;i++){
        uint8_t key[32]; trial_bytes("MCL-P5-ADVKEY",(uint64_t)i,key);
        uint8_t kd[96]; mcl_kdf256(key,"MCL-T4-Q30-v1",(const uint8_t*)"\0\0\0\0\0\0\0\0",8,kd,96);
        MCL_Q30_Sextet w{}; uint32_t* wp=reinterpret_cast<uint32_t*>(&w);
        for(int l=0;l<12;l++){ uint64_t v=0; std::memcpy(&v,kd+8*l,8); wp[l]=(uint32_t)(2+(v%((1u<<30)-2))); }
        uint8_t tag[32]; { MCL_T4_Q30 e(key,0,PUBLIC_SEED,K_DEFAULT); e.gen_bytes(tag,32); }
        for(int l=0;l<12;l++) for(int b=0;b<30;b++) wbit[l*30+b]=(uint8_t)((wp[l]>>b)&1u);
        for(int b=0;b<TB;b++) tbit[b]=(uint8_t)((tag[b>>3]>>(b&7))&1u);
        for(int a=0;a<WB;a++){ sw[a]+=wbit[a]; if(wbit[a]) { double* row=&swt[(size_t)a*TB]; for(int b=0;b<TB;b++) row[b]+=tbit[b]; } }
        for(int b=0;b<TB;b++) st[b]+=tbit[b];
    }
    double maxabs=0; int ma=-1,mb=-1; double nf=1.0/std::sqrt((double)N);
    for(int a=0;a<WB;a++){ double pa=sw[a]/N; if(pa<=0||pa>=1) continue;
        for(int b=0;b<TB;b++){ double pb=st[b]/N; if(pb<=0||pb>=1) continue;
            double pab=swt[(size_t)a*TB+b]/N; double r=(pab-pa*pb)/std::sqrt(pa*(1-pa)*pb*(1-pb));
            if(std::fabs(r)>maxabs){ maxabs=std::fabs(r); ma=a; mb=b; } } }
    double zmax=maxabs/nf;
    // Bonferroni over 92,160 tests at alpha=0.001 -> two-sided threshold ~4.6 sigma
    std::printf("   noise floor 1/sqrt(N) = %.5f ; max |r| = %.5f at (weight bit %d [lane %d bit %d], tag bit %d) = %.2f sigma\n",
        nf, maxabs, ma, ma/30, ma%30, mb, zmax);
    std::printf("   Bonferroni threshold over 92,160 tests at alpha=0.001 is ~4.6 sigma -> %s\n",
        zmax<4.6? "NO first-order weight leak detected":"LEAK CANDIDATE -- investigate");
    std::printf("   A2 verdict (BURNIN=%d): %s\n", BURNIN, zmax<4.6? "negative result: the tag reveals no weight bit at first order":"POSITIVE -- see above");
    return 0;
}
