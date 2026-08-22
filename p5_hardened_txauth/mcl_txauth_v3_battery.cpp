/*
 * ============================================================================
 * mcl_txauth_v3_battery.cpp — Paper-5 SS-VI battery re-executed on profile v3
 *                             (patent Claim-4 route: TX -> derivation input)
 * Doc ID: MCL-P5-V3BATTERY-2026-0821-001
 * ============================================================================
 * Produces exactly the rows Paper 5 SS-VI reports, on the v3 tag construction:
 *   ctx   = SHA-256( canon(TX) || LE64(nonce) || LE64(account) || LE64(verifier) )
 *   K_eff = KDF(K,     "MCL-KeyDevice-v1",   S_device)      [Claim 28]
 *   K_tx  = KDF(K_eff, "MCL-TxChallenge-v1", ctx)           [Claim 4]
 *   tag   = MCL_T4(public seed, weights(K_tx)).gen_bytes(32) [Claim 8: public seed]
 * Engine mcl_core.hpp v8.1.1 UNMODIFIED. Deterministic (fixed seeds).
 * Build: clang++ -std=c++17 -O3 -DNDEBUG mcl_txauth_v3_battery.cpp -o mcl_txauth_v3_battery
 * Usage: ./mcl_txauth_v3_battery [far_trials=100000] [threads=2]
 * ============================================================================
 */
#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Key256 = std::array<uint8_t, 32>;
using Tag = std::array<uint8_t, 32>;
using clk = std::chrono::high_resolution_clock;

static Bytes sha256v(const Bytes& m) { Bytes d(32); CC_SHA256(m.data(), (CC_LONG)m.size(), d.data()); return d; }
static void put_u64(Bytes& v, uint64_t x) { for (int i=0;i<8;i++) v.push_back((uint8_t)(x>>(8*i))); }
static int ham(const Tag& a, const Tag& b) {
    int h=0; for (int i=0;i<32;i++) h+=__builtin_popcount((unsigned)(a[i]^b[i])); return h;
}
struct Tx { uint64_t chain_id, nonce, to, value; Bytes calldata; };
static Bytes canon(const Tx& t) {
    Bytes c; put_u64(c,t.chain_id); put_u64(c,t.nonce); put_u64(c,t.to); put_u64(c,t.value);
    put_u64(c,(uint64_t)t.calldata.size()); c.insert(c.end(),t.calldata.begin(),t.calldata.end()); return c;
}
struct Device { Key256 K, S; uint64_t account; };
static const uint64_t PUBLIC_SEED = 12345678901234ULL;

static Tag tag_v3(const Device& d, const Tx& tx, uint64_t verifier) {
    Bytes pre = canon(tx); put_u64(pre,tx.nonce); put_u64(pre,d.account); put_u64(pre,verifier);
    Bytes ctx = sha256v(pre);
    uint8_t keff[32], ktx[32];
    mcl_keff_from_key_device(d.K.data(), d.S.data(), keff);
    mcl_kdf256(keff, "MCL-TxChallenge-v1", ctx.data(), ctx.size(), ktx, 32);
    CouplingSextet cs = mcl_t4_params_from_key(ktx, 0);
    Tag out{};
    { MCL_T4 eng(PUBLIC_SEED, cs, K_DEFAULT); eng.gen_bytes(out.data(), 32); }
    secure_zero(keff,32); secure_zero(ktx,32); secure_zero(&cs,sizeof(cs));
    return out;
}

// Deterministic trial material from SHA-256(tag || LE64(i)).
static void trial_bytes(const char* tag, uint64_t i, uint8_t out[32]) {
    uint8_t buf[32+8]; std::memset(buf,0,32); std::strncpy((char*)buf, tag, 31);
    for (int k=0;k<8;k++) buf[32+k]=(uint8_t)(i>>(k*8));
    CC_SHA256(buf,sizeof(buf),out);
}
static Tx tx_of(uint64_t i) {
    uint8_t h[32]; trial_bytes("MCL-P5-V3-TX", i, h);
    Tx t; t.chain_id=1; t.nonce=i;
    std::memcpy(&t.to,h,8); std::memcpy(&t.value,h+8,8); t.value%=1000000;
    t.calldata.assign(h+16, h+16+16);
    return t;
}
static Device dev_of(uint64_t i) {
    Device d{}; uint8_t h[32];
    trial_bytes("MCL-P5-V3-KEY", i, h); std::memcpy(d.K.data(),h,32);
    trial_bytes("MCL-P5-V3-SDV", i, h); std::memcpy(d.S.data(),h,32);
    d.account = 0xA0 + i; return d;
}

static int pass=0, fail=0;
static void check(const char* n, bool ok) {
    std::printf("  %-58s %s\n", n, ok?"PASS":"FAIL"); (ok?pass:fail)++;
}

// Verifier with single-use nonce ledger (lifecycle layer, unchanged from v2).
struct Verifier {
    uint64_t id; std::map<uint64_t,Device> enrolled;
    std::map<uint64_t,std::set<uint64_t>> spent;
    bool authorize(uint64_t acct, const Tx& tx, const Tag& t) {
        auto it=enrolled.find(acct); if (it==enrolled.end()) return false;
        auto& sp=spent[acct]; if (sp.count(tx.nonce)) return false; sp.insert(tx.nonce);
        return tag_v3(it->second, tx, id)==t;
    }
    bool rebind(uint64_t acct, const Key256& newS, const Tx& rb, const Tag& t) {
        if (!authorize(acct, rb, t)) return false;
        enrolled[acct].S = newS; return true;
    }
};

int main(int argc, char** argv) {
    const uint64_t FAR_TRIALS = (argc>1)?std::strtoull(argv[1],nullptr,10):100000ull;
    const unsigned THREADS = (argc>2)?(unsigned)std::atoi(argv[2]):2u;
    std::printf("================================================================\n");
    std::printf("  Paper-5 SS-VI battery on profile v3 (patent Claim-4 route)\n");
    std::printf("  MCL-P5-V3BATTERY-2026-0821-001  engine mcl_core v%s UNMODIFIED\n", MCL_VERSION_STRING);
    std::printf("  FAR trials %llu | threads %u\n", (unsigned long long)FAR_TRIALS, THREADS);
    std::printf("================================================================\n\n");

    Device A = dev_of(1), B = dev_of(2);
    const uint64_t V1=0x5601, V2=0x5602;

    // --- Test 1: uniqueness (5,000 distinct transactions) ---
    {
        std::vector<Tag> tags(5000);
        std::vector<std::thread> th;
        for (unsigned t=0;t<THREADS;t++) th.emplace_back([&,t]{
            for (size_t i=t;i<tags.size();i+=THREADS) tags[i]=tag_v3(A, tx_of(1000000+i), V1);
        });
        for (auto& x:th) x.join();
        std::set<Tag> s(tags.begin(),tags.end());
        std::printf("T1 uniqueness: %zu distinct / 5000\n", s.size());
        check("T1 5000/5000 unique tags", s.size()==5000);
    }
    // --- Test 2: transaction avalanche (1-bit TX flip), 5,000 pairs ---
    {
        const int N=5000; std::vector<int> hd((size_t)N);
        std::vector<std::thread> th;
        for (unsigned t=0;t<THREADS;t++) th.emplace_back([&,t]{
            for (int i=(int)t;i<N;i+=(int)THREADS) {
                Tx a=tx_of(2000000+(uint64_t)i);
                Tag ta=tag_v3(A,a,V1);
                Tx b=a; b.calldata[(size_t)(i%16)]^=(uint8_t)(1u<<(i%8));
                hd[(size_t)i]=ham(ta, tag_v3(A,b,V1));
            }
        });
        for (auto& x:th) x.join();
        double s=0; int mn=256,mx=0; for(int h:hd){s+=h; mn=std::min(mn,h); mx=std::max(mx,h);}
        std::printf("T2 TX avalanche: mean %.3f/256 (min %d, max %d), n=%d\n", s/N, mn, mx, N);
        check("T2 avalanche mean within 128 +/- 3", s/N>125.0 && s/N<131.0);
    }
    // --- Test 3: byte-frequency chi^2 over 20,000 tags ---
    {
        const int N=20000; std::vector<std::array<uint64_t,256>> h((size_t)THREADS);
        for (auto& a:h) a.fill(0);
        std::vector<std::thread> th;
        for (unsigned t=0;t<THREADS;t++) th.emplace_back([&,t]{
            for (int i=(int)t;i<N;i+=(int)THREADS) {
                Tag g=tag_v3(A, tx_of(3000000+(uint64_t)i), V1);
                for (uint8_t b:g) h[t][b]++;
            }
        });
        for (auto& x:th) x.join();
        std::array<uint64_t,256> hist{}; hist.fill(0);
        for (auto& a:h) for (int b=0;b<256;b++) hist[(size_t)b]+=a[(size_t)b];
        double e=(double)N*32.0/256.0, chi=0;
        for (uint64_t c:hist){ double d=(double)c-e; chi+=d*d/e; }
        std::printf("T3 byte chi2: %.1f (df 255, crit.001 ~330.5)\n", chi);
        check("T3 byte chi2 below the 0.001 critical value", chi<330.5);
    }
    // --- Test 4: device binding, 10 devices pairwise ---
    {
        Tx t=tx_of(4000001);
        std::vector<Tag> tg;
        for (uint64_t i=0;i<10;i++){ Device d=dev_of(100+i); d.account=A.account; tg.push_back(tag_v3(d,t,V1)); }
        double s=0; int n=0, mn=256, mx=0;
        for (size_t i=0;i<tg.size();i++) for (size_t j=i+1;j<tg.size();j++){
            int h=ham(tg[i],tg[j]); s+=h; n++; mn=std::min(mn,h); mx=std::max(mx,h);
        }
        std::printf("T4 device binding: %d pairs, mean %.2f/256 (%.1f%%), range %d-%d\n",
                    n, s/n, 100.0*s/n/256.0, mn, mx);
        check("T4 inter-device Hamming ~50%", s/n>115 && s/n<141);
    }
    // --- Test 5: no gradient — 1-bit neighbours of K and of S_device ---
    {
        Tx t=tx_of(5000001); Tag ref=tag_v3(A,t,V1);
        double s=0; int n=0, mn=256, mx=0, near=0;
        for (int which=0; which<2; which++)
            for (int bit=0; bit<256; bit+=4) {           // 64 probes per secret
                Device d=A;
                if (which==0) d.K[(size_t)(bit/8)] ^= (uint8_t)(1u<<(bit%8));
                else          d.S[(size_t)(bit/8)] ^= (uint8_t)(1u<<(bit%8));
                int h=ham(ref, tag_v3(d,t,V1));
                s+=h; n++; mn=std::min(mn,h); mx=std::max(mx,h); if (h<=32) near++;
            }
        std::printf("T5 no gradient: %d single-bit-neighbour secrets, mean %.2f/256 (%.1f%%),"
                    " range %d-%d, near-misses(HD<=32) %d\n", n, s/n, 100.0*s/n/256.0, mn, mx, near);
        check("T5 flat landscape, zero near-misses", near==0 && s/n>115 && s/n<141);
    }
    // --- Test 6: lifecycle (replay / cross-account / cross-verifier / reuse / double-submit / rebinding) ---
    {
        Verifier v1{V1,{},{}}, v2{V2,{},{}};
        v1.enrolled[A.account]=A; v1.enrolled[B.account]=B; v2.enrolled[A.account]=A;
        Tx t1=tx_of(6000001); t1.nonce=6000001;
        Tag g1=tag_v3(A,t1,V1);
        bool ok1=v1.authorize(A.account,t1,g1), replay=v1.authorize(A.account,t1,g1);
        Tx t2=tx_of(6000002); t2.nonce=6000002;
        Tag gx=tag_v3(A,t2,V1);
        bool cross_v = v2.authorize(A.account,t2,gx);
        Tx t3=tx_of(6000003); t3.nonce=6000003;
        Tag g3=tag_v3(A,t3,V1);
        bool cross_a = v1.authorize(B.account,t3,g3);
        Tx t4=tx_of(6000004); t4.nonce=6000004;
        Tag bad{}; bad.fill(0x42);
        bool wrong = v1.authorize(A.account,t4,bad);
        Tag g4=tag_v3(A,t4,V1);
        bool reuse = v1.authorize(A.account,t4,g4);
        Tx t5=tx_of(6000005); t5.nonce=6000005;
        Tag g5=tag_v3(A,t5,V1);
        bool d1=v1.authorize(A.account,t5,g5), d2=v1.authorize(A.account,t5,g5);
        check("T6a legitimate authorization accepted", ok1);
        check("T6b replay of consumed nonce rejected", !replay);
        check("T6c cross-verifier transfer rejected", !cross_v);
        check("T6d cross-account transfer rejected", !cross_a);
        check("T6e reuse after failed attempt rejected", !wrong && !reuse);
        check("T6f double-submit: exactly one acceptance", d1 && !d2);
        // rebinding requires current-device presence
        Verifier vr{0x5603,{},{}}; Device C=dev_of(3); vr.enrolled[C.account]=C;
        Tx rb=tx_of(6100001); rb.nonce=6100001;
        Device forged=C; forged.S=dev_of(999).S;
        bool atk = vr.rebind(C.account, dev_of(998).S, rb, tag_v3(forged,rb,vr.id));
        Tx rb2=tx_of(6100002); rb2.nonce=6100002;
        bool legit = vr.rebind(C.account, dev_of(998).S, rb2, tag_v3(vr.enrolled[C.account],rb2,vr.id));
        check("T6g rebinding without device secret rejected", !atk);
        check("T6h rebinding with device presence accepted", legit);
    }
    // --- Test 7: FAR — random wrong devices forging a fixed target ---
    {
        Tx target=tx_of(7000001);
        Tag truth=tag_v3(A,target,V1);
        std::atomic<uint64_t> acc{0}, near{0};
        std::vector<double> hsum((size_t)THREADS,0.0);
        auto t0=clk::now();
        std::vector<std::thread> th;
        for (unsigned t=0;t<THREADS;t++) th.emplace_back([&,t]{
            for (uint64_t i=t;i<FAR_TRIALS;i+=THREADS) {
                Device g=dev_of(10000000+i); g.account=A.account;
                Tag gt=tag_v3(g,target,V1);
                if (gt==truth) acc++;
                int h=ham(gt,truth); hsum[t]+=h; if (h<=32) near++;
            }
        });
        for (auto& x:th) x.join();
        double wall=std::chrono::duration<double>(clk::now()-t0).count();
        double s=0; for(double d:hsum) s+=d;
        std::printf("T7 FAR: %llu accepts / %llu trials | mean HD %.3f/256 | near-misses %llu"
                    " | %.1f s (%.0f tags/s)\n",
                    (unsigned long long)acc.load(), (unsigned long long)FAR_TRIALS,
                    s/(double)FAR_TRIALS, (unsigned long long)near.load(), wall,
                    (double)FAR_TRIALS/wall);
        check("T7 zero forgeries by random wrong devices", acc.load()==0);
        check("T7b zero near-misses (flat landscape at scale)", near.load()==0);
    }
    // --- Test 8: single-thread throughput ---
    {
        Tx t=tx_of(8000001); const int R=300;
        auto t0=clk::now();
        for (int i=0;i<R;i++){ t.nonce=(uint64_t)i; Tag g=tag_v3(A,t,V1); (void)g; }
        double ms=std::chrono::duration<double,std::milli>(clk::now()-t0).count()/R;
        std::printf("T8 throughput: %.3f ms/tag single-thread = %.0f tags/s\n", ms, 1000.0/ms);
        check("T8 latency under 10 ms/tag", ms<10.0);
    }

    std::printf("\nRESULT: %d PASS / %d FAIL\n", pass, fail);
    return fail==0?0:1;
}
