/*
 * ============================================================================
 * mcl_d1_collision.cpp — CONSTRUCTS a genuine defect-D1 collision and shows
 *                        that the derivation route (v3) defeats it
 * Doc ID: MCL-P5-D1COLL-2026-0821-001
 * ============================================================================
 * WHY THIS EXISTS
 *   The 2026-08-21 code review found that the D1 "attack reproduction" in
 *   mcl_txauth_hardened.cpp (test C-1a) compared a message with ITSELF — a
 *   tautology that proved nothing — and that the pair used in
 *   mcl_txauth_v3_claim4.cpp (V3-3) does NOT in fact collide under the legacy
 *   64-bit fold (verified: FNV 13ad72b7... vs 2cad797e...). The claim "D1 is
 *   closed" therefore rested on the referees' demonstration, not on ours.
 *   This program removes that gap: it SEARCHES for and EXHIBITS a real
 *   collision, then measures both protocols on it.
 *
 * THE DEFECT
 *   The published path computes  seed = FNV1a-64(canon(TX)) ^ nonce(counter)
 *   and  Tag = MCL_T2(seed, p, q).gen_bytes(32).  FNV-1a is a 64-bit,
 *   non-cryptographic hash. Two transactions whose canonical bytes share an
 *   FNV-1a value therefore share the seed, hence the tag, for the SAME
 *   counter — a signed transaction is interchangeable with its collision
 *   partner while the verifier's counter check still passes.
 *
 * THE SEARCH
 *   Brent's cycle-finding algorithm over f(x) = FNV1a(prefix || LE64(x)),
 *   restricted to an 8-byte call-data payload so the FNV state of the fixed
 *   canonical prefix is precomputed and each probe costs eight multiply-xor
 *   steps. Expected work is birthday-scale, ~2^32 probes, memoryless.
 *   The result is a genuine pair, printed in full so it can be re-verified
 *   independently of this program.
 *
 * Build: clang++ -std=c++17 -O3 -DNDEBUG mcl_d1_collision.cpp -o mcl_d1_collision
 * ============================================================================
 */
#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdlib>

using Bytes = std::vector<uint8_t>;
using Key256 = std::array<uint8_t, 32>;
using clk = std::chrono::high_resolution_clock;

static const uint64_t FNV_OFF = 0xCBF29CE484222325ULL, FNV_P = 0x100000001B3ULL;
static const uint64_t PUBLIC_SEED = 12345678901234ULL;

static void put_u64(Bytes& v, uint64_t x) { for (int i=0;i<8;i++) v.push_back((uint8_t)(x>>(8*i))); }
static Bytes sha256v(const Bytes& m){ Bytes d(32); CC_SHA256(m.data(),(CC_LONG)m.size(),d.data()); return d; }

struct Tx { uint64_t chain_id, nonce, to, value; Bytes calldata; };
static Bytes canon(const Tx& t){
    Bytes c; put_u64(c,t.chain_id); put_u64(c,t.nonce); put_u64(c,t.to); put_u64(c,t.value);
    put_u64(c,(uint64_t)t.calldata.size()); c.insert(c.end(),t.calldata.begin(),t.calldata.end()); return c;
}
static uint64_t fnv1a(const Bytes& d){ uint64_t h=FNV_OFF; for(uint8_t b:d){h^=b;h*=FNV_P;} return h; }

// FNV state after the fixed canonical prefix, then eight payload bytes.
static uint64_t g_prefix_state;
static inline uint64_t f_probe(uint64_t x){
    uint64_t h=g_prefix_state;
    for (int i=0;i<8;i++){ h ^= (uint8_t)(x>>(8*i)); h *= FNV_P; }
    return h;
}

// ---- legacy (superseded) path -------------------------------------------
// EXACT replica of the published mcl_txn_verify.cpp: hash_tx applies the
// fmix64 finaliser to the FNV-1a value, and the nonce is fmix64(counter).
// (Verified line-for-line against MCL_Public_Code/mcl_txn_verify.cpp:215-241.)
// fmix64 is a bijection, so an FNV-1a collision survives it unchanged — the
// exhibited pair therefore collides on the published path itself, not merely
// on a simplification of it.
static uint64_t fmix64_(uint64_t z){
    z=(z^(z>>33))*0xFF51AFD7ED558CCDULL; z=(z^(z>>33))*0xC4CEB9FE1A85EC53ULL;
    return z^(z>>33);
}
static uint64_t nonce_from_counter(uint64_t c){ return fmix64_(c); }
static Bytes legacy_tag(const Tx& t, uint64_t counter, int64_t p, int64_t q){
    uint64_t seed = fmix64_(fnv1a(canon(t))) ^ nonce_from_counter(counter);
    if (!seed) seed=1;
    Bytes tag(32); MCL_T2 eng(seed,p,q,K_DEFAULT); eng.gen_bytes(tag.data(),32); return tag;
}
// ---- v3 derivation route -------------------------------------------------
static Bytes v3_tag(const Key256& K, const Key256& S, uint64_t account,
                    const Tx& t, uint64_t verifier){
    Bytes pre = canon(t); put_u64(pre,t.nonce); put_u64(pre,account); put_u64(pre,verifier);
    Bytes ctx = sha256v(pre);
    uint8_t keff[32], ktx[32];
    mcl_keff_from_key_device(K.data(), S.data(), keff);
    mcl_kdf256(keff,"MCL-TxChallenge-v1",ctx.data(),ctx.size(),ktx,32);
    CouplingSextet cs = mcl_t4_params_from_key(ktx,0);
    Bytes tag(32);
    { MCL_T4 eng(PUBLIC_SEED,cs,K_DEFAULT); eng.gen_bytes(tag.data(),32); }
    secure_zero(keff,32); secure_zero(ktx,32); secure_zero(&cs,sizeof(cs));
    return tag;
}
static int ham(const Bytes& a,const Bytes& b){
    int h=0; for(size_t i=0;i<a.size();i++) h+=__builtin_popcount((unsigned)(a[i]^b[i])); return h;
}
static void hexdump(const char* lab, const Bytes& b){
    std::printf("  %-14s ",lab); for(uint8_t x:b) std::printf("%02x",x); std::printf("\n");
}

int main(){
    std::printf("================================================================\n");
    std::printf("  Defect D1 — constructed collision on the superseded fold\n");
    std::printf("  MCL-P5-D1COLL-2026-0821-001   engine mcl_core v%s UNMODIFIED\n", MCL_VERSION_STRING);
    std::printf("================================================================\n\n");

    // Fixed canonical prefix: everything except the 8-byte call-data payload.
    Tx tmpl{1, 42, 0x1111222233334444ULL, 1000, Bytes(8,0)};
    { Bytes c = canon(tmpl); c.resize(c.size()-8);          // strip the payload
      uint64_t h=FNV_OFF; for(uint8_t b:c){h^=b;h*=FNV_P;} g_prefix_state=h; }

    // ---- Brent's cycle finding on f_probe ---------------------------------
    if (const char* pre = std::getenv("MCL_D1_PAIR")) {   // known pair, skip the search
        (void)pre;
        uint64_t A=0x4f4f2eb40f25758dULL, B=0x14349ecffb59edc0ULL;
        Tx t1=tmpl, t2=tmpl;
        for (int i=0;i<8;i++){ t1.calldata[(size_t)i]=(uint8_t)(A>>(8*i));
                               t2.calldata[(size_t)i]=(uint8_t)(B>>(8*i)); }
        std::printf("known pair: FNV %016llx / %016llx  equal=%s\n",
            (unsigned long long)fnv1a(canon(t1)),(unsigned long long)fnv1a(canon(t2)),
            fnv1a(canon(t1))==fnv1a(canon(t2))?"YES":"NO");
        Bytes L1=legacy_tag(t1,42,3,5), L2=legacy_tag(t2,42,3,5);
        std::printf("published-path (fmix64 both terms) tags identical: %s\n",
            (L1==L2)?"YES — D1 reproduced on the REAL published construction":"no");
        hexdump("tag(A)",L1); hexdump("tag(B)",L2);
        return (L1==L2)?0:1;
    }
    std::printf("searching for an FNV-1a collision (Brent, birthday scale ~2^32)...\n");
    auto t0=clk::now();
    uint64_t power=1, lam=1, tortoise=0x0123456789ABCDEFULL, hare=f_probe(tortoise);
    uint64_t probes=1;
    while (tortoise!=hare){
        if (power==lam){ tortoise=hare; power<<=1; lam=0; }
        hare=f_probe(hare); lam++; probes++;
    }
    uint64_t mu=0; tortoise=0x0123456789ABCDEFULL; hare=tortoise;
    for (uint64_t i=0;i<lam;i++) hare=f_probe(hare);
    while (tortoise!=hare){ tortoise=f_probe(tortoise); hare=f_probe(hare); mu++; probes+=2; }
    // x = element entering the cycle from the tail; y = its cycle counterpart
    uint64_t x=0x0123456789ABCDEFULL; for(uint64_t i=0;i<mu;i++) x=f_probe(x);
    uint64_t y=x; for(uint64_t i=0;i<lam;i++) y=f_probe(y);
    // step back one: predecessors of the meeting point collide
    uint64_t px=0x0123456789ABCDEFULL; for(uint64_t i=0;i+1<mu;i++) px=f_probe(px);
    uint64_t py=y; for(uint64_t i=0;i+1<lam;i++) py=f_probe(py);
    if (mu==0){ std::printf("  (mu = 0; using the cycle pair directly)\n"); px=x; py=y; }
    double secs=std::chrono::duration<double>(clk::now()-t0).count();
    std::printf("  lambda = %llu, mu = %llu, probes ~ %llu, %.1f s\n\n",
                (unsigned long long)lam,(unsigned long long)mu,(unsigned long long)probes,secs);

    if (f_probe(px)!=f_probe(py) || px==py){
        std::printf("SEARCH DID NOT YIELD A USABLE PAIR (px==py or unequal images).\n");
        return 1;
    }
    // ---- exhibit the two transactions -------------------------------------
    Tx t1=tmpl, t2=tmpl;
    for (int i=0;i<8;i++){ t1.calldata[(size_t)i]=(uint8_t)(px>>(8*i)); t2.calldata[(size_t)i]=(uint8_t)(py>>(8*i)); }
    uint64_t h1=fnv1a(canon(t1)), h2=fnv1a(canon(t2));
    std::printf("COLLISION FOUND — two distinct transactions, identical FNV-1a:\n");
    std::printf("  payload A      %016llx\n  payload B      %016llx\n",
                (unsigned long long)px,(unsigned long long)py);
    std::printf("  FNV1a(canon A) %016llx\n  FNV1a(canon B) %016llx   equal = %s\n\n",
                (unsigned long long)h1,(unsigned long long)h2, h1==h2?"YES":"NO");
    if (h1!=h2){ std::printf("INTERNAL ERROR: images differ.\n"); return 1; }

    // ---- the attack on the superseded path --------------------------------
    const uint64_t COUNTER=42;
    Bytes L1=legacy_tag(t1,COUNTER,3,5), L2=legacy_tag(t2,COUNTER,3,5);
    std::printf("SUPERSEDED PATH  Tag = MCL_T2(FNV1a(canon) ^ nonce(c), p, q):\n");
    hexdump("tag(A)",L1); hexdump("tag(B)",L2);
    bool broken = (L1==L2);
    std::printf("  identical = %s   -> D1 %s\n\n", broken?"YES":"no",
                broken?"REPRODUCED: distinct transactions share one tag":"not reproduced");

    // ---- the same pair under the derivation route -------------------------
    Key256 K{},S{}; for(int i=0;i<32;i++){K[(size_t)i]=(uint8_t)(0x11*i+7); S[(size_t)i]=(uint8_t)(0x2B*i+3);}
    Bytes V1=v3_tag(K,S,0xA1,t1,0x5601), V2=v3_tag(K,S,0xA1,t2,0x5601);
    std::printf("DERIVATION ROUTE (v3)  Tag = MCL_T4(seed_pub, params(KDF(K_eff, ctx))):\n");
    hexdump("tag(A)",V1); hexdump("tag(B)",V2);
    bool fixed = !(V1==V2);
    std::printf("  identical = %s   Hamming = %d/256   -> %s\n\n",
                (V1==V2)?"YES":"no", ham(V1,V2),
                fixed?"D1 CLOSED on a genuine collision pair":"STILL BROKEN");

    std::printf("VERDICT: %s\n", (broken&&fixed)
        ? "attack reproduced on the superseded path AND defeated by the derivation route"
        : "inconclusive — see above");
    return (broken&&fixed)?0:1;
}
