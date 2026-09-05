/*
 * p5_system_eval.cpp — Paper 5 §VII system evaluation: the CONSOLIDATED MCL wallet stack
 * against a hash-based stack performing the SAME three roles, on the same host and harness.
 *
 * Roles per wallet device (all at a 256-bit key-material target):
 *   R1 enrollment   : derive one channel identity from a parent/master secret
 *   R2 authenticate : per-transaction tag generation, and the verifier's recomputation
 *   R3 generate     : 1 KiB of pseudorandom output (nonces / blinding)
 * MCL stack : one engine + one stored 256-bit secret (channel identity via derive_child_v2;
 *             tag via Eqs. (3a)-(3) on MCL_T4_Q30; PRNG via the same engine).
 * Hash stack: KDF1/SHA-256 derivation + HMAC-SHA-256 tag + SHA-256 counter-mode DRBG.
 * Also reports the mutable per-channel state and the read-only table footprint.
 * The point of the experiment is an HONEST accounting, including where MCL loses.
 * Doc ID: MCL-P5-SYSEVAL-2026-0905-001
 * Build: clang++ -std=c++17 -O3 -DNDEBUG -I.. -I../keyed_q30_PQ -I../hd_v2 p5_system_eval.cpp -o p5_system_eval
 */
#include "mcl_core.hpp"
#include "mcl_keyed_q30.hpp"
#include "mcl_hd_v2.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <vector>
static const uint64_t PUBLIC_SEED = 12345678901234ULL;
using Clock = std::chrono::steady_clock;
static double ms_since(Clock::time_point t0){ return std::chrono::duration<double,std::milli>(Clock::now()-t0).count(); }

static void hmac_sha256(const uint8_t key[32], const uint8_t* m, size_t n, uint8_t out[32]) {
    uint8_t ki[64], ko[64]; std::memset(ki,0x36,64); std::memset(ko,0x5c,64);
    for (int i=0;i<32;i++){ ki[i]^=key[i]; ko[i]^=key[i]; }
    std::vector<uint8_t> in; in.insert(in.end(), ki, ki+64); in.insert(in.end(), m, m+n);
    uint8_t ih[32]; mcl_sha256(in.data(), in.size(), ih);
    uint8_t ob[96]; std::memcpy(ob,ko,64); std::memcpy(ob+64,ih,32); mcl_sha256(ob,96,out);
}
// SHA-256 counter-mode DRBG (the hash-stack PRNG role)
static void sha256_drbg(const uint8_t key[32], uint8_t* out, size_t n) {
    uint8_t buf[40]; std::memcpy(buf,key,32); uint64_t c=0; size_t done=0;
    while (done<n) { for(int k=0;k<8;k++) buf[32+k]=(uint8_t)(c>>(8*k));
        uint8_t blk[32]; mcl_sha256(buf,40,blk);
        size_t take = (n-done<32)? (n-done):32; std::memcpy(out+done,blk,take); done+=take; c++; }
}
int main(int argc, char** argv) {
    const int REP  = argc>1? atoi(argv[1]) : 200;      // MCL ops (ms-scale)
    const int REPH = argc>2? atoi(argv[2]) : 200000;  // hash ops (sub-microsecond) -- needs many more reps
    uint8_t K[32], ctx[32], sink=0;
    for (int i=0;i<32;i++){ K[i]=(uint8_t)(i*7+1); ctx[i]=(uint8_t)(i*13+5); }
    std::printf("=== Paper-5 SS-VII system evaluation (MCL-P5-SYSEVAL-2026-0905-001) ===\n");
    std::printf("engine mcl_core v%s + keyed sidecar (MCL_T4_Q30), single thread, reps=%d\n\n", MCL_VERSION_STRING, REP);

    // ---------------- R1 enrollment: derive one channel identity ----------------
    { auto t0=Clock::now(); volatile int64_t acc=0;
      for(int i=0;i<REP;i++){ DerivedKey d=derive_child_v2(PUBLIC_SEED,3,5,i,1000000,K_DEFAULT); acc+=d.p; }
      double a=ms_since(t0)/REP; std::printf("R1 enrollment  MCL derive_child_v2 (bare)        : %10.6f ms  (n=%d)\n", a, REP); sink^=(uint8_t)acc; }
    { auto t0=Clock::now(); volatile int64_t acc=0; int n=(REP<20?REP:20);
      for(int i=0;i<n;i++){ DerivedKey d=derive_child_safe_v2(PUBLIC_SEED,3,5,i,1000000,K_DEFAULT); acc+=d.p; }
      double a=ms_since(t0)/n; std::printf("R1 enrollment  MCL derive_child_safe_v2 (+screen): %10.6f ms  (n=%d)\n", a, n); sink^=(uint8_t)acc; }
    { auto t0=Clock::now(); uint8_t o[32];
      for(int i=0;i<REPH;i++){ uint8_t info[8]; for(int k=0;k<8;k++) info[k]=(uint8_t)(i>>(8*k)); mcl_kdf256(K,"MCL-Chan-v1",info,8,o,32); }
      double a=ms_since(t0)/REPH; std::printf("R1 enrollment  hash KDF1/SHA-256 -> 256-bit key  : %10.6f ms  (%.3f us, n=%d)\n", a, a*1000.0, REPH); sink^=o[0]; }

    // ---------------- R2 authenticate: tag generation ----------------
    { auto t0=Clock::now(); uint8_t tag[32];
      for(int i=0;i<REP;i++){ uint8_t keff[32],ktx[32]; mcl_keff_from_key_device(K,K,keff);
        mcl_kdf256(keff,"MCL-TxChallenge-v1",ctx,32,ktx,32);
        MCL_T4_Q30 e(ktx,0,PUBLIC_SEED,K_DEFAULT); e.gen_bytes(tag,32); }
      double a=ms_since(t0)/REP; std::printf("\nR2 auth        MCL tag, Eqs. (3a)-(3), Q30      : %10.6f ms  (n=%d)\n", a, REP); sink^=tag[0]; }
    { auto t0=Clock::now(); uint8_t tag[32];
      for(int i=0;i<REPH;i++){ uint8_t km[32]; mcl_kdf256(K,"MCL-TxMAC-v1",nullptr,0,km,32); hmac_sha256(km,ctx,32,tag); }
      double a=ms_since(t0)/REPH; std::printf("R2 auth        hash HMAC-SHA-256 tag            : %10.6f ms  (%.3f us, n=%d)\n", a, a*1000.0, REPH); sink^=tag[0]; }
    { auto t0=Clock::now(); uint8_t tag[32];
      for(int i=0;i<REP;i++){ uint8_t km[32],ktx[32],th[32]; mcl_kdf256(K,"MCL-TxMAC-v1",nullptr,0,km,32);
        hmac_sha256(km,ctx,32,th); mcl_kdf256(K,"MCL-TxChallenge-v1",ctx,32,ktx,32);
        MCL_T4_Q30 e(ktx,0,PUBLIC_SEED,K_DEFAULT); e.gen_bytes(tag,32); for(int j=0;j<32;j++) tag[j]^=th[j]; }
      double a=ms_since(t0)/REP; std::printf("R2 auth        MCL combiner, Eq. (7)            : %10.6f ms  (n=%d)\n", a, REP); sink^=tag[0]; }

    // ---------------- R3 generate: 1 KiB ----------------
    { std::vector<uint8_t> b(1024); auto t0=Clock::now();
      for(int i=0;i<REP;i++){ MCL_T4_Q30 e(K,0,PUBLIC_SEED,K_DEFAULT); e.gen_bytes(b.data(),1024); }
      double a=ms_since(t0)/REP; std::printf("\nR3 prng 1 KiB  MCL engine (same engine, reused)  : %10.6f ms  (n=%d)\n", a, REP); sink^=b[0]; }
    { std::vector<uint8_t> b(1024); const int n=REPH/10; auto t0=Clock::now();
      for(int i=0;i<n;i++) sha256_drbg(K,b.data(),1024);
      double a=ms_since(t0)/n; std::printf("R3 prng 1 KiB  hash SHA-256 counter DRBG        : %10.6f ms  (%.3f us, n=%d)\n", a, a*1000.0, n); sink^=b[0]; }

    // ---------------- footprint ----------------
    std::printf("\n-- footprint --\n");
    std::printf("mutable per-channel state : MCL_T4_Q30 %zu B   |  SHA-256 ctx ~104 B (32 B chaining + 64 B block + counter)\n", sizeof(MCL_T4_Q30));
    std::printf("read-only table           : MCL sine LUT 65,536 x int32 = %zu B (262,144; quarter-wave form 65,536 B)  |  hash stack 0 B\n", (size_t)65536*4);
    std::printf("stored secrets (3 roles)  : MCL 1 x 256-bit  |  hash stack 1 x 256-bit (same key, distinct labels)\n");
    std::printf("distinct primitives       : MCL 1 (engine) + SHA-256 for the KDF  |  hash stack 1 (SHA-256) for all three roles\n");
    std::printf("(sink=%u)\n",(unsigned)sink);
    return 0;
}
