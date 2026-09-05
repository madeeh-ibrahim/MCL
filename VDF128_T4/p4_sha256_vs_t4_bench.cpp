// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// P4 review measurement 2026-09-05 (round 5, R5-6): per-iteration cost of VDF128-T4 v2 against a SHA-256 hash chain on the SAME host,
// interleaved and best-of-5. SHA-256 is measured two ways: (a) one compression per link through the ARMv8 SHA-2 instructions
// (the floor: no library overhead; cross-checked against CommonCrypto), (b) the system library call CC_SHA256.
// Build: clang++ -std=c++17 -O3 -DNDEBUG -march=armv8-a+crypto -I.. p4_sha256_vs_t4_bench.cpp -o p4_sha256_vs_t4_bench
// SHA-256 hash chain using the ARMv8 SHA-2 instructions directly (one 64-byte block per
// link: 32-byte state + fixed padding). This is the per-iteration FLOOR of a hash chain on
// this host, without any library call overhead. Also cross-checked against CommonCrypto.
#include "mcl_vdf128_t4_v2.hpp"
#include <arm_neon.h>
#include <sys/sysctl.h>
#include <string>
#include <CommonCrypto/CommonDigest.h>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <cstdint>
static const uint32_t K[64] = {
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
// one compression of a 64-byte block (big-endian words) into state[8]
static inline void compress(uint32_t st[8], const uint8_t blk[64]) {
    uint32x4_t ab = vld1q_u32(st), ef = vld1q_u32(st+4);
    uint32x4_t a0 = ab, e0 = ef;
    uint32x4_t w0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk)));
    uint32x4_t w1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk+16)));
    uint32x4_t w2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk+32)));
    uint32x4_t w3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(blk+48)));
    uint32x4_t t0, t1, tmp;
    #define RND(w, k) tmp = vaddq_u32(w, vld1q_u32(K + k)); t0 = ab; ab = vsha256hq_u32(ab, ef, tmp); ef = vsha256h2q_u32(ef, t0, tmp);
    #define SCHED(a, b, c, d) a = vsha256su1q_u32(vsha256su0q_u32(a, b), c, d);
    RND(w0,0)  SCHED(w0,w1,w2,w3)
    RND(w1,4)  SCHED(w1,w2,w3,w0)
    RND(w2,8)  SCHED(w2,w3,w0,w1)
    RND(w3,12) SCHED(w3,w0,w1,w2)
    RND(w0,16) SCHED(w0,w1,w2,w3)
    RND(w1,20) SCHED(w1,w2,w3,w0)
    RND(w2,24) SCHED(w2,w3,w0,w1)
    RND(w3,28) SCHED(w3,w0,w1,w2)
    RND(w0,32) SCHED(w0,w1,w2,w3)
    RND(w1,36) SCHED(w1,w2,w3,w0)
    RND(w2,40) SCHED(w2,w3,w0,w1)
    RND(w3,44) SCHED(w3,w0,w1,w2)
    RND(w0,48) RND(w1,52) RND(w2,56) RND(w3,60)
    vst1q_u32(st, vaddq_u32(ab, a0)); vst1q_u32(st+4, vaddq_u32(ef, e0));
    (void)t1;
}
static inline void sha256_32(const uint8_t in[32], uint8_t out[32]) {
    uint32_t st[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    uint8_t blk[64]; std::memcpy(blk, in, 32); blk[32] = 0x80; std::memset(blk+33, 0, 29); blk[62] = 0x01; blk[63] = 0x00; // length 256 bits = 0x0100
    compress(st, blk);
    for (int i = 0; i < 8; i++) { out[4*i] = (uint8_t)(st[i]>>24); out[4*i+1] = (uint8_t)(st[i]>>16); out[4*i+2] = (uint8_t)(st[i]>>8); out[4*i+3] = (uint8_t)st[i]; }
}

static std::string hw() { char buf[256]; size_t len = sizeof buf; return sysctlbyname("machdep.cpu.brand_string", buf, &len, nullptr, 0) == 0 ? std::string(buf) : "unknown"; }
int main(){
    uint8_t a[32], b[32]; std::memset(a, 0x5a, 32); std::memcpy(b, a, 32);
    for (int i = 0; i < 1000; i++) { sha256_32(a, a); CC_SHA256(b, 32, b); }
    std::printf("host: %s\nintrinsics vs CommonCrypto after 1000 links: %s\n", hw().c_str(), std::memcmp(a,b,32)==0 ? "IDENTICAL" : "MISMATCH");
    const char* X = "MCL-VDF128-T4 benchmark input 2026-08-21"; const size_t XL = std::strlen(X);
    const MCL_Q30_Sextet W = mcl_vdf128v2_weights((const uint8_t*)X, XL); const int64_t kp = mcl_q30_K_phase(K_DEFAULT);
    double bt4 = 1e30, bsi = 1e30, bsl = 1e30; const uint64_t MT = 100000000, MS = 20000000, ML = 5000000;
    VDF128_State s = mcl_vdf128_init((const uint8_t*)X, XL);
    for (int rep = 0; rep < 5; rep++) {
        auto t0 = std::chrono::steady_clock::now(); for (uint64_t i = 0; i < MT; i++) mcl_q30t4_iterate_raw(s.t1,s.t2,s.t3,s.t4,W,kp);
        double d = std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count()/MT*1e9; if (d < bt4) bt4 = d;
        t0 = std::chrono::steady_clock::now(); for (uint64_t i = 0; i < MS; i++) sha256_32(a, a);
        d = std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count()/MS*1e9; if (d < bsi) bsi = d;
        t0 = std::chrono::steady_clock::now(); for (uint64_t i = 0; i < ML; i++) CC_SHA256(b, 32, b);
        d = std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count()/ML*1e9; if (d < bsl) bsl = d;
        std::printf("  rep %d: T4 %.1f ns  SHA-256/intrinsics %.1f ns  SHA-256/library %.1f ns\n", rep, bt4, bsi, bsl);
    }
    std::printf("BEST-OF-5  VDF128-T4 v2 iterate: %.1f ns (%.1f M/s)   SHA-256 chain, ARMv8 SHA-2 instructions: %.1f ns (%.1f M/s)   SHA-256 chain, system library: %.1f ns (%.1f M/s)   [t1 %08x, a0 %02x]\n",
        bt4, 1e3/bt4, bsi, 1e3/bsi, bsl, 1e3/bsl, s.t1, a[0]);
    return 0;
}
