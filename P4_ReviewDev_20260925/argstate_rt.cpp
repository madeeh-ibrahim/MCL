// P4 development 2026-09-25 (review #16, test #1 first step): Algorithm 1 reference = lines 1-117 of vdf128_t4v3_standalone.cpp (its main removed) + the argument-state reformulation and a new main below; not part of any release.
// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
//
// vdf128_t4_standalone.cpp — Paper 4, Algorithm 1 (VDF128-T4) re-implemented FROM THE PAPER'S
// TEXT (VDF128-T4 v3, per-input weights, 2026-09-05) with no engine code: its own SHA-256, KDF, weight derivation, table loader, four-oscillator
// Gauss-Seidel iterate and output finalization. Reproduces Appendix Vector 5 and exits non-zero if
// any intermediate differs. Build: c++ -std=c++17 -O2 -o vdf128_t4_standalone vdf128_t4_standalone.cpp
// Run:   ./vdf128_t4_standalone q30_lut_int32le.bin        (table = the normative byte sequence)
//        ./vdf128_t4_standalone                            (regenerate the table with sin(); the
//                                                            SHA-256 check then tells you whether your
//                                                            libm reproduces the normative table)
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <string>
#include <vector>

// ---------------------------------------------------------------- SHA-256 (FIPS 180-4)
struct Sha256 {
    uint32_t h[8]; uint64_t len = 0; uint8_t buf[64]; size_t n = 0;
    static uint32_t rotr(uint32_t x, int r) { return (x >> r) | (x << (32 - r)); }
    static const uint32_t K[64];
    Sha256() { const uint32_t iv[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}; std::memcpy(h, iv, 32); }
    void block(const uint8_t* p) {
        uint32_t w[64]; for (int i = 0; i < 16; i++) w[i] = (uint32_t)p[4*i] << 24 | (uint32_t)p[4*i+1] << 16 | (uint32_t)p[4*i+2] << 8 | p[4*i+3];
        for (int i = 16; i < 64; i++) { uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3), s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10); w[i] = w[i-16] + s0 + w[i-7] + s1; }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; i++) { uint32_t S1 = rotr(e,6)^rotr(e,11)^rotr(e,25), ch = (e&f)^(~e&g), t1 = hh+S1+ch+K[i]+w[i], S0 = rotr(a,2)^rotr(a,13)^rotr(a,22), mj = (a&b)^(a&c)^(b&c), t2 = S0+mj; hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2; }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    void update(const uint8_t* p, size_t m) { len += m; while (m) { size_t k = 64 - n; if (k > m) k = m; std::memcpy(buf + n, p, k); n += k; p += k; m -= k; if (n == 64) { block(buf); n = 0; } } }
    void final(uint8_t out[32]) { uint64_t bits = len * 8; uint8_t pad = 0x80; update(&pad, 1); uint8_t z = 0; while (n != 56) update(&z, 1); uint8_t L[8]; for (int i = 0; i < 8; i++) L[i] = (uint8_t)(bits >> (56 - 8*i)); update(L, 8); for (int i = 0; i < 8; i++) { out[4*i] = (uint8_t)(h[i] >> 24); out[4*i+1] = (uint8_t)(h[i] >> 16); out[4*i+2] = (uint8_t)(h[i] >> 8); out[4*i+3] = (uint8_t)h[i]; } }
};
const uint32_t Sha256::K[64] = {0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static void sha256(const uint8_t* p, size_t n, uint8_t out[32]) { Sha256 s; s.update(p, n); s.final(out); }

// ---------------------------------------------------------------- helpers
static uint32_t le32(const uint8_t* p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t le64(const uint8_t* p) { uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8*i); return v; }
static void put32(uint8_t* p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8*i)); }
static void put64(uint8_t* p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8*i)); }
static std::string hex(const uint8_t* p, size_t n) { static const char* d = "0123456789abcdef"; std::string s; for (size_t i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; } return s; }
static uint32_t crc32(const uint8_t* d, size_t n) { uint32_t c = 0xFFFFFFFFu; for (size_t i = 0; i < n; i++) { c ^= d[i]; for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u))); } return ~c; }

// KDF (Algorithm 1): block_i = SHA-256(key || label || info || BE32(i)), concatenated
static void kdf(const uint8_t key[32], const char* label, const uint8_t* info, size_t infolen, uint8_t* out, size_t outlen) {
    std::vector<uint8_t> pre(32 + std::strlen(label) + infolen + 4);
    std::memcpy(pre.data(), key, 32); std::memcpy(pre.data() + 32, label, std::strlen(label)); std::memcpy(pre.data() + 32 + std::strlen(label), info, infolen);
    size_t off = 0; uint32_t i = 0;
    while (off < outlen) { uint8_t* be = pre.data() + pre.size() - 4; be[0] = (uint8_t)(i >> 24); be[1] = (uint8_t)(i >> 16); be[2] = (uint8_t)(i >> 8); be[3] = (uint8_t)i; uint8_t blk[32]; sha256(pre.data(), pre.size(), blk); size_t k = outlen - off < 32 ? outlen - off : 32; std::memcpy(out + off, blk, k); off += k; i++; }
}

// ---------------------------------------------------------------- Algorithm 1
static const double TWO_PI = 6.283185307179586;
static const double OMEGA[4] = {0.6180339887498949, 1.3247179572447460, 0.4142135623730950, 0.7182818284590452}; // phi-1, rho, sqrt2-1, e-2
static uint32_t omega_q32(int i) { return (uint32_t)(OMEGA[i] / TWO_PI * 4294967296.0); }
static int64_t k_phase(double K) { return (int64_t)(K * 4294967296.0 / TWO_PI); }

struct Weights { uint32_t w[12]; }; // p12 q12 p13 q13 p14 q14 p23 q23 p24 q24 p34 q34

static int parity_rank(const int64_t w[12]) {   // rank over GF(2) of the 12x4 parity matrix of the weights
    static const int I[6] = {0,0,0,1,1,2}, J[6] = {1,2,3,2,3,3}; unsigned rows[12]; int n = 0;
    for (int e = 0; e < 6; e++) { unsigned p = (unsigned)(w[2*e] & 1), q = (unsigned)(w[2*e+1] & 1); rows[n++] = (q << I[e]) | (p << J[e]); rows[n++] = (p << I[e]) | (q << J[e]); }
    int rank = 0;
    for (int bit = 0; bit < 4; bit++) { int piv = -1; for (int r = rank; r < 12; r++) if ((rows[r] >> bit) & 1u) { piv = r; break; } if (piv < 0) continue;
        unsigned t = rows[piv]; rows[piv] = rows[rank]; rows[rank] = t; for (int r = 0; r < 12; r++) if (r != rank && ((rows[r] >> bit) & 1u)) rows[r] ^= rows[rank]; rank++; }
    return rank;
}
static Weights input_weights(const uint8_t hx[32]) {   // v2: W_x = params_from_key(SHA-256(x), challenge 0)
    uint8_t info[8] = {0}; uint8_t kd[96]; kdf(hx, "VDF128-T4-v3-kdf", info, 8, kd, 96);
    const int64_t R = (1LL << 30) - 2; int64_t w[12];
    for (int l = 0; l < 12; l++) w[l] = 2 + (int64_t)(le64(kd + 8*l) % (uint64_t)R);
    auto fix = [&](int64_t& p, int64_t& q) { if (p == q) q = 2 + ((q - 2 + 1) % R); };
    for (int e = 0; e < 6; e++) fix(w[2*e], w[2*e+1]);
    for (int k = 0; k < 96; k++) { if (parity_rank(w) == 4) break; int lane = 11 - (k % 12); w[lane] = 2 + ((w[lane] - 2 + 1) % R); fix(w[lane & ~1], w[lane | 1]); }
    Weights W; for (int i = 0; i < 12; i++) W.w[i] = (uint32_t)w[i]; return W;
}
struct State { uint32_t t[4]; };
static State init(const uint8_t* x, size_t xl) { uint8_t h[32]; sha256(x, xl, h); State s; for (int i = 0; i < 4; i++) s.t[i] = le32(h + 4*i) ^ le32(h + 16 + 4*i); return s; }
static void iterate(State& s, const Weights& W, const int32_t* lut, int64_t kp) {
    // pair index for {i,j}: (0,1)->0 (0,2)->1 (0,3)->2 (1,2)->3 (1,3)->4 (2,3)->5
    static const int pair[4][4] = {{-1,0,1,2},{0,-1,3,4},{1,3,-1,5},{2,4,5,-1}};
    for (int i = 0; i < 4; i++) {
        uint32_t acc = omega_q32(i);
        for (int j = 0; j < 4; j++) if (j != i) {
            uint32_t p = W.w[2*pair[i][j]], q = W.w[2*pair[i][j] + 1];
            uint32_t a = (uint32_t)(p * s.t[j] - q * s.t[i]);
            int32_t sv = lut[a >> 16];
            acc += (uint32_t)(((uint64_t)((int64_t)kp * (int64_t)sv)) >> 30);
        }
        s.t[i] += acc;
    }
}
// ---------------------------------------------------------------- argument-state reformulation (review test #1, first step)
// The twelve coupling arguments A[i][j] = p_ij*t_j - q_ij*t_i are carried as state. With the table
// INC[idx] = low32(((uint64)(K_phase*LUT[idx])) >> 30) and per-input premultiplied tables
// TP_e[idx] = p_e*INC[idx], TQ_e[idx] = q_e*INC[idx] (twelve tables, rebuilt once per input), a sub-step is
//   idx_j = A[i][j] >> 16 (three reads) ; Delta = omega_i + sum INC[idx_j]  (feeds t_i only, off the chain)
//   A[i][j] -= q*omega_i + sum_k TQ_e[idx_k] ; A[j][i] += p*omega_i + sum_k TP_e[idx_k]
// so the dependency chain between sub-steps is: table read -> multi-operand add -> top 16 bits -> table read.
// No multiplication remains on it (the reference chain per sub-step: 32-bit multiply, subtract, table read,
// 33x31-bit product, add). Output must equal the reference bit for bit.
struct ArgState { uint32_t A[4][4]; uint32_t t[4]; };
static const int PAIR[4][4] = {{-1,0,1,2},{0,-1,3,4},{1,3,-1,5},{2,4,5,-1}};
struct Tables { std::vector<uint32_t> INC, TP[6], TQ[6]; uint32_t pw[6], qw[6], om[4]; };
static Tables build_tables(const Weights& W, const int32_t* lut, int64_t kp) {
    Tables T; T.INC.resize(65536);
    for (int i = 0; i < 65536; i++) T.INC[i] = (uint32_t)(((uint64_t)((int64_t)kp * (int64_t)lut[i])) >> 30);
    for (int e = 0; e < 6; e++) { T.pw[e] = W.w[2*e]; T.qw[e] = W.w[2*e+1]; T.TP[e].resize(65536); T.TQ[e].resize(65536);
        for (int i = 0; i < 65536; i++) { T.TP[e][i] = T.pw[e] * T.INC[i]; T.TQ[e][i] = T.qw[e] * T.INC[i]; } }
    for (int i = 0; i < 4; i++) T.om[i] = omega_q32(i);
    return T;
}
static ArgState to_args(const State& s, const Tables& T) { ArgState a; for (int i = 0; i < 4; i++) { a.t[i] = s.t[i]; for (int j = 0; j < 4; j++) if (j != i) { int e = PAIR[i][j]; a.A[i][j] = T.pw[e] * s.t[j] - T.qw[e] * s.t[i]; } } return a; }
static void iterate_args(ArgState& a, const Tables& T) {
    for (int i = 0; i < 4; i++) {
        int js[3], n = 0; for (int j = 0; j < 4; j++) if (j != i) js[n++] = j;
        uint32_t ix[3] = { a.A[i][js[0]] >> 16, a.A[i][js[1]] >> 16, a.A[i][js[2]] >> 16 };
        a.t[i] += T.om[i] + T.INC[ix[0]] + T.INC[ix[1]] + T.INC[ix[2]];             // off the dependency chain
        for (int m = 0; m < 3; m++) { int j = js[m], e = PAIR[i][j];
            a.A[i][j] -= T.qw[e] * T.om[i] + T.TQ[e][ix[0]] + T.TQ[e][ix[1]] + T.TQ[e][ix[2]];   // q*om is a per-input constant
            a.A[j][i] += T.pw[e] * T.om[i] + T.TP[e][ix[0]] + T.TP[e][ix[1]] + T.TP[e][ix[2]]; }
    }
}
#include <chrono>
int main(int argc, char** argv) {
    static int32_t lut[65536]; static uint8_t tb[65536*4];
    FILE* f = std::fopen(argv[1], "rb"); if (!f || std::fread(tb, 1, sizeof tb, f) != sizeof tb) { std::fprintf(stderr, "table?\n"); return 2; } std::fclose(f);
    for (int i = 0; i < 65536; i++) lut[i] = (int32_t)le32(tb + 4*i);
    const int64_t kp = k_phase(12.0); const uint64_t B = 10000;
    auto run = [&](const char* xs, uint64_t N, bool reform, double& ns_per_it, std::string& yhex) {
        const uint8_t* x = (const uint8_t*)xs; size_t xl = std::strlen(xs); uint8_t hx[32]; sha256(x, xl, hx); Weights W = input_weights(hx);
        State s = init(x, xl); auto t0 = std::chrono::steady_clock::now();
        if (!reform) { for (uint64_t i = 0; i < B + N; i++) iterate(s, W, lut, kp); }
        else { Tables T = build_tables(W, lut, kp); t0 = std::chrono::steady_clock::now(); ArgState a = to_args(s, T); for (uint64_t i = 0; i < B + N; i++) iterate_args(a, T); for (int i = 0; i < 4; i++) s.t[i] = a.t[i];
               // consistency: the carried arguments must equal those recomputed from the final state
               ArgState chk = to_args(s, T); for (int i = 0; i < 4; i++) for (int j = 0; j < 4; j++) if (j != i && chk.A[i][j] != a.A[i][j]) { std::printf("argument drift!\n"); std::exit(3); } }
        double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(); ns_per_it = sec * 1e9 / (double)(B + N);
        uint8_t pre[80]; for (int i = 0; i < 4; i++) put32(pre + 4*i, s.t[i]); std::memcpy(pre + 16, hx, 32); put64(pre + 48, N); static const char otag[24] = "VDF128-T4-v3-out"; std::memcpy(pre + 56, otag, 24);
        uint8_t y[32]; sha256(pre, 80, y); yhex = hex(y, 32);
    };
    struct Case { const char* x; uint64_t N; const char* want; } cases[] = {
        {"VDF128-T4-KAT-01", 1000, "75d76880369509b44a709e1f33c350f257e76eae29de7cc537f0a05113321273"},
        {"VDF128-T4-KAT-01", 100000, "ee2ff4adb22c0ce9d01ce2223b0f3c780145a33a74b2ea4c3cca6014dcce2a21"} };
    int bad = 0;
    for (auto& c : cases) { double r_ns, a_ns; std::string ry, ay; run(c.x, c.N, false, r_ns, ry); run(c.x, c.N, true, a_ns, ay);
        std::printf("x=%s N=%llu | reference y=%.16s… (%s) | argument-state y=%.16s… (%s)\n", c.x, (unsigned long long)c.N, ry.c_str(), ry == c.want ? "= paper" : "≠ paper", ay.c_str(), ay == ry ? "= reference" : "≠ REFERENCE");
        bad += (ry != c.want) + (ay != ry); }
    // 200 further random inputs, N = 20,000 each: bit-exact agreement
    int agree = 0; for (int k = 0; k < 200; k++) { char buf[40]; std::snprintf(buf, sizeof buf, "argstate-check-%d", k); double r1, r2; std::string y1, y2; run(buf, 20000, false, r1, y1); run(buf, 20000, true, r2, y2); agree += (y1 == y2); }
    std::printf("200 further inputs, N = 20,000: %d/200 outputs bit-identical\n", agree); bad += (agree != 200);
    double r_ns, a_ns; std::string ry, ay; run("VDF128-T4-KAT-01", 20000000, false, r_ns, ry); run("VDF128-T4-KAT-01", 20000000, true, a_ns, ay);
    std::printf("timing (this CPU, N = 2e7): reference %.2f ns/iter, argument-state %.2f ns/iter; outputs %s\n", r_ns, a_ns, ry == ay ? "identical" : "DIFFER");
    return bad ? 1 : 0;
}
