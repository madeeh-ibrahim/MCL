// ============================================================================
// mcl_txauth_v3_claim4.cpp — Paper-5 tx-auth profile v3: full-width transaction
//                            binding THROUGH THE DERIVATION (patent Claim 4 route)
// ============================================================================
// Date: 2026-08-21.  Engine: mcl_core.hpp v8.1.1 (UNMODIFIED, header-only).
//
// WHY v3 SUPERSEDES v2
//   v2 closed defect D1 (the 64-bit seed fold) by moving the transaction hash
//   into an HMAC wrap, which left the engine output constant per device and
//   demoted the engine to a key-derivation function. That was one route, not
//   the only one. The FILED patent (PCT/IB2026/058860) supplies a better one:
//
//     Claim 4  — "receiving a public challenge value and including said public
//                 challenge value in the input to said deterministic derivation
//                 function, whereby said map-defining parameters, and hence said
//                 cryptographic output data, are cryptographically bound to said
//                 public challenge value without exposing said secret key."
//     Claim 28 — the device-bound secret enters the SAME derivation input.
//     Claim 8  — the seed is public; no secret is carried solely in the state.
//     [0005]   — the initial state cannot represent a wide secret at all
//                 (N*w bits); the PARAMETER space is what is sized to carry it.
//
//   A transaction hash is exactly a "public challenge value". Routing it into
//   the DERIVATION rather than the seed binds the tag to the full 256 bits and
//   keeps the engine a per-transaction MAC. No engine change; no HMAC wrap.
//
// PROFILE v3
//   ctx   = SHA-256( canon(TX) || LE64(nonce) || LE64(account) || LE64(verifier) )
//   K_eff = KDF(K,     "MCL-KeyDevice-v1",   S_device)      // Claim 28
//   K_tx  = KDF(K_eff, "MCL-TxChallenge-v1", ctx)           // Claim 4
//   weights = twelve coupling weights derived from K_tx     // [0018]-[0019]
//   tag   = MCL_T4(public_seed, weights).gen_bytes(32)      // engine IS the MAC
//
//   Offline enumeration (referee gap G2) is closed by width, not by a wrapper:
//   the searchable secret is the 256-bit key in the durable weights
//   (2^128 post-Grover), not a small (p, q) pair.
//
// Build: clang++ -std=c++17 -O2 mcl_txauth_v3_claim4.cpp -o mcl_txauth_v3_claim4
// ============================================================================
#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <set>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Key256 = std::array<uint8_t, 32>;
using clk = std::chrono::high_resolution_clock;

static Bytes sha256(const Bytes& m) {
    Bytes d(32); CC_SHA256(m.data(), (CC_LONG)m.size(), d.data()); return d;
}
static void put_u64(Bytes& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((uint8_t)(x >> (8 * i)));
}
static bool eq(const Bytes& a, const Bytes& b) {
    return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size()) == 0;
}
static int ham(const Bytes& a, const Bytes& b) {
    int h = 0; for (size_t i = 0; i < a.size(); i++) h += __builtin_popcount((unsigned)(a[i]^b[i]));
    return h;
}

struct Tx { uint64_t chain_id, nonce, to, value; Bytes calldata; };
static Bytes canon(const Tx& t) {
    Bytes c; put_u64(c, t.chain_id); put_u64(c, t.nonce); put_u64(c, t.to); put_u64(c, t.value);
    put_u64(c, (uint64_t)t.calldata.size());
    c.insert(c.end(), t.calldata.begin(), t.calldata.end());
    return c;
}
struct Device { Key256 K, S_device; uint64_t account; };

static const uint64_t PUBLIC_SEED = 12345678901234ULL;   // public, per Claim 8

static Bytes tag_v3(const Device& d, const Tx& tx, uint64_t verifier) {
    Bytes pre = canon(tx);
    put_u64(pre, tx.nonce); put_u64(pre, d.account); put_u64(pre, verifier);
    Bytes ctx = sha256(pre);                                  // 256-bit public challenge
    uint8_t keff[32], ktx[32];
    mcl_keff_from_key_device(d.K.data(), d.S_device.data(), keff);        // Claim 28
    mcl_kdf256(keff, "MCL-TxChallenge-v1", ctx.data(), ctx.size(), ktx, 32); // Claim 4
    CouplingSextet cs = mcl_t4_params_from_key(ktx, 0);
    Bytes tag(32);
    { MCL_T4 eng(PUBLIC_SEED, cs, K_DEFAULT); eng.gen_bytes(tag.data(), 32); }
    secure_zero(keff, 32); secure_zero(ktx, 32); secure_zero(&cs, sizeof(cs));
    return tag;
}

static int pass = 0, fail = 0;
static void check(const char* n, bool ok) {
    std::printf("  %-58s %s\n", n, ok ? "PASS" : "FAIL"); (ok ? pass : fail)++;
}

int main() {
    std::printf("mcl_txauth_v3_claim4 — Paper-5 profile v3 (patent Claim 4 route)\n");
    std::printf("engine: MCL v%s (%s), UNMODIFIED\n\n", MCL_VERSION_STRING, MCL_VERSION_DATE);
    std::mt19937_64 rng(20260821);
    auto key = [&]{ Key256 k; uint64_t* w=(uint64_t*)k.data(); for(int i=0;i<4;i++) w[i]=rng(); return k; };
    Device A{key(), key(), 0xA1}, B{key(), key(), 0xB2};
    const uint64_t V1 = 0x5601, V2 = 0x5602;

    // 1. Determinism + per-transaction dependence (the property v2 lost)
    {
        Tx t1{1, 7, 0x1111, 100, {0xde,0xad,0xbe,0xef}};
        Tx t2 = t1; t2.value = 101;
        Bytes a = tag_v3(A, t1, V1), a2 = tag_v3(A, t1, V1), b = tag_v3(A, t2, V1);
        check("V3-1 deterministic (same TX -> same tag)", eq(a, a2));
        check("V3-2 tag DEPENDS on the transaction (engine is the MAC)", !eq(a, b));
        std::printf("     HD(t1,t2) = %d/256\n", ham(a, b));
    }
    // 2. D1: a CONSTRUCTED legacy collision pair must separate here
    {
        // Genuine FNV-1a collision (mcl_d1_collision.cpp, Brent search,
        // 1.63e10 probes). The review of 2026-08-21 established that the pair
        // previously used here did NOT collide under the legacy fold, so the
        // test was mislabelled; these two payloads do.
        const uint64_t PAY_A = 0x4f4f2eb40f25758dULL, PAY_B = 0x14349ecffb59edc0ULL;
        auto mk = [](uint64_t pay) {
            Tx t{1, 42, 0x1111222233334444ULL, 1000, Bytes(8, 0)};
            for (int i = 0; i < 8; i++) t.calldata[(size_t)i] = (uint8_t)(pay >> (8 * i));
            return t;
        };
        Tx t1 = mk(PAY_A), t2 = mk(PAY_B);
        uint64_t f1 = 0, f2 = 0;
        { Bytes c = canon(t1); f1 = 0xCBF29CE484222325ULL;
          for (uint8_t b : c) { f1 ^= b; f1 *= 0x100000001B3ULL; } }
        { Bytes c = canon(t2); f2 = 0xCBF29CE484222325ULL;
          for (uint8_t b : c) { f2 ^= b; f2 *= 0x100000001B3ULL; } }
        Bytes a = tag_v3(A, t1, V1), b = tag_v3(A, t2, V1);
        check("V3-3a pair genuinely collides under the legacy 64-bit fold", f1 == f2);
        check("V3-3b derivation route separates it (D1 closed)", !eq(a, b));
        std::printf("     legacy FNV both %016llx | v3 HD = %d/256\n",
                    (unsigned long long)f1, ham(a, b));
    }
    // 3. calldata mutation with identical display fields
    {
        Tx t1{1, 9, 0x2222, 500, {0xaa,0xbb,0xcc,0xdd}};
        Tx t2 = t1; t2.calldata[3] = 0xde;
        check("V3-4 calldata mutation changes the tag", !eq(tag_v3(A,t1,V1), tag_v3(A,t2,V1)));
    }
    // 4. D2: device secret governs the weights (one byte flip -> different tag)
    {
        Tx t{1, 11, 0x3333, 7, {0x01}};
        Device A2 = A; A2.S_device[0] ^= 0x01;
        Bytes a = tag_v3(A, t, V1), a2 = tag_v3(A2, t, V1);
        check("V3-5 D2: 1-bit S_device flip changes the tag", !eq(a, a2));
        std::printf("     HD = %d/256\n", ham(a, a2));
    }
    // 5. cross-account and cross-verifier binding
    {
        Tx t{1, 13, 0x4444, 9, {0x02}};
        check("V3-6 cross-verifier binding (V1 tag != V2 tag)", !eq(tag_v3(A,t,V1), tag_v3(A,t,V2)));
        Device A_asB = A; A_asB.account = 0xB2;
        check("V3-7 account binding (same key, other account -> different tag)",
              !eq(tag_v3(A,t,V1), tag_v3(A_asB,t,V1)));
        check("V3-8 different device -> different tag", !eq(tag_v3(A,t,V1), tag_v3(B,t,V1)));
    }
    // 6. uniqueness + avalanche at protocol-logic scale
    {
        std::set<Bytes> seen; double hsum = 0; int hmin = 256, hmax = 0; const int N = 500;
        for (int i = 0; i < N; i++) {
            Tx t{1, (uint64_t)(1000+i), rng(), rng()%1000, {}};
            t.calldata.resize(8); for (auto& c : t.calldata) c = (uint8_t)rng();
            Bytes a = tag_v3(A, t, V1); seen.insert(a);
            Tx tf = t; tf.calldata[0] ^= 1;
            int h = ham(a, tag_v3(A, tf, V1)); hsum += h;
            if (h < hmin) hmin = h; if (h > hmax) hmax = h;
        }
        std::printf("     uniqueness %zu/%d | avalanche mean %.2f/256 (min %d, max %d)\n",
                    seen.size(), N, hsum/N, hmin, hmax);
        check("V3-9 all tags distinct", (int)seen.size() == N);
        check("V3-10 avalanche mean within 128 +/- 6", hsum/N > 122 && hsum/N < 134);
    }
    // 7. cost per transaction (the price of per-transaction derivation)
    {
        Tx t{1, 99, 0x5555, 1, {0x03}};
        const int R = 200;
        auto t0 = clk::now();
        for (int i = 0; i < R; i++) { t.nonce = (uint64_t)i; Bytes x = tag_v3(A, t, V1); (void)x; }
        double ms = std::chrono::duration<double, std::milli>(clk::now() - t0).count() / R;
        std::printf("     per-transaction cost: %.3f ms (KDF x2 + 12-weight derivation "
                    "+ 10k burn-in + 32B output)\n", ms);
        check("V3-11 cost under 10 ms per transaction", ms < 10.0);
    }

    std::printf("\nRESULT: %d PASS / %d FAIL\n", pass, fail);
    std::printf(fail == 0
        ? "v3 closes D1 at full width WITHOUT demoting the engine: the transaction\n"
          "enters the derivation as the public challenge of Claim 4, the device secret\n"
          "as the device-bound value of Claim 28, and the seed stays public per Claim 8.\n"
        : "FAILURES PRESENT.\n");
    return fail == 0 ? 0 : 1;
}
