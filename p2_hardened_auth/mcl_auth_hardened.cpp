// ============================================================================
// mcl_auth_hardened.cpp — Paper-2 hardened challenge-response profile (v2)
// ============================================================================
// Date: 2026-08-21.  Engine: mcl_core.hpp v8.1.1 (unmodified, header-only).
//
// WHAT THIS IS
// The E2/TIFS referee round (FivePersona 2026-07-11/18) established three
// protocol-level gaps in the Paper-2 authentication profile as published:
//   (G1) the challenge reaches the engine through a 64-bit seed, so any two
//        challenges agreeing on the folded value produce identical responses
//        (the 2^64-fold class; demonstrated by the referees on the txn path);
//   (G2) the raw engine response is the transcript, so one observed (C, R)
//        pair enables OFFLINE enumeration of the (p, q) parameter space;
//   (G3) no challenge lifecycle: nothing prevents replay, cross-verifier /
//        cross-account transfer, or reuse of a challenge after a failure.
// This harness implements the hardened profile that closes all three and
// validates it with an adversarial battery. It is a PROTOCOL-LOGIC harness:
// the large-N statistical campaigns of Paper 2 §VI remain a separate,
// required follow-up on this profile before the paper text adopts it.
//
// HARDENED PROFILE (v2)
//   Secure element holds:  (p, q, K)  — device coupling identity (as in v1)
//                          K_wrap     — independent 256-bit wrap key
//   Challenge C: 256 bits, CSPRNG, issued per (account, verifier), SINGLE-USE:
//                consumed on the first verification attempt, success OR fail.
//   ctx   = C (32 B) || IMSI (8 B) || verifier_id (8 B)
//   seed  = low64(SHA-256(ctx)) | 1          // engine requires nonzero seed
//   raw   = 32 engine bytes from MCL_T2(seed, p, q, K)   // never transmitted
//   R     = HMAC-SHA-256(K_wrap, ctx || raw)
// Closure map: full-width C + ids inside the HMAC context closes G1 (a seed
// collision no longer collapses R) and binds verifier/account; K_wrap closes
// G2 (checking a candidate (p, q) against a transcript requires K_wrap, so a
// transcript alone no longer feeds offline parameter search); the single-use
// ledger closes G3.  The chaotic engine keeps its Paper-2 role: (p, q) is the
// device-bound identity whose full-width sensitivity the campaigns measure.
//
// LEGACY MODEL USED FOR THE CONTRAST TEST ONLY (T-H): seed = XOR-fold of the
// four challenge words, response = raw engine bytes (the published v1 shape).
//
// Build:  clang++ -std=c++17 -O2 mcl_auth_hardened.cpp -o mcl_auth_hardened
// (CommonCrypto ships with macOS; no OpenSSL dependency.)
// Deterministic: fixed RNG seeds; output is byte-stable across runs.
// ============================================================================

#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <array>
#include <cstdio>
#include <cstring>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
using Key256 = std::array<uint8_t, 32>;

static Bytes sha256(const Bytes& m) {
    Bytes d(CC_SHA256_DIGEST_LENGTH);
    CC_SHA256(m.data(), (CC_LONG)m.size(), d.data());
    return d;
}
static Bytes hmac_sha256(const Key256& k, const Bytes& m) {
    Bytes d(CC_SHA256_DIGEST_LENGTH);
    CCHmac(kCCHmacAlgSHA256, k.data(), k.size(), m.data(), m.size(), d.data());
    return d;
}
static bool ct_equal(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    uint8_t acc = 0;
    for (size_t i = 0; i < a.size(); i++) acc |= (uint8_t)(a[i] ^ b[i]);
    return acc == 0;
}
static void put_u64(Bytes& v, uint64_t x) {
    for (int i = 0; i < 8; i++) v.push_back((uint8_t)(x >> (8 * i)));
}

// ---------------------------------------------------------------- protocol --
struct Challenge { std::array<uint64_t, 4> w; };   // 256-bit wide challenge

struct DeviceSecret {                              // contents of the SE
    int64_t p, q; double K; Key256 k_wrap;
};

static Bytes make_ctx(const Challenge& c, uint64_t imsi, uint64_t verifier) {
    Bytes ctx;
    for (uint64_t w : c.w) put_u64(ctx, w);
    put_u64(ctx, imsi);
    put_u64(ctx, verifier);
    return ctx;
}

// Device side (runs inside the SE): raw engine bytes never leave this function.
static Bytes respond_v2(const DeviceSecret& d, const Challenge& c,
                        uint64_t imsi, uint64_t verifier, Bytes* leak_raw = nullptr) {
    Bytes ctx = make_ctx(c, imsi, verifier);
    Bytes h = sha256(ctx);
    uint64_t seed = 0;
    std::memcpy(&seed, h.data(), 8);
    seed |= 1;                                     // engine contract: seed != 0
    Bytes raw(32);
    {
        MCL_T2 eng(seed, d.p, d.q, d.K);
        eng.gen_bytes(raw.data(), (int64_t)raw.size());
    }                                              // dtor erases chaotic state
    if (leak_raw) *leak_raw = raw;                 // test T-I introspection only
    Bytes msg = ctx; msg.insert(msg.end(), raw.begin(), raw.end());
    return hmac_sha256(d.k_wrap, msg);
}

// Legacy v1 shape (contrast test T-H only): 64-bit fold, raw response.
static Bytes respond_v1_folded(const DeviceSecret& d, const Challenge& c) {
    uint64_t seed = c.w[0] ^ c.w[1] ^ c.w[2] ^ c.w[3];
    if (seed == 0) seed = 1;
    Bytes raw(32);
    MCL_T2 eng(seed, d.p, d.q, d.K);
    eng.gen_bytes(raw.data(), (int64_t)raw.size());
    return raw;
}

// Verifier with single-use challenge ledger.
struct Verifier {
    uint64_t verifier_id;
    std::map<uint64_t, DeviceSecret> db;           // IMSI -> enrolled secret
    struct Issued { Challenge c; uint64_t imsi; bool consumed; };
    std::map<uint64_t, Issued> ledger;             // challenge_handle -> state
    uint64_t next_handle = 1;
    std::mt19937_64 rng;                           // sim CSPRNG (fixed seed)

    explicit Verifier(uint64_t id, uint64_t rseed) : verifier_id(id), rng(rseed) {}

    uint64_t issue(uint64_t imsi) {
        Challenge c{{rng(), rng(), rng(), rng()}};
        uint64_t h = next_handle++;
        ledger[h] = {c, imsi, false};
        return h;
    }
    // Consumes the challenge on FIRST attempt, success or failure.
    bool verify(uint64_t handle, uint64_t imsi, const Bytes& r) {
        auto it = ledger.find(handle);
        if (it == ledger.end() || it->second.consumed) return false;   // stale/replay
        it->second.consumed = true;                                    // burn now
        if (it->second.imsi != imsi) return false;                     // wrong account
        auto db_it = db.find(imsi);
        if (db_it == db.end()) return false;
        Bytes expect = respond_v2(db_it->second, it->second.c, imsi, verifier_id);
        return ct_equal(expect, r);
    }
};

// ----------------------------------------------------------------- battery --
static int g_pass = 0, g_fail = 0;
static void check(const char* name, bool ok) {
    std::printf("  %-58s %s\n", name, ok ? "PASS" : "FAIL");
    (ok ? g_pass : g_fail)++;
}

int main() {
    std::printf("mcl_auth_hardened — Paper-2 hardened-profile battery (v1.0.0)\n");
    std::printf("engine: MCL v%s (%s)\n\n", MCL_VERSION_STRING, MCL_VERSION_DATE);

    const uint64_t IMSI_A = 0x62A001, IMSI_B = 0x62A002;
    DeviceSecret dev_a{3, 5, 12.0, {}};
    DeviceSecret dev_b{7, 11, 12.0, {}};
    for (int i = 0; i < 32; i++) { dev_a.k_wrap[i] = (uint8_t)(0xA0 + i); dev_b.k_wrap[i] = (uint8_t)(0xB0 + i); }

    Verifier v1(/*id*/ 0x5601, /*rseed*/ 20260821);
    Verifier v2(/*id*/ 0x5602, /*rseed*/ 47);
    v1.db[IMSI_A] = dev_a; v1.db[IMSI_B] = dev_b;
    v2.db[IMSI_A] = dev_a;

    // T-A legitimate flow, 1000 sessions
    {
        int ok = 0;
        for (int i = 0; i < 1000; i++) {
            uint64_t h = v1.issue(IMSI_A);
            Bytes r = respond_v2(dev_a, v1.ledger[h].c, IMSI_A, v1.verifier_id);
            if (v1.verify(h, IMSI_A, r)) ok++;
        }
        std::printf("T-A legit sessions accepted: %d/1000\n", ok);
        check("T-A legitimate flow 1000/1000", ok == 1000);
    }
    // T-B replay of a consumed (C,R) in the same verifier
    {
        uint64_t h = v1.issue(IMSI_A);
        Bytes r = respond_v2(dev_a, v1.ledger[h].c, IMSI_A, v1.verifier_id);
        bool first = v1.verify(h, IMSI_A, r);
        bool replay = v1.verify(h, IMSI_A, r);
        check("T-B replay of consumed challenge rejected", first && !replay);
    }
    // T-C old response submitted against a fresh session
    {
        uint64_t h1 = v1.issue(IMSI_A);
        Bytes r_old = respond_v2(dev_a, v1.ledger[h1].c, IMSI_A, v1.verifier_id);
        (void)v1.verify(h1, IMSI_A, r_old);
        uint64_t h2 = v1.issue(IMSI_A);
        check("T-C stale response in new session rejected", !v1.verify(h2, IMSI_A, r_old));
    }
    // T-D cross-verifier transfer: R computed for v1 presented to v2 (same C forced)
    {
        uint64_t h2 = v2.issue(IMSI_A);
        Bytes r_for_v1 = respond_v2(dev_a, v2.ledger[h2].c, IMSI_A, v1.verifier_id);
        check("T-D cross-verifier transfer rejected", !v2.verify(h2, IMSI_A, r_for_v1));
    }
    // T-E cross-account transfer: device A's response on B's account
    {
        uint64_t h = v1.issue(IMSI_B);
        Bytes r_a = respond_v2(dev_a, v1.ledger[h].c, IMSI_A, v1.verifier_id);
        check("T-E cross-account transfer rejected", !v1.verify(h, IMSI_B, r_a));
    }
    // T-F challenge reuse after a FAILED attempt
    {
        uint64_t h = v1.issue(IMSI_A);
        Bytes garbage(32, 0x42);
        bool wrong = v1.verify(h, IMSI_A, garbage);
        Bytes r_good = respond_v2(dev_a, v1.ledger[h].c, IMSI_A, v1.verifier_id);
        check("T-F reuse after failure rejected", !wrong && !v1.verify(h, IMSI_A, r_good));
    }
    // T-G double-submit: two submissions of the same correct R, one consume
    {
        uint64_t h = v1.issue(IMSI_A);
        Bytes r = respond_v2(dev_a, v1.ledger[h].c, IMSI_A, v1.verifier_id);
        bool s1 = v1.verify(h, IMSI_A, r);
        bool s2 = v1.verify(h, IMSI_A, r);
        check("T-G double-submit: exactly one acceptance", s1 && !s2);
    }
    // T-H wide-challenge anti-fold: C1 != C2 with identical 64-bit XOR fold
    {
        Challenge c1{{0x1111222233334444ull, 0x5555666677778888ull,
                      0x9999AAAABBBBCCCCull, 0xDDDDEEEEFFFF0123ull}};
        Challenge c2 = c1; std::swap(c2.w[0], c2.w[1]);       // same XOR fold
        Bytes v1_r1 = respond_v1_folded(dev_a, c1), v1_r2 = respond_v1_folded(dev_a, c2);
        Bytes v2_r1 = respond_v2(dev_a, c1, IMSI_A, 0x5601);
        Bytes v2_r2 = respond_v2(dev_a, c2, IMSI_A, 0x5601);
        check("T-H1 legacy fold collision reproduced (attack)", ct_equal(v1_r1, v1_r2));
        check("T-H2 hardened profile separates the pair (fix)", !ct_equal(v2_r1, v2_r2));
    }
    // T-I transcript confidentiality: raw engine bytes absent from transcript
    {
        uint64_t h = v1.issue(IMSI_A);
        Bytes raw;
        Bytes r = respond_v2(dev_a, v1.ledger[h].c, IMSI_A, v1.verifier_id, &raw);
        Bytes transcript = make_ctx(v1.ledger[h].c, IMSI_A, v1.verifier_id);
        transcript.insert(transcript.end(), r.begin(), r.end());
        bool leaked = std::search(transcript.begin(), transcript.end(),
                                  raw.begin(), raw.end()) != transcript.end();
        check("T-I raw engine response absent from transcript", !leaked);
    }
    // T-J avalanche + distribution smoke on R (protocol-logic scale)
    {
        std::mt19937_64 rng(0xC0FFEE);
        double hd_sum = 0; int hd_min = 256, hd_max = 0;
        const int N = 2000;
        std::array<uint64_t, 256> hist{};
        for (int i = 0; i < N; i++) {
            Challenge c{{rng(), rng(), rng(), rng()}};
            Bytes r1 = respond_v2(dev_a, c, IMSI_A, 0x5601);
            int word = (int)(rng() % 4), bit = (int)(rng() % 64);
            Challenge cf = c; cf.w[word] ^= (1ull << bit);
            Bytes r2 = respond_v2(dev_a, cf, IMSI_A, 0x5601);
            int hd = 0;
            for (int b = 0; b < 32; b++) hd += __builtin_popcount((unsigned)(r1[b] ^ r2[b]));
            hd_sum += hd; if (hd < hd_min) hd_min = hd; if (hd > hd_max) hd_max = hd;
            for (uint8_t by : r1) hist[by]++;
        }
        double mean = hd_sum / N;
        double expect = N * 32.0 / 256.0; double chi2 = 0;
        for (uint64_t hcnt : hist) { double d = (double)hcnt - expect; chi2 += d * d / expect; }
        std::printf("T-J avalanche: mean HD %.2f/256 (min %d, max %d); "
                    "byte chi2 %.1f (df 255)\n", mean, hd_min, hd_max, chi2);
        check("T-J1 mean avalanche within 128 +/- 3 bits", mean > 125.0 && mean < 131.0);
        check("T-J2 byte-distribution chi2 in [190, 330]", chi2 > 190.0 && chi2 < 330.0);
    }

    std::printf("\nRESULT: %d PASS / %d FAIL\n", g_pass, g_fail);
    std::printf(g_fail == 0
        ? "All protocol-logic checks passed. Full Paper-2 SS-VI statistical "
          "campaigns on this profile remain the required follow-up.\n"
        : "FAILURES PRESENT - do not adopt this profile.\n");
    return g_fail == 0 ? 0 : 1;
}
