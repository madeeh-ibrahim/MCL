// ============================================================================
// mcl_txauth_hardened.cpp — Paper-5 hardened transaction-authorization
//                           profile (v2) + adversarial + §VI-style battery
// ============================================================================
// Date: 2026-08-21.  Engine: mcl_core.hpp v8.1.1 (unmodified, header-only).
//
// WHAT THIS IS
// The E5/A adversarial rounds (FivePersona 2026-07-11/18) proved three
// defects in the Paper-5 transaction-authentication path as shipped in
// mcl_txn_verify.cpp:
//   (D1) TX BINDING IS 64-BIT.  Tag = MCL_T2(hash_tx(TX) ^ nonce, p, q):
//        hash_tx is FNV-1a (NON-cryptographic) folded into a uint64_t seed,
//        so two different transactions whose 64-bit fold agrees produce a
//        BYTE-IDENTICAL 256-bit tag.  Referees compiled the collision.
//   (D2) DEVICE SECRET NEVER ENTERS.  The path has (p,q) only; S_device is
//        absent (grep S_device in the txn code = 0), so the "84-94 post-
//        Grover bit" band that the paper ties to S_device is not exercised.
//   (D3) NO CANONICALIZATION / LIFECYCLE.  Nothing binds the *canonical*
//        transaction bytes, and nothing prevents cross-account / cross-
//        verifier replay, reuse-after-failure, stale nonce, or a recovery
//        (device-rebinding) path that bypasses device presence.
//
// This harness implements the hardened profile that closes D1-D3 with REAL
// cryptography and the engine's own device-bound 12-weight derivation, then
// runs the adversarial battery plus a §VI-style statistical battery.
//
// HARDENED PROFILE (v2)
//   Device identity (in the secure element):
//       master_key : 256-bit  (per-subscriber)
//       S_device   : 256-bit  RANDOM, != 0     (D2: the device secret)
//       K_wrap     : 256-bit  transport wrap key
//   Engine binding (D2): the FULL 256-bit (master_key, S_device) drives the
//       DURABLE map-defining weights via the engine's own route-A factory
//       mcl_t4_from_key_device() -> 12 coupling weights (twelve-weight T4,
//       the recommended NIST-PQ Cat-5 path), NOT a 64-bit seed.
//   Canonical TX (D3): fields are serialized in a fixed canonical order
//       (chain_id, nonce, to, value, calldata) -> canon bytes; the *display*
//       (value,to) is a strict subset, so any calldata/encoding mutation that
//       preserves the display still changes canon.
//   Tag (D1): tag = HMAC-SHA-256( K_wrap,
//                    SHA-256(canon) || LE64(nonce) || LE64(account) ||
//                    LE64(verifier) || raw )
//       where raw = 32 device-bound engine bytes.  The full 256-bit TX hash
//       enters the tag at full width — a 64-bit fold collision no longer
//       collapses it.
//   Lifecycle (D3): the verifier keeps a single-use nonce ledger per account
//       and binds account+verifier into the tag; rebinding S_device requires
//       a valid tag from the CURRENT device (device-presence proof).
//
// LEGACY PATH (contrast test C-1 only): the published mcl_txn_verify.cpp uses
//   seed = fmix64(FNV1a(canon)) ^ fmix64(counter). The replica below applies
//   the same fmix64 finaliser to both terms, so it is byte-faithful to the
//   published construction rather than a simplification of it.
//
// Build:  clang++ -std=c++17 -O2 mcl_txauth_hardened.cpp -o mcl_txauth_hardened
// Deterministic (fixed RNG seeds). CommonCrypto ships with macOS.
// ============================================================================

#include "../mcl_core.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <algorithm>
#include <array>
#include <cmath>
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
static int ham256(const Bytes& a, const Bytes& b) {
    int h = 0;
    for (size_t i = 0; i < 32; i++) h += __builtin_popcount((unsigned)(a[i] ^ b[i]));
    return h;
}

// --------------------------------------------------------------- legacy path
static const uint64_t FNV_OFFSET = 0xCBF29CE484222325ULL, FNV_PRIME = 0x100000001B3ULL;
static uint64_t fnv1a(const Bytes& d) {
    uint64_t h = FNV_OFFSET;
    for (uint8_t b : d) { h ^= b; h *= FNV_PRIME; }
    return h;
}
static uint64_t fmix64_(uint64_t z) {
    z=(z^(z>>33))*0xFF51AFD7ED558CCDULL; z=(z^(z>>33))*0xC4CEB9FE1A85EC53ULL;
    return z^(z>>33);
}
static Bytes legacy_tag(const Bytes& tx, uint64_t counter, int64_t p, int64_t q) {
    uint64_t seed = fmix64_(fnv1a(tx)) ^ fmix64_(counter);
    if (seed == 0) seed = 1;
    Bytes raw(32);
    MCL_T2 eng(seed, p, q);
    eng.gen_bytes(raw.data(), (int64_t)raw.size());
    return raw;
}

// ------------------------------------------------------------- hardened path
struct Tx {
    uint64_t chain_id, nonce, to, value;
    Bytes calldata;
};
// Canonical serialization: fixed field order + length-prefixed calldata.
static Bytes canon(const Tx& t) {
    Bytes c;
    put_u64(c, t.chain_id); put_u64(c, t.nonce); put_u64(c, t.to); put_u64(c, t.value);
    put_u64(c, (uint64_t)t.calldata.size());
    c.insert(c.end(), t.calldata.begin(), t.calldata.end());
    return c;
}

struct Device {
    Key256 master_key;   // 256-bit
    Key256 s_device;     // 256-bit, random != 0  (D2)
    Key256 k_wrap;       // 256-bit transport
    uint64_t account;    // account id bound into the tag
    uint64_t epoch;      // rebinding epoch (challenge arg to the derivation)
};

// Device-bound engine bytes: FULL 256-bit (master_key, S_device) -> 12 weights.
static Bytes device_bytes(const Device& d) {
    MCL_T4 eng = mcl_t4_from_key_device(d.master_key.data(), d.s_device.data(), d.epoch);
    Bytes raw(32);
    eng.gen_bytes(raw.data(), (int64_t)raw.size());
    return raw;
}

static Bytes hardened_tag(const Device& d, const Tx& tx, uint64_t verifier_id,
                          const Bytes& dev_raw) {
    Bytes msg = sha256(canon(tx));       // FULL 256-bit TX hash (D1)
    put_u64(msg, tx.nonce);
    put_u64(msg, d.account);
    put_u64(msg, verifier_id);
    msg.insert(msg.end(), dev_raw.begin(), dev_raw.end());
    return hmac_sha256(d.k_wrap, msg);
}

// Verifier: enrolled device copy + single-use nonce ledger per account.
struct Verifier {
    uint64_t verifier_id;
    std::map<uint64_t, Device> enrolled;              // account -> device
    std::map<uint64_t, std::set<uint64_t>> spent;     // account -> spent nonces

    bool authorize(uint64_t account, const Tx& tx, const Bytes& tag) {
        auto it = enrolled.find(account);
        if (it == enrolled.end()) return false;
        auto& sp = spent[account];
        if (sp.count(tx.nonce)) return false;         // replay / stale / double-submit
        Bytes raw = device_bytes(it->second);
        Bytes expect = hardened_tag(it->second, tx, verifier_id, raw);
        if (!ct_equal(expect, tag)) return false;     // a wrong tag consumes nothing:
                                                      // the counter advances ONLY on
                                                      // acceptance (Paper 5 §V.B), so a
                                                      // third party cannot burn a
                                                      // victim's nonces (denial of
                                                      // service) by submitting garbage.
        sp.insert(tx.nonce);                          // consume on acceptance
        return true;
    }
    // Rebinding (recovery) REQUIRES a valid authorization from the CURRENT
    // device over a canonical "rebind" transaction — device-presence proof.
    bool rebind(uint64_t account, const Key256& new_s_device,
                const Tx& rebind_tx, const Bytes& tag) {
        if (!authorize(account, rebind_tx, tag)) return false;  // must prove presence
        enrolled[account].s_device = new_s_device;
        enrolled[account].epoch += 1;
        return true;
    }
};

// ----------------------------------------------------------------- battery --
static int g_pass = 0, g_fail = 0;
static void check(const char* name, bool ok) {
    std::printf("  %-60s %s\n", name, ok ? "PASS" : "FAIL");
    (ok ? g_pass : g_fail)++;
}
static Key256 fill_key(std::mt19937_64& rng) {
    Key256 k; uint64_t w[4];
    for (int i = 0; i < 4; i++) w[i] = rng();
    std::memcpy(k.data(), w, sizeof(w));   // no aliasing of a byte array as u64
    return k;
}
static Tx sample_tx(std::mt19937_64& rng, uint64_t nonce) {
    Tx t; t.chain_id = 1; t.nonce = nonce; t.to = rng(); t.value = rng() % 1000000;
    t.calldata.resize(4 + (rng() % 40));
    for (auto& b : t.calldata) b = (uint8_t)rng();
    return t;
}

int main() {
    std::printf("mcl_txauth_hardened — Paper-5 hardened tx-auth battery (v1.0.0)\n");
    std::printf("engine: MCL v%s (%s); path = mcl_t4_from_key_device (12-weight)\n\n",
                MCL_VERSION_STRING, MCL_VERSION_DATE);
    std::mt19937_64 rng(20260821);

    // Enroll device A (account 0xA1) and B (account 0xB2) on verifier V1; A also on V2.
    Device A{fill_key(rng), fill_key(rng), fill_key(rng), 0xA1, 0};
    Device B{fill_key(rng), fill_key(rng), fill_key(rng), 0xB2, 0};
    // guard: S_device != 0 (D2)
    {   uint64_t za=0, zb=0;
        std::memcpy(&za, A.s_device.data(), 8); std::memcpy(&zb, B.s_device.data(), 8);
        check("D2 S_device is nonzero (A,B)", za != 0 && zb != 0); }
    Verifier V1{0x5601, {}, {}}, V2{0x5602, {}, {}};
    V1.enrolled[0xA1] = A; V1.enrolled[0xB2] = B; V2.enrolled[0xA1] = A;

    // ---- adversarial lifecycle (D3) ----
    {   // legit flow
        int ok = 0;
        for (uint64_t n = 1; n <= 1000; n++) {
            Tx t = sample_tx(rng, n);
            Bytes raw = device_bytes(A);
            Bytes tag = hardened_tag(A, t, V1.verifier_id, raw);
            if (V1.authorize(0xA1, t, tag)) ok++;
        }
        std::printf("L-A legit authorizations: %d/1000\n", ok);
        check("L-A legitimate flow 1000/1000", ok == 1000);
    }
    {   // replay of an already-authorized (tx,tag)
        Tx t = sample_tx(rng, 5001);
        Bytes tag = hardened_tag(A, t, V1.verifier_id, device_bytes(A));
        bool first = V1.authorize(0xA1, t, tag), replay = V1.authorize(0xA1, t, tag);
        check("D3 replay of consumed nonce rejected", first && !replay);
    }
    {   // cross-account: A's tag presented on B's account
        Tx t = sample_tx(rng, 6001);
        Bytes tag = hardened_tag(A, t, V1.verifier_id, device_bytes(A));
        check("D3 cross-account transfer rejected", !V1.authorize(0xB2, t, tag));
    }
    {   // cross-verifier: tag bound to V1 presented to V2
        Tx t = sample_tx(rng, 7001);
        Bytes tag_v1 = hardened_tag(A, t, V1.verifier_id, device_bytes(A));
        check("D3 cross-verifier transfer rejected", !V2.authorize(0xA1, t, tag_v1));
    }
    {   // reuse after a failed attempt (nonce burns on first sight)
        Tx t = sample_tx(rng, 8001);
        Bytes garbage(32, 0x42);
        bool wrong = V1.authorize(0xA1, t, garbage);
        Bytes good = hardened_tag(A, t, V1.verifier_id, device_bytes(A));
        check("D3 reuse after failure rejected", !wrong && !V1.authorize(0xA1, t, good));
    }
    {   // double-submit of the same valid tag: exactly one acceptance
        Tx t = sample_tx(rng, 9001);
        Bytes tag = hardened_tag(A, t, V1.verifier_id, device_bytes(A));
        bool s1 = V1.authorize(0xA1, t, tag), s2 = V1.authorize(0xA1, t, tag);
        check("D3 double-submit: exactly one acceptance", s1 && !s2);
    }

    // ---- canonical-byte binding (D3, item #8) ----
    {   // Canonical binding, isolated from the nonce ledger.
        // The tag comparison uses ONE nonce and varies ONLY the call data, so
        // nothing but the canonical bytes can explain a difference. The
        // verifier call then uses a nonce that is still UNSPENT, so the ledger
        // cannot be what rejects it — only the tag check can.
        Tx base = sample_tx(rng, 11002);
        base.nonce = 11002; base.value = 500; base.to = 0x9999;
        base.calldata = {0xde,0xad,0xbe,0xef};
        Tx mut = base;                                   // identical in every field...
        mut.calldata = {0xde,0xad,0xbe,0xee};            // ...except one call-data byte
        Bytes raw = device_bytes(A);
        Bytes tag_base = hardened_tag(A, base, V1.verifier_id, raw);
        Bytes tag_mut  = hardened_tag(A, mut,  V1.verifier_id, raw);
        bool tags_differ = !ct_equal(tag_base, tag_mut);
        // nonce 11002 is unspent here: rejection can only come from the tag
        bool wrong_tag_rejected = !V1.authorize(0xA1, mut, tag_base);
        // honest submission of the mutated transaction at a fresh nonce
        Tx honest = mut; honest.nonce = 11003;
        Bytes tag_h = hardened_tag(A, honest, V1.verifier_id, raw);
        bool honest_ok = V1.authorize(0xA1, honest, tag_h);
        check("Q8 one call-data byte changes the tag (canonical binding, same nonce)",
              tags_differ);
        check("Q8b wrong tag rejected at an UNSPENT nonce; honest tag accepted",
              wrong_tag_rejected && honest_ok);
    }

    // ---- D1 anti-fold: a CONSTRUCTED collision, not an assumed one ----
    {
        // The 2026-08-21 code review found the earlier version of this test
        // compared a message with itself, proving nothing. The pair below is a
        // genuine FNV-1a collision located by Brent cycle search over an
        // 8-byte call-data payload (mcl_d1_collision.cpp, 1.63e10 probes,
        // log d1_collision_20260821.log): two DISTINCT transactions whose
        // canonical bytes share one FNV-1a value, hence one legacy seed.
        const uint64_t PAY_A = 0x4f4f2eb40f25758dULL, PAY_B = 0x14349ecffb59edc0ULL;
        auto mk = [](uint64_t pay) {
            Tx t{1, 42, 0x1111222233334444ULL, 1000, Bytes(8, 0)};
            for (int i = 0; i < 8; i++) t.calldata[(size_t)i] = (uint8_t)(pay >> (8 * i));
            return t;
        };
        Tx t1 = mk(PAY_A), t2 = mk(PAY_B);
        Bytes c1 = canon(t1), c2 = canon(t2);
        bool distinct  = (c1 != c2);
        bool fnv_equal = (fnv1a(c1) == fnv1a(c2));
        // Superseded path: identical seed -> identical 256-bit tag.
        Bytes leg1 = legacy_tag(c1, 42, 3, 5);
        Bytes leg2 = legacy_tag(c2, 42, 3, 5);
        // Hardened path: the full-width transaction hash enters the tag.
        Bytes raw = device_bytes(A);
        Bytes h1 = hardened_tag(A, t1, V1.verifier_id, raw);
        Bytes h2 = hardened_tag(A, t2, V1.verifier_id, raw);
        check("C-1a transactions are distinct yet FNV-1a-equal (real collision)",
              distinct && fnv_equal);
        check("C-1b superseded path yields ONE tag for both (attack reproduced)",
              ct_equal(leg1, leg2));
        check("C-1c hardened path separates the collision pair (D1 closed)",
              !ct_equal(h1, h2));
    }

    // ---- recovery / rebinding abuse (D3, item #9) ----
    {
        Verifier Vr{0x5603, {}, {}};
        Device D0{fill_key(rng), fill_key(rng), fill_key(rng), 0xC3, 0};
        Vr.enrolled[0xC3] = D0;
        Key256 attacker_new_s = fill_key(rng);
        // Attacker attempts rebind WITHOUT the current device's S_device:
        Tx rb{1, 20001, /*to=REBIND*/ 0xEE, 0, {'R','E','B','I','N','D'}};
        Device forged = Vr.enrolled[0xC3]; forged.s_device = fill_key(rng);  // wrong secret
        Bytes forged_tag = hardened_tag(forged, rb, Vr.verifier_id, device_bytes(forged));
        bool attacker_rebind = Vr.rebind(0xC3, attacker_new_s, rb, forged_tag);
        // Legitimate rebind WITH the current device proves presence:
        Tx rb2{1, 20002, 0xEE, 0, {'R','E','B','I','N','D'}};
        Bytes ok_tag = hardened_tag(Vr.enrolled[0xC3], rb2, Vr.verifier_id,
                                    device_bytes(Vr.enrolled[0xC3]));
        bool legit_rebind = Vr.rebind(0xC3, attacker_new_s, rb2, ok_tag);
        check("R-1 rebinding without device secret rejected", !attacker_rebind);
        check("R-2 rebinding with device presence accepted", legit_rebind);
    }

    // ================= §VI-style statistical battery on the hardened tag =====
    std::printf("\n--- SS-VI statistical battery (hardened tag, device-bound) ---\n");
    // S1 uniqueness: 5000 distinct TXs -> 5000 distinct tags
    {
        std::set<Bytes> seen; int dup = 0;
        for (uint64_t n = 0; n < 5000; n++) {
            Tx t = sample_tx(rng, 100000 + n);
            Bytes tag = hardened_tag(A, t, V1.verifier_id, device_bytes(A));
            if (!seen.insert(tag).second) dup++;
        }
        std::printf("S1 uniqueness: %zu distinct / 5000 (dups %d)\n", seen.size(), dup);
        check("S1 5000/5000 distinct tags", (int)seen.size() == 5000);
    }
    // S2 avalanche: 1-bit TX flip -> ~50% tag Hamming distance
    {
        double sum = 0; int mn = 256, mx = 0; const int N = 5000;
        Bytes raw = device_bytes(A);
        for (int i = 0; i < N; i++) {
            Tx t = sample_tx(rng, 200000 + i);
            Bytes tag = hardened_tag(A, t, V1.verifier_id, raw);
            Tx tf = t; int bit = (int)(rng() % (tf.calldata.size() * 8));
            tf.calldata[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            Bytes tag2 = hardened_tag(A, tf, V1.verifier_id, raw);
            int h = ham256(tag, tag2); sum += h; mn = std::min(mn, h); mx = std::max(mx, h);
        }
        double mean = sum / N;
        std::printf("S2 avalanche: mean %.2f/256 (min %d, max %d)\n", mean, mn, mx);
        check("S2 mean avalanche 128 +/- 3 bits", mean > 125.0 && mean < 131.0);
    }
    // S3 byte-distribution chi^2 over tag bytes
    {
        std::array<uint64_t, 256> hist{}; const int N = 20000;
        for (int i = 0; i < N; i++) {
            Tx t = sample_tx(rng, 300000 + i);
            Bytes tag = hardened_tag(A, t, V1.verifier_id, device_bytes(A));
            for (uint8_t b : tag) hist[b]++;
        }
        double expect = N * 32.0 / 256.0, chi2 = 0;
        for (uint64_t c : hist) { double d = (double)c - expect; chi2 += d * d / expect; }
        std::printf("S3 byte chi2 %.1f (df 255, crit.001 ~330.5)\n", chi2);
        check("S3 byte chi2 in [190, 330]", chi2 > 190.0 && chi2 < 330.0);
    }
    // S4 FAR (device forgery): wrong-device authorization attempts, staged 10^6
    {
        const uint64_t TRIALS = 1000000;
        uint64_t accepts = 0;
        Tx target = sample_tx(rng, 400000);
        Bytes real_raw = device_bytes(A);
        Bytes real_tag = hardened_tag(A, target, V1.verifier_id, real_raw);
        for (uint64_t i = 0; i < TRIALS; i++) {
            // adversary guesses a device (random master_key,S_device) and forges a tag
            Device G{fill_key(rng), fill_key(rng), A.k_wrap, 0xA1, 0}; // even if K_wrap known
            Bytes graw = device_bytes(G);
            Bytes gtag = hardened_tag(G, target, V1.verifier_id, graw);
            if (ct_equal(gtag, real_tag)) accepts++;
        }
        double far = (double)accepts / TRIALS;
        std::printf("S4 FAR (device forgery, K_wrap known): %llu/%llu accepts (FAR %.3e)\n",
                    (unsigned long long)accepts, (unsigned long long)TRIALS, far);
        check("S4 zero forgeries in 10^6 (device-secret guessing)", accepts == 0);
    }

    std::printf("\nRESULT: %d PASS / %d FAIL\n", g_pass, g_fail);
    std::printf(g_fail == 0
        ? "All hardened-path checks passed. Real SHA-256/HMAC; 256-bit device "
          "binding via 12-weight T4; full-width TX binding. Large-N Paper-5 "
          "SS-VI campaigns (10^8 auth, 40M SIM-swap) remain the required "
          "follow-up on THIS path.\n"
        : "FAILURES PRESENT - do not adopt this profile.\n");
    return g_fail == 0 ? 0 : 1;
}
