/*
 * ============================================================================
 * mcl_txauth_verifier_state.cpp — Paper-5 §V.A verifier under state loss
 * Doc ID: MCL-P5-VERIFIERSTATE-2026-0925-001
 * Question (watch digest 2026-09-18, item 2; IETF draft-ietf-seat-use-cases-01):
 *   the monotonic counter c_last rejects replay only while the verifier's state is
 *   durable and updated atomically. What does the REFERENCE verifier of Paper 5
 *   (harness v3.2, struct Verifier) do under (S1) unsynchronised replicas,
 *   (S2) a crash before c_last is persisted, (S3) a restore from an older backup,
 *   (S4) a lost acknowledgement, (S5) a device restored from an old snapshot?
 * Method: the device model, ctx, tag_v3 (derivation route, MCL_T4_Q30 twelve Q30
 *   weights, K_eff = KDF(K,"MCL-KeyDevice-v1",S_device)), ct_equal and struct
 *   Verifier are copied VERBATIM from mcl_txauth_v3_battery_q30.cpp (harness
 *   v3.2, Doc ID MCL-P5-V3BATTERY-Q30-2026-0904-003). State loss is modelled by
 *   copying the Verifier value (a snapshot) and restoring it. No engine change.
 * Engine: repository-root mcl_core.hpp (v8.1.3) + keyed sidecar, unmodified.
 * Build:  clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_txauth_verifier_state.cpp -o mcl_txauth_verifier_state
 * Usage:  ./mcl_txauth_verifier_state          (deterministic; no arguments)
 * ============================================================================
 */
#include "../mcl_core.hpp"
#include "../keyed_q30_PQ/mcl_keyed_q30.hpp"
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <vector>

static void sha256_portable(const uint8_t* m, size_t n, uint8_t out[32]) { mcl_sha256(m, n, out); }
static std::atomic<uint64_t> g_redraws{0}, g_derivations{0};
using Bytes = std::vector<uint8_t>;
using Key256 = std::array<uint8_t, 32>;
using Tag = std::array<uint8_t, 32>;
static Bytes sha256v(const Bytes& m) { Bytes d(32); sha256_portable(m.data(), m.size(), d.data()); return d; }
static void put_u64(Bytes& v, uint64_t x) { for (int i=0;i<8;i++) v.push_back((uint8_t)(x>>(8*i))); }
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
    uint8_t ktx[32]; Tag out{};
    uint8_t keff[32];
    mcl_keff_from_key_device(d.K.data(), d.S.data(), keff);
    mcl_kdf256(keff, "MCL-TxChallenge-v1", ctx.data(), ctx.size(), ktx, 32);
    secure_zero(keff,32);
    { uint8_t info[8]={0}; uint8_t kd[96]; mcl_kdf256(ktx, "MCL-T4-Q30-v1", info, 8, kd, 96);
      MCL_Q30_Sextet rawv{}; int32_t* w=reinterpret_cast<int32_t*>(&rawv);
      for(int l=0;l<12;l++){ uint64_t v=0; std::memcpy(&v,kd+8*l,8); w[l]=(int32_t)(2+(v%((1u<<30)-2))); }
      g_derivations++; if (mcl_t4_q30_has_reachable_symmetry(rawv)) g_redraws++; secure_zero(kd,96); }
    { MCL_T4_Q30 eng(ktx, 0, PUBLIC_SEED, K_DEFAULT); eng.gen_bytes(out.data(), 32); }
    secure_zero(ktx,32);
    return out;
}
static void trial_bytes(const char* tag, uint64_t i, uint8_t out[32]) {
    uint8_t buf[32+8]; std::memset(buf,0,32); std::strncpy((char*)buf, tag, 31);
    for (int k=0;k<8;k++) buf[32+k]=(uint8_t)(i>>(k*8));
    sha256_portable(buf,sizeof(buf),out);
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
static bool ct_equal(const Tag& a, const Tag& b) {
    unsigned d=0; for (int i=0;i<32;i++) d |= (unsigned)(a[i]^b[i]); return d==0;
}
// Verifier per Paper 5 SS-V.A (verbatim from harness v3.2).
struct Verifier {
    uint64_t id; std::map<uint64_t,Device> enrolled;
    std::map<uint64_t,uint64_t> c_last;
    bool authorize(uint64_t acct, const Tx& tx, const Tag& t) {
        auto it=enrolled.find(acct); if (it==enrolled.end()) return false;
        uint64_t& last=c_last[acct];
        if (tx.nonce <= last) return false;
        if (!ct_equal(tag_v3(it->second, tx, id), t)) return false;
        last = tx.nonce; return true;
    }
};
// A verifier whose counter store is SHARED and updated atomically (one map for all replicas).
struct SharedStoreVerifier {
    uint64_t id; std::map<uint64_t,Device> enrolled; std::map<uint64_t,uint64_t>* store;
    bool authorize(uint64_t acct, const Tx& tx, const Tag& t) {
        auto it=enrolled.find(acct); if (it==enrolled.end()) return false;
        uint64_t& last=(*store)[acct];
        if (tx.nonce <= last) return false;
        if (!ct_equal(tag_v3(it->second, tx, id), t)) return false;
        last = tx.nonce; return true;                       // single-writer store: check-and-set is one step here
    }
};
static int n_obs=0;
static void obs(const char* scenario, const char* what, bool accepted, const char* reading) {
    std::printf("  %-4s %-62s %-8s  %s\n", scenario, what, accepted?"ACCEPT":"REJECT", reading); n_obs++;
}
int main() {
    std::printf("MCL Paper-5 verifier state-loss record | Doc ID MCL-P5-VERIFIERSTATE-2026-0925-001\n");
    std::printf("engine mcl_core.hpp %s | tag = MCL_T4_Q30 derivation route (harness v3.2 code, verbatim)\n", MCL_VERSION_STRING);
    const uint64_t V1=0x5601;
    Device A=dev_of(1);
    auto msg=[&](uint64_t c){ Tx t=tx_of(c); t.nonce=c; return std::make_pair(t, tag_v3(A,t,V1)); };

    std::printf("\nS0  control — one verifier, durable in-memory state\n");
    { Verifier v{V1,{},{}}; v.enrolled[A.account]=A;
      auto m1=msg(1); obs("S0","accept (TX,1,Tag)", v.authorize(A.account,m1.first,m1.second), "expected");
      obs("S0","replay the same (TX,1,Tag)", v.authorize(A.account,m1.first,m1.second), "expected: rejected, c_last=1");
      auto m0=msg(1); m0.first=tx_of(7); m0.first.nonce=1; m0.second=tag_v3(A,m0.first,V1);
      obs("S0","fresh TX with a stale counter c=1", v.authorize(A.account,m0.first,m0.second), "expected: rejected"); }

    std::printf("\nS1  two replicas WITHOUT a shared counter store (each keeps its own c_last)\n");
    { Verifier ra{V1,{},{}}, rb{V1,{},{}}; ra.enrolled[A.account]=A; rb.enrolled[A.account]=A;
      auto m2=msg(2);
      bool a=ra.authorize(A.account,m2.first,m2.second), b=rb.authorize(A.account,m2.first,m2.second);
      obs("S1","replica A receives (TX,2,Tag)", a, "");
      obs("S1","replica B receives the SAME (TX,2,Tag)", b, b?"DOUBLE ACCEPTANCE — replay window open":"");
      std::printf("      → same message accepted %d times across replicas\n", (int)a+(int)b); }
    std::printf("S1' two replicas WITH one shared, atomically updated counter store\n");
    { std::map<uint64_t,uint64_t> store; SharedStoreVerifier ra{V1,{},&store}, rb{V1,{},&store}; ra.enrolled[A.account]=A; rb.enrolled[A.account]=A;
      auto m2=msg(2);
      bool a=ra.authorize(A.account,m2.first,m2.second), b=rb.authorize(A.account,m2.first,m2.second);
      obs("S1'","replica A receives (TX,2,Tag)", a, ""); obs("S1'","replica B receives the SAME (TX,2,Tag)", b, b?"":"rejected via the shared store — expected"); }

    std::printf("\nS2  crash after acceptance but BEFORE c_last is persisted (restart from the pre-acceptance snapshot)\n");
    { Verifier v{V1,{},{}}; v.enrolled[A.account]=A; auto m3=msg(3);
      Verifier snapshot=v;                                   // last persisted state (before the acceptance)
      obs("S2","accept (TX,3,Tag) in memory", v.authorize(A.account,m3.first,m3.second), "");
      v=snapshot;                                            // crash + restart: in-memory update lost
      obs("S2","after restart: replay (TX,3,Tag)", v.authorize(A.account,m3.first,m3.second), "RE-ACCEPTED — persisted state predates the acceptance"); }
    std::printf("S2' persist-before-act ordering (c_last written durably BEFORE the acceptance takes effect)\n");
    { Verifier v{V1,{},{}}; v.enrolled[A.account]=A; auto m3=msg(3);
      bool ok=v.authorize(A.account,m3.first,m3.second); Verifier snapshot=v;   // persisted AFTER the update, BEFORE acting
      obs("S2'","accept (TX,3,Tag), then persist", ok, "");
      v=snapshot; obs("S2'","after restart: replay (TX,3,Tag)", v.authorize(A.account,m3.first,m3.second), "rejected — expected"); }

    std::printf("\nS3  restore from an older backup (state rolled back to after c=4)\n");
    { Verifier v{V1,{},{}}; v.enrolled[A.account]=A;
      auto m4=msg(4), m5=msg(5), m6=msg(6);
      obs("S3","accept (TX,4,Tag)", v.authorize(A.account,m4.first,m4.second), "");
      Verifier backup=v;
      obs("S3","accept (TX,5,Tag)", v.authorize(A.account,m5.first,m5.second), "");
      obs("S3","accept (TX,6,Tag)", v.authorize(A.account,m6.first,m6.second), "");
      v=backup;                                              // restore from backup taken after c=4
      obs("S3","after restore: replay (TX,5,Tag)", v.authorize(A.account,m5.first,m5.second), "RE-ACCEPTED");
      obs("S3","after restore: replay (TX,6,Tag)", v.authorize(A.account,m6.first,m6.second), "RE-ACCEPTED — every transaction above the restored counter replays"); }

    std::printf("\nS4  lost acknowledgement (accepted and persisted; the client never saw the reply and retries)\n");
    { Verifier v{V1,{},{}}; v.enrolled[A.account]=A; auto m7=msg(7);
      obs("S4","accept (TX,7,Tag)", v.authorize(A.account,m7.first,m7.second), "");
      obs("S4","client retries the identical (TX,7,Tag)", v.authorize(A.account,m7.first,m7.second), "rejected — at-most-once holds; the client must query status, not re-submit"); }

    std::printf("\nS5  device restored from an old snapshot (device counter rolled back below c_last)\n");
    { Verifier v{V1,{},{}}; v.enrolled[A.account]=A; auto m8=msg(8), m9=msg(9);
      obs("S5","accept (TX,8,Tag)", v.authorize(A.account,m8.first,m8.second), "");
      obs("S5","accept (TX,9,Tag)", v.authorize(A.account,m9.first,m9.second), "");
      Tx t=tx_of(10); t.nonce=5; Tag g=tag_v3(A,t,V1);        // device now emits c=5 again
      obs("S5","restored device emits a fresh TX with c=5", v.authorize(A.account,t,g), "rejected — legitimate device locked out until its counter is re-synchronised above c_last"); }

    std::printf("\n%d observations | weak-key re-draws %llu / %llu derivations\n", n_obs,
                (unsigned long long)g_redraws.load(), (unsigned long long)g_derivations.load());
    std::printf("Reading: c_last rejects replay only while the verifier's state is durable, updated atomically before the acceptance\n"
                "takes effect, and shared by every replica; S1/S2/S3 each re-admit previously accepted transactions; S1'/S2' close them.\n");
    return 0;
}
