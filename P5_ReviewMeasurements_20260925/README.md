# P5_ReviewMeasurements_20260925 — Paper 5 §V.A verifier under state loss

**Doc ID:** MCL-P5-VERIFIERSTATE-2026-0925-001 · **Engine:** repository-root `mcl_core.hpp` v8.1.3 + keyed sidecar `keyed_q30_PQ/mcl_keyed_q30.hpp` v1.0.6 at the time of the measurement (the release ships v1.0.7 at that path since v0.2.15, byte-identical on this code path), both unmodified · **Platform:** Apple Silicon, Apple clang. Compiled binaries are not shipped.

**Build (from this directory):** `clang++ -std=c++17 -O3 -DNDEBUG -I.. mcl_txauth_verifier_state.cpp -o mcl_txauth_verifier_state` · **Run:** `./mcl_txauth_verifier_state` (deterministic, no arguments, < 1 s).

**Question.** Paper 5 §V.A states that the per-account last-accepted counter c_last "prevents replay of any previously accepted transaction". That holds only while the verifier's state is durable, updated atomically before the acceptance takes effect, and shared by every replica (cf. IETF draft-ietf-seat-use-cases-01 and arXiv:2609.16214). What does the *reference* verifier do when those conditions fail?

**Method.** The device model, ctx, `tag_v3` (derivation route, twelve Q30 weights), the constant-time comparison and `struct Verifier` are copied verbatim from the Paper 5 battery harness v3.2 (`p5_hardened_txauth/mcl_txauth_v3_battery_q30.cpp`, Doc ID MCL-P5-V3BATTERY-Q30-2026-0904-003). State loss is modelled by copying the verifier value (a snapshot) and restoring it; a shared store is modelled by two verifiers referencing one counter map.

**Result (`verifier_state_apple_20260925.log`, 21 observations).**

| Scenario | Behaviour of the reference verifier |
|---|---|
| S0 single verifier, durable state | replay rejected; stale counter rejected (control) |
| S1 two replicas, no shared counter store | the same (TX, c, Tag) **accepted by both** — double acceptance |
| S1' two replicas, one shared atomically updated store | second acceptance rejected |
| S2 crash after acceptance, before c_last is persisted | after restart the same message is **re-accepted** |
| S2' c_last persisted before the acceptance takes effect | replay rejected |
| S3 restore from an older backup (rolled back to c = 4) | (TX, 5) and (TX, 6) **re-accepted** — every transaction above the restored counter replays |
| S4 lost acknowledgement, client retries the identical message | rejected (at-most-once); the client must query status rather than re-submit |
| S5 device restored from an old snapshot (counter below c_last) | fresh transactions rejected until the device counter is re-synchronised |

**Reading.** Replay protection is a property of the verifier's state management, not of the tag: durable, atomic, shared c_last is a stated precondition of the §V.A guarantee (sentence added to Paper 5 §V.A on 2026-09-25; the equivalent clause enters the updated Paper 2 §IV.B).

Files: `mcl_txauth_verifier_state.cpp` · `verifier_state_apple_20260925.log` · `README.md` · `SHA256SUMS`.
