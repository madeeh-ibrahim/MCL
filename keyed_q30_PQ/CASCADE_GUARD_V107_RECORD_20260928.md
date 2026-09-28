# Sidecar v1.0.7 — cascade symmetry check and opt-in seed rule — record

**Document ID:** MCL-KEYED-Q30-V107-2026-0928-RECORD · **Date:** 2026-09-28 · **Author:** Madeeh Ibrahim

| File | Version | SHA-256 |
|---|---|---|
| `mcl_keyed_q30.hpp` | **1.0.7** | `05c01cf8a15626c0e6f892103868afc11f36b07bad3a27472b9a8d608f396a29` |
| `mcl_keyed_q30.hpp` of release v0.2.14 | 1.0.6 | `71a0dbaf84725ac77d0b3f1eab5a40ba90c088e88df7d41aab19aed39a6f6512` |
| `../mcl_core.hpp` | 8.1.3 — **not modified** | `416ad145e79c095b8295497ca85cf2593c0cb0fabd029b3353d0013daab4ff80` |

The default behaviour of v1.0.7 is that of v1.0.6 for every key outside the
class of §1.1. Every known-answer value of record is unchanged.

---

## 1. What was measured

Both properties were counted by the structural inventory
(`../Quantum_Structural_Analysis_20260927/`).

### 1.1 A class of cascade keys

An epoch of `mcl_cascade_q30` iterates the two-oscillator integer map with one
pair (p, q). The map commutes with the translation of the state by
(2^31, 2^31) exactly when p ≡ q (mod 2). ω₁ and ω₂ are odd, so under the seed
rule of every version up to 1.0.6 the seed offset 2^31 produces that
translation of the initial state.

If **every** epoch of a key has p ≡ q (mod 2), the seeds s and s + 2^31 give
raw states that differ by (2^31, 2^31) at every step of the run.

| Quantity | Value |
|---|---|
| epochs with p ≡ q (mod 2), measured | 0.2508 per epoch (351,067 of 1,400,000) |
| expected share of keys at m = 7 | 0.2508⁷ ≈ 6.2 × 10⁻⁵ ≈ 2^−14 |
| expected count in 200,000 keys | 12.5 |
| counted in three key families of 200,000 keys each | 12, 18 and 6 |

The relation is **not visible at the output**. The cascade ends with SHA-256 of
the raw states; for the keys of the class the outputs of the two seeds differ
in 129.7 of 256 bits on average (18 keys). It is a property of the derived
weights, removed here at its source, as v1.0.6 did for the four-oscillator
path (`NOSYM_V106_RECORD_20260822.md`).

### 1.2 The seed interface

Under the same rule the initial state is t_i = hash_seed(s)·ω_i mod 2^32, and
`hash_seed` is the identity for seeds up to 2^52. Consequently:

- only s mod 2^32 enters the state — 2^32 initial states;
- seeds that differ by a multiple of 2^32 give identical output;
- the initial state is a linear image of the seed.

The seed is public (in authentication it is the challenge), and the form of
record uses a fixed public seed with the challenge entering through the key
derivation. The property concerns a caller who varies the seed.

---

## 2. What changed in the file

614 lines became 858: 16 lines replaced, 260 added. Every other line is
byte-identical to v1.0.6.

| # | Addition | What it does |
|---|---|---|
| 1 | `mcl_cascade_q30_has_reachable_symmetry(epochs)` | Exact check. A seed offset D moves the state by (D·ω₁, D·ω₂) and commutes with the map of an epoch iff D·(p·ω₂ − q·ω₁) ≡ 0 and D·(p·ω₁ − q·ω₂) ≡ 0 (mod 2^32). A non-zero D for the whole run exists iff all these terms are even. It is the criterion of v1.0.6 applied to the cascade. |
| 2 | `mcl_cascade_q30_params_from_key()` | Derives the epoch list as before, then re-draws a list of the class **deterministically**: q of the first epoch advances one step at a time inside [2, 2^30) until it differs from p, is coprime to p, and the list no longer admits the symmetry. Fail-closed: the process aborts if 4,096 steps do not suffice. Both parties run the same rule and derive the same weights. |
| 3 | `mcl_cascade_q30_derive_unchecked()` | The derivation of v1.0.6 under its own name — for measurement of the class, not for use. |
| 4 | `MCL_Q30_SeedInit::{Legacy, Hashed}`, `mcl_q30_seed_state2()`, `mcl_q30_seed_state4()` | How the public seed sets the initial state. `Legacy` is the rule of §1.2. `Hashed` takes the state words from SHA-256(label ‖ seed as eight little-endian bytes), with the labels `MCL-Q30-SeedInit-T2-v1` and `MCL-Q30-SeedInit-T4-v1`. A seed of zero is fatal under both rules, as in the engine. |
| 5 | last parameter `seed_init` of `MCL_T4_Q30(...)` and of `mcl_cascade_q30(...)` | Selects the rule. **The default is `Legacy`.** |
| 6 | `mcl_keyed_q30_self_test()` | Six known-answer values (§4). |

---

## 3. Verification

Host: Apple M1 Pro, macOS 14.5, Apple clang 16.0.0. Every expectation was
written before the run in which it was first checked.

| # | Check | Result |
|---|---|---|
| 1 | `mcl_keyed_q30_v107_verify.cpp` — 36 expectations over eight sections | **36 met, 0 failed** (`MCL_KEYED_Q30_V107_VERIFY_20260928.txt`) |
| 2 | the same program: arm64 -O3, arm64 -O0, x86-64 -O3, arm64 with AddressSanitizer and UndefinedBehaviorSanitizer | output **byte-identical** in the four builds; sanitizer output empty; no compiler diagnostic under `-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion` |
| 3 | default rule against a statement-for-statement replica of the v1.0.6 rule: 64 keys × 6 seeds, keystream, `commit32`, `commit32_oneway`, cascade | 384 + 384 comparisons, **0 differ** |
| 4 | cascade class over 200,000 keys | 18 before the check, **0 after**; 0 keys outside the class changed; inside the class only q of the first epoch changes, by 1 to 3 steps; final weights coprime, distinct, inside [2, 2^30) |
| 5 | the criterion against the map itself, 64 random states per epoch, 2,017 epoch lists | criterion and map agree on 2,017 of 2,017; outside the class, and after the check, no offset 2^k commutes |
| 6 | raw states of the seeds s and s + 2^31 for the 18 keys of the class | before: translation (2^31, 2^31) at every step for 18 of 18. After the check: 0 of 18; distance 128.7 of 256 bits. `Hashed` rule alone, unchecked weights: 0 of 18; 128.6 of 256 bits |
| 7 | seed interface | `Legacy`: 16 of 16 pairs (a, a + k·2^32) give identical output; the state is additive in the seed in 1,000 of 1,000 trials. `Hashed`: 0 of 16 and 0 of 1,000; 2^20 seeds give 2^20 distinct states; one seed bit flipped changes 0.4997 of the state bits |
| 8 | `Hashed` rule, 1 MiB of keystream | χ² = 254.05 (threshold 330.52); entropy 7.999825 bits per byte |
| 9 | **differential dump** — `mcl_keyed_q30_v107_dump.cpp` built once against each header, compared by `mcl_keyed_q30_v107_compare.py` | 65,536 four-oscillator weight sets: **0 differ**. 1,024 engine runs: **0 differ**. 200,000 epoch lists: 6 differ — the 6 keys that v1.0.6 places in the class. Keys in the class under v1.0.7: **0**. 5,006 cascade outputs: 6 differ — the same 6 keys (`MCL_KEYED_Q30_V107_COMPARE_20260928.txt`) |
| 10 | controls of the comparison | one weight line altered, the engine line altered, v1.0.6 compared with itself: the comparison **fails** in all three, as it must |
| 11 | regression: 59 programs that include the sidecar, a header built on it, or the engine — the folders `keyed_q30_PQ/`, `VDF128_T4/`, `T4_CycleStructure/`, `ReturnMap_Attack/` and `p5_hardened_txauth/` of this repository, and three folders of campaign programs that are not part of it | **56 compile to byte-identical executables** under the two headers (clang -O2). The three whose executables differ — `mcl_keyed_q30_test`, `mcl_keyed_q30_measure` and `../T4_CycleStructure/mcl_symmetry_impact` — print identical output (61, 38 and 22 lines; timing lines aside) |
| 12 | `mcl_keyed_q30_nosym_verify` run to completion; `mcl_keyed_q30_dump_weights` (65,536 weight sets) | output byte-identical under the two headers |
| 13 | `mcl_keyed_q30_test` | 9 passed, 0 failed; output identical to the published v1.0.6 output except four timing lines |
| 14 | the six known-answer values in a build with `-DMCL_Q30_CONSTANT_TIME_SIN` | identical to the default build. The row compares values; it measures no timing |

Dumps of row 9 (6.3 MB each, not shipped): SHA-256 `4cc364c074b1c3a6…` for
v1.0.6 and `f66b5a9adadfeeb2…` for v1.0.7; 271,568 lines each.

---

## 4. Known-answer values

Key of record: key[i] = 7·i + 1 (mod 256), challenge 0, seed 12345678901234.
Each value is the CRC-32 of the bytes named.

| # | What | Value | Since |
|---|---|---|---|
| 1 | four-oscillator `commit32`, `Legacy` | `0x58C99E3E` | unchanged |
| 2 | cascade m = 7, `Legacy` | `0xF7C81BC4` | unchanged |
| 3 | four-oscillator re-draw path of v1.0.6: key `39925d4210d4efe37c022a1f7851d6ea0b1c4d655971945c62030293269cf536`, 4,096 keystream bytes | `0x808C5B2E` | value of v1.0.6, now inside the self-test |
| 4 | cascade re-draw path: key `2e343d1a887e33a6024522d1181d324811b48bc0e9047def3311cbc30cc04571`; q of the first epoch 2711267 → 2711270 | `0x944BD55E` | new |
| 5 | four-oscillator `commit32`, `Hashed` | `0x399183A1` | new |
| 6 | cascade m = 7, `Hashed` | `0x229E97B8` | new |

---

## 5. Effect on earlier records

- **Four-oscillator path.** Weight derivation, keystream and both commitments
  are byte-identical. Every record measured on that path stands as it is.
- **Cascade.** Identical for every key outside the class. A campaign over N
  random keys contains about N · 2^−14 keys of the class; their outputs are
  different under v1.0.7. No campaign was re-measured; the programs of the
  regression that use the cascade print identical output.
- **Hardware vectors.** The default rule is unchanged, so hardware vectors of
  the four-oscillator path computed with v1.0.6 hold under v1.0.7.
- **Reproduction of published measurements.** A measurement published with
  v1.0.6 is reproduced with the header of release v0.2.14.

---

## 6. What this version does not do

1. It proves nothing about the map. It removes one class of derived weights
   and offers one alternative for the interface.
2. State translations that no seed reaches are outside its scope — 7.16% of
   the four-oscillator weight sets in the record run of the inventory admit
   one.
3. `Hashed` is not the default. Making it the default would change every
   keystream, every known-answer value and every hardware vector, and would
   require the verification campaigns to be repeated.
4. Under `Legacy` the seed interface of §1.2 is as it was.

---

## 7. Build and run

```sh
# from keyed_q30_PQ/
c++ -std=c++17 -O3 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
    -I.. -o v107_verify mcl_keyed_q30_v107_verify.cpp
./v107_verify                 # 200,000 keys, about 6 seconds; exit code 0 when every expectation holds

# differential dump: the header of v1.0.6 in a directory that holds no mcl_core.hpp
mkdir -p /tmp/v106
git show v0.2.14:keyed_q30_PQ/mcl_keyed_q30.hpp > /tmp/v106/mcl_keyed_q30_v106.hpp
c++ -std=c++17 -O3 -I.. -DHDR='"/tmp/v106/mcl_keyed_q30_v106.hpp"' -o dump106 mcl_keyed_q30_v107_dump.cpp
c++ -std=c++17 -O3 -I.. -o dump107 mcl_keyed_q30_v107_dump.cpp
./dump106 > first.txt
./dump106 $(awk '$1=="CEP" && $3==1 {print $2}' first.txt) > dump_v106.txt
./dump107 $(awk '$1=="CEP" && $3==1 {print $2}' first.txt) > dump_v107.txt
python3 mcl_keyed_q30_v107_compare.py dump_v106.txt dump_v107.txt
```

The first line of each dump names the engine. The comparison requires the two
to agree: a header placed next to another `mcl_core.hpp` would otherwise be
compared across two engines.

---

*MCL-KEYED-Q30-V107-2026-0928-RECORD · Madeeh Ibrahim, Cairo*
