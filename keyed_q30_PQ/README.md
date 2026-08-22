> **Publication note (2026-08-22, MCL v0.2.0):** this folder is published as shipped in the working tree. The "planned 4th PCT filing" referred to below was **filed on 21 August 2026 as PCT/IB2026/058860**. Sidecar header `mcl_keyed_q30.hpp` is **v1.0.6** (SHA-256 `71a0dbaf8472…`; engine of record `mcl_core.hpp` v8.1.3, SHA-256 `416ad145e79c…`). README/STATUS bodies are historical measurement records and were deliberately not rewritten; see `NOSYM_V106_RECORD_20260822.md` for the v1.0.6 change. Compiled binaries are not shipped. `mcl_keyed_q30_lyap_sweep.cpp` / `mcl_keyed_q30_mpfr_lyap.cpp` need GNU MPFR (`-I/opt/homebrew/include -lmpfr -lgmp` on macOS); `mcl_keyed_q30_dump_weights.cpp` is built with `-DHDR='"mcl_keyed_q30.hpp"'`.

# MCL Keyed Q30 — FPU-free, key-bound, post-quantum extension

**Date:** 2026-06-11 (NIST-category labels corrected inline 2026-07-07) · **Engine of record:** `mcl_core.hpp` v7.0.1
**Author:** Madeeh Ibrahim · ORCID 0009-0002-8562-8325
**Status:** reference + verification harness — patent-support anchor for the planned 4th PCT filing.

> **NIST-category labels (corrected inline 2026-07-07).** An earlier draft of this
> README (2026-06-11) labeled the 256-bit-key T4 paths **"NIST PQ Level 1 / L1"**;
> that was wrong by four categories and has now been corrected in place. The ladder
> anchors to AES key search: Cat 1 = AES-128 = 64 post-Grover bits; Cat 3 = AES-192
> = 96; **Cat 5 = AES-256 = 128 post-Grover (highest)**. A full 256-bit key ⇒ 128
> post-Grover ⇒ **Category 5**; the Float64 `mcl_t2_from_key` path carries only ~208
> bits ⇒ ~104 post-Grover ⇒ **Category 3**, so it is labeled separately below. The
> code was always correct (`mcl_core.hpp` `meets_category5` / `mcl_pq_security`);
> authoritative ladder = Tech Guide §4. *(The "Q30 keystream-constrained b_eff open
> risk" once mentioned in the test output was later RETRACTED — see STATUS.md; it
> was an overstated risk, not a confirmed weakness.)*

---

## ملخّص (Arabic)

هذا الفولدر يُغلق الفجوة المعمارية التي كشفها تحليل السرعة: مسارات v6.1.0 المفتاحية (Float64) تبلغ
فئات NIST العليا (حتى الفئة الخامسة لمسار T4) لكنها تحتاج FPU غير موجود في شريحة الـSIM. هنا محرّكان
**خاليان من FPU بالكامل** (عددي + جدول سين صحيح) يبلغان الفئة الخامسة على عتاد الـSIM:
- **(A) `MCL_T4_Q30`** — محرّك مفتاحي بأربعة مذبذبات (12 وزناً صحيحاً ≤ 2³⁰) يحمل مفتاح 256 بت ⇒
  Grover 2¹²⁸ = **NIST PQ Category 5 (AES-256-equivalent، الأعلى)، بنيوياً، بلا انضباط بروتوكولي** (الرائد).
- **(B) `mcl_cascade_q30`** — سلسلة زمنية سرّية فوق محرّك Q30-T2 الصحيح (`mcl_q30_iterate_raw`).
  ملاحظة: هذا المحرّك الصحيح **لم يُختبَر بالبطاريات بعد** (BigCrush/PractRand معلّقة)؛ نتيجة BigCrush
  160/160 (الورقة 1، Run 2) كانت لمحرّك Float64 ثنائي القنوات بجدول LUT — تحقيق مختلف، لا هذا المحرّك.
  m حقبة بأوزان مشتقّة من المفتاح، بصفر إخراج وسيط (مسار انتقالي سريع الشحن).

كل الادّعاءات مقيسة في `mcl_keyed_q30_test.cpp` — **10/10 ناجحة، ASan+UBSan نظيف.**

---

## What this closes

The speed audit found the central tension: the v6.1.0 Float64 keyed paths
(`mcl_t2_from_key` → Category 3, `mcl_t4_from_key` → Category 5) call `std::sin` on
doubles and need an FPU + libm. The flagship MCL target — SIM / eSIM / iSIM
secure elements (ARM SecurCore SC000/SC300 = Cortex-M0/M3) — has **no
double-precision FPU**, so those Float64 paths could not run there. The FPU-free
integer path (`mcl_q30_iterate_raw`) had no 256-bit keyed construction.

This folder adds two **FPU-free** keyed engines (integer arithmetic + the existing
65536-entry integer sin LUT only — no float in the hot path):

| Engine | What | Secret capacity | Post-Grover | NIST Cat | Notes |
|---|---|---|---|---|---|
| **`MCL_T4_Q30`** (A) | keyed 4-oscillator, 12 integer weights ∈ [2,2³⁰) | 360-bit repr., key-bounded 256 | **128** | **5** | structural, misuse-resistant; **flagship** |
| **`mcl_cascade_q30`** (B) | secret temporal cascade over the Q30-T2 integer engine, m epochs | m·59.3 bits (m=7 → 415) | 207 (joint) | 5 (joint) | reuses the existing engine; conditional on protocol discipline |

## Security accounting (Grover bound)

- **T4-Q30:** 12 weights × 30 bits = **360-bit representation space ≫ 256**. For any
  FIXED key, the probability that some OTHER key derives the same 12 weights is
  ≈ 2²⁵⁶/2³⁶⁰ = 2⁻¹⁰⁴ (union bound); the map is not literally injective on all
  2²⁵⁶ keys, but the expected key-entropy loss is ≈ 2⁻¹⁰⁴ bits — negligible. The
  brute-forceable secret is the **full 256-bit key** → Grover √(2²⁵⁶) =
  **2¹²⁸ = NIST PQ Category 5** (AES-256-equivalent, highest). All 12 weights act on
  every output byte → entropy is joint by construction, no protocol assumption needed.
- **Cascade:** m epochs × ~59.3 bits (ordered coprime pair in [2,2³⁰]); m=7 →
  ~415-bit representation → ~207 post-Grover **under a joint search**.
  Security basis (CORRECTED after the scientific review, §"Findings" below):
  1. **No intermediate output** between epochs (enforced in `mcl_cascade_q30`;
     verified in test [5]). Without it the search collapses to additive m·2³⁰.
  2. **Backward branching b > 1** so a full epoch cannot be peeled back: the
     definitive image-cardinality measurement (science [T3]) gives per-coordinate
     **b ≈ 1.59** (2-D step ≈ 2.5) — WEAKLY many-to-one (~24× less folding than
     the Float64 engine's b ≈ 38, because the coarse 16-bit LUT linearizes the
     map). Even so, b > 1 makes a full-epoch back-peel explode (b^256) and blocks
     meet-in-the-middle, so the attacker must guess all m (p,q) FORWARD from the
     public seed → joint **2^(30m)** post-Grover. **m ≥ 5 reaches Category 5**
     (≥2¹²⁸); m = 7 (2^207) is extra margin.

  Together these make the cascade Category 5 by joint forward search. This is
  **empirical, not a proof**.

**Recommendation:** ship **T4-Q30 as the flagship** (Category 5 with no protocol
assumptions); offer the cascade as a transitional drop-in on the existing
engine where re-validation cost must be avoided.

## Verification (measured, this run — Apple Silicon, clang -O3)

`mcl_keyed_q30_test.cpp` → **10/10 PASS**, ASan+UBSan clean, −Wall −Wextra clean,
identical at −O0/−O2/−O3:

| # | Check | Result |
|---|---|---|
| 1 | Determinism / integer KAT | T4-Q30 commit CRC `0x58C99E3E`; cascade(m=7) CRC `0xF7C81BC4` (SHA-256-hashed final commitment since 2026-06-15; raw was `0xAC441A9A`) (platform-independent) |
| 2 | T4-Q30 keystream (1 MiB) | chi² = 230.2 (< 330.52); entropy = 7.99984 bits/byte |
| 3 | Key avalanche (1-bit) | 50.07 % output bits change (ideal 50 %) |
| 4 | Capacity realized | **12 / 12** weights change output (min 45.3 %) |
| 5 | Cascade epoch dependency | **7 / 7** epochs change final output (min 47.3 %); no intermediate leak |
| 6 | Forward non-monotonicity | INFORMATIONAL only (327k slope reversals); non-monotone ≠ non-injective — see science [T3] for the real number |
| 7 | PQ accounting | T4-Q30 = 128 post-Grover (Cat 5 ✓); cascade m=7 = 207 (joint) |
| 8 | Timing / footprint | T4-Q30 0.39 ms, cascade(m=7) 0.24 ms (host); state 120 B; LUT 256 KB (ROM-able) |

**FPU-free claim:** the hot path is integer ops + LUT reads only. Scaling to a
28 MHz Cortex-M0 is ~×125 (clock) with **no software-double / software-sin
penalty** — unlike the Float64 keyed path (~×8000). Both engines therefore land
well inside the MILENAGE < 500 ms budget on-card. (Build with
`MCL_Q30_USE_STATIC_LUT` for a fully libm-free build — the LUT is otherwise
populated once at static init via `std::sin`.)

## Build & run

```sh
c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish \
    -o mcl_keyed_q30_test mcl_keyed_q30_test.cpp && ./mcl_keyed_q30_test
```

## Files

- `mcl_keyed_q30.hpp` — the two engines + Q30 PQ-accounting helpers (depends on `../MCL_publish/mcl_core.hpp`).
- `mcl_keyed_q30_test.cpp` — verification & measurement harness (8 sections, 10 checks).
- `MCL_KEYED_Q30_RESULTS_20260611.txt` — saved run output.

## Patent-support mapping (planned 4th PCT)

This folder is the working code support for the draft claims in
`../MCL_publish/Final Papers/10 June 2026/PCT_04_Draft_Claims_Keyed_PQ_Integer_Engine.md`:

- **Group II (integer FPU-free engine), claims 11–18** ← `mcl_q30t4_iterate_raw`,
  the integer LUT, per-term phase scaling (claim 17), endian-independent commit
  (claim 18a). Closes the "planned mcl_t4_q30 specification" anchor with built,
  measured code.
- **Group I capacity (claims 1c, 6, 7)** ← 12×30 = 360-bit capacity proof
  (test [4]/[7]); each weight < 2³⁰ is below the 2⁵³ collapse onset (claim 7).
- **Group V cascade (claims 27–28)** ← `mcl_cascade_q30`: joint-space dependency
  (test [5]), no intermediate output (construction), non-invertibility evidence
  (test [6]). **Filing caveat:** claim 27's "whereby recovery requires joint
  search" is **evidentiary** (rests on the measured b_eff > 1, not a proof) — the
  description must state the non-invertibility assumption and mandate m ≥ 7, and
  the claim should add a non-invertibility limitation (b_eff > 1) so it does not
  assert a security level the construction delivers only conditionally.

## Scientific verification (`mcl_keyed_q30_science.cpp`) — findings & corrections

> ⚠️ **SUPERSEDED below.** This section is an intermediate snapshot. Two of its
> conclusions were later overturned by deeper work: **(T1) hyperchaos is now
> PROVEN** (256-bit MPFR — see "Resolved by science v2"), and **(T3) the
> "keystream OPEN RISK" was RETRACTED** as a misinterpretation (see item 2 of
> that section). Read those for the final word; the text here is kept for the
> honest record of how the analysis evolved.

A deeper review (run `mcl_keyed_q30_science`) tested the three things the basic
harness could not, and CORRECTED two overstatements in the earlier version:

- **[T1] Lyapunov spectrum — hyperchaos UNVERIFIED for the real engine.** The
  continuous-analog Benettin QR validates on small structural weights
  (λ ≈ [14.1, 2.7, 0.9, −0.2], 3 positive → hyperchaotic). For the actual
  key-derived weights (~2³⁰), λ₁ is enormous (~87) but the double-precision QR
  **underflows** on the subdominant directions (λ₃ = λ₄ pinned at ln(1e-300), and
  the spectrum sum −1958 violates the Oseledets identity ⟨ln|det J|⟩ ≈ +90),
  so λ₂…λ₄ are numerical garbage. **Conclusion: λ₁ ≫ 0 is robust (definitely
  chaotic; R1 avalanche saturates in 1 iteration), but ≥2-positive-exponent
  HYPERCHAOS is not established** — it needs a higher-precision / λ₁-only method.
- **[T2] Statistics — EXCELLENT.** 64 MiB: chi² = 226 (< 330.5), entropy
  7.9999976, bit-freq 0.50001, runs z = −0.67, all autocorr (lags 1–8) < 2×10⁻⁴,
  spectral SNR 9.2 (pass), per-bit chi² all < 6. (Sample `t4q30_sample.bin`
  emitted for offline `ent` / `dieharder` / PractRand.)
- **[T3] Backward branching — CORRECTION.** Definitive image-cardinality scan:
  the Q30 per-coordinate map covers only **62.8 %** of its codomain → mean
  backward branching **b ≈ 1.59** (weakly many-to-one), about **24× less folding
  than the Float64 engine (b ≈ 38)** because the coarse 16-bit LUT linearizes the
  map. b > 1 is enough to make the **cascade** one-way (full-epoch back-peel
  explodes), but whether the **keystream-constrained b_eff** (the one-wayness
  condition for the *stream/PRNG* use, where output is observed; Float64 ≈ 6)
  stays > 1 for Q30 is **NOT established — an OPEN RISK**.

**Corrections to earlier claims (honest record):**
- The basic test's old "[6] image-folding chi² ⇒ b > 1 (strong folding)" was
  **methodologically wrong** — image non-uniformity (and slope non-monotonicity)
  is *also* produced by an injective steep map, so it proved neither folding nor
  non-injectivity. [6] is now INFORMATIONAL only; the real number (b ≈ 1.59) is
  the image-cardinality measurement in science [T3].
- The "b_eff ≈ 6 transfers to Q30" assumption is **false**: Q30's branching is
  far weaker (LUT coarsening). The cascade does NOT rely on Float64's b_eff; it
  relies on no-intermediate-output + b > 1 + joint forward search (m ≥ 5).
- **T4-Q30's NIST Category 5 claim is UNAFFECTED**: it rests on Grover over the
  256-bit KEY (structural, all 12 weights act every step), not on state
  non-invertibility.

## Resolved by science v2 (`mcl_keyed_q30_science2.cpp`) — and what they mean

Both risks were investigated to a definitive answer (not closed by hand-waving):

1. **Hyperchaos of T4-Q30 — PROVEN (256-bit MPFR).** Double precision failed
   (λ₁≈86 ≫ 36 nats/step → Gram-Schmidt cancellation → λ₂ pinned at ln(1e-300)).
   Re-run at 256-bit mantissa (≈177 nats) in `mcl_keyed_q30_mpfr_lyap.cpp`
   resolves the FULL spectrum for all 6 sampled keys: λ₁ ≈ 83–89, **λ₂ ∈ [2.10,
   6.49] (worst 2.097 > 0)**, λ₃ mixed, λ₄ < 0 — i.e. ≥2 positive exponents ⇒
   **HYPERCHAOTIC**. The sums match the independently-measured ⟨ln|det J|⟩
   (science3), confirming consistency, and the small-weight case reproduces the
   double result (λ₁=13.99, λ₂=2.87). Definitive. (Neither keyed path's security
   *requires* hyperchaos, but it is now established.)
2. **Q30 "keystream weakness" — RETRACTED (was a misinterpretation).** Exact 2^32
   backward enumeration gives b_2D ≈ 3.25 preimages/state and a byte-constrained
   **b_eff = 1.00** — but a width-scaling re-audit (`MCL_KEYED_Q30_BEFF_RECHECK`)
   shows b_eff = 1.92 / 1.33 / 1.00 / 1.00 at output widths k = 1/2/4/8 bits,
   tracking the GENERIC `1 + (b_2D−1)/2^k`. So **b_eff≈1 at 8 bits is pure
   arithmetic (few preimages + 8-bit byte), NOT a weakness.** An ~invertible
   state-update map is normal for a keystream generator (LFSRs, counters, strong
   permutations are all invertible); "state-recoverable from the keystream" does
   **not** follow from b_eff=1 — it was never tested, and `ent` + `dieharder`
   (42 PASSED / 1 WEAK / 0 FAILED) show no statistical weakness.
   The **real, correct finding** is just that the Q30 map is far LESS folding than
   Float64 (b_2D ≈ 3.25 vs ~1444; 16-bit LUT linearizes it). That matters ONLY for
   *map-based one-wayness* (HD derivation on the bare map) — which **no MCL
   construction uses**: HD uses the Float64 engine, and the keyed Q30 paths get
   one-wayness from SHA-256, not the map. `commit32_oneway()` stays as harmless
   hygiene but was added against an OVERSTATED risk.

## Remaining open items

1. ~~Prove T4-Q30 hyperchaos~~ — **DONE** (256-bit MPFR; grid sweep `MCL_KEYED_Q30_LYAP_SWEEP_20260616.txt`: λ₂>0 in 100/100 key-derived configs, min≈1.5; robust to q=p+1. Orig. 6-key run λ₂∈[2.10,6.49]).
2. Measure the *4-oscillator* keystream b_eff (2^128 state — needs a smarter
   method than full enumeration); the 2-osc b_eff=1 already mandates hashing any
   exposed Q30 stream, so this is for completeness.
3. T4-Q30 statistics: internal 64 MiB battery + `ent` (entropy 7.999998/byte,
   χ²=226, serial corr 3e-5) + `dieharder` (13 tests streamed: **42 PASSED /
   1 WEAK / 0 FAILED** — the WEAK is expected noise, paired re-run passed).
   **UPDATE 2026-06-23 (supersedes the earlier "NOT yet PractRand / not
   installable" note):** PractRand 0.95 WAS built and run on the keyed
   `MCL_T4_Q30` keystream (key `{0..31}`) — **clean through 32 GB (2³⁵ B),
   173 test results, 0 anomalies** at every power-of-two 64 MB→32 GB; the
   `mcl_cascade_q30` keystream is clean through 512 MB. Both were *stopped*
   (CPU contended with FPGA synthesis), **never failed**; restartable toward
   the 1 TB / 16 GB targets. Logs:
   `08_FPGA_Tang138K_Pro 1/Results/logs/PractRand_{T4Q30_clean32GB,cascade_clean512MB}.log`;
   authoritative write-up: `.../Results/INTERNAL_Keyed_Q30_Validation.md §3`.
   **TestU01/BigCrush was evaluated and deliberately DROPPED** (painful MinGW
   build; bottlenecked by the same slow generator; PractRand-1TB judged at
   least as sensitive → cost without new coverage). Remaining depth gap is
   therefore only PractRand 32 GB → 1 TB, an author call vs the achieved
   32 GB-clean evidence. NOTE: this covers the KEYED 4-oscillator T4-Q30
   keystream; the BARE 2-oscillator `mcl_q30_iterate_raw` core (the VDF
   substrate) is a DIFFERENT engine and remains battery-PENDING (see
   `mcl_core.hpp` sec.16). Results: `MCL_KEYED_Q30_DIEHARDER_20260611.txt`.

## Next steps (not done here)

1. Fold `mcl_t4_q30_from_key` / `mcl_cascade_q30` into `mcl_core.hpp` proper with
   frozen KATs in `mcl_self_test()` (currently a sidecar header).
2. Re-run the existing `mcl_beff_compounding.cpp` methodology **adapted to the Q30
   integer engine** (keystream-constrained b_eff to depth 4) — test [6] here shows
   raw many-to-one-ness; the full keystream-constrained measurement is the next
   evidence tier.
3. Cross-platform bit-exactness: rebuild on Linux/glibc and confirm the two CRCs
   (`0x58C99E3E`, `0xF7C81BC4`) match (integer-only ⇒ they must).
4. Measure on real M0/M3 silicon to replace the ×125 clock estimate with hardware
   numbers before any latency claim in the filing.

- **2026-08-22 v1.0.6:** `mcl_t4_q30_has_reachable_symmetry()` + deterministic re-draw in `mcl_t4_q30_params_from_key` — see NOSYM_V106_RECORD_20260822.md
