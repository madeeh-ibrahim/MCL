# MCL Post-Quantum / Keyed-Q30 — STATUS truth table

**Date:** 2026-06-11 (updated 2026-06-12; category labels + engine ref refreshed 2026-07-07) · **Engine of record:** `mcl_core.hpp` v7.0.1 (KAT-identical to the v6.1.0 build these results were measured on) · **Author:** Madeeh Ibrahim
**Legend:** ✅ done & proven/verified · ⚠️ done but conditional / below-Category-5 / accounting-only · ❌ open or confirmed-weakness

> This file records what is **measured/proven** vs **assumed/unproven**, so that no
> filing or publication claims more than the evidence supports. Every ✅ below was
> reproduced on this machine (Apple Silicon, clang -O3; ASan+UBSan clean where code).

---

## 1) Quantum-algorithm analysis (32-agent audit, adversarially verified)

| Item | Status | What it PROVES (and its limit) |
|---|---|---|
| Shor inapplicable | ✅ | No public-key structure ⇒ factoring/DLP quantum attacks give zero advantage. Does NOT imply overall quantum security (Grover governs that). |
| VDF sequentiality quantum-robust | ✅ | Grover does not parallelize sequential depth ⇒ the delay property survives quantum adversaries. |
| Default `(p,q)` secret too small | ✅ | Quantified: production [2,1e9] ≈ 2⁵⁹ ⇒ Grover ≈ 2³⁰ ⇒ **NOT post-quantum**. Even Max [2,1e18] ≈ 2¹¹⁹ ⇒ ≈2⁵⁹ < 128. |
| Precision ceilings (Float64 2⁵³ / Q30 2³⁰) | ✅ | (p,q) width alone CANNOT reach a 256-bit brute-forceable secret. |

## 2) v6.1.0 keyed paths in `mcl_core.hpp` (Float64)

| Item | Status | What it PROVES (and its limit) |
|---|---|---|
| SHA-256 + KAT vs "abc" | ✅ | Implementation matches FIPS 180-4 gold vector. |
| `mcl_t2_from_key` | ⚠️ | ~208-bit capacity ⇒ ~104 post-Grover = **NIST PQ Category 3** (AES-192; ≥96), below the T4 path's Category 5. |
| `mcl_t4_from_key` | ⚠️✅ | 256-bit key ⇒ 128 post-Grover = NIST PQ Category 5 (AES-256-equivalent, highest; BUDGET accounting). Limit: Float64 ⇒ needs FPU; accounting ≠ security proof. |
| Existing KATs unchanged | ✅ | The bump is purely additive; all pre-6.1.0 numerical output is byte-identical. |

## 3) White paper §10

| Item | Status | What it PROVES |
|---|---|---|
| §10 + engine-of-record + Appendix B | ✅ | Document is consistent with v6.1.0; first post-quantum treatment on record. |

## 4) FPU-free Q30 engines (this folder)

| Item | Status | What it PROVES (and its limit) |
|---|---|---|
| `MCL_T4_Q30` builds / deterministic | ✅ | Commit CRC `0x58C99E3E` (platform-independent integer path); **72 B** working set since the 2026-06-12 uint32-weight change (see §6). |
| `mcl_cascade_q30` builds / deterministic | ✅ | Commit CRC `0xF7C81BC4` (SHA-256-hashed final commitment since the 2026-06-15 hardening, §7; was `0xAC441A9A` when it emitted raw state). |
| FPU-free | ✅ | Hot path = integer + LUT only ⇒ runs on a SIM-class Cortex-M0 (no FPU), unlike the Float64 keyed path. **Confirmed at ARMv6-M instruction level: 0 FPU ops** (§6). |
| Keystream statistics (internal, 64 MiB) | ✅ | chi²=226 (<330.5), entropy 7.9999976, runs z=−0.67, autocorr <2e-4, spectral SNR 9.2 ⇒ excellent. |
| Keystream — `ent` + `dieharder` | ✅ | `ent`: entropy 7.999998/byte, χ²=226 (p=90%), serial corr 3e-5, π-err 0.01%, bit-χ²=0.38. `dieharder` (13 tests, streamed): **42 PASSED / 1 WEAK / 0 FAILED** (the lone WEAK = sts_serial ntup14 p=0.0018; its paired re-run passed at 0.281 ⇒ expected noise in 43 sub-tests). |
| Keystream — **PractRand 0.95** (2026-06-23) | ✅ | Keyed `MCL_T4_Q30` keystream **clean through 32 GB (2³⁵ B), 173 tests, 0 anomalies**; `mcl_cascade_q30` clean through 512 MB. Both *stopped* (CPU contended with FPGA synth), **never failed**; restartable toward 1 TB. Logs in `08_FPGA_Tang138K_Pro 1/Results/logs/`; write-up `INTERNAL_Keyed_Q30_Validation.md §3`. **Supersedes** the earlier "NOT yet PractRand / not installable" note. **BigCrush/TestU01 evaluated and DROPPED** (MinGW-painful, same slow generator, PractRand-1TB ≥ as sensitive). Remaining: PractRand 32 GB→1 TB (author call). Covers the KEYED T4-Q30 only; the BARE 2-osc `mcl_q30_iterate_raw` VDF core stays battery-PENDING. |
| Capacity realized (12 weights + 7 epochs) | ✅ | Every weight/epoch changes the output ⇒ the 256-bit key is genuinely carried. |
| T4-Q30 = Category 5 (accounting) | ⚠️✅ | Grover over 256-bit key = 2¹²⁸ (AES-256-equivalent, highest). Limit: key-space security, not state non-invertibility. |
| ASan/UBSan / -O0–O3 clean | ✅ | No undefined behavior; optimization-independent. |
| `commit32_oneway()` (SHA-256 of state) | ✅ | A one-way hashed output is available (standard hygiene). NOTE: added in response to an OVERSTATED b_eff risk — see the retraction in §5; not closing a confirmed break. |

## 5) Deep scientific verification (the decisive, honest part)

| Item | Status | What it PROVES / does NOT prove |
|---|---|---|
| T4-Q30 is chaotic (λ₁) | ✅ | λ₁≈85.6 + 1-iteration avalanche saturation ⇒ definitely chaotic. |
| Hyperchaos on small weights | ✅ | λ₁=14.06, λ₂=2.70 ⇒ the map STRUCTURE is hyperchaotic; validates the Lyapunov code. |
| Hyperchaos on real ~2³⁰ weights (λ₂>0) | ✅ | **PROVEN** at 256-bit (MPFR, `mcl_keyed_q30_mpfr_lyap.cpp`). Full spectrum resolved at 256-bit. **Grid sweep (`mcl_keyed_q30_lyap_sweep.cpp`, `MCL_KEYED_Q30_LYAP_SWEEP_20260616.txt`): λ₂>0 in 100/100 random key-derived configs** (min 1.506, median 3.16, max 14.34 at **N=40000** reference depth — the N=15000 and N=40000 runs agree to 3 sig figs ⇒ converged, not a quick estimate; λ₁≈81–89, λ₄<0 ⇒ ≥2 positive ⇒ HYPERCHAOTIC). Boundary probe: λ₂ stays ≈1.95 even at q=p+1 (q/p→1), i.e. sustained by the 4-D coupling, not the per-pair ratio — so the 2-osc formula 2ln(q/p) is a conservative lower reference, not the realized λ₂. (Orig. 6-key run: λ₂∈[2.10,6.49].) **The λ₂ computation itself is independently cross-validated (`lyap_independent_check.py`, mpmath 266-bit, 5 lenses): analytic-vs-finite-difference Jacobian exact to 1e-50; sum rule Σλ=⟨ln|det J|⟩ (independent det formula Π(1−ΣQ·K·cos)) exact; known-matrix Benettin converges to ln(eig); and the independent mpmath reimplementation agrees with the C++ MPFR λ₂ to <1.2% (N-convergence, not disagreement), including λ₂≈1.98>0 at q/p→1.** (Double underflowed because λ₁≈86 ≫ 36 nats/step; 256-bit ≈177 nats clears it. Sum matches ⟨ln|det J|⟩ — internally consistent.) |
| Q30 state-map folding (b_2D) | ✅ | **MEASURED.** Exact full-2³² backward enum: b_2D≈3.25 preimages/state — the Q30 map is far LESS folding than Float64 (~1444), because the 16-bit LUT linearizes the per-coord map (b/coord≈1.59 vs 38). A real structural property. |
| ~~"Raw Q30 keystream state-recoverable (b_eff=1)"~~ | 🔁 **RETRACTED** | My earlier "confirmed weakness" was a **misinterpretation**. b_eff=1.00 at 8-bit is the GENERIC arithmetic of small b_2D + 8-bit byte: a width-scaling re-audit gives b_eff = 1.92/1.33/1.00/1.00 at k=1/2/4/8 ≈ `1+(b_2D−1)/2^k`. An ~invertible state map is NORMAL for a keystream generator; "state-recoverable from keystream" does NOT follow from b_eff=1 (it was never tested, and dieharder/ent show no weakness). |
| Does low b_2D affect any MCL use? | ✅ | NO. It matters only for *map-based one-wayness* (HD directly on the bare map). MCL's HD uses the Float64 engine; keyed Q30 (T4/cascade) gets one-wayness from SHA-256, and T4-auth security is Grover over the 256-bit key. The cascade's back-peel block needs only b_2D>1 (3.25>1 ✓). |

## 6) PCT-04 measurement round + Claim-13 native-multiply realization (2026-06-12)

Resolved all seven `[MEASURE]` flags in PCT-04 Description v4 from the in-hand build
(runner `mcl_keyed_q30_measure.cpp`, record `MCL_KEYED_Q30_MEASURE_20260612.txt`),
then made one output-preserving code change that turned a *describable* enablement
claim into a *measured-in-code* one.

| Item | Status | What it PROVES (and its limit) |
|---|---|---|
| Quarter-wave LUT bit-identity (Claim 17) | ✅ | Full 65,536-entry table (262,144 B) reconstructed from 16,385-entry quarter-wave (65,540 B, 4.0×): **0 mismatches**, both CRC `0xDE1340CF`. |
| Per-term overflow bounds (Claim 19 / [0033]) | ✅ | Per-term scaling admits K ≤ 4π≈12.566 (overflow onset); sum-first fails beyond 4π/3≈4.189; enforced cap K=12 has 4.7% margin (worst product 0.955·INT64_MAX). |
| Cross-platform bit-identity (Claim 13 / [0035]) | ✅ | 6 KATs (LUT, T4 commit, T4 oneway, cascade m=5, m=7, 1 MiB keystream) **identical** across arm64 + x86_64 × -O0/-O2/-O3. |
| Working memory (Claim 24 / [0047]) | ✅ | MCL_T4_Q30 = **72 B** (was 120 B); cascade 120 B; commit 32 B; LUT 262,144 B (→65,540 B quarter-wave) in ROM. Fixed-size, output-length-independent. |
| Latency (host only) | ⚠️ | T4-Q30 full auth 0.38 ms, cascade m=7 0.24 ms, raw iterate 38 ns — **on arm64 host, NOT target M0**. M0 figure = analytic or real-silicon, NOT QEMU. |
| **Claim 15 native-word multiply — realized in code** | ✅ | uint32 weights ⇒ coupling-argument multiply compiles on ARMv6-M (Cortex-M0) to **2× native `muls` + `subs`, ZERO `__aeabi_lmul`, ZERO FPU**. The former int64 form emitted `__aeabi_lmul` (multi-word). So Claim 15 / [0032] is now literally true *of the reference code*, not just *possible*. Evidence: `M0_CODEGEN_CLAIM13_20260612.txt`, `m0_codegen_probe.c`, `m0_probe.s`. |
| Output-preserving proof (not sample) | ✅ | uint32 form ≡ int64 form by the ring identity (P−Q) mod 2³² ≡ ((P mod 2³²)−(Q mod 2³²)) mod 2³², **sign-agnostic** (holds when q·b>p·a). CRCs unchanged (0x58C99E3E / 0xAC441A9A — cascade value as of that 12-Jun change; later → 0xF7C81BC4 after the §7 hashing) = confirmation of no coding slip, NOT the proof. |
| Test bug fixed | ✅ | `mcl_keyed_q30_test.cpp` [4] punned the 48-B struct as `int64_t*` (read pairs, ran off end after the type change) → fixed to `uint32_t*`. Now 9/9 pass, 12/12 weights affect output, ASan/UBSan clean. |

**Scope limit (open, separate decision):** the cascade reuses core `mcl_q30_iterate_raw`
(int64 params) → it **still emits `__aeabi_lmul` on M0**. Core (`mcl_core.hpp`) was
left untouched this round because papers cite its CRCs as the engine of record; the
same output-preserving reduction applies and can be made there as a deliberate
separate change.

---

## 7) Parameter-recovery attack on the BARE single-pair engine (2026-06-15)

A faithful adversarial re-run (`../Verfications codes June 2026/`, `gen_states.cpp` + `06_attack_real_lattice.py`) **broke** the bare 2-oscillator `mcl_q30_iterate_raw` engine in the **raw-consecutive-state-observation** model — fixing two defects in the earlier (Claude, 11 Jun) suite that had wrongly concluded "no break": (a) the Python re-impl used `OMEGA=0x9E3779B9=(φ−1)·2³²`, dropping the `/2π` (real `omega1=422466573`); (b) Attack-05 subsampled the low-16 slack by stride 257, preordaining its 0/8.

| Item | Status | What it shows |
|---|---|---|
| Pivot: a1 known ⇒ (p,q) by linear solve | ✅ 8/8 | omega-independent algebraic fact (real states) |
| Phase-argument high-16 leak | ✅ | sine-LUT (`a>>16`) leaks high-16 to **exactly 2 candidates/step**, true-in-set 100% (real engine) |
| **Lattice recovery of (p,q)** | ❌ **BROKEN 256/256, NO-ORACLE** | small-roots LLL over the 32-bit low-bit slack; high-16 from the leak only, enumerated (≤256 combos/key); **oracle-free** verified by forward simulation. Polynomial-time, ≪ 2⁵⁹. |
| Adversarial self-audit of the break | ✅ PASSED (`09`) | solver takes `obs` only (leak impossible by construction); each `(p,q)` regenerates the **full 47-state trajectory** (coincidence ≈2⁻³⁰⁰⁸); corrupting input ⇒ attack fails; output tracks the data → **break is real, not a test artifact** |
| Hardened: fpylll + 256 keys + boundary proof | ✅ (`10`,`11`) | **gold-standard fpylll**, **256/256** (full window), each full-trajectory-verified. The only failure mode = a **structural GF(2)² determinant boundary** (usable anchor ⇔ two states' low bits form a GF(2) basis, rate 6/16; theory 0.375 = measured 0.355), an observation-window artifact that dissolves with more of the same observed states — **not** cipher resistance, **not** a sampling fluke |

**SCOPE (corrected + TESTED).** A code check + the **4-state test** (`07_attack_4state.py`, using BOTH coupling args → 6 eqs from 4 states) overturned the first draft's "no construction exposes raw state":
- `commit32` and the **cascade's final commitment EMIT raw state** (cascade output = 4 consecutive raw (t1,t2) of the last epoch). From **only those 4 states**, the lattice recovers the last epoch's `(p,q)` **7/8, no oracle** (the 1 miss is the **GF(2)² determinant boundary** later characterized in `11` — an even-determinant anchor, removable with a wider observation window, not a structural failure).
- **Central claim SURVIVES:** one epoch's `(p,q)` ≠ the 256-bit key — every epoch is derived via SHA-256 (`mcl_kdf256`), preimage-resistant. So **the Category-5 / key claim is unaffected**; only a derived per-epoch secret leaks.
- `commit32_oneway` (hashed) ✅ safe. **`MCL_T4_Q30 commit32` — now TESTED (`08_attack_t4_commit32.py`): the 2-osc vector does NOT port.** Two structural blockers: (1) the osc-1 increment is a SUM of 3 sines (single-term high-16 leak = mean 0.000 candidates — gone); (2) `commit32` exposes only `t2^t3^t4`, never the individual coupled states the coupling arguments need. Flagship `commit32` resists this attack (independent audit still warranted; `commit32_oneway` remains the safe default).

**IMPLICATION (load-bearing) + hardening:** "never expose raw Q30 state" is **proven**; PCT-04 non-invertibility Claims 20/29/31 + [0034]/[0041] are **load-bearing** (strengthens their inventive step). **Concrete fix (DONE):** `mcl_cascade_q30` now **hashes its final commitment** (raw → SHA-256; CRC 0xAC441A9A→0xF7C81BC4), and `commit32_oneway` is **mandatory** for secret-bearing tags. Remaining caveat: still one adversary / one framework — now self-audited (`09`) and hardened to **256/256 on fpylll** (`10`,`11`), so the residual is independent review, not scale. Show an independent cryptanalyst as **"found, hardened, mitigated."** Full write-up: `FINDINGS_20260615.md`.

---

## 8) VDF security — conditional model (formalized; see `../VDF_security/`)

The MCL-VDF (Paper 4 / Patent 3) is a **candidate** parallel-verifiable sequential function (O(N/k) verify, **not** a strict poly-log VDF). Its security is **formalized honestly**:

| Property | Status |
|---|---|
| Soundness (OP5) ⟸ Sequentiality (OP1) | ✅ **UNCONDITIONAL** reduction (determinism + exact checkpoint verify; no proof object to forge) |
| Sequentiality (OP1) | ⚠️ **conditional on SCIA** (a named, falsifiable assumption); reduction to SCIA tight & unconditional |
| SCIA itself | ❌ **OPEN** — sole cryptographic obligation (discharge via R1 reduction-to-iterated-RO or R3 chaos-hardness; R2 = complexity-separation-hard) |
| Cryptanalysis suite (`VDF_security/`) | ✅ rules out within-step parallelization + approximation/algebraic-degree/Koopman shortcuts; ❌ does NOT bound cross-iteration parallel depth (Lyapunov = forward sensitivity, not a depth bound; cf. MinRoot) |

Epistemic status = same as hash-chain VDFs (conditional theorem + failed-attack body). The honest claim is "Theorems 1–2 conditional on SCIA"; **do not state the VDF as proven/strict.**

---

## Bottom line: PROVEN vs NOT PROVEN

**✅ PROVEN / DONE**
- Shor inapplicable; VDF quantum-robust; default (p,q) is sub-PQ.
- T4-Q30 and the cascade reach **NIST Category 5 via the 256-bit key space** (256-bit key = AES-256-equivalent = 128 post-Grover bits = the **highest** category; the earlier "Level 1" label was wrong by four categories — see Tech Guide §4 / `mcl_core.hpp` `meets_category5`).
- Both run **FPU-free** (deployable on SIM/eSIM secure elements); **0 FPU ops confirmed at ARMv6-M instruction level** (§6).
- **Claim 15 native-word multiply realized IN CODE** (uint32 weights ⇒ 2× native `muls`, no `__aeabi_lmul` on M0); engine working set **72 B** (§6).
- All seven PCT-04 `[MEASURE]` flags resolved from the in-hand build (§6).
- Excellent keystream statistics; capacity (256-bit key) genuinely carried.
- Correct, sanitizer-clean implementation; a one-way output (`commit32_oneway`) exists.
- **HYPERCHAOS proven** (λ₂>0 in **100/100** key-derived configs, 256-bit MPFR grid sweep; min≈1.5; robust to q=p+1).

**⚠️ MEASURED-BUT-LIMITED**
- Latency (0.38 ms T4 / 0.24 ms cascade) is **host-only (arm64)**, not target M0 — M0 figure needs analytic cycle count or real silicon, NOT QEMU.
- Security has **no independent audit** — the dominant caveat for any size/perf comparison; never present a footprint advantage without tying it to the verification path.
- Cascade still emits `__aeabi_lmul` on M0 (core `mcl_q30_iterate_raw` untouched; separate decision).

**🔁 RETRACTED (was wrongly flagged as a weakness)**
- **"Raw Q30 keystream state-recoverable (b_eff=1)"** — RETRACTED. b_eff=1.00 at
  8-bit is generic arithmetic (small b_2D≈3.25 + 8-bit byte; width-scaling
  confirms `1+(b_2D−1)/2^k`), NOT a weakness. An ~invertible state-update map is
  normal for a keystream generator; state recovery from keystream does NOT follow
  and was never demonstrated (dieharder/ent show no weakness). No FAILED test
  anywhere. `commit32_oneway()` remains as harmless defensive hygiene, but it was
  added against an OVERSTATED risk, not a confirmed break.

**Honest residual (a property, not a break):** the Q30 map is much less folding
than Float64 (b_2D≈3.25 vs ~1444) — relevant only to map-based one-wayness, which
no MCL construction uses.

## Disclosure / filing rule

Claim the green rows (Shor-inapplicable, VDF-robust, Category-5-via-256-bit-key,
FPU-free, hyperchaos, statistics pass). Do NOT repeat the retracted "Q30
keystream state-recoverable" claim — it was a misinterpretation of b_eff=1.
Honest wording for the Q30 map: "less folding than the Float64 engine
(b_2D≈3.25 vs ~1444); this is immaterial to the keyed constructions, whose
one-wayness comes from SHA-256, not the map." (Optional: a true keystream
state-recovery analysis and 4-osc b_eff, for completeness — neither is implied
to be a problem.)

## Reproduce

```sh
cd 20260611_keyed_q30
c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish -o t   mcl_keyed_q30_test.cpp      && ./t   # 9/9 pass
c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish -o m   mcl_keyed_q30_measure.cpp   && ./m   # [MEASURE] runner (72 B, CRCs, matrix)
# Claim-13 ARMv6-M codegen evidence (clang is a cross-compiler; no install needed):
clang -target thumbv6m-none-eabi -mcpu=cortex-m0 -ffreestanding -O2 -S m0_codegen_probe.c -o m0_probe.s
c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish -o s1  mcl_keyed_q30_science.cpp   && ./s1
c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish -o s2  mcl_keyed_q30_science2.cpp  && ./s2
c++ -std=c++17 -O3 -Wall -Wextra -I ../MCL_publish -o s3  mcl_keyed_q30_science3.cpp  && ./s3
# definitive hyperchaos (needs Homebrew gmp+mpfr):
c++ -std=c++17 -O2 -I ../MCL_publish -I /opt/homebrew/opt/mpfr/include -I /opt/homebrew/opt/gmp/include \
    mcl_keyed_q30_mpfr_lyap.cpp -L /opt/homebrew/opt/mpfr/lib -L /opt/homebrew/opt/gmp/lib \
    -lmpfr -lgmp -o mpfr_lyap && ./mpfr_lyap
```

Saved outputs: `MCL_KEYED_Q30_RESULTS_20260611.txt`, `MCL_KEYED_Q30_SCIENCE_20260611.txt`,
`MCL_KEYED_Q30_SCIENCE2_20260611.txt`, `MCL_KEYED_Q30_SCIENCE3_20260611.txt`,
`MCL_KEYED_Q30_MPFR_LYAP_20260611.txt` (the definitive hyperchaos proof),
`MCL_KEYED_Q30_MEASURE_20260612.txt` (PCT-04 [MEASURE] runner: 72 B, CRCs, overflow bounds, cross-platform matrix),
`M0_CODEGEN_CLAIM13_20260612.txt` + `m0_probe.s` (ARMv6-M Claim-13 evidence: native muls, 0 FPU, 0 __aeabi_lmul for the coupling argument).

## VDF128_T4 — 128-bit-state integer VDF path (2026-08-17, adjacent artifact)

The sibling folder `../VDF128_T4/` reuses this sidecar's `mcl_q30t4_iterate_raw` + `mcl_t4_q30_params_from_key`
(included read-only) as the delay engine for a **public-parameter** VDF (Paper 4 §IV.C). It replaces the
two-oscillator `mcl_q30_iterate_raw` (64-bit state) in the VDF role only — that path was measured to close
its orbit at cycle length **λ = 1,671,196,332 ≈ 2³⁰·⁶** and its init collapses the input to s mod 2³²
(Paper 4 §VII.E′). VDF128_T4 fixes both: 128-bit reachable state, SHA-256 input injection, SHA-256-finalized
output bound to (x, N). Public weights = KDF from SHA-256("MCL-VDF128-T4-v1 public parameters"), no secret.
Cycle-probe (`vdf128_cycleprobe_apple_20260817.log`): old path closes at ~2³¹; new path no closure ≤2³³ ×3
inputs; init avalanche 60/128 bits (old: 0); 33.9 M iter/s. Compiles clean under the full strict-flag set
(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion). The keyed (secret-key) VDF variant is
unchanged and remains available. This sidecar's own truth-table above is unaffected — VDF128_T4 is additive.

**Battery status (2026-08-17):** the adapted 10-property + 4-attack VDF battery
(`../VDF128_T4/mcl_vdf128_battery.cpp`) runs **14/14 PASS** on VDF128_T4. Adding that
artifact left this sidecar bit-identical: suite 9/9, and the frozen CRCs (LUT `0xDE1340CF`,
T4 commit `0x58C99E3E`, cascade `0xF7C81BC4`) re-verified unchanged the same day.

- **2026-08-22 v1.0.6:** symmetry rejection in from_key (fail-closed); KATs unchanged; 0.19% of keys re-drawn — see NOSYM_V106_RECORD_20260822.md
