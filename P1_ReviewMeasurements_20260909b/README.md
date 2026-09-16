# P1_ReviewMeasurements_20260909b — Paper 1, external review #5 (item ت-49)

**Doc ID:** MCL-P1-SINGLEWIN-2026-0909-001 · **Engine of record:** `mcl_core.hpp` v6.0.0 (MD5 `241db79ecf8a42897eb9a8399cf37929`, frozen copy included) · **Platform:** Apple Silicon, macOS, Apple clang.

**Build line:** `c++ -O3 -std=c++17 -ffp-contract=off -o mcl_p1_singlewindow_bytes mcl_p1_singlewindow_bytes.cpp -lm`. Compiled binaries are not shipped.

**Question.** The production extractor (Paper 1, Eq. 5) XORs two eight-bit windows of the XOR-mixed mantissa, bits [20, 27] and [36, 43], into one byte. Why two windows rather than one, when a single window starting at 36 already passes the byte-level test in the single-extractor scan (Table 6) and both forms emit eight bits per sample?

**Protocol.** Same six seeds and same production decimation D = 2 as MCL-P1-GOLDBIT-2026-0907-001; N = 10⁸ samples per seed; 256-bin byte-level χ² (df = 255, critical 310.46 at α = 0.01) of S20 = xm[20:27], S36 = xm[36:43] and A = S20 ⊕ S36 (Table 9 configuration A), plus the worst emitted-bit χ²(df = 1) of each.

**Result (log `singlewindow_apple_20260909.log`).** All six seeds pass for all three forms. Byte-level χ²: S20 mean 240.5 (208.9–266.5), S36 mean 263.4 (227.6–300.1), A mean 273.4 (232.9–294.1). Worst single bit: S20 6.196 (seed 12345678901234, bit 22), S36 9.728 (seed 17320508075688), A 12.096 (seed 12345678901234, the residual disclosed in Supplementary S5). The output yield is identical by construction (eight bits per decimated sample either way); speed was not measured for either form. The dual-window form is therefore a design choice justified by the second-order suppression of independent marginal biases (Eq. 6), not by measured byte-level quality, and no speed advantage is claimed.

Files: `mcl_p1_singlewindow_bytes.cpp` · `singlewindow_apple_20260909.log` · `mcl_core.hpp` · `SHA256SUMS`.

---

## Second record in this directory — Doc ID MCL-P1-LSBPARADOX-2026-0909-001 (Figure 5 / §3.3, Float64 vs Q30)

**Why.** The Figure 5 inherited from the May 2026 draft was a synthetic rendering: its generator (`make_fig4.py`, old project) states that the curves were "reverse-engineered" from a prior rendering and rescaled to three headline values (~41% and ~7% avalanche, χ² ≈ 261); its panel (b) was drawn with pseudo-random noise around 261. No log stood behind any plotted point. This tool measures the depicted quantities against the engine of record under a stated protocol.

**Protocol.** (A) Float64: M = 10⁶ orbit states after burn-in (seed 12345678901234, (p,q) = (3,5), K = 12); θ₁ perturbed by one ULP (`nextafter`); one iteration (Eqs. 1–2, same arithmetic as `MCL_T2::iterate`); per-bit difference fraction of the resulting θ₁ mantissa and of the XOR-mixed mantissa. (B) Q30 path of the same engine (`mcl_q30_iterate_raw`, `mcl_q30_init_state`, K_phase(12.0)): t1 perturbed by +1 phase unit; one iteration; per-bit difference fraction of t1 and of t1 ⊕ t2. (C) Q30 byte-level χ² (df = 255, critical 310.46) of window [P, P+7] of t1 ⊕ t2, P = 0..24, N = 10⁸ at D = 2.

**Result (log `lsb_paradox_apple_20260909.log`).** (A) Float64 single-ULP avalanche of the θ₁ mantissa peaks at 42.5% at bit 4 (bits 3–5: 39.6–42.5%), is 12.2% at bit 0, and falls below 0.25% from bit 16 onward; the XOR-mixed mantissa holds 40.9–41.7% across bits 3–8 and falls below 1% from bit 19 onward. (B) Q30 single-unit perturbation propagates as a carry chain to within measurement resolution — 99.997% at bit 0, 50.10% at bit 1, 25.00% at bit 2, halving per bit, with a residual of at most 0.006% at bits 15–31 for the t₁ word (≤ 0.009% for t₁ ⊕ t₂) — because one phase unit is far below the sine-table resolution (2¹⁶ entries); it is not a measure of chaotic sensitivity. (C) Q30 byte-level χ² passes at window starts 0–8 (192.0–266.5) and fails from start 9 upward (389.8 … 2.4 × 10⁵ at 24). The "7%" of the synthetic figure has no counterpart under any stated protocol; the "~41%" survives as the XOR-mixed plateau (40.9–41.7% across bits 3–8) and the θ₁ peak (42.5% at bit 4). Paper 1, Figure 5 and the Float64/Q30 table of §3.3 are generated from this log.

**Build:** `c++ -O3 -std=c++17 -ffp-contract=off -o mcl_p1_lsb_paradox_measure mcl_p1_lsb_paradox_measure.cpp -lm` (5 s). Files: `mcl_p1_lsb_paradox_measure.cpp` · `lsb_paradox_apple_20260909.log`.

---

## Third record in this directory — Doc ID MCL-P1-INITCONV-2026-0909-001 (Supplementary S3, initial-state conventions)

**Why.** Supplementary S3 compared the window-start-0 byte-level χ² under two initial-state derivations ("decimal multipliers (0.1, 0.2)" of a historical reference code vs the production derivation of `mcl_core.hpp`) and stated that the Safe Zone boundary is identical under both. Neither quoted value (5.8 × 10⁸, 173,441,741) had a log, and the second contradicted the archived Table 6 scan. This tool measures the claim.

**Protocol.** The single-extractor scan of Paper 1 §3.3 / Table 6 (Doc ID MCL-SAFEZONE-HOLDOUT-2026-0719-001): one iterate per sample, N = 10⁸, byte = (mantissa >> P) & 0xFF for P ∈ [0, 44], three streams θ₁ / θ₂ / XOR, χ² with df = 255 and critical value 310.46; (p,q) = (3,5), K = 12, burn-in 10⁴, seed 12345678901234. Four initial-state conventions on the same map: **A** production (`MCL_T2`; hash_seed for seeds > 2⁵², θᵢ(0) = (s·ωᵢ) mod 2π) — positive control; **A′** the same initial state iterated by a local copy of `MCL_T2::iterate` — self-check of the stepper used for B and C; **B** decimal multipliers θ₁(0) = (s·0.1) mod 2π, θ₂(0) = (s·0.2) mod 2π; **C** fixed decimal angles θ(0) = (0.1, 0.2).

**Result (log `initconv_apple_20260909.log`, 82 s).** A reproduces the archived Table 6 scan to the last printed digit (0 of 135 values differ from `safezone_scan_canonical_apple_20260719.csv`); A′ equals A in all 135 values. Window-start-0 θ₁ χ²: 209,268,665 (A), 209,391,948 (B), 209,385,913 (C) — 2.09 × 10⁸ under every convention, 5.8 orders of magnitude above 310.46; XOR 6.53–6.54 × 10⁷. The XOR Safe Zone is [6, 39] under A, B and C with the same eleven failing starts [0, 5] ∪ [40, 44] (pass/fail identical at 45 of 45 start positions; Safe-Zone mean χ² 250.6 / 259.7 / 251.8). The single-oscillator zones move with the convention (θ₁: [11, 36] / [11, 34] / [12, 35]; θ₂: [12, 34] / [12, 35] / [23, 34]). Neither previously quoted value (5.8 × 10⁸, 173,441,741) is reproduced by any convention; the Supplement S3 note and main-text §1.2 / §3.3 now carry the recorded value.

**Build:** `c++ -O3 -std=c++17 -ffp-contract=off -o mcl_p1_init_convention_scan mcl_p1_init_convention_scan.cpp -lm` (82 s). Files: `mcl_p1_init_convention_scan.cpp` · `initconv_apple_20260909.log`.

