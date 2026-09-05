# VDF128_T4 — 128-bit-state integer VDF path (Paper 4 path-A rebuild, 2026-08-17)

Additive artifact — no existing engine file modified (root mcl_core.hpp and keyed_q30_PQ sidecar included read-only; engine pins untouched).

| File | Role |
|---|---|
| `mcl_vdf128_t4.hpp` | Spec + reference implementation (Doc ID MCL-VDF128-T4-2026-0817-001): public nothing-up-my-sleeve weights via sidecar KDF, SHA-256 input injection into the 4×32-bit state, `mcl_q30t4_iterate_raw` delay loop, SHA-256(state‖H(x)‖N‖tag) output |
| `mcl_vdf128_cyclecheck.cpp` | Brent control (old 2-osc path) + budgeted Brent on the new path + init avalanche + throughput + KAT (Doc ID MCL-VDF128-CYCLE-2026-0817-001) |
| `kat345.cpp` | Standalone re-run of tests 3–5 |
| `mcl_vdf128_battery.cpp` | **VDF property + falsification battery adapted to this interface** (Doc ID MCL-VDF128-BATTERY-2026-0817-001): the project's `mcl_vdf_verify` (10 properties) and `mcl_vdf_falsification` (4 attacks, OP1/OP3/OP4/OP5) are written against `VDF(seed,p,q,N)` and do NOT apply unmodified — this re-implements both for the public-parameter 128-bit interface. Adaptation log in the file header. |
| `vdf128_battery_apple_20260817.log` | Battery results: **14/14 pass** |
| `mcl_vdf128_xplat.cpp` + `vdf128_xplat_apple_20260817.log` | Cross-architecture / cross-optimization fingerprint (Doc ID MCL-VDF128-XPLAT-2026-0817-001): **8/8 identical** across arm64+x86_64 × -O0..-O3. Scope limits stated in the log — x86_64 ran under Rosetta, so a native Linux/glibc/GCC run is still outstanding. |
| `vdf128_cycleprobe_apple_20260817.log` | Combined measured results |

Headline: old 64-bit-state path closes at λ=1,671,196,332 (4th confirmation); new 128-bit path shows NO closure within 2³³ steps × 3 inputs; init collapse fixed (60/128 bits differ for s vs s+2³²; old: 0); 33.9 M iter/s.

## Test status (2026-08-17, Apple M2 Max)

| Layer | Result |
|---|---|
| Additivity proof (nothing existing moved) | engine `self_test` 7/7 KAT PASS · sidecar suite 9/9 · frozen CRCs **identical**: LUT `0xDE1340CF`, T4 commit `0x58C99E3E`, cascade `0xF7C81BC4` |
| Strict-flag compile (`-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion`) | clean, both artifacts |
| Cycle / init / throughput / KAT probe | see `vdf128_cycleprobe_apple_20260817.log` |
| **10 VDF properties + 4 falsification attacks (adapted)** | **14/14 PASS** — `vdf128_battery_apple_20260817.log` |
| Cross-arch (arm64 / x86_64) × cross-opt (-O0..-O3) | **8/8 bit-identical** — `vdf128_xplat_apple_20260817.log` (partial: Rosetta, not native Linux) |

Pending: ship to Zenodo archive with next version; FPGA re-validation of the VDF128 wrapper (the underlying T4 iterate is already silicon-proven); a NATIVE Linux/glibc/GCC x86_64 run (the arch axis is covered by the Rosetta matrix above; the OS+compiler-family axis is not). Big-endian hosts remain gated by the sidecar's `MCL_BIG_ENDIAN_ACK` guard and untested.

## v2 — per-input weights (2026-09-05, Paper 4 referee-eye round R4-1, option b)

`mcl_vdf128_t4_v2.hpp` (additive; Doc ID MCL-VDF128-T4-2026-0905-002) derives the twelve coupling weights from **h = SHA-256(x)** through `mcl_t4_q30_params_from_key(h, 0)` instead of a fixed public constant, so every input evaluates its own map F_x; the initial state is unchanged and the output tag is `MCL-VDF128-T4-v2-out`. Reason: against a fixed 128-bit map a Hellman / distinguished-point precomputation covering W₀ = 2⁸⁰ points gives a jump-ahead probability ≈ N·W₀/2¹²⁸ (≈ 2⁻⁸ at N = 2⁴⁰), three orders of magnitude above the v1 conjecture's generic term. The v1 header stays for the record; **Paper 4 now specifies v2** (Algorithm 1) and every VDF128-T4 number in the paper is re-measured on v2:

| File | Role | Result |
|---|---|---|
| `mcl_vdf128v2_battery.cpp` → `vdf128v2_battery_apple_20260905.log` | 10 properties + 4 attacks + **3 structural probes** (single-bit linear correlation, cube/degree, avalanche profile) | **22/22 PASS** |
| `mcl_vdf128v2_cyclecheck.cpp` → `vdf128v2_cycleprobe_apple_20260905.log` | budgeted Brent on three inputs (each its own F_x) | **no closure within 2³³ × 3** |
| `mcl_vdf128v2_bench.cpp` → `vdf128v2_bench_apple_20260905.log` | Eval throughput + checkpoint Verify with real threads (Apple M1 Pro) | 34.2 M iter/s; k = 1/2/4/8/16 → 1.02/2.01/3.92/6.47/6.70× |
| `mcl_vdf128v2_xplat.cpp` → `vdf128v2_xplat_apple_20260905.log`, `vdf128v2_xplat_linux_glibc_20260905.log` | fingerprint across arm64/x86_64 × −O0…−O3 + Linux GCC | **9/9 identical** |
| `p4_vdf128v2_kat.cpp` → `vdf128v2_kat_apple_20260905.log`, `vdf128v2_kat_linux_glibc_20260905.log` | Vector 5 v2 with every intermediate + avalanche profile + input-flip statistics | y = `1d0f60cc602b12ed…`, byte-identical on both platforms |

Engine-free re-implementation of v2 and the complete record: `../P4_ReviewMeasurements_20260905/`.
