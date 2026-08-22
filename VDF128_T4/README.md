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
