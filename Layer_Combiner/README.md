# Layer_Combiner — robust-combiner (non-degradation) demonstration

Empirical evidence that MCL, used as an **additional / defense-in-depth layer** on top of
a base cipher with an **independent key**, is **non-degrading**: it cannot weaken the base,
and it adds an independent factor. Construction:

```
C = P  XOR  K_AES  XOR  K_MCL          (independent keys)
```

By the standard robust-combiner result, the composite is at least as strong as the
**stronger** of the two layers. This experiment demonstrates the property empirically with
the real MCL engine and a real AES-256-CTR keystream.

## Files
| File | Role |
|---|---|
| `gen_mcl_ks.cpp` | emits an MCL keystream (`MCL_T2::gen_bytes`) to stdout |
| `combiner_analysis.py` | builds the combiner, runs the stats + non-degradation demo (needs numpy) |
| `RESULTS.txt` | captured verdict (2026-06-21) |

## Reproduce
```sh
ENG=..                                  # path containing mcl_core.hpp
c++ -std=c++17 -O2 -I "$ENG" gen_mcl_ks.cpp -o gen_mcl_ks
./gen_mcl_ks 8000000 > mcl_ks.bin
head -c 8000000 /dev/zero | openssl enc -aes-256-ctr \
  -K 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  -iv 00000000000000000000000000000001 -nosalt > aes_ks.bin
python3 combiner_analysis.py mcl_ks.bin aes_ks.bin
```

## Result (N = 8,000,000 bytes/stream, 2026-06-21)
- **Independence** — `r(K_MCL, K_AES) = -3.97e-04` (at the `1/√N` noise floor) ⇒ MCL adds
  *diversity*, not correlated redundancy.
- **Non-degradation** — with a deliberately zero-entropy plaintext (`'AAAA…'`), removing **one**
  keystream from `C` leaves a residual at **8.0000 bits/byte** (still fully random): breaking
  AES alone leaves P hidden behind MCL, and vice versa.
- **Both required** — only removing **both** keystreams recovers P (entropy → 0).

⇒ As an additional layer with an independent key, MCL is provably non-degrading and contributes
an independent (algorithmically diverse) protection factor. The property is variant-agnostic;
shown here with `MCL_T2`, it holds identically for the keyed `MCL_T4_Q30` flagship (any
high-quality independent keystream). Combiner soundness requires the two keys be independent.
