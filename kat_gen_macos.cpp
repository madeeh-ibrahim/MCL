/*
 * ============================================================================
 * MCL KAT Generator — macOS Apple-libm Reference CRCs
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-KAT-GEN-MACOS-2026-0526-001
 * Version:       6.0.0
 * Date:          May 26, 2026, 10:00 UTC
 * Author:        Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:       madeeh.chaotic.lock@gmail.com
 * ORCID:         https://orcid.org/0009-0002-8562-8325
 * ============================================================================
 *
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Copyright (c) 2026 Madeeh Ibrahim. All rights reserved.
 *
 * MCL Reference Implementation. Free security research / evaluation for all
 * (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
 * a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673.
 * ============================================================================
 *
 * PURPOSE: Generate Known Answer Test (KAT) CRC-32 vectors for MCL_T2 engine
 *   using macOS Apple-libm. Outputs platform-specific CRC values for
 *   cross-platform verification.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -o kat_gen_macos kat_gen_macos.cpp -lm && ./kat_gen_macos
 *
 * EXPECTED RESULTS: 7 KAT vectors printed with CRC-32 checksums.
 *
 * ============================================================================
 *
 * NO WARRANTY / LIMITATION OF LIABILITY
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 *   OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE,
 *   AND NONINFRINGEMENT. IN NO EVENT SHALL THE COPYRIGHT HOLDER BE
 *   LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER IN
 *   AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING FROM, OUT
 *   OF, OR IN CONNECTION WITH THE SOFTWARE. TO THE FULLEST EXTENT
 *   PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE COPYRIGHT
 *   HOLDER BE LIABLE FOR ANY SPECIAL, INCIDENTAL, INDIRECT, OR
 *   CONSEQUENTIAL DAMAGES WHATSOEVER.
 */

#include "mcl_core.hpp"
int main() {
    struct KAT { const char* name; uint64_t seed; int64_t p, q; size_t nbytes; };
    KAT kats[] = {
        {"T2 default seed, (3,5), 1KB",     12345678901234ULL, 3, 5,    1000},
        {"T2 default seed, (3,5), 10KB",    12345678901234ULL, 3, 5,   10000},
        {"T2 default seed, (3,5), 100KB",   12345678901234ULL, 3, 5,  100000},
        {"T2 seed=12345, (3,5), 1KB",                12345ULL, 3, 5,    1000},
        {"T2 seed=12345, (7,11), 1KB",               12345ULL, 7,11,    1000},
        {"T2 pi-seed, (3,5), 10KB",         31415926535897ULL, 3, 5,   10000},
        {"T2 e-seed, (3,5), 10KB",          27182818284590ULL, 3, 5,   10000},
    };
    std::printf("// macOS Apple-libm CRCs (mcl_core.hpp v%s)\n", mcl_version());
    for (auto& k : kats) {
        MCL_T2 g(k.seed, k.p, k.q);
        std::vector<uint8_t> buf(k.nbytes);
        g.gen_bytes(buf.data(), static_cast<int64_t>(k.nbytes));
        std::printf("    {0x%08X, %lluULL, %lld, %lld, %zu, \"%s\"},\n",
                    compute_crc32(buf.data(), k.nbytes),
                    (unsigned long long)k.seed, (long long)k.p, (long long)k.q,
                    k.nbytes, k.name);
    }
    return 0;
}
