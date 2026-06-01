/*
 * ============================================================================
 * MCL Q30 Cross-Platform Validation Test
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-Q30-MACOS-VALIDATION-2026-0526-001
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
 * PURPOSE: Validate MCL Q30 (fixed-point engine) cross-platform bit-exactness
 *   between macOS Apple-libm and Linux glibc-libm for the Q30 engine; the
 *   Float64 MCL_T2 baseline is expected to differ by platform.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -o q30_macos_validation q30_macos_validation.cpp -lm && ./q30_macos_validation
 *
 * EXPECTED RESULTS:
 *   Q30 init state, 10000-iter state, and LUT CRC all match Linux reference
 *   values. Specifically: theta1(0) = 0xc8afd74a, theta2(0) = 0x0db2bac6,
 *   after 10000 iter theta1 = 0x6f88c52e, theta2 = 0xe06c516c,
 *   LUT CRC-32 = 0xde1340cf.
 *
 * REFERENCES:       mcl_core.hpp v6.0.0 (Q30 engine fix for Apple-libm).
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
#include <cstdio>

int main() {
    const uint64_t seed = 12345678901234ULL;
    
    std::printf("════════════════════════════════════════════\n");
    std::printf(" MCL Q30 v6.0.0 — macOS Cross-Platform Test\n");
    std::printf("════════════════════════════════════════════\n\n");
    
    // Test Q30 init_state (the FIX target)
    uint32_t t1, t2;
    mcl_q30_init_state(seed, t1, t2);
    std::printf("Q30 Initial State:\n");
    std::printf("  θ₁(0) = 0x%08x   (expected: 0xc8afd74a)\n", t1);
    std::printf("  θ₂(0) = 0x%08x   (expected: 0x0db2bac6)\n", t2);
    std::printf("  Match Linux? %s\n\n",
        (t1 == 0xc8afd74a && t2 == 0x0db2bac6) ? "✓ YES — bit-exact!" : "✗ MISMATCH");
    
    // Test Q30 iterate (after 10000 iterations)
    int64_t K_phase = mcl_q30_K_phase(12.0);
    uint32_t a = t1, b = t2;
    for (int i = 0; i < 10000; i++) {
        mcl_q30_iterate_raw(a, b, 3, 5, K_phase);
    }
    std::printf("Q30 State after 10000 iterations:\n");
    std::printf("  θ₁ = 0x%08x   (expected: 0x6f88c52e)\n", a);
    std::printf("  θ₂ = 0x%08x   (expected: 0xe06c516c)\n", b);
    std::printf("  Match Linux? %s\n\n",
        (a == 0x6f88c52e && b == 0xe06c516c) ? "✓ YES — bit-exact!" : "✗ MISMATCH");
    
    // Test LUT CRC
    const MCL_Q30_Table& tab = mcl_q30_table();
    uint32_t lut_crc = compute_crc32((const uint8_t*)tab.lut, 65536 * sizeof(int32_t));
    std::printf("LUT CRC-32:\n");
    std::printf("  Computed: 0x%08x   (expected: 0xde1340cf)\n", lut_crc);
    std::printf("  Match Linux? %s\n\n",
        (lut_crc == 0xde1340cf) ? "✓ YES — bit-exact!" : "✗ MISMATCH");
    
    // Test Float64 (must remain unchanged on macOS — different from Linux)
    std::printf("Float64 baseline (MCL_T2):\n");
    MCL_T2 gen(seed, 3, 5);
    uint8_t buf[10000];
    gen.gen_bytes(buf, 10000);
    uint32_t crc = compute_crc32(buf, 10000);
    std::printf("  CRC-32 (10KB) = 0x%08x\n", crc);
    std::printf("  Expected on macOS: 0x1A734C6F (Apple-libm)\n");
    std::printf("  Expected on Linux: 0xF5E977E0 (glibc-libm)\n");
    std::printf("  Note: Float64 is libm-dependent; cross-platform divergence is expected.\n\n");
    
    std::printf("════════════════════════════════════════════\n");
    // Exit code gates on the three platform-INDEPENDENT Q30 bit-exact checks
    // (init state, 10000-iter state, LUT CRC). The Float64 baseline above is
    // libm-dependent and intentionally NOT gated.
    return (t1 == 0xc8afd74a && t2 == 0x0db2bac6 &&
            a  == 0x6f88c52e && b  == 0xe06c516c &&
            lut_crc == 0xde1340cf) ? 0 : 1;
}
