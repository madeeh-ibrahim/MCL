/*
 * ============================================================================
 * MCL Keyed Q30 -- sidecar v1.0.6 / v1.0.7 differential dump
 * ============================================================================
 *
 * Document ID:   MCL-KEYED-Q30-V107-2026-0928-002
 * Version:       1.0.0
 * Date:          September 28, 2026
 * Author:        Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:       madeeh.chaotic.lock@gmail.com
 *
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * Patent Pending: PCT/IB2026/052737, PCT/IB2026/053253, PCT/IB2026/053673,
 *                 PCT/IB2026/058860.
 *
 * PURPOSE: Dump what the sidecar computes, through the interface that v1.0.6
 * and v1.0.7 share, so that the two versions can be compared line by line.
 *
 * The program uses no symbol that v1.0.6 lacks. Build it twice, once against
 * each header, run both, and compare the two outputs with
 * mcl_keyed_q30_v107_compare.py.
 *
 * The header of v1.0.6 is the file keyed_q30_PQ/mcl_keyed_q30.hpp of release
 * v0.2.14 (SHA-256 71a0dbaf84725ac7...). Put a copy of it in a directory that
 * holds no mcl_core.hpp, so that both builds take the engine from "-I..":
 *
 *   mkdir -p /tmp/v106
 *   git show v0.2.14:keyed_q30_PQ/mcl_keyed_q30.hpp > /tmp/v106/mcl_keyed_q30_v106.hpp
 *   c++ -std=c++17 -O3 -I.. -DHDR='"/tmp/v106/mcl_keyed_q30_v106.hpp"' \
 *       -o dump106 mcl_keyed_q30_v107_dump.cpp
 *   c++ -std=c++17 -O3 -I.. -o dump107 mcl_keyed_q30_v107_dump.cpp
 *   ./dump106 > first.txt
 *   ./dump106 $(awk '$1=="CEP" && $3==1 {print $2}' first.txt) > dump_v106.txt
 *   ./dump107 $(awk '$1=="CEP" && $3==1 {print $2}' first.txt) > dump_v107.txt
 *   python3 mcl_keyed_q30_v107_compare.py dump_v106.txt dump_v107.txt
 *
 * Without HDR the program includes the header that lies next to it. The first
 * line of each dump names the engine; the comparison requires the two to agree.
 *
 * Arguments: key indices whose cascade output is dumped in addition to the
 * first 5,000. v1.0.7 cannot name the keys of the class -- it has re-drawn
 * them -- so the list comes from the v1.0.6 build.
 *
 * Lines:
 *   T4W <key index> <challenge> <CRC-32 of the twelve weights>      65,536 keys
 *   T4C <key index> <seed index> <CRC-32 of 64 keystream bytes> <commit32> <commit32_oneway>
 *                                                                   256 keys x 4 seeds
 *   CEP <key index> <class flag> <CRC-32 of the epoch list>         200,000 keys
 *   COUT <key index> <CRC-32 of the cascade output>                 5,000 keys + arguments
 *
 * The class flag is computed HERE, from the parity of the epoch list that the
 * header returns: 1 when every epoch has p = q (mod 2).
 * ============================================================================
 */
#ifdef HDR
#include HDR
#else
#include "mcl_keyed_q30.hpp"
#endif
#include <cstdio>
#include <cstdlib>
#include <vector>

static void test_key(const char* lab, uint32_t i, uint8_t key[32]) {
    uint8_t msg[48];
    const size_t n = std::strlen(lab);
    std::memcpy(msg, lab, n);
    for (int b = 0; b < 4; b++) msg[n + (size_t)b] = (uint8_t)(i >> (b * 8));
    mcl_sha256(msg, n + 4, key);
}

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);
    std::vector<uint32_t> extra;
    for (int i = 1; i < argc; i++) {
        char* end = nullptr;
        const unsigned long v = std::strtoul(argv[i], &end, 10);
        if (end == nullptr || *end != '\0' || v >= 200000UL) {
            std::fprintf(stderr, "bad key index: %s\n", argv[i]);
            return 2;
        }
        extra.push_back((uint32_t)v);
    }
    std::printf("# engine %s\n", mcl_version());

    for (uint32_t i = 0; i < 65536; i++) {
        uint8_t key[32];
        test_key("MCL-V107-T4", i, key);
        const uint64_t ch = (uint64_t)(i % 3) * 0x9E3779B97F4A7C15ULL;
        const MCL_Q30_Sextet w = mcl_t4_q30_params_from_key(key, ch);
        std::printf("T4W %u %u 0x%08X\n", i, i % 3,
                    compute_crc32(reinterpret_cast<const uint8_t*>(&w), sizeof(w)));
    }

    const uint64_t seeds[4] = { DEFAULT_SEED, 1ULL, (1ULL << 31) + 5ULL,
                                (1ULL << 52) + 12345ULL };
    for (uint32_t i = 0; i < 256; i++) {
        uint8_t key[32];
        test_key("MCL-V107-T4", i, key);
        for (int s = 0; s < 4; s++) {
            MCL_T4_Q30 e(key, (uint64_t)i, seeds[s], K_DEFAULT);
            uint8_t ks[64], c[32], o[32];
            e.gen_bytes(ks, 64);
            e.commit32(c);
            e.commit32_oneway(o);
            std::printf("T4C %u %d 0x%08X 0x%08X 0x%08X\n", i, s,
                        compute_crc32(ks, 64), compute_crc32(c, 32),
                        compute_crc32(o, 32));
        }
    }

    std::vector<uint32_t> cls;
    for (uint32_t i = 0; i < 200000; i++) {
        uint8_t key[32];
        test_key("MCL-V107-CASC", i, key);
        const std::vector<std::pair<int64_t,int64_t> > ep =
            mcl_cascade_q30_params_from_key(key, 7, 0);
        bool all_same_parity = true;
        std::vector<uint8_t> ser;
        for (size_t e = 0; e < ep.size(); e++) {
            if (((ep[e].first ^ ep[e].second) & 1) != 0) all_same_parity = false;
            for (int b = 0; b < 8; b++) ser.push_back((uint8_t)((uint64_t)ep[e].first >> (b * 8)));
            for (int b = 0; b < 8; b++) ser.push_back((uint8_t)((uint64_t)ep[e].second >> (b * 8)));
        }
        if (all_same_parity) cls.push_back(i);
        std::printf("CEP %u %d 0x%08X\n", i, all_same_parity ? 1 : 0,
                    compute_crc32(ser.data(), ser.size()));
    }

    for (uint32_t i = 0; i < 5000; i++) {
        uint8_t key[32], o[32];
        test_key("MCL-V107-CASC", i, key);
        mcl_cascade_q30(key, o, 7, 0, DEFAULT_SEED, K_DEFAULT);
        std::printf("COUT %u 0x%08X\n", i, compute_crc32(o, 32));
    }
    for (size_t k = 0; k < extra.size(); k++) {
        if (extra[k] < 5000) continue;          // already dumped
        uint8_t key[32], o[32];
        test_key("MCL-V107-CASC", extra[k], key);
        mcl_cascade_q30(key, o, 7, 0, DEFAULT_SEED, K_DEFAULT);
        std::printf("COUT %u 0x%08X\n", extra[k], compute_crc32(o, 32));
    }
    std::printf("# class keys seen by this build: %zu\n", cls.size());
    return 0;
}
