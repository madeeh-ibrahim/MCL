/*
 * ============================================================================
 * MCL PractRand Streaming Test
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ============================================================================
 *
 * Document ID:   MCL-PRACTRAND-2026-0526-001
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
 * PURPOSE: Stream cryptographic-quality bytes from the MCL_T2 engine to
 *          stdout for piping to PractRand (RNG_test stdin8) or other
 *          statistical test suites (ent, dieharder, NIST SP 800-22).
 *
 *          MODES:
 *            stream (default)  Periodic progress messages on stderr (every 1 GiB).
 *                              Continues until interrupted (SIGINT / SIGTERM)
 *                              or downstream pipe closes.
 *            raw               No progress messages. Suitable for short captures
 *                              piped to ent or other quick analyzers.
 *
 *          USAGE:
 *            ./mcl_practrand                | RNG_test stdin8
 *            ./mcl_practrand 12345          | RNG_test stdin8 -tlmax 1TB
 *            ./mcl_practrand raw            | ent
 *            ./mcl_practrand raw 12345 | dd bs=1M count=1024 of=test.bin
 *            ./mcl_practrand --help
 *
 *          STREAMING NOTE: stdout is intentionally left buffered (default fully-
 *          buffered for binary streams) to maximize throughput. stderr is set to
 *          unbuffered so progress messages are visible promptly. Do not call
 *          setbuf(stdout, nullptr) here -- doing so would cripple throughput by
 *          forcing per-byte flushes.
 *
 *          PLATFORM SUPPORT: Linux and macOS (POSIX). Windows is not in scope:
 *          Windows opens stdout in TEXT mode by default, which translates LF to
 *          CRLF and corrupts binary streams. A Windows port would require
 *          _setmode(_fileno(stdout), _O_BINARY) at main() entry.
 *
 * BUILD & RUN (one line, from this file's directory):
 *   g++ -O3 -std=c++17 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -DMCL_UNSAFE_ALLOW_INVALID -o mcl_practrand mcl_practrand.cpp -lm && ./mcl_practrand
 *
 * EXPECTED RESULTS: Continuous binary stream to stdout; periodic GiB progress on stderr.
 * REFERENCES:       Paper 1 §III (Safe-Zone PRNG, T2 engine, Goldilocks extraction);
 *                   Paper 1 §V (PractRand validation methodology);
 *                   mcl_core.hpp v5.0.0 MCL_T2 engine (uniform-quality bytes).
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
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// ============================================================================
// Document version constants (mirror header).
// Use 'constexpr const char* const' to make BOTH the pointer AND the
// pointed-to data immutable.
// ============================================================================
static constexpr const char* const DOC_VERSION = "6.0.0";
static constexpr const char* const DOC_ID      = "MCL-PRACTRAND-2026-0526-001";

// ============================================================================
// Streaming parameters
// ============================================================================
static constexpr size_t   BUFFER_SIZE       = 65536;          // 64 KiB
static constexpr uint64_t BYTES_PER_GB      = 1024ULL * 1024ULL * 1024ULL;
static constexpr uint64_t PROGRESS_INTERVAL = BYTES_PER_GB;   // every 1 GiB
static constexpr size_t   STREAM_WARMUP     = 16ULL * 1024ULL * 1024ULL; // 16 MiB

// R4.11: protect invariants. The warmup loop and the progress trigger
// both assume that BUFFER_SIZE divides their respective totals exactly.
// If a future maintainer changes BUFFER_SIZE to a non-divisor (e.g.,
// 65535 or 100000), warmup would have a partial last chunk and the
// progress comparison (g_total_bytes >= next_progress) would still
// fire but the staircase of next_progress values would drift away from
// clean 1 GiB / 2 GiB / 3 GiB labels. Catch it at compile time.
static_assert(STREAM_WARMUP % BUFFER_SIZE == 0,
    "STREAM_WARMUP must be a multiple of BUFFER_SIZE");
static_assert(PROGRESS_INTERVAL % BUFFER_SIZE == 0,
    "PROGRESS_INTERVAL must be a multiple of BUFFER_SIZE");

// 64 KiB is chosen to match the Linux PIPE_BUF size, so that fwrite()
// to a pipe is typically delivered atomically by the kernel.
static_assert(BUFFER_SIZE >= 4096,
    "BUFFER_SIZE below 4 KiB hurts throughput on most platforms");

// Default seed -- a deliberately different value from the verifier suite
// (which uses 12345678901234ULL) so PractRand runs do not produce the
// same byte stream as the verifier suite.
static constexpr uint64_t DEFAULT_PRACTRAND_SEED = 98765432109876ULL;

// Default coupling parameters (Paper 1 primary embodiment).
static constexpr int64_t DEFAULT_P = 3;
static constexpr int64_t DEFAULT_Q = 5;

// ============================================================================
// Global state for signal-based graceful shutdown.
//
// Use std::atomic<bool> rather than 'volatile bool': in C++, only
// 'volatile std::sig_atomic_t' is strictly guaranteed to be safe for
// signal-handler reads/writes. std::atomic<bool> with the default
// memory_order (sequentially consistent) is also signal-safe in
// practice on every platform MCL targets, and produces clearer code
// than the 'volatile std::sig_atomic_t' alternative.
//
// g_total_bytes is read/written only in the main loop (never in the
// signal handler), so it does not need atomicity.
// ============================================================================
static std::atomic<bool> g_running{true};
static uint64_t          g_total_bytes = 0;

static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_running.store(false, std::memory_order_relaxed);
    }
}

// ============================================================================
// Warmup: discards STREAM_WARMUP bytes after engine construction so that
// the first published bytes are well past any initial-condition transient.
// MCL_T2 already burns in 10000 iterations internally; this additional
// 16 MiB warmup is belt-and-suspenders for very-long-run PractRand tests.
// ============================================================================
static void do_warmup(MCL_T2& eng) {
    std::vector<uint8_t> buf(BUFFER_SIZE);
    size_t remaining = STREAM_WARMUP;
    while (remaining > 0) {
        const size_t chunk = (remaining < BUFFER_SIZE)
            ? remaining : BUFFER_SIZE;
        eng.gen_bytes(buf.data(), static_cast<int64_t>(chunk));
        remaining -= chunk;
    }
}

// ============================================================================
// Stream mode: continuous output with periodic progress on stderr.
// ============================================================================
static void run_stream(uint64_t seed) {
    // R3.18: install signal handlers BEFORE construction + warmup so that
    // a SIGINT/SIGTERM arriving during the ~3-5 second warmup phase is
    // recorded by the handler and produces clean shutdown (exit 0) rather
    // than process termination by the default signal handler (exit 130
    // from SIGINT). do_warmup() does not check g_running, so the warmup
    // still runs to completion; the streaming loop then exits on its
    // first iteration when it observes g_running == false.
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);
    // SIGPIPE: When the downstream process (e.g., RNG_test) closes the
    // pipe -- normally because it has read enough data or is exiting --
    // the kernel sends SIGPIPE. Default action is termination, which
    // would skip our cleanup. Ignoring it lets fwrite() return a short
    // count or 0, which our loop detects and breaks gracefully.
    std::signal(SIGPIPE, SIG_IGN);

    MCL_T2 eng(seed, DEFAULT_P, DEFAULT_Q);
    do_warmup(eng);

    std::fprintf(stderr,
        "MCL PractRand %s | seed=%llu | (p,q)=(%lld,%lld) | streaming\n",
        DOC_VERSION,
        static_cast<unsigned long long>(seed),
        static_cast<long long>(DEFAULT_P),
        static_cast<long long>(DEFAULT_Q));

    std::vector<uint8_t> buffer(BUFFER_SIZE);
    uint64_t next_progress = PROGRESS_INTERVAL;
    const auto start_time = std::chrono::steady_clock::now();

    while (g_running.load(std::memory_order_relaxed)) {
        eng.gen_bytes(buffer.data(), static_cast<int64_t>(BUFFER_SIZE));
        if (std::fwrite(buffer.data(), 1, BUFFER_SIZE, stdout)
            != BUFFER_SIZE) break;
        g_total_bytes += BUFFER_SIZE;

        if (g_total_bytes >= next_progress) {
            const auto elapsed_sec =
                std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - start_time).count();
            const double mb_s = (elapsed_sec > 0)
                ? (static_cast<double>(g_total_bytes) / (1024.0 * 1024.0))
                  / static_cast<double>(elapsed_sec)
                : 0.0;
            std::fprintf(stderr,
                "  %llu GB | %02lld:%02lld:%02lld | %.1f MB/s\n",
                static_cast<unsigned long long>(g_total_bytes / BYTES_PER_GB),
                static_cast<long long>(elapsed_sec / 3600),
                static_cast<long long>((elapsed_sec % 3600) / 60),
                static_cast<long long>(elapsed_sec % 60),
                mb_s);
            next_progress += PROGRESS_INTERVAL;
        }
    }
}

// ============================================================================
// Raw mode: continuous output with NO progress messages. Suitable for
// short captures (dd, head -c, ent) where progress noise would pollute
// the parent's output.
// ============================================================================
static void run_raw(uint64_t seed) {
    // R3.18: install signal handlers BEFORE warmup so a signal during
    // the warmup phase results in clean exit rather than termination.
    // Raw mode does not honor SIGINT/SIGTERM (no g_running check in the
    // tight loop -- behavior preserved from v1.2.0), but SIGPIPE is
    // still ignored so 'head -c N' etc. close the pipe gracefully.
    std::signal(SIGPIPE, SIG_IGN);

    MCL_T2 eng(seed, DEFAULT_P, DEFAULT_Q);
    do_warmup(eng);

    std::vector<uint8_t> buffer(BUFFER_SIZE);
    while (true) {
        eng.gen_bytes(buffer.data(), static_cast<int64_t>(BUFFER_SIZE));
        if (std::fwrite(buffer.data(), 1, BUFFER_SIZE, stdout)
            != BUFFER_SIZE) break;
    }
}

// ============================================================================
// Help / usage
// ============================================================================
static void print_help(const char* progname) {
    std::fprintf(stderr,
        "Usage:\n"
        "  %s [seed]              # default mode: stream + progress on stderr\n"
        "  %s raw [seed]          # raw mode: no progress messages\n"
        "  %s --help              # this message\n"
        "\n"
        "If seed is omitted, default is %llu.\n"
        "Engine: MCL_T2 (p=%lld, q=%lld), warmup %llu MiB before first output.\n"
        "Document: %s v%s\n",
        progname, progname, progname,
        static_cast<unsigned long long>(DEFAULT_PRACTRAND_SEED),
        static_cast<long long>(DEFAULT_P),
        static_cast<long long>(DEFAULT_Q),
        static_cast<unsigned long long>(STREAM_WARMUP / (1024ULL * 1024ULL)),
        DOC_ID, DOC_VERSION);
}

int main(int argc, char* argv[]) {
    // stderr unbuffered for prompt progress messages.
    // stdout INTENTIONALLY LEFT BUFFERED for throughput (see header note).
    std::setbuf(stderr, nullptr);

    uint64_t seed         = DEFAULT_PRACTRAND_SEED;
    bool     raw_mode     = false;
    bool     seed_set     = false;  // tracks whether user provided a seed

    for (int i = 1; i < argc; i++) {
        const std::string arg = argv[i];
        if (arg == "raw") {
            raw_mode = true;
        } else if (arg == "-h" || arg == "--help") {
            print_help(argv[0]);
            return 0;
        } else {
            // R3.14: Reject negative arguments explicitly. std::stoull
            // accepts "-1" silently and wraps it to UINT64_MAX, which
            // looks like a successful but unexpected seed to the user.
            if (!arg.empty() && arg[0] == '-') {
                std::fprintf(stderr,
                    "Error: seed must be non-negative: %s\n"
                    "Try '%s --help' for usage.\n",
                    argv[i], argv[0]);
                return 1;
            }
            uint64_t parsed_seed = 0;
            try {
                parsed_seed = std::stoull(arg);
            } catch (...) {
                std::fprintf(stderr,
                    "Error: Invalid argument: %s\n"
                    "Try '%s --help' for usage.\n",
                    argv[i], argv[0]);
                return 1;
            }
            if (seed_set) {
                // R2.15: warn the user that a second seed silently
                // overrides the first.
                std::fprintf(stderr,
                    "Warning: multiple seeds provided; using last (%llu)\n",
                    static_cast<unsigned long long>(parsed_seed));
            }
            seed = parsed_seed;
            seed_set = true;
        }
    }

    // R2.13: mcl_core.hpp asserts seed != 0 inside the engine
    // constructor and abort()s. Catch the case here with a clear error
    // message instead of a cryptic assert dump.
    if (seed == 0) {
        std::fprintf(stderr,
            "Error: seed must be non-zero (mcl_core requires non-zero seed).\n"
            "Try '%s --help' for usage.\n",
            argv[0]);
        return 1;
    }

    if (raw_mode) run_raw(seed);
    else          run_stream(seed);
    return 0;
}
