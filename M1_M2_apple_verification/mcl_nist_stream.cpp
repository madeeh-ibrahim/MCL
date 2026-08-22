// mcl_nist_stream.cpp — generate the single-channel production byte stream
// for the NIST SP 800-22 campaign (Doc ID MCL-NIST-STS-2026-0721-001).
// Engine: frozen v6.0.0 copy (M1_M2_apple_verification/mcl_core.hpp) — the
// engine of record cited by MD5 in Paper 1 §4.1.
// Config: MCL_T2, seed 12345678901234, (p,q)=(3,5), K=12, production
// gen_byte() (Goldilocks dual-zone, decimation D=2, burn-in 10,000).
// Output: 125,000,000 bytes = 1e9 bits = 1000 bitstreams x 1e6 bits.
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdint>

int main(int argc, char** argv) {
    const char* path = (argc > 1) ? argv[1] : "mcl_nist_stream.bin";
    const int64_t NBYTES = 125000000LL;
    MCL_T2 eng(12345678901234ULL, 3, 5, 12.0);
    FILE* f = std::fopen(path, "wb");
    if (!f) { std::perror("fopen"); return 1; }
    static uint8_t buf[1 << 20];
    int64_t written = 0;
    while (written < NBYTES) {
        int64_t chunk = NBYTES - written;
        if (chunk > (int64_t)sizeof(buf)) chunk = sizeof(buf);
        for (int64_t i = 0; i < chunk; i++) buf[i] = eng.gen_byte();
        std::fwrite(buf, 1, (size_t)chunk, f);
        written += chunk;
    }
    std::fclose(f);
    std::printf("wrote %lld bytes to %s (engine v6.0.0, seed 12345678901234, gen_byte)\n",
                (long long)written, path);
    return 0;
}
