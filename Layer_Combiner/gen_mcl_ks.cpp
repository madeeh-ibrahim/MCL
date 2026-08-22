// gen_mcl_ks.cpp — emit an MCL keystream to stdout (robust-combiner experiment).
// Usage: ./gen_mcl_ks [nbytes] [seed_hex] [p] [q]  >  mcl_ks.bin
#include "mcl_core.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <string>

int main(int argc, char** argv) {
    int64_t  N    = (argc > 1) ? std::atoll(argv[1]) : 8000000;
    uint64_t seed = (argc > 2) ? std::strtoull(argv[2], nullptr, 16)
                               : 0xC0FFEE1234567890ULL;   // MCL layer "key" (independent of AES)
    int p = (argc > 3) ? std::atoi(argv[3]) : 3;
    int q = (argc > 4) ? std::atoi(argv[4]) : 5;

    MCL_T2 g(seed, p, q);
    const int64_t CH = 1 << 20;
    std::vector<uint8_t> buf(CH);
    int64_t left = N;
    while (left > 0) {
        int64_t m = left < CH ? left : CH;
        g.gen_bytes(buf.data(), m);
        std::fwrite(buf.data(), 1, (size_t)m, stdout);
        left -= m;
    }
    return 0;
}
