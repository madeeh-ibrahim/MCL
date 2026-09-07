#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cmath>
static const double OMEGA1 = 0.6180339887498949;
static inline double mod1(double x) { x = std::fmod(x, 1.0); if (x < 0) x += 1.0; return x; }
int main(int argc, char** argv) { for (int i = 1; i < argc; i++) { uint64_t s = std::strtoull(argv[i], nullptr, 10);
    double x0a = 0.05 + 0.9 * mod1((double)s * OMEGA1);                 // thirdmap expression
    double x0b = 0.05 + 0.9 * std::fmod((double)s * OMEGA1, 1.0);       // cycle-tool expression
    std::printf("seed %llu  thirdmap-expr %a  cycletool-expr %a  %s\n", (unsigned long long)s, x0a, x0b, x0a == x0b ? "same" : "DIFFERENT"); } }
