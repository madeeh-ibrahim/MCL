// SHA-256 hash-chain iteration rate on this host (CommonCrypto, hardware SHA extensions on Apple Silicon)
#include <CommonCrypto/CommonDigest.h>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <cstdint>
int main(){
  uint8_t s[32]; std::memset(s, 0x5a, 32);
  const uint64_t warm = 1000000, M = 20000000;
  for (uint64_t i = 0; i < warm; i++) CC_SHA256(s, 32, s);
  auto t0 = std::chrono::steady_clock::now();
  for (uint64_t i = 0; i < M; i++) CC_SHA256(s, 32, s);
  double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  std::printf("SHA-256 chain (32-byte state, CommonCrypto): %.1f M hashes/s, %.1f ns/hash  [%02x%02x%02x%02x]\n", M/1e6/sec, sec*1e9/M, s[0],s[1],s[2],s[3]);
  return 0;
}
