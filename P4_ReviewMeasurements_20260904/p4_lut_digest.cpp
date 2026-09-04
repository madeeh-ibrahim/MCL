// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// P4 review measurement 2026-09-04 (external review round 2, item 4): the normative sine table as a
// byte sequence -- 65,536 int32 little-endian entries -- with its SHA-256 and CRC-32, written to
// q30_lut_int32le.bin so the table can ship with the artifact independently of any libm.
#include "mcl_core.hpp"
#include <cstdio>
#include <cstring>
static uint32_t crc32(const uint8_t* d,size_t n){uint32_t c=0xFFFFFFFFu;for(size_t i=0;i<n;i++){c^=d[i];for(int k=0;k<8;k++)c=(c>>1)^(0xEDB88320u&(0u-(c&1u)));}return ~c;}
int main(){
  const MCL_Q30_Table& t=mcl_q30_table(); static uint8_t b[65536*4];
  for(int i=0;i<65536;i++){ uint32_t v=(uint32_t)t.lut[i]; b[4*i]=(uint8_t)v; b[4*i+1]=(uint8_t)(v>>8); b[4*i+2]=(uint8_t)(v>>16); b[4*i+3]=(uint8_t)(v>>24); }
  uint8_t h[32]; mcl_sha256(b,sizeof b,h);
  std::printf("Q30 sine table: 65536 x int32 little-endian = %zu bytes\n", sizeof b);
  std::printf("  CRC-32  : 0x%08x\n", crc32(b,sizeof b));
  std::printf("  SHA-256 : "); for(int i=0;i<32;i++) std::printf("%02x",h[i]); std::printf("\n");
  std::printf("  in-memory CRC over lut[] bytes (engine convention): 0x%08x\n", crc32((const uint8_t*)t.lut,65536*4));
  std::printf("  lut[0]=%d lut[16384]=%d lut[32768]=%d lut[49152]=%d  (0, 2^30, 0, -2^30 expected)\n", t.lut[0],t.lut[16384],t.lut[32768],t.lut[49152]);
  FILE* f=std::fopen("q30_lut_int32le.bin","wb"); std::fwrite(b,1,sizeof b,f); std::fclose(f); std::printf("  written q30_lut_int32le.bin\n");
  return 0;
}
