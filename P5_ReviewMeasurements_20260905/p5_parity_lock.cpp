#include "mcl_core.hpp"
#include <cstdio>
int main(){ MCL_T2 e(12345678901234ULL,3,5,K_DEFAULT); uint8_t r[32]; e.gen_bytes(r,32);
 printf("raw[0]=0x%02x (parity %d)  raw[8]=0x%02x (parity %d)  M-2=%d (%s)  0x9E3779B97F4A7C15 is %s\n", r[0], r[0]&1, r[8], r[8]&1, 1000000-2, ((1000000-2)%2==0)?"even":"odd", (0x9E3779B97F4A7C15ULL&1)?"odd":"even");
 int ee=0,oo=0,mix=0; for(int i=0;i<200000;i++){ DerivedKey d=derive_child(12345678901234ULL,3,5,i,1000000,K_DEFAULT); /* post-gcd */ }
 // pre-gcd parity classes via the same mapping
 for(int i=0;i<200000;i++){ uint8_t raw[32]; for(int b=0;b<32;b++) raw[b]=r[b]; uint64_t h=fmix64((uint64_t)i), h2=h*0x9E3779B97F4A7C15ULL; for(int b=0;b<8;b++){raw[b]^=(uint8_t)(h>>(8*b)); raw[8+b]^=(uint8_t)(h2>>(8*b));}
   uint64_t c1=0,c2=0; memcpy(&c1,raw,8); memcpy(&c2,raw+8,8); int64_t p=2+(int64_t)(c1%999998), q=2+(int64_t)(c2%999998); if(p==q) q=2+((q-2+1)%999998);
   if((p&1)==0&&(q&1)==0)ee++; else if((p&1)&&(q&1))oo++; else mix++; }
 printf("pre-gcd parity classes over 2e5 indices: even-even %d, odd-odd %d, mixed %d\n",ee,oo,mix);
 int qodd=0; for(int i=0;i<20000;i++){ DerivedKey d=derive_child(12345678901234ULL,3,5,i,1000000,K_DEFAULT); qodd+=(d.q&1);} printf("post-gcd: q odd in %d/20000 = %.2f%%\n",qodd,100.0*qodd/20000); return 0; }
