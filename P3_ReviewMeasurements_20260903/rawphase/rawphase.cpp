// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// Review measurement: dump raw phases (theta1, theta2) of the public engine after its own burn-in.
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cassert>
#include <vector>
#include <string>
#include <algorithm>
#include <functional>
#include <array>

#include "mcl_core.hpp"

int main(int argc,char**argv){
  int64_t p=atoll(argv[1]), q=atoll(argv[2]); double K=atof(argv[3]); long N=atol(argv[4]);
  MCL_T2 e(12345678901234ULL,p,q,K);
  std::vector<double> buf(2*(size_t)N);
  for(long i=0;i<N;i++){ e.iterate(); buf[2*i]=e.t1_; buf[2*i+1]=e.t2_; }
  FILE*f=fopen(argv[5],"wb"); fwrite(buf.data(),sizeof(double),buf.size(),f); fclose(f);
  return 0;
}
