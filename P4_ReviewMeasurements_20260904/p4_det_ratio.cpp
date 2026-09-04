// SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// MCL Reference Implementation. Free security research / evaluation for all
// (incl. companies) under SECURITY-RESEARCH-GRANT.md; commercial use requires
// a license (COMMERCIAL.md). See LICENSE and PATENTS.md in the repo root.
// Review measurement: direct phase-locking diagnostics on the Fig. 1 grid (K in [0.30,1.00] step 0.02).
// P4 review measurement 2026-09-04: orbit-averaged log-determinants and the determinant-ratio estimator.
// det J_GS = (1-qKc1)(1-qKc2), det J_J = (1-qKc1)(1-qKc2) - p^2K^2 c1 c2 (exact one-step identities).
#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
int main(){
  const int64_t N=10000000; const int64_t p=3,q=5; const double K=K_DEFAULT;
  MCL_T2 g(12345678901234ULL,p,q); double t1=g.theta1(), t2=g.theta2();
  double Lgs=0, Lj_shared=0, Lj_ownc=0;
  for(int64_t i=0;i<N;i++){
    double c1=std::cos(p*t2-q*t1);
    double c2J=std::cos(p*t1-q*t2);                  // Jacobi's own second argument (old t1)
    double n1=mod2pi(t1+OMEGA_1+K*std::sin(p*t2-q*t1));
    double c2=std::cos(p*n1-q*t2);                    // GS second argument (new t1)
    double dgs=(1-q*K*c1)*(1-q*K*c2);
    Lgs      += std::log(std::fabs(dgs));
    Lj_shared+= std::log(std::fabs(dgs - p*p*K*K*c1*c2));            // shared (c1,c2): the cancellation estimator
    Lj_ownc  += std::log(std::fabs((1-q*K*c1)*(1-q*K*c2J) - p*p*K*K*c1*c2J)); // each map's own Jacobian at the same input state
    t1=n1; t2=mod2pi(t2+OMEGA_2+K*std::sin(p*n1-q*t2));
  }
  // Jacobi orbit's own average (its SRB measure)
  MCL_T2 h(12345678901234ULL,p,q); double j1=h.theta1(), j2=h.theta2(); double Ljo=0;
  for(int64_t i=0;i<N;i++){ double c1=std::cos(p*j2-q*j1), c2=std::cos(p*j1-q*j2); Ljo+=std::log(std::fabs((1-q*K*c1)*(1-q*K*c2)-p*p*K*K*c1*c2)); mcl_iterate_jacobi(j1,j2,p,q,K); }
  double cf=std::log((double)(q*q)/(q*q-p*p));
  std::printf("engine %d.%d.%d  (p,q)=(3,5) K=12  N=%lld post-burn-in\n",MCL_VERSION_MAJOR,MCL_VERSION_MINOR,MCL_VERSION_PATCH,(long long)N);
  std::printf("E_GS[ln|det J_GS|]                 = %.4f   (Oseledets: should match lambda1+lambda2 of GS ~ 6.80)\n", Lgs/N);
  std::printf("E_Jorbit[ln|det J_J|]              = %.4f   (should match lambda1+lambda2 of Jacobi ~ 6.35)\n", Ljo/N);
  std::printf("difference of orbit averages       = %.4f\n", (Lgs-Ljo)/N);
  std::printf("determinant-ratio estimator (shared c1,c2 on GS orbit) = %.4f   closed form ln(q^2/(q^2-p^2)) = %.4f\n", (Lgs-Lj_shared)/N, cf);
  std::printf("same-input-state, own-c2 variant                        = %.4f\n", (Lgs-Lj_ownc)/N);
  return 0;
}
