// Data for Figure 2 of the paper (Supplementary Material B.1): distance between the Gauss-Seidel and the
// Jacobi trajectory of the two-oscillator floating-point model (Eqs. (1)-(2), K = 12, (p, q) = (3, 5)),
// both started from the SAME post-burn-in state of the reference engine; raw |a - b| per phase, averaged
// over the two phases (the metric of Part 4 of the post-quantum test program). 200 seeds, 10^4 iterations.
// Columns: t, instantaneous distance (first seed), mean over the 200 seeds, running mean over 1..t (first seed).
// Build (from this folder): clang++ -std=c++17 -O2 -I.. -o fig2_gs_jacobi_divergence fig2_gs_jacobi_divergence.cpp
// Run:   ./fig2_gs_jacobi_divergence > fig2_gs_jacobi_divergence_20260930.csv 2> fig2_gs_jacobi_divergence_20260930.log
#include "mcl_core.hpp"
#include <cstdio>
#include <cmath>
#include <vector>
int main(){
    const int T=10000, S=200; std::vector<double> ens(T+1,0.0), inst(T+1,0.0), cum(T+1,0.0);
    for(int k=0;k<S;k++){ uint64_t seed=12345678901234ULL+1000003ULL*(uint64_t)k; MCL_T2 g(seed,3,5); double b1=g.theta1(), b2=g.theta2(); double c=0;
        for(int t=1;t<=T;t++){ g.iterate(); mcl_iterate_jacobi(b1,b2,3,5); double d=(std::fabs(g.theta1()-b1)+std::fabs(g.theta2()-b2))/2.0; ens[t]+=d/S; if(k==0){ inst[t]=d; c+=d; cum[t]=c/t; } } }
    std::printf("t,instantaneous_seed0,mean_200_seeds,running_mean_seed0\n"); for(int t=1;t<=T;t++) std::printf("%d,%.6f,%.6f,%.6f\n",t,inst[t],ens[t],cum[t]);
    double tail=0; for(int t=101;t<=T;t++) tail+=ens[t];
    std::fprintf(stderr,"engine %d.%d.%d; %d seeds x %d iterations from a common post-burn-in state\n",MCL_VERSION_MAJOR,MCL_VERSION_MINOR,MCL_VERSION_PATCH,S,T);
    std::fprintf(stderr,"mean over the 200 seeds at t = 1, 2, 3, 5, 10, 100: %.3f %.3f %.3f %.3f %.3f %.3f\n",ens[1],ens[2],ens[3],ens[5],ens[10],ens[100]);
    std::fprintf(stderr,"mean of the 200-seed average over t = 101..10000: %.4f  (2*pi/3 = %.4f)\n",tail/(T-100),2.0*M_PI/3.0);
    { uint64_t seed=12345678901234ULL; MCL_T2 g(seed,3,5); double t1,t2; mcl_init_state(seed,t1,t2); for(int i=0;i<BURNIN;i++) mcl_iterate_jacobi(t1,t2,3,5); double tot=0;
      for(int i=0;i<10000;i++){ g.iterate(); mcl_iterate_jacobi(t1,t2,3,5); tot+=std::fabs(g.theta1()-t1)+std::fabs(g.theta2()-t2); }
      std::fprintf(stderr,"Part-4 measurement of the post-quantum test program (separate burn-ins, seed 12345678901234): %.4f\n",tot/20000.0); }
    return 0; }
