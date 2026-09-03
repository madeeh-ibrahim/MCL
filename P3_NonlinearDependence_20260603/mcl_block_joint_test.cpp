/* ============================================================================
 * MCL (Madeeh Chaotic Lock) — Cryptographic Reference Implementation
 * ----------------------------------------------------------------------------
 * Block-Level Joint Distribution Test  (Paper 3 v3, Experiment 5 / optional)
 *
 * Chi-square test of independence on the 256x256 joint byte histogram of two
 * MCL channels: chi2 = sum (O_ij - E_ij)^2 / E_ij, E_ij = hx_i*hy_j/N.
 * For large df, z = (chi2 - df)/sqrt(2 df) ~ N(0,1) under independence.
 *
 * Acceptance: one-sided z < 3.5 (dependence inflates chi2 -> upper tail only; a large NEGATIVE z is
 *   benign under-dispersion, not dependence). See Paper3_v3_MANIFEST.md "Methodological correction".
 * Positive controls: --control identical|quadratic -> enormous chi2 (z huge).
 *
 * Document ID:  MCL-BLOCKJOINT-2026-0526-v6-0-0
 * Version:      6.0.0
 * Date:         June 3, 2026
 * Author:       Madeeh Ibrahim, Independent Researcher, Cairo, Egypt
 * Contact:      madeeh.chaotic.lock@gmail.com
 * ORCID:        https://orcid.org/0009-0002-8562-8325
 * Engine:       mcl_core.hpp (frozen, MD5 241db79ecf8a42897eb9a8399cf37929).
 * License:      PolyForm Noncommercial 1.0.0.  Patent Pending.
 * SPDX-FileCopyrightText: 2026 Madeeh Ibrahim <madeeh.chaotic.lock@gmail.com>
 * SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
 * NO WARRANTY:  PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
 * ============================================================================
 */
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cmath>
#include <vector>
#include <string>
#include "mcl_core.hpp"

namespace {
constexpr const char* DOC_ID  = "MCL-BLOCKJOINT-2026-0526-v6-0-0";
constexpr const char* DOC_VER = "6.0.0";

void print_help() {
    std::printf("MCL (Madeeh Chaotic Lock) - Block-Level Joint Distribution Test\n");
    std::printf("DOC_ID %s  DOC_VER %s\n", DOC_ID, DOC_VER);
    std::printf("Usage: mcl_block_joint_test [--p1 P][--q1 Q][--p2 P][--q2 Q]\n");
    std::printf("       [--K K][--N N][--seed S][--control identical|quadratic]\n");
    std::printf("Defaults: p1=2 q1=3 p2=3 q2=5 K=12 N=1000000 seed=12345678901234\n");
}
}  // namespace

int main(int argc, char** argv) {
    std::setbuf(stdout, nullptr);
    int64_t p1=2,q1=3,p2=3,q2=5,N=1000000;
    double K=12.0; uint64_t seed=12345678901234ULL;
    std::string control;
    for (int i=1;i<argc;++i){ std::string a=argv[i];
        if (a=="--help"||a=="-h"){print_help();return 0;}
        else if (a=="--p1"&&i+1<argc){p1=std::atoll(argv[++i]);}
        else if (a=="--q1"&&i+1<argc){q1=std::atoll(argv[++i]);}
        else if (a=="--p2"&&i+1<argc){p2=std::atoll(argv[++i]);}
        else if (a=="--q2"&&i+1<argc){q2=std::atoll(argv[++i]);}
        else if (a=="--K"&&i+1<argc){K=std::atof(argv[++i]);}
        else if (a=="--N"&&i+1<argc){N=std::atoll(argv[++i]);}
        else if (a=="--seed"&&i+1<argc){seed=static_cast<uint64_t>(std::strtoull(argv[++i],nullptr,10));}
        else if (a=="--control"&&i+1<argc){control=argv[++i];}
        else {std::fprintf(stderr,"unknown arg: %s\n",a.c_str());return 1;}
    }
    if (N<256){std::fprintf(stderr,"FATAL: N>=256\n");return 1;}

    const size_t NN=static_cast<size_t>(N);
    std::vector<uint8_t> X(NN), Y(NN);
    { MCL_T2 ex(seed,p1,q1,K); ex.gen_bytes(X.data(),N); ex.erase(); }
    if (control=="identical"){ Y=X; }
    else if (control=="quadratic"){ for (size_t i=0;i<NN;++i){ const double d=static_cast<double>(X[i])-128.0;
        long v=std::lround((d*d)/64.0); if(v<0)v=0; if(v>255)v=255; Y[i]=static_cast<uint8_t>(v);} }
    else { MCL_T2 ey(seed,p2,q2,K); ey.gen_bytes(Y.data(),N); ey.erase(); }

    std::vector<int64_t> joint(256u*256u,0), hx(256u,0), hy(256u,0);
    for (int64_t t=0;t<N;++t){ const size_t xi=X[static_cast<size_t>(t)];
        const size_t yi=Y[static_cast<size_t>(t)];
        joint[xi*256u+yi]+=1; hx[xi]+=1; hy[yi]+=1; }

    int64_t nx=0,ny=0;
    for (size_t i=0;i<256u;++i) if (hx[i]>0) ++nx;
    for (size_t j=0;j<256u;++j) if (hy[j]>0) ++ny;
    const double Nd=static_cast<double>(N);
    long double chi2=0.0L;
    for (size_t i=0;i<256u;++i){ if (hx[i]==0) continue;
        const double hxi=static_cast<double>(hx[i]);
        for (size_t j=0;j<256u;++j){ if (hy[j]==0) continue;
            const double E=hxi*static_cast<double>(hy[j])/Nd;
            const double O=static_cast<double>(joint[i*256u+j]);
            const double d=O-E;
            chi2 += static_cast<long double>(d*d/E);
        } }
    const double chi2d=static_cast<double>(chi2);
    const double df=static_cast<double>((nx-1)*(ny-1));
    const double z=(df>0.0)?(chi2d-df)/std::sqrt(2.0*df):0.0;
    const bool pass=(z<3.5);  // one-sided: dependence inflates chi2 (upper tail); negative z = benign under-dispersion

    std::printf("# MCL block-joint-chi2  DOC_ID %s\n",DOC_ID);
    std::printf("ch1=(%lld,%lld) ch2=(%lld,%lld) K=%.4f N=%lld seed=%llu%s%s\n",
        static_cast<long long>(p1),static_cast<long long>(q1),
        static_cast<long long>(p2),static_cast<long long>(q2),K,
        static_cast<long long>(N),static_cast<unsigned long long>(seed),
        control.empty()?"":" control=",control.c_str());
    std::printf("chi2 = %.4f   df = %.0f\n",chi2d,df);
    std::printf("z = (chi2-df)/sqrt(2df) = % .4f\n",z);
    std::printf("VERDICT: %s  (z<3.5 one-sided => joint independent)\n",pass?"PASS(indep)":"FAIL(dependent)");
    return 0;
}
