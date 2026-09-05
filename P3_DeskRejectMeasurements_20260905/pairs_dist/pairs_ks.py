#!/usr/bin/env python3
"""Paper 3 measurement 5c (2026-09-05): is the DISTRIBUTION of the pairwise correlation
statistics the null distribution?  Input A: the Fig. 3 matrix (190 signed r, N=1e7 bytes,
seed 12345678901234) -> z = r*sqrt(N) tested against N(0,1) (KS, Anderson-Darling,
Cramer-von Mises, Shapiro-Wilk, moments).  Input B: the evidence TSV of `mcl_orth_verify --full`
(3,800 |r| values, 20 seeds) -> |z| tested against the half-normal (KS, AD via folded CDF,
moments).  Writes a QQ figure and a results text file."""
import sys, re, math, numpy as np
from scipy import stats
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt

def summarize(name, z, folded, out):
    n = len(z)
    if folded:
        cdf = lambda x: 2*stats.norm.cdf(x) - 1
        ks = stats.kstest(z, cdf)
        # AD for fully specified distribution
        zs = np.sort(z); F = np.clip(cdf(zs), 1e-300, 1-1e-16)
        i = np.arange(1, n+1); A2 = -n - np.mean((2*i-1)*(np.log(F) + np.log(1-F[::-1])))
        theo_mean, theo_var = math.sqrt(2/math.pi), 1 - 2/math.pi
        lines = [f"[{name}] n={n}  half-normal null",
                 f"  KS D={ks.statistic:.4f} p={ks.pvalue:.3f}",
                 f"  AD A^2={A2:.3f} (fully specified: 5%=2.492, 1%=3.857)",
                 f"  mean|z|={z.mean():.4f} (theory {theo_mean:.4f}, SE {math.sqrt(theo_var/n):.4f})  var={z.var():.4f} (theory {theo_var:.4f})",
                 f"  max|z|={z.max():.3f} (expected max of {n} half-normals ~ {stats.norm.ppf(1-0.5/n):.2f})"]
    else:
        ks = stats.kstest(z, 'norm'); ad = stats.anderson(z, 'norm'); cvm = stats.cramervonmises(z, 'norm'); sw = stats.shapiro(z)
        zs = np.sort(z); F = np.clip(stats.norm.cdf(zs), 1e-300, 1-1e-16); i = np.arange(1, n+1)
        A2 = -n - np.mean((2*i-1)*(np.log(F) + np.log(1-F[::-1])))
        lines = [f"[{name}] n={n}  N(0,1) null",
                 f"  KS D={ks.statistic:.4f} p={ks.pvalue:.3f}",
                 f"  AD A^2={A2:.3f} fully specified N(0,1) (5%=2.492, 1%=3.857); scipy-estimated-params A^2={ad.statistic:.3f} (crit 5%={ad.critical_values[2]:.3f})",
                 f"  CvM W^2={cvm.statistic:.4f} p={cvm.pvalue:.3f}   Shapiro-Wilk W={sw.statistic:.4f} p={sw.pvalue:.3f}",
                 f"  mean={z.mean():+.4f} (SE {1/math.sqrt(n):.4f})  var={z.var():.4f}  skew={stats.skew(z):+.3f}  ex.kurt={stats.kurtosis(z):+.3f}",
                 f"  max|z|={np.abs(z).max():.3f} (expected max|z| of {n} normals ~ {stats.norm.ppf(1-0.25/n):.2f})",
                 f"  t-test mean=0: t={stats.ttest_1samp(z,0).statistic:+.3f} p={stats.ttest_1samp(z,0).pvalue:.3f}; chi2 var=1: {(n-1)*z.var(ddof=1):.1f} on {n-1} df, p={2*min(stats.chi2.cdf((n-1)*z.var(ddof=1), n-1), 1-stats.chi2.cdf((n-1)*z.var(ddof=1), n-1)):.3f}"]
    out.extend(lines); print("\n".join(lines))

def load_fig3(path):
    r = []
    for line in open(path):
        if line.startswith('#') or line.startswith('i,'): continue
        parts = line.strip().split(','); r.append(float(parts[-1]))
    m = re.search(r'N=(\d+)', open(path).readline()); N = int(m.group(1))
    return np.array(r), N

def load_evidence(path):
    """Pearson section rows: test_id seed (i,j) abs_r pvalue thresh PASS"""
    absr = []; inP = False
    for line in open(path):
        if 'Pearson' in line and 'entries' in line: inP = True; continue
        if 'Hamming' in line and 'entries' in line: inP = False; continue
        if not inP: continue
        m = re.match(r'\s*(\d+)\s+(\d+)\s+\(\s*(\d+),\s*(\d+)\)\s+([0-9.]+)\s+([0-9.eE+-]+)', line)
        if m: absr.append(float(m.group(5)))
    return np.array(absr)

if __name__ == '__main__':
    out = []
    fig3 = sys.argv[1]; r, N = load_fig3(fig3); z = r*math.sqrt(N)
    summarize(f"Fig.3 matrix {fig3.split('/')[-1]} (N={N})", z, False, out)
    zb = None
    if len(sys.argv) > 2:
        absr = load_evidence(sys.argv[2]); Nfull = int(sys.argv[3]) if len(sys.argv) > 3 else 10000000
        zb = absr*math.sqrt(Nfull); summarize(f"FULL campaign evidence {sys.argv[2].split('/')[-1]} (N={Nfull})", zb, True, out)
    open('pairs_ks_results.txt','w').write("\n".join(out)+"\n")
    # QQ figure
    fig, ax = plt.subplots(1, 2 if zb is not None else 1, figsize=(9 if zb is not None else 4.5, 4.2)); ax = np.atleast_1d(ax)
    (osm, osr), (sl, ic, R) = stats.probplot(z, dist='norm'); ax[0].plot(osm, osr, 'o', ms=3); lim = [min(osm), max(osm)]; ax[0].plot(lim, lim, 'k--', lw=1)
    ax[0].set_xlabel('N(0,1) quantiles'); ax[0].set_ylabel('z = r sqrt(N), 190 pairs'); ax[0].set_title('Fig. 3 pair statistics vs null')
    if zb is not None:
        zs = np.sort(zb); q = stats.norm.ppf(0.5 + 0.5*(np.arange(1, len(zs)+1)-0.5)/len(zs)); ax[1].plot(q, zs, 'o', ms=2); ax[1].plot([0, q.max()], [0, q.max()], 'k--', lw=1)
        ax[1].set_xlabel('half-normal quantiles'); ax[1].set_ylabel('|z|, 3,800 pairs'); ax[1].set_title('FULL campaign |r| sqrt(N) vs null')
    fig.tight_layout(); fig.savefig('pairs_qq.png', dpi=160); print('wrote pairs_ks_results.txt, pairs_qq.png')

# ---- 2026-09-05 addendum: rounded-null calibration + jacobi_orth CSV input -------------------------
def ad_half(z):
    n = len(z); zs = np.sort(z); F = np.clip(2*stats.norm.cdf(zs) - 1, 1e-300, 1-1e-16); i = np.arange(1, n+1)
    return -n - np.mean((2*i-1)*(np.log(F) + np.log(1-F[::-1])))
def rounded_null_p(A2_obs, n, N, dp=6, reps=4000, seed=1):
    """P(A^2 >= A2_obs) when |r| is rounded to `dp` decimals before z = |r| sqrt(N) (the evidence-file format)."""
    rng = np.random.default_rng(seed); A = np.empty(reps)
    for k in range(reps):
        rr = np.round(np.abs(rng.standard_normal(n))/math.sqrt(N), dp); A[k] = ad_half(rr*math.sqrt(N))
    return float((A >= A2_obs).mean()), float(np.median(A)), float(np.quantile(A, 0.95))
def load_pairs_csv(path, col='abs_r_bytes'):
    import csv as _csv
    return np.array([float(r[col]) for r in _csv.DictReader(open(path))])
if __name__ == '__main__' and len(sys.argv) > 4:
    # extra args: <jacobi_orth pairs csv (full precision)> <N>
    out2 = []
    absr6 = load_evidence(sys.argv[2]); N6 = int(sys.argv[3]); z6 = absr6*math.sqrt(N6); A6 = ad_half(z6)
    p6, med6, q95 = rounded_null_p(A6, len(z6), N6, 6)
    out2.append(f"[rounded-null calibration] evidence file prints |r| to 6 dp: observed A^2={A6:.3f}; under an iid half-normal null with the same rounding, P(A^2>=obs)={p6:.3f}, median A^2={med6:.2f}, 95%={q95:.2f} -> the tabulated 5%/1% points (2.49/3.86) do not apply to 6-dp data")
    zf = load_pairs_csv(sys.argv[4])*math.sqrt(int(sys.argv[5])); summarize(f"fresh-seed full-precision replicate {sys.argv[4].split('/')[-1]} (N={sys.argv[5]})", zf, True, out2)
    open('pairs_ks_results.txt','a').write("\n".join(out2)+"\n"); print("\n".join(out2))
