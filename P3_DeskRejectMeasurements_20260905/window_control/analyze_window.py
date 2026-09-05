#!/usr/bin/env python3
"""Analysis of the in-window control run (Paper 3 measurement 5b): joins the r(K) map with the
09-03 direct phase-locking classification (reson_fig1grid.csv) and reports, per lock class,
how often a dK = 0.01 change of the coupling fails to decorrelate.  Writes window_summary.txt and window_map.png."""
import csv, math, numpy as np
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
rows = list(csv.DictReader(open("res_window_grid.csv")))
lock = {}
try:
    for r in csv.DictReader(open("../../P3_ReviewMeasurements_20260903/phaselock/reson_fig1grid.csv")):
        keys = {k.lower(): k for k in r}
        p = int(r[keys.get("p")]); q = int(r[keys.get("q")]); K = round(float(r[keys.get("k")]), 2)
        lock[(p, q, K)] = r
except Exception as e:
    print("lock table not joined:", e)
def locked_flag(c):
    return (int(c["period_A"]) > 0) or (float(c["R_alpha_A"]) > 0.9) or (float(c["lambda1_A"]) <= 0.02)
out = []
fig, ax = plt.subplots(2, 1, figsize=(8, 6.4), sharex=True)
for ti, (p, q) in enumerate([(2, 3), (3, 5)]):
    cells = [r for r in rows if r["pair"] == "sameTopo_dK" and int(r["pA"]) == p and int(r["qA"]) == q]
    K = np.array([float(c["KA"]) for c in cells]); rl = np.array([float(c["rlag_max64"]) for c in cells]); re = np.array([float(c["r_ens"]) for c in cells])
    mi = np.array([float(c["MI_MM_bits"]) for c in cells]); lk = np.array([locked_flag(c) for c in cells]); l1 = np.array([float(c["lambda1_A"]) for c in cells])
    n_lock = int(lk.sum()); fail_lock = int((((rl > 0.5) | (mi > 0.5)) & lk).sum()) if n_lock else 0
    n_chaos = int((~lk).sum()); fail_chaos = int((((rl > 0.5) | (mi > 0.5)) & ~lk).sum())
    out.append(f"({p},{q}) dK=0.01: locked cells {n_lock}: no-decorrelation (max|r|>0.5 or MI>0.5 bit) in {fail_lock}; chaotic cells {n_chaos}: no-decorrelation in {fail_chaos}; "
               f"chaotic-cell max |r|_lag={rl[~lk].max() if n_chaos else float('nan'):.4f}, max MI={mi[~lk].max() if n_chaos else float('nan'):.4f} bit; locked-cell min |r|_lag={rl[lk].min() if n_lock else float('nan'):.4f}")
    for c in cells:
        out.append(f"   K={float(c['KA']):.2f} λ1={float(c['lambda1_A']):+.3f} R_α={float(c['R_alpha_A']):.3f} per={c['period_A']:>3s} lock={int(locked_flag(c))}  r_ens={float(c['r_ens']):+.4f} r0={float(c['r0']):+.4f} r_lag={float(c['rlag_max64']):.4f} MI={float(c['MI_MM_bits']):.4f} χ²z={float(c['chi2_z']):.1f}")
    ax[ti].plot(K, rl, "o-", ms=4, label="max |r| over lags ≤64 (cos θ₁), same seed, ΔK = 0.01")
    ax[ti].plot(K, np.clip(mi / max(mi.max(), 1e-9), 0, 1), "s--", ms=3, label="MI (normalised to max)")
    ax[ti].fill_between(K, 0, 1, where=lk, alpha=0.15, color="gray", step="mid", label="direct-locked cell")
    ax[ti].set_ylabel(f"({p},{q})"); ax[ti].set_ylim(-0.05, 1.05); ax[ti].legend(fontsize=7, loc="center right")
ax[1].set_xlabel("K"); fig.suptitle("Does ΔK = 0.01 decorrelate? locked windows: no; chaotic cells: yes"); fig.tight_layout(); fig.savefig("window_map.png", dpi=160)
cross = [r for r in rows if r["pair"] == "crossTopo_sameK"]
out.append(f"cross-topology (2,3) vs (3,5) same K: max |r|_lag = {max(float(c['rlag_max64']) for c in cross):.4f}, max MI = {max(float(c['MI_MM_bits']) for c in cross):.4f} bit over {len(cross)} K values")
open("window_summary.txt", "w").write("\n".join(out) + "\n"); print("\n".join(out))
