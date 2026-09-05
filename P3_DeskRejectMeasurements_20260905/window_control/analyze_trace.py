#!/usr/bin/env python3
"""Ensemble-correlation analysis (measurement 5b'): (a) r_ens(t) traces for selected cells (periodic-locked,
quasi-periodic-locked, chaotic), (b) grid map of max|r_ens(t)| over t in [10^4, 10^4+200] for dK = 0.01 on the
Fig. 1 grid with the direct-locking classification.  Writes trace_summary.txt and trace_fig.png."""
import csv, math, numpy as np
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
grid = list(csv.DictReader(open("res_trace_grid.csv"))); cells = list(csv.DictReader(open("res_trace_cells.csv")))
ctrl = {(int(r["pA"]), int(r["qA"]), round(float(r["KA"]), 2)): r for r in csv.DictReader(open("res_window_grid.csv")) if r["pair"] == "sameTopo_dK"}
def locked(r): return (int(r["period_A"]) > 0) or (float(r["R_alpha_A"]) > 0.9) or (float(r["lambda1_A"]) <= 0.02)
out = []
fig, ax = plt.subplots(1, 2, figsize=(12, 4.2))
for (p, q, K) in sorted({(int(r["p"]), int(r["q"]), float(r["K"])) for r in cells}):
    rs = [r for r in cells if int(r["p"]) == p and int(r["q"]) == q and float(r["K"]) == K]
    t = np.array([int(r["t"]) for r in rs]) - 10000; re = np.array([float(r["r_ens"]) for r in rs])
    c = ctrl.get((p, q, round(K, 2))); tag = ("locked" if locked(c) else "chaotic") if c else ("chaotic" if K >= 6 else "?")
    per = c["period_A"] if c else "-"; lam = float(c["lambda1_A"]) if c else float("nan")
    out.append(f"trace ({p},{q}) K={K:g} [{tag}, period {per}, λ1={lam:+.3f}]: max|r_ens|={np.abs(re).max():.4f} rms={np.sqrt((re**2).mean()):.4f} mean={re.mean():+.4f} last={re[-1]:+.4f}")
    ax[0].plot(t[:600], re[:600], lw=0.9, label=f"({p},{q}) K={K:g} — {tag}" + (f", period {per}" if per not in ("0", "-") else ""))
ax[0].axhline(0, color="gray", lw=0.5); ax[0].set_xlabel("t − 10⁴ (iterations after the burn-in length)"); ax[0].set_ylabel("r_ens(t), 4,096 seeds, ΔK = 0.01"); ax[0].set_title("(a) ensemble correlation of two ΔK-perturbed trajectories"); ax[0].legend(fontsize=6.5)
for ti, (p, q) in enumerate([(2, 3), (3, 5)]):
    g = [r for r in grid if r["pair"] == "sameTopo_dK" and int(r["p"]) == p and int(r["q"]) == q]
    K = np.array([float(r["K"]) for r in g]); mx = np.array([float(r["max_abs_r_ens"]) for r in g]); rms = np.array([float(r["rms_r_ens"]) for r in g])
    lk = np.array([locked(ctrl[(p, q, round(k, 2))]) for k in K]); fl = float(g[0]["floor_3sigma"])
    ax[1].plot(K, mx, "o-" if ti == 0 else "s-", ms=3.5, lw=0.9, label=f"({p},{q}): max|r_ens(t)|, t ∈ [10⁴, 10⁴+200]")
    ax[1].fill_between(K, 0, 1.02, where=lk, alpha=0.12, color="C%d" % ti, step="mid", label=f"({p},{q}) direct-locked cells")
    nl, nc = int(lk.sum()), int((~lk).sum())
    out.append(f"grid ({p},{q}) dK=0.01: locked cells {nl}: max|r_ens| ≥ 0.3 in {int((mx[lk] >= 0.3).sum())} (min {mx[lk].min() if nl else float('nan'):.3f}); chaotic cells {nc}: max|r_ens| ≥ 0.3 in {int((mx[~lk] >= 0.3).sum())} (max {mx[~lk].max() if nc else float('nan'):.3f}, 3σ floor {fl:.3f}, expected max of 200 null values ≈ {3.0/math.sqrt(2048)*0.0+ (2*math.log(200))**0.5/math.sqrt(2048):.3f})")
    for r, l in zip(g, lk): out.append(f"   ({p},{q}) K={float(r['K']):.2f} lock={int(l)} max|r_ens|={float(r['max_abs_r_ens']):.4f} rms={float(r['rms_r_ens']):.4f} mean_ln_d={float(r['mean_ln_d_end']):+.3f}")
x = [r for r in grid if r["pair"] == "crossTopo_sameK"]; out.append(f"cross-topology (2,3)/(3,5), same K, over {len(x)} K values: max|r_ens| = {max(float(r['max_abs_r_ens']) for r in x):.4f}")
ax[1].axhline(fl, color="gray", lw=0.6, ls=":"); ax[1].set_xlabel("K"); ax[1].set_ylabel("max |r_ens(t)| after 10⁴ steps"); ax[1].set_ylim(-0.02, 1.05); ax[1].set_title("(b) where a ΔK = 0.01 change fails to decorrelate"); ax[1].legend(fontsize=6.5, loc="center right")
fig.tight_layout(); fig.savefig("trace_fig.png", dpi=320); open("trace_summary.txt", "w").write("\n".join(out) + "\n"); print("\n".join(o for o in out if not o.startswith("   ")))
