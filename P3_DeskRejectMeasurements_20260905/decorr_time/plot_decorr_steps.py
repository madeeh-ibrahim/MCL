#!/usr/bin/env python3
"""Figure for Paper 3 v3 (measurement 5a): (a) <ln d(t)> vs t for several delta at (3,5), K=12, GS, with the
engine Lyapunov slope as reference; (b) ensemble correlation r_ens(t) for the same runs; (c) t_dec vs ln(1/delta_1)
for K = 6, 12, 20 (GS) and Jacobi K = 12, with lines of slope 1/lambda_1 through the fitted intercept."""
import csv, math, numpy as np
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
def load_steps(f): return list(csv.DictReader(open(f)))
def series(rows, delta):
    rs = [r for r in rows if abs(float(r["delta"]) - delta) <= 1e-6 * delta + 1e-15]
    return np.array([int(r["t"]) for r in rs]), np.array([float(r["mean_ln_d"]) for r in rs]), np.array([float(r["r_cos1"]) for r in rs])
fig, ax = plt.subplots(1, 3, figsize=(13, 4.0))
rows = load_steps("res_omega_35_K12_gs_steps.csv"); lam = float(next(csv.DictReader(open("res_omega_35_K12_gs_summary.csv")))["lambda1"])
for d in [1e-12, 1e-8, 1e-4]:
    t, ld, r = series(rows, d); m = t <= 12
    ax[0].plot(t[m], ld[m], "o-", ms=3, label=f"δ = {d:g}"); ax[1].plot(t[m], r[m], "o-", ms=3, label=f"δ = {d:g}")
t0 = np.array([1, 6]); ax[0].plot(t0, math.log(1e-12) + lam * (t0 - 1), "k--", lw=1, label=f"slope λ₁ = {lam:.2f} (engine)")
ax[0].axhline(0, color="gray", lw=0.6); ax[0].set_xlabel("iteration t"); ax[0].set_ylabel("⟨ln d(t)⟩  (rad)"); ax[0].set_title("(a) separation growth, (3,5), K = 12"); ax[0].legend(fontsize=7)
ax[1].axhline(4 / math.sqrt(16384), color="gray", lw=0.6, ls=":"); ax[1].axhline(-4 / math.sqrt(16384), color="gray", lw=0.6, ls=":")
ax[1].set_xlabel("iteration t"); ax[1].set_ylabel("r_ens(t) of cos θ₁ over 16,384 seeds"); ax[1].set_title("(b) ensemble correlation"); ax[1].legend(fontsize=7)
fit = {(r["update"], r["K"], r["mode"]): r for r in csv.DictReader(open("decorr_fit_table.csv")) if r["p"] == "3"}
for (upd, K, mode, mk) in [("gs", "6", "omega", "o"), ("gs", "12", "omega", "s"), ("gs", "20", "omega", "^"), ("jacobi", "12", "omega", "D")]:
    summ = list(csv.DictReader(open(f"res_omega_35_K{K}_{upd}_summary.csv"))); steps = load_steps(f"res_omega_35_K{K}_{upd}_steps.csv")
    x, y = [], []
    for s in summ:
        d = float(s["delta"]); ld1 = float(s["mean_ln_d1"]); 
        if -ld1 < 3: continue
        _, _, r = series(steps, d); vals = np.abs(r); fl = 4 / math.sqrt(16384); td = next((i + 1 for i in range(len(vals) - 4) if all(vals[i:i + 5] < fl)), -1)
        if td > 0: x.append(-ld1); y.append(td)
    x, y = np.array(x), np.array(y); l1 = float(fit[(upd, K, mode)]["lambda1_engine"]); b = np.mean(y - x / l1)
    ax[2].plot(x, y, mk, ms=5, label=f"{'GS' if upd=='gs' else 'Jacobi'} K={K}: λ₁={l1:.2f}"); xx = np.array([x.min(), x.max()]); ax[2].plot(xx, xx / l1 + b, "-", lw=0.8, color=ax[2].lines[-1].get_color())
ax[2].set_xlabel("ln(1/δ₁)   (δ₁ = separation after one step)"); ax[2].set_ylabel("t_dec  (steps to |r_ens| < 4σ, persisting)"); ax[2].set_title("(c) decorrelation time; lines: slope 1/λ₁"); ax[2].legend(fontsize=7)
fig.tight_layout(); fig.savefig("decorr_steps_fig.png", dpi=320); print("wrote decorr_steps_fig.png")
