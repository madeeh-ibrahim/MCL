#!/usr/bin/env python3
"""Analysis of the decorrelation-time runs (Paper 3 measurement 5a).
For every (update, topology, K, mode) summary file: regress t_sat and t_dec on ln(1/delta_1)
(delta_1 = exp(mean_ln_d1), the measured separation after one step) and compare the slope with
1/lambda_1 from the engine.  Also fits the growth slope of <ln d(t)> against lambda_1.
Writes decorr_fit_table.csv and decorr_fit.png."""
import glob, csv, math, numpy as np
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt

rows = []
def robust_tdec(steps_file, delta, n_floor_sigma=4.0, persist=5):
    """first t such that |r_cos1(t')| < n_floor_sigma/sqrt(n) for t' in [t, t+persist) — recomputed from the per-step file"""
    rs = [r for r in csv.DictReader(open(steps_file)) if abs(float(r["delta"]) - delta) <= 1e-15 + 1e-6*delta]
    if not rs: return -1
    n = N_SEEDS; floor = n_floor_sigma / math.sqrt(n)
    vals = [abs(float(r["r_cos1"])) for r in rs]
    for t in range(len(vals) - persist + 1):
        if all(v < floor for v in vals[t:t+persist]): return t + 1
    return -1
N_SEEDS = 16384
for f in sorted(glob.glob("res_*_summary.csv")):
    for r in csv.DictReader(open(f)):
        r["file"] = f; r["t_dec_tool"] = r["t_dec"]; r["t_dec"] = str(robust_tdec(f.replace("_summary.csv", "_steps.csv"), float(r["delta"]))); rows.append(r)
out = []
groups = {}
for r in rows:
    if r["mode"] in ("zero", "pq"): continue
    key = (r["update"], r["p"], r["q"], r["K"], r["mode"]); groups.setdefault(key, []).append(r)
fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))
for key, rs in sorted(groups.items()):
    lam = float(rs[0]["lambda1"])
    x = np.array([-float(r["mean_ln_d1"]) for r in rs])          # ln(1/delta_1)
    ts = np.array([float(r["t_sat"]) for r in rs]); td = np.array([float(r["t_dec"]) for r in rs])
    ok = (ts > 0) & (td > 0) & (x > 3)                            # exclude delta >= e^-3 (no exponential phase)
    if ok.sum() < 3: continue
    A = np.vstack([x[ok], np.ones(ok.sum())]).T
    (a_s, b_s), res_s = np.linalg.lstsq(A, ts[ok], rcond=None)[:2]
    (a_d, b_d), res_d = np.linalg.lstsq(A, td[ok], rcond=None)[:2]
    slopes = [float(r["growth_slope"]) for r in rs if r["growth_slope"] not in ("nan", "") and int(r["growth_pts"]) >= 3]
    gs = np.mean(slopes) if slopes else float("nan")
    out.append({"update": key[0], "p": key[1], "q": key[2], "K": key[3], "mode": key[4], "lambda1_engine": lam, "inv_lambda1": 1/lam,
                "slope_t_sat": a_s, "intercept_t_sat": b_s, "slope_t_dec": a_d, "intercept_t_dec": b_d,
                "ratio_slope_tdec_to_invlambda": a_d*lam, "growth_slope_mean": gs, "growth_over_lambda": gs/lam if slopes else float("nan"), "n_points": int(ok.sum())})
    lab = f'{key[0]} ({key[1]},{key[2]}) K={key[3]} {key[4]}'
    if key[0] == "gs" and key[1] == "3" and key[4] == "omega": axes[0].plot(x[ok], td[ok], "o-", ms=4, label=f"K={key[3]}  (1/λ={1/lam:.3f}, fit {a_d:.3f})")
    if key[3] == "12" and key[1] == "3" and key[4] == "omega": axes[1].plot(x[ok], td[ok], "s-", ms=4, label=f"{key[0]}  (1/λ={1/lam:.3f}, fit {a_d:.3f})")
axes[0].set_xlabel("ln(1/δ₁)"); axes[0].set_ylabel("t_dec (steps)"); axes[0].set_title("(3,5), Gauss-Seidel, ω₂ perturbation"); axes[0].legend(fontsize=8)
axes[1].set_xlabel("ln(1/δ₁)"); axes[1].set_ylabel("t_dec (steps)"); axes[1].set_title("(3,5), K=12: Gauss-Seidel vs Jacobi"); axes[1].legend(fontsize=8)
fig.tight_layout(); fig.savefig("decorr_fit.png", dpi=160)
with open("decorr_fit_table.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys())); w.writeheader(); w.writerows(out)
for o in out: print(f'{o["update"]:6s} ({o["p"]},{o["q"]}) K={o["K"]:>3s} {o["mode"]:5s} λ1={o["lambda1_engine"]:.3f} 1/λ1={o["inv_lambda1"]:.4f}  slope(t_dec)={o["slope_t_dec"]:.4f} ratio={o["ratio_slope_tdec_to_invlambda"]:.3f}  slope(t_sat)={o["slope_t_sat"]:.4f}  growth/λ1={o["growth_over_lambda"]:.4f}  n={o["n_points"]}')
