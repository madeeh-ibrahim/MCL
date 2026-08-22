#!/usr/bin/env python3
"""Cross-prediction R^2 for Paper 3 §IV — determinism of the state versus
structurelessness of the extraction.

TWO HARNESS ERRORS THIS DESIGN AVOIDS (both were made and measured first)
1. A LINEAR autoregressor scores ~0 on every channel, including the state.
   The update lives entirely in a sine of an integer combination of the phases,
   which a linear model cannot represent, so ~0 there is a statement about the
   model, not about the system.
2. Predicting the phase INCREMENT fails as well: at K = 12 the increment spans
   about +/-K radians, so recovering it from wrapped phases folds it into
   (-pi, pi] and destroys it. The predictable quantities are cos and sin of the
   NEXT phase, which are well defined on the wrapped domain.

WHAT IS MEASURED
Ridge regression on a harmonic basis of the current state (theta1, theta2),
fitted on the first half and scored strictly out-of-sample on the second half.
Because cos(theta + K sin a) expands in harmonics of a with Bessel weights
J_n(K) that stay significant up to n ~ K, the basis order H must reach that
scale before the state becomes predictable — so H is swept rather than fixed,
and the sweep is itself the result.

  cos/sin(theta1 next)  the state one step ahead   -> rises with H toward 1
  extracted byte        the Safe-Zone output       -> stays at the control level
  control               counter-driven SHA-256     -> fixes the zero point

The claim supported is the CONTRAST: the same predictor that reconstructs the
dynamics from its own state cannot predict the extraction taken from it.
Usage: xpred.py series.tsv [Hmax]
"""
import sys, numpy as np

path = sys.argv[1]
HMAX = int(sys.argv[2]) if len(sys.argv) > 2 else 16

names, rows = None, []
for line in open(path):
    if line.startswith("#"):
        continue
    if names is None:
        names = line.split(); continue
    rows.append([float(x) for x in line.split()])
D = np.asarray(rows)
col = {n: D[:, i] for i, n in enumerate(names)}
t1, t2 = col["theta1"], col["theta2"]

def features(a, b, H):
    """1, and sin/cos of k*a, k*b and of every integer combination (i*b - j*a)
    up to order H — the basis the coupling argument itself lives in."""
    f = [np.ones(len(a))]
    for s in (a, b):
        for k in range(1, H + 1):
            f += [np.sin(k * s), np.cos(k * s)]
    for i in range(1, H + 1):
        for j in range(1, H + 1):
            arg = i * b - j * a
            f += [np.sin(arg), np.cos(arg)]
    return np.stack(f, axis=1)

def r2_oos(X, y, lam=1e-8):
    y = np.asarray(y, dtype=float)
    cut = len(y) // 2
    Xtr, ytr, Xte, yte = X[:cut], y[:cut], X[cut:], y[cut:]
    A = Xtr.T @ Xtr + lam * len(Xtr) * np.eye(X.shape[1])
    w = np.linalg.solve(A, Xtr.T @ ytr)
    pred = Xte @ w
    return 1.0 - float(((yte - pred) ** 2).sum()) / float(((yte - yte.mean()) ** 2).sum())

# row t holds the state BEFORE the iteration whose byte is byte[t];
# the state after that iteration is row t+1. All targets are one step ahead.
a, b = t1[:-1], t2[:-1]
tgt_cos = np.cos(t1[1:])
tgt_sin = np.sin(t1[1:])
tgt_byte = col["raw"][:-1]
tgt_ctrl = col["control"][:-1]

print(f"{'H':>3} {'cos(theta1 next)':>18} {'sin(theta1 next)':>18} {'byte':>10} {'control':>10}")
print("-" * 64)
for H in (2, 4, 6, 8, 12, HMAX):
    X = features(a, b, H)
    if X.shape[1] * 4 > len(a):
        print(f"{H:>3}  (skipped: {X.shape[1]} features vs {len(a)} samples)")
        continue
    print(f"{H:>3} {r2_oos(X,tgt_cos):>18.5f} {r2_oos(X,tgt_sin):>18.5f} "
          f"{r2_oos(X,tgt_byte):>10.5f} {r2_oos(X,tgt_ctrl):>10.5f}")
