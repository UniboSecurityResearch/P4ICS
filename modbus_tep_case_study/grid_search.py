#!/usr/bin/env python3
import argparse
import time
import numpy as np

from main_train import load_saved_model
from data_loader import load_train_data, load_test_data
import metrics

WINDOWS_DEFAULT = [1, 3, 4, 5, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100]
PERCENTILES_DEFAULT = [0.95, 0.96, 0.97, 0.98, 0.99,
                       0.991, 0.992, 0.993, 0.994, 0.995,
                       0.996, 0.997, 0.998, 0.999, 0.9995, 0.99995]

def fmt_eta(seconds: float) -> str:
    seconds = max(0, int(round(seconds)))
    h = seconds // 3600; m = (seconds % 3600) // 60; s = seconds % 60
    return f"{h:d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

def confusion_counts(y_pred, y_true):
    y_pred = np.asarray(y_pred).astype(int).ravel()
    y_true = (np.asarray(y_true).astype(float) > 0).astype(int).ravel()
    n = min(len(y_pred), len(y_true))
    y_pred, y_true = y_pred[:n], y_true[:n]
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    return tp, tn, fp, fn

# ---------- chi2 scoring helpers (no leakage: fit on TRAIN only) ----------
def fit_residual_scaler(E_train, robust=False, eps=1e-8):
    """E_train: squared errors (N,D) -> per-feature residual stats on TRAIN."""
    R = np.sqrt(E_train)  # residuals
    if robust:
        mu = np.median(R, axis=0)
        mad = np.median(np.abs(R - mu), axis=0)
        sigma = 1.4826 * mad
    else:
        mu = R.mean(axis=0)
        sigma = R.std(axis=0)
    sigma = np.maximum(sigma, eps)
    return {"mu": mu, "sigma": sigma}

def compute_scores(E, method, stats=None, topk=3):
    """Return per-instance scores from squared errors E (N,D)."""
    if method == "mse":
        return E.mean(axis=1).ravel()
    # chi2 (default) and variants use standardized residuals
    R = np.sqrt(E)
    Z = (R - stats["mu"]) / stats["sigma"]
    if method == "chi2":
        return np.sum(Z**2, axis=1).ravel()
    if method == "rmse_std":
        return np.mean(Z**2, axis=1).ravel()
    if method == "max_std":
        return np.max(np.abs(Z), axis=1).ravel()
    if method == "topk":
        k = min(topk, Z.shape[1])
        return np.mean(np.sort(np.abs(Z), axis=1)[:, -k:], axis=1).ravel()
    # fallback
    return E.mean(axis=1).ravel()

# -------------------------------------------------------------------------

def run_grid(args):
    # Load data
    Xtrain, _ = load_train_data(args.dataset, verbose=False)
    Xtest, Ytest, _ = load_test_data(args.dataset, verbose=True)
    Ytest = (np.asarray(Ytest).astype(float) > 0).astype(int)

    # Load model
    det = load_saved_model(args.model, args.run_name, args.model_name)
    is_forecast = (args.model != 'AE')
    history = int(det.params.get('history', 0)) if is_forecast else 0

    # Squared reconstruction errors
    Etr = det.reconstruction_errors(Xtrain, batches=is_forecast)
    Ete = det.reconstruction_errors(Xtest,  batches=is_forecast)

    # Fit TRAIN-only stats for chi2 (no test leakage)
    stats = None
    if args.score_method != "mse":
        stats = fit_residual_scaler(Etr, robust=args.robust_scaler)

    # Scores
    train_score = compute_scores(Etr, method=args.score_method, stats=stats, topk=args.topk)
    test_score  = compute_scores(Ete, method=args.score_method, stats=stats, topk=args.topk)

    # Correct label alignment for forecasting (front clipping of history+1)
    start = history + 1 if is_forecast and history > 0 else 0
    end = min(len(Ytest), start + len(test_score))
    Y_eval = Ytest[start:end]
    test_score = test_score[: (end - start)]  # ensure same length as Y_eval

    windows = args.windows or WINDOWS_DEFAULT
    percentiles = args.percentiles or PERCENTILES_DEFAULT
    total = len(windows) * len(percentiles)

    print(f"\n=== Grid Search (dataset: {args.dataset} | model: {args.model} | run: {args.run_name}) ===")
    print(f"Model name: {args.model_name}")
    print(f"Score method: {args.score_method} "
          f"{'(robust scaler)' if args.robust_scaler and args.score_method!='mse' else ''}")
    print(f"Train N={len(train_score)} | Test N={len(test_score)} | history={history} | batches={is_forecast}")
    print(f"Grid size: {total} combos ({len(percentiles)} percentiles × {len(windows)} windows)\n")

    # Precompute thetas from TRAIN scores
    thetas = {p: float(np.quantile(train_score, float(p))) for p in percentiles}

    results = []
    t0 = time.perf_counter()
    done = 0

    for p in percentiles:
        theta = thetas[p]
        # Raw detect from test_score; window smoothing applied per window
        raw_det = (test_score > theta).astype(int)

        for w in windows:
            if w > 1:
                det_w = (np.convolve(raw_det, np.ones(int(w), dtype=int), mode='same') // int(w)).astype(int)
            else:
                det_w = raw_det

            m = min(len(det_w), len(Y_eval))
            Yhat = det_w[:m]; Ycmp = Y_eval[:m]

            acc = metrics.accuracy(Yhat, Ycmp)
            prec = metrics.precision(Yhat, Ycmp)
            rec = metrics.recall(Yhat, Ycmp)
            f1 = metrics.f1_score(Yhat, Ycmp)
            tp, tn, fp, fn = confusion_counts(Yhat, Ycmp)

            results.append({
                "percentile": float(p),
                "window": int(w),
                "theta": float(theta),
                "N": int(m),
                "positives": int(Ycmp.sum()),
                "pred_pos": int(Yhat.sum()),
                "precision": float(prec),
                "recall": float(rec),
                "f1": float(f1),
                "accuracy": float(acc),
                "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            })

            done += 1
            elapsed = time.perf_counter() - t0
            avg_per = elapsed / done
            remain = total - done
            eta = avg_per * remain
            pct = 100.0 * done / total
            print(f"[{done}/{total}] {pct:5.1f}% — left: {remain:3d} — ETA: {fmt_eta(eta)} "
                  f"| p={p:.6f}, w={w:3d}, θ={theta:.6f}, F1={f1:.4f}, P={prec:.4f}, R={rec:.4f}, Acc={acc:.4f}")

    if results:
        best = sorted(results, key=lambda r: (r["f1"], r["precision"], r["accuracy"]), reverse=True)[0]
        print("\n-- Best by F1 --")
        print(f"percentile={best['percentile']:.6f} | window={best['window']} | θ={best['theta']:.6f}")
        print(f"F1={best['f1']:.6f} | P={best['precision']:.6f} | R={best['recall']:.6f} | Acc={best['accuracy']:.6f}")
        print(f"N={best['N']} | TP={best['tp']} TN={best['tn']} FP={best['fp']} FN={best['fn']} | pred_pos={best['pred_pos']} | pos={best['positives']}")

    if args.save_csv and results:
        import csv
        with open(args.save_csv, "w", newline="") as f:
            wcsv = csv.DictWriter(f, fieldnames=list(results[0].keys()))
            wcsv.writeheader()
            for r in results:
                wcsv.writerow(r)
        print(f"\nSaved grid results to: {args.save_csv}")

def build_argparser():
    p = argparse.ArgumentParser(description="Grid search over (window, percentile) with TRAIN-based thresholds.")
    p.add_argument("model", choices=['ID','LIN','AE','CNN','DNN','GRU','LSTM'])
    p.add_argument("dataset", choices=['BATADAL','SWAT','SWAT-CLEAN','WADI','WADI-CLEAN','TEP'])
    p.add_argument("--run_name", default="results", help="models/<run_name> directory (e.g., results/cnn)")
    p.add_argument("--model_name", required=True)
    p.add_argument("--windows", type=int, nargs="+", default=WINDOWS_DEFAULT)
    p.add_argument("--percentiles", type=float, nargs="+", default=PERCENTILES_DEFAULT)
    # NEW: chi2 scoring options (default chi2). Use --score_method mse to keep old behavior.
    p.add_argument("--score_method", choices=["chi2","mse","rmse_std","max_std","topk"], default="chi2",
                   help="Per-instance score. Default: chi2 (standardized residuals).")
    p.add_argument("--topk", type=int, default=3, help="k for --score_method topk.")
    p.add_argument("--robust_scaler", action="store_true",
                   help="Use median/MAD instead of mean/std when standardizing residuals (TRAIN only).")
    p.add_argument("--save_csv", default=None, help="Save all grid rows to CSV.")
    return p

if __name__ == "__main__":
    args = build_argparser().parse_args()
    run_grid(args)