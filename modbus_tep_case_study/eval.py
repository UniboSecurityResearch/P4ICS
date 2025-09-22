#!/usr/bin/env python3
import argparse
import time
import numpy as np

from main_train import load_saved_model
from data_loader import load_train_data, load_test_data
import metrics


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


def choose_theta_window(detector, Xtrain, percentile, cli_theta, cli_window, is_forecast):
    """
    Priority for detection params:
    1) CLI (--theta/--window)
    2) Saved params in model (best_theta/best_window)
    3) TRAIN MSE percentile (for theta) + CLI/default window
    """
    # 1) CLI override
    if cli_theta is not None:
        theta = float(cli_theta)
        try:
            saved_w = int(detector.params.get('best_window', 1))
        except Exception:
            saved_w = 1
        window = int(cli_window) if cli_window is not None else saved_w
        return theta, window, 'cli'

    # 2) Saved params
    try:
        t_saved = detector.params.get('best_theta', None)
        w_saved = detector.params.get('best_window', None)
    except Exception:
        t_saved = w_saved = None
    if t_saved is not None and w_saved is not None:
        return float(t_saved), int(w_saved), 'saved'

    # 3) TRAIN MSE percentile
    train_errs = detector.reconstruction_errors(Xtrain, batches=bool(is_forecast))
    train_mse = train_errs.mean(axis=1)
    theta = float(np.quantile(train_mse, float(percentile)))
    window = int(cli_window) if cli_window is not None else 1
    return theta, window, 'train_mse'


def evaluate(args):
    model_type = args.model
    dataset_name = args.dataset
    run_name = args.run_name

    # Load data
    Xtrain, _ = load_train_data(dataset_name, verbose=False)
    Xtest, Ytest, _ = load_test_data(dataset_name, verbose=True)
    Ytest = (np.asarray(Ytest).astype(float) > 0).astype(int)

    # Load model
    det = load_saved_model(model_type, run_name, args.model_name)
    is_forecast = (model_type != 'AE')
    history = int(det.params.get('history', 0)) if is_forecast else 0

    # Pick theta/window
    theta, window, how = choose_theta_window(
        det, Xtrain, args.percentile, args.theta, args.window, is_forecast
    )

    # ---- Detect on FULL test (model returns binary decisions 0/1) ----
    # batches=True for forecasting models so lengths match N_eff = len(X) - (history+1)
    Yhat = det.detect(Xtest, theta=float(theta), window=int(window), batches=bool(is_forecast)).astype(int)
    m = len(Yhat)

    # ---- Correct alignment of labels ----
    # Errors/detections start at index (history+1) in the original timeline.
    start = history + 1 if is_forecast and history > 0 else 0
    end = min(len(Ytest), start + m)
    Y_eval = Ytest[start:end]
    Yhat = Yhat[: (end - start)]  # ensure equal length

    # ---- Metrics ----
    acc = metrics.accuracy(Yhat, Y_eval)
    prec = metrics.precision(Yhat, Y_eval)
    rec = metrics.recall(Yhat, Y_eval)
    f1 = metrics.f1_score(Yhat, Y_eval)
    tp, tn, fp, fn = confusion_counts(Yhat, Y_eval)

    num_pos = int(Y_eval.sum())
    num_neg = int(len(Y_eval) - num_pos)
    pred_pos = int(Yhat.sum())

    # ---- Inference timing (repeat full detect on Xtest) ----
    # Warm-up (optional)
    try:
        _ = det.detect(Xtest[: max(2, history + 2)], theta=float(theta), window=int(window), batches=bool(is_forecast))
    except Exception:
        pass

    times = []
    for _ in range(args.timing_repeats):
        t0 = time.perf_counter()
        _ = det.detect(Xtest, theta=float(theta), window=int(window), batches=bool(is_forecast))
        t1 = time.perf_counter()
        times.append(t1 - t0)
    times = np.asarray(times, dtype=float)
    total_avg = float(times.mean())
    total_std = float(times.std(ddof=1)) if len(times) > 1 else 0.0

    # Effective rows per detect call = length of Yhat before alignment (m) or len(instance errors)
    n_eff = int(m) if m > 0 else 1
    per_row_avg = total_avg / n_eff
    per_row_std = total_std / n_eff

    # ---- Report ----
    print(f"\n=== Detect Evaluation (dataset: {dataset_name} | model: {model_type} | run: {run_name}) ===")
    print("Model name:", args.model_name)
    print(f"Detection params: theta={theta:.6f} | window={window} (source={how})")
    print("-- Metrics on FULL test set (aligned with history+1) --")
    print(f"N={len(Y_eval)} | positives={num_pos} | negatives={num_neg} | predicted_positives={pred_pos}")
    print(f"F1:        {f1:.6f}")
    print(f"Precision: {prec:.6f}")
    print(f"Recall:    {rec:.6f}")
    print(f"Accuracy:  {acc:.6f}")
    print(f"TP: {tp} | TN: {tn} | FP: {fp} | FN: {fn}")
    print("\n-- Inference timing (detect on FULL test) --")
    print(f"Repeats: {args.timing_repeats}")
    print(f"Total time avg: {total_avg:.6f} s | std: {total_std:.6f} s")
    print(f"Per-row time avg: {per_row_avg:.6e} s | std: {per_row_std:.6e} s (n_eff={n_eff})")


def build_argparser():
    p = argparse.ArgumentParser(description="Evaluate via event_detector.detect on full test set (metrics + timing).")
    p.add_argument("model", choices=['ID','LIN','AE','CNN','DNN','GRU','LSTM'])
    p.add_argument("dataset", choices=['BATADAL','SWAT','SWAT-CLEAN','WADI','WADI-CLEAN','TEP'])
    p.add_argument("--run_name", default="results", help="models/<run_name> directory (e.g., results/cnn)")
    p.add_argument("--model_name", required=True)
    p.add_argument("--theta", type=float, default=None, help="Override threshold (if omitted, use saved then TRAIN percentile).")
    p.add_argument("--window", type=int, default=None, help="Override window (if omitted, use saved then 1).")
    p.add_argument("--percentile", type=float, default=0.995, help="Used only if no saved theta and no --theta.")
    p.add_argument("--timing_repeats", type=int, default=3, help="Times to call detect() for timing stats.")
    return p


if __name__ == "__main__":
    args = build_argparser().parse_args()
    evaluate(args)
