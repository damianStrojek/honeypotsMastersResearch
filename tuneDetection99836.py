#!/usr/bin/env python3
import argparse
import itertools
import pandas as pd
import numpy as np

from analyzeHoneypots99836 import engineer_window_features, baseline_alerts, run_isolation_forest

# Przykładowe uruchomienie
# python3 tuneDetection99836.py --labeled-csv data/curated/analysis/anomaly/label_sample_enriched_labeled_v1.csv --out-csv data/curated/analysis/anomaly/tuning_results.csv

def metrics(y_true, y_pred):
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--labeled-csv", required=True)
    ap.add_argument("--out-csv", default="tuning_results.csv")

    # baseline sweep
    ap.add_argument("--attempts", default="10,15,20,30")
    ap.add_argument("--users", default="5,10,15")
    ap.add_argument("--passwords", default="5,10,15")
    ap.add_argument("--mean-interarrival", default="1.0,2.0,-1")  # -1 = wyłącz

    # IF sweep
    ap.add_argument("--contamination", default="0.005,0.01,0.02,0.05,0.1")
    ap.add_argument("--topk-percent", default="1,2,5,10")  # ranking po if_score

    args = ap.parse_args()

    df = pd.read_csv(args.labeled_csv)
    df["label"] = pd.to_numeric(df["label"], errors="coerce")
    df = df[df["label"].notna()].copy()
    df["label"] = df["label"].astype(int)

    # cechy pochodne jak w pipeline
    df_feat = engineer_window_features(df)

    attempts_list = [int(x) for x in args.attempts.split(",")]
    users_list = [int(x) for x in args.users.split(",")]
    passwords_list = [int(x) for x in args.passwords.split(",")]
    mi_list_raw = [float(x) for x in args.mean_interarrival.split(",")]
    mi_list = [None if x < 0 else x for x in mi_list_raw]

    contamination_list = [float(x) for x in args.contamination.split(",")]
    topk_list = [float(x) for x in args.topk_percent.split(",")]

    rows = []
    for a, u, p, mi, cont in itertools.product(attempts_list, users_list, passwords_list, mi_list, contamination_list):
        # baseline
        base_pred = baseline_alerts(
            df_feat,
            attempts_ge=a,
            unique_users_ge=u,
            unique_passwords_ge=p,
            max_mean_interarrival_s=mi,
        )
        base_m = metrics(df_feat["label"], base_pred)

        # IF: pred + ranking po score
        df_if = run_isolation_forest(df_feat, contamination=cont, random_state=42)
        if_m = metrics(df_if["label"], df_if["if_pred"])

        # ranking: top-k% najniższych if_score
        for k in topk_list:
            q = k / 100.0
            thr = np.quantile(df_if["if_score"], q)
            rank_pred = (df_if["if_score"] <= thr).astype(int)
            rank_m = metrics(df_if["label"], rank_pred)

            rows.append({
                "attempts_ge": a, "unique_users_ge": u, "unique_passwords_ge": p,
                "max_mean_interarrival_s": mi if mi is not None else -1,
                "contamination": cont, "topk_percent": k,
                "baseline_precision": base_m["precision"], "baseline_recall": base_m["recall"], "baseline_f1": base_m["f1"],
                "if_precision": if_m["precision"], "if_recall": if_m["recall"], "if_f1": if_m["f1"],
                "rank_precision": rank_m["precision"], "rank_recall": rank_m["recall"], "rank_f1": rank_m["f1"],
                "baseline_tp": base_m["tp"], "baseline_fp": base_m["fp"], "baseline_fn": base_m["fn"],
                "if_tp": if_m["tp"], "if_fp": if_m["fp"], "if_fn": if_m["fn"],
                "rank_tp": rank_m["tp"], "rank_fp": rank_m["fp"], "rank_fn": rank_m["fn"],
            })

    out = pd.DataFrame(rows).sort_values(["rank_f1", "baseline_f1"], ascending=False)
    out.to_csv(args.out_csv, index=False)
    print(f"Saved: {args.out_csv} (rows={len(out)})")

if __name__ == "__main__":
    main()
