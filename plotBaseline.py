import argparse
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

## python3 plotBaseline.py --csv baseline_6_2_2_table_real.csv --outdir exp62_real_outputs --annotate-top 12

def ensure_metrics(df: pd.DataFrame) -> pd.DataFrame:
    """
    1) Upewnia się, że sample_precision/recall/f1 są liczbami.
    2) Jeśli sample_recall wygląda na "spłaszczony" (np. same 1),
       próbuje przeliczyć go z TP/FN (gdy są w CSV).
    """
    for c in ["sample_precision", "sample_recall", "sample_f1"]:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce")

    # Spróbuj znaleźć kolumny TP/FP/FN (różne warianty nazewnictwa)
    tp_col = next((c for c in ["sample_tp", "baseline_tp", "tp"] if c in df.columns), None)
    fp_col = next((c for c in ["sample_fp", "baseline_fp", "fp"] if c in df.columns), None)
    fn_col = next((c for c in ["sample_fn", "baseline_fn", "fn"] if c in df.columns), None)

    # Jeśli recall wygląda podejrzanie, a mamy tp/fn -> przelicz
    if "sample_recall" in df.columns:
        uniq = df["sample_recall"].dropna().unique()
        looks_flat = (len(uniq) <= 2) and np.all(np.isin(np.round(uniq, 6), [0.0, 1.0]))
        if looks_flat and tp_col and fn_col:
            tp = pd.to_numeric(df[tp_col], errors="coerce")
            fn = pd.to_numeric(df[fn_col], errors="coerce")
            df["sample_recall"] = tp / (tp + fn)

            if "sample_precision" in df.columns and fp_col:
                fp = pd.to_numeric(df[fp_col], errors="coerce")
                df["sample_precision"] = tp / (tp + fp)

            if "sample_f1" in df.columns:
                p = df["sample_precision"]
                r = df["sample_recall"]
                df["sample_f1"] = (2 * p * r) / (p + r)

    return df


def make_label_text(df: pd.DataFrame) -> pd.Series:
    # Jeśli nie ma label_text w CSV, zbuduj go z progów
    if "label_text" in df.columns:
        return df["label_text"].astype(str)

    # Standardowe nazwy progów z tuning table
    cols = ["attempts_ge", "unique_users_ge", "unique_passwords_ge", "max_mean_interarrival_s"]
    missing = [c for c in cols if c not in df.columns]
    if missing:
        # fallback: numer wiersza
        return pd.Series([f"cfg_{i}" for i in range(len(df))])

    def fmt_mi(x):
        try:
            x = float(x)
        except Exception:
            return "mi=?"
        return "mi=off" if x < 0 else f"mi<={x:g}s"

    return df.apply(
        lambda r: f"a>={int(r['attempts_ge'])}, u>={int(r['unique_users_ge'])}, p>={int(r['unique_passwords_ge'])}, {fmt_mi(r['max_mean_interarrival_s'])}",
        axis=1,
    )


def pr_scatter(df: pd.DataFrame, out_png: str, annotate_top: int = 12):
    fig, ax = plt.subplots()
    ax.scatter(df["sample_recall"], df["sample_precision"])

    ax.set_xlabel("Recall (próbka etykietowana)")
    ax.set_ylabel("Precision (próbka etykietowana)")
    ax.set_title("Baseline: Precision vs Recall (strojenie progów)")
    ax.grid(True, linestyle="--", linewidth=0.5)

    top = df.sort_values("sample_f1", ascending=False).head(annotate_top)
    for _, r in top.iterrows():
        ax.annotate(
            r["label_text"],
            (r["sample_recall"], r["sample_precision"]),
            textcoords="offset points",
            xytext=(5, 5),
            ha="left",
            fontsize=8,
        )

    fig.tight_layout()
    fig.savefig(out_png, dpi=300)
    plt.close(fig)


def tradeoff(df: pd.DataFrame, out_png: str, annotate_top: int = 12):
    # X: wolumen alertów, Y: recall
    if "alerts_full_count" not in df.columns:
        raise ValueError("Brakuje kolumny alerts_full_count w CSV (wolumen alertów na pełnym zbiorze).")

    df["alerts_full_count"] = pd.to_numeric(df["alerts_full_count"], errors="coerce")

    fig, ax = plt.subplots()
    ax.scatter(df["alerts_full_count"], df["sample_recall"])

    ax.set_xlabel("Wolumen alertów na pełnym zbiorze (count)")
    ax.set_ylabel("Recall (próbka etykietowana)")
    ax.set_title("Baseline: Recall vs koszt operacyjny (wolumen alertów)")
    ax.grid(True, linestyle="--", linewidth=0.5)

    # Zwykle rozrzut count jest duży -> log pomaga
    ax.set_xscale("log")

    top = df.sort_values("sample_f1", ascending=False).head(annotate_top)
    for _, r in top.iterrows():
        ax.annotate(
            r["label_text"],
            (r["alerts_full_count"], r["sample_recall"]),
            textcoords="offset points",
            xytext=(5, 5),
            ha="left",
            fontsize=8,
        )

    fig.tight_layout()
    fig.savefig(out_png, dpi=300)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="baseline_6_2_2_table_real.csv")
    ap.add_argument("--outdir", default="exp62_real_outputs")
    ap.add_argument("--annotate-top", type=int, default=12)
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    df = pd.read_csv(args.csv)
    df = ensure_metrics(df)

    # zbuduj etykiety konfiguracji
    df["label_text"] = make_label_text(df)

    # sanity check: pokaż min/max recall (to Ci od razu powie, czy nadal 'same 1')
    print("sample_recall min/max:", df["sample_recall"].min(), df["sample_recall"].max())
    print("sample_recall unique (<=10):", sorted(df["sample_recall"].dropna().unique())[:10])

    # zapisz "naprawioną" wersję z dużą precyzją liczb
    fixed_csv = os.path.join(args.outdir, "baseline_6_2_2_table_real_fixed.csv")
    df.to_csv(fixed_csv, index=False, float_format="%.6f")
    print("Zapisano poprawiony CSV:", fixed_csv)

    pr_png = os.path.join(args.outdir, "baseline_6_2_2_pr_scatter_real.png")
    tr_png = os.path.join(args.outdir, "baseline_6_2_2_tradeoff_real.png")

    pr_scatter(df, pr_png, annotate_top=args.annotate_top)
    tradeoff(df, tr_png, annotate_top=args.annotate_top)

    print("Zapisano wykresy:")
    print(" -", pr_png)
    print(" -", tr_png)


if __name__ == "__main__":
    main()