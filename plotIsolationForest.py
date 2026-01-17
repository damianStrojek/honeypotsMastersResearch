import argparse
import os
import pandas as pd
import matplotlib.pyplot as plt

def plot_623a_ifpred(csv_path: str, out_png: str, include_alerts: bool = True):
    df = pd.read_csv(csv_path)

    # wymagane kolumny (nazwy jak w tabelach, które generowaliśmy)
    required = {"contamination", "sample_precision", "sample_recall", "sample_f1"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Brakuje kolumn w {csv_path}: {sorted(missing)}")

    df["contamination"] = pd.to_numeric(df["contamination"], errors="coerce")
    for c in ["sample_precision", "sample_recall", "sample_f1"]:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    df = df.dropna(subset=["contamination", "sample_precision", "sample_recall", "sample_f1"])
    df = df.sort_values("contamination")

    fig, ax = plt.subplots()

    ax.plot(df["contamination"], df["sample_precision"], marker="o", label="Precision (próbka)")
    ax.plot(df["contamination"], df["sample_recall"], marker="o", label="Recall (próbka)")
    ax.plot(df["contamination"], df["sample_f1"], marker="o", label="F1 (próbka)")

    ax.set_xlabel("Contamination")
    ax.set_ylabel("Metryka (na próbce etykietowanej)")
    ax.set_title("Isolation Forest: metryki vs contamination (wariant if_pred)")
    ax.grid(True, which="both", linestyle="--", linewidth=0.5)
    ax.legend()

    # opcjonalnie: drugi wymiar “kosztu operacyjnego” jako druga oś
    if include_alerts and "alerts_full_count" in df.columns:
        df["alerts_full_count"] = pd.to_numeric(df["alerts_full_count"], errors="coerce")
        if df["alerts_full_count"].notna().any():
            ax2 = ax.twinx()
            ax2.plot(df["contamination"], df["alerts_full_count"], marker="x", label="Alerty (pełny zbiór)")
            ax2.set_ylabel("Liczba alertów (pełny zbiór)")
            # wspólna legenda (zbierz etykiety z obu osi)
            h1, l1 = ax.get_legend_handles_labels()
            h2, l2 = ax2.get_legend_handles_labels()
            ax2.legend(h1 + h2, l1 + l2, loc="lower right")

    fig.tight_layout()
    fig.savefig(out_png, dpi=300)
    plt.close(fig)


def plot_623b_ranking(csv_path: str, out_png: str):
    df = pd.read_csv(csv_path)

    required = {"topk_percent", "sample_precision", "sample_recall", "sample_f1"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Brakuje kolumn w {csv_path}: {sorted(missing)}")

    df["topk_percent"] = pd.to_numeric(df["topk_percent"], errors="coerce")
    for c in ["sample_precision", "sample_recall", "sample_f1"]:
        df[c] = pd.to_numeric(df[c], errors="coerce")

    df = df.dropna(subset=["topk_percent", "sample_precision", "sample_recall", "sample_f1"])
    df = df.sort_values("topk_percent")

    fig, ax = plt.subplots()

    ax.plot(df["topk_percent"], df["sample_precision"], marker="o", label="Precision (próbka)")
    ax.plot(df["topk_percent"], df["sample_recall"], marker="o", label="Recall (próbka)")
    ax.plot(df["topk_percent"], df["sample_f1"], marker="o", label="F1 (próbka)")

    ax.set_xlabel("Top-k% wg if_score (budżet analityczny)")
    ax.set_ylabel("Metryka (na próbce etykietowanej)")
    ax.set_title("Isolation Forest: metryki vs top-k% (ranking if_score)")
    ax.grid(True, which="both", linestyle="--", linewidth=0.5)
    ax.legend()

    fig.tight_layout()
    fig.savefig(out_png, dpi=300)
    plt.close(fig)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ifpred-csv", required=True, help="if_6_2_3_ifpred_table_real.csv")
    ap.add_argument("--ranking-csv", required=True, help="if_6_2_3_ranking_table_real.csv")
    ap.add_argument("--outdir", default="exp62_real_outputs")
    ap.add_argument("--no-alerts-axis", action="store_true", help="Nie rysuj drugiej osi z alerts_full_count")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    out_a = os.path.join(args.outdir, "if_6_2_3_ifpred_contamination_real.png")
    out_b = os.path.join(args.outdir, "if_6_2_3_ranking_topk_real.png")

    plot_623a_ifpred(args.ifpred_csv, out_a, include_alerts=(not args.no_alerts_axis))
    plot_623b_ranking(args.ranking_csv, out_b)

    print("Zapisano:")
    print(" -", out_a)
    print(" -", out_b)

if __name__ == "__main__":
    main()
