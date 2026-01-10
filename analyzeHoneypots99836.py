#!/usr/bin/env python3
#
# SAP Parameter Validator
# Copyright (C) 2026 Damian Strojek
#
"""
analyzeHoneypots99836.py

Kolejny etap po cleanHoneypots99836.py: analiza na danych "curated/processed" (DuckDB/Parquet).

Dostępne moduły (subcommands):
  1) anomaly  - wykrywanie automatyzacji logowań (bruteforce/spraying) na oknach IP (baseline + IsolationForest)
              + eksport próbki do ręcznego etykietowania
  2) eval     - ocena jakości (precision/recall) na podstawie ręcznie oznaczonej próbki
  3) cluster  - klastrowanie zachowań w sesjach Cowrie (bag-of-commands TF-IDF + KMeans)
              + tabela top tokenów per klaster + 2D projekcja (PCA)

Wejście:
  - data/processed/logs.duckdb (tabele: ip_windows_5m, cowrie_sessions) LUB
  - data/curated/ip_windows/ip_windows_5m.parquet oraz data/curated/sessions/cowrie_sessions.parquet

Wyjście:
  - data/curated/analysis/anomaly/* (parquet/csv/json)
  - data/curated/analysis/cluster/* (parquet/csv)

Wymagania:
  pip install duckdb pandas numpy tqdm scikit-learn --break-system-packages
"""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import duckdb
import numpy as np
import pandas as pd
from tqdm import tqdm

LOG = logging.getLogger("analyze_honeypots")


# -----------------------------
# Utils
# -----------------------------

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(message)s")


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def optional_sklearn() -> Tuple[Any, Any, Any, Any]:
    """
    Importy scikit-learn tylko gdy potrzebne, z czytelnym komunikatem.
    """
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.cluster import KMeans
        from sklearn.decomposition import PCA
        return IsolationForest, TfidfVectorizer, KMeans, PCA
    except Exception as e:
        raise RuntimeError(
            "Brak scikit-learn. Zainstaluj: pip install scikit-learn\n"
            f"Szczegóły: {e}"
        )


@dataclass
class Inputs:
    data_dir: Path
    duckdb_path: Path
    ip_windows_parquet: Path
    sessions_parquet: Path


def resolve_inputs(data_dir: Path, duckdb_path: Optional[Path]) -> Inputs:
    data_dir = data_dir.resolve()
    duckdb_path = (duckdb_path.resolve() if duckdb_path else (data_dir / "processed" / "logs.duckdb"))
    ip_windows_parquet = data_dir / "curated" / "ip_windows" / "ip_windows_5m.parquet"
    sessions_parquet = data_dir / "curated" / "sessions" / "cowrie_sessions.parquet"
    return Inputs(
        data_dir=data_dir,
        duckdb_path=duckdb_path,
        ip_windows_parquet=ip_windows_parquet,
        sessions_parquet=sessions_parquet,
    )


def duckdb_table_exists(con: duckdb.DuckDBPyConnection, table: str) -> bool:
    rows = con.execute("SHOW TABLES").fetchall()
    tables = {r[0] for r in rows}
    return table in tables


def load_ip_windows(inputs: Inputs, prefer: str = "duckdb") -> pd.DataFrame:
    """
    prefer: 'duckdb' lub 'parquet'
    """
    if prefer == "duckdb" and inputs.duckdb_path.exists():
        con = duckdb.connect(inputs.duckdb_path.as_posix(), read_only=True)
        try:
            if duckdb_table_exists(con, "ip_windows_5m"):
                return con.execute("SELECT * FROM ip_windows_5m").df()
        finally:
            con.close()

    if inputs.ip_windows_parquet.exists():
        return pd.read_parquet(inputs.ip_windows_parquet)

    raise FileNotFoundError("Nie znaleziono źródła ip_windows_5m (ani w DuckDB, ani w Parquet).")


def load_sessions(inputs: Inputs, prefer: str = "duckdb") -> pd.DataFrame:
    if prefer == "duckdb" and inputs.duckdb_path.exists():
        con = duckdb.connect(inputs.duckdb_path.as_posix(), read_only=True)
        try:
            if duckdb_table_exists(con, "cowrie_sessions"):
                return con.execute("SELECT * FROM cowrie_sessions").df()
        finally:
            con.close()

    if inputs.sessions_parquet.exists():
        return pd.read_parquet(inputs.sessions_parquet)

    raise FileNotFoundError("Nie znaleziono źródła cowrie_sessions (ani w DuckDB, ani w Parquet).")


def choose_events_table(con: duckdb.DuckDBPyConnection, preferred: Optional[str] = None) -> str:
    tables = {r[0] for r in con.execute("SHOW TABLES").fetchall()}
    if preferred and preferred in tables:
        return preferred
    if "events" in tables:
        return "events"
    if "events_raw" in tables:
        return "events_raw"
    raise RuntimeError("Nie znaleziono tabeli events ani events_raw w DuckDB.")


def format_top_counts(rows) -> str:
    # rows: [(hash, cnt), ...]
    if not rows:
        return ""
    return ", ".join([f"{h}:{c}" for (h, c) in rows if h is not None])


def enrich_label_sample(
    duckdb_path: Path,
    sample_csv: Path,
    out_csv: Path,
    events_table: Optional[str],
    window_minutes: int = 5,
    top_k: int = 5,
    examples: int = 3,
) -> None:
    df = pd.read_csv(sample_csv)

    required_cols = {"window_start", "source", "service", "src_ip_hash"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(f"Brak wymaganych kolumn w sample CSV: {missing}")

    # window_start jako datetime UTC
    df["window_start"] = pd.to_datetime(df["window_start"], errors="coerce", utc=True)
    if df["window_start"].isna().any():
        bad = int(df["window_start"].isna().sum())
        raise ValueError(f"Nie udało się sparsować window_start w {bad} wierszach.")

    con = duckdb.connect(duckdb_path.as_posix(), read_only=True)
    try:
        table = choose_events_table(con, events_table)

        # SQL-y parametryzowane (OK przy 80-200 wierszach)
        sql_counts = f"""
            SELECT
                COUNT(*) AS events_in_window,
                SUM(CASE WHEN event_type IN ('login_fail','login_attempt') THEN 1 ELSE 0 END) AS login_fail_like,
                SUM(CASE WHEN event_type = 'login_success' THEN 1 ELSE 0 END) AS login_success
            FROM {table}
            WHERE source = ?
              AND service = ?
              AND src_ip_hash = ?
              AND ts_utc >= ?
              AND ts_utc <  ?
        """

        sql_top_users = f"""
            SELECT username_hash, COUNT(*) AS cnt
            FROM {table}
            WHERE source = ?
              AND service = ?
              AND src_ip_hash = ?
              AND ts_utc >= ?
              AND ts_utc <  ?
              AND username_hash IS NOT NULL
            GROUP BY username_hash
            ORDER BY cnt DESC
            LIMIT ?
        """

        sql_top_passwords = f"""
            SELECT password_hash, COUNT(*) AS cnt
            FROM {table}
            WHERE source = ?
              AND service = ?
              AND src_ip_hash = ?
              AND ts_utc >= ?
              AND ts_utc <  ?
              AND password_hash IS NOT NULL
            GROUP BY password_hash
            ORDER BY cnt DESC
            LIMIT ?
        """

        # Przykłady eventów — bierzemy "najbardziej informacyjne" pola
        sql_examples = f"""
            SELECT ts_utc, event_type, eventid,
                   COALESCE(command, '') AS command,
                   COALESCE(raw_json, '') AS raw_json
            FROM {table}
            WHERE source = ?
              AND service = ?
              AND src_ip_hash = ?
              AND ts_utc >= ?
              AND ts_utc <  ?
            ORDER BY ts_utc
            LIMIT ?
        """

        # Kolumny wyjściowe
        df["events_in_window"] = 0
        df["login_fail_like"] = 0
        df["login_success"] = 0
        df["top_usernames"] = ""
        df["top_passwords"] = ""
        df["example_events"] = ""

        for i in tqdm(range(len(df)), desc="Enrich label sample", unit="row"):
            row = df.iloc[i]
            ws = row["window_start"].to_pydatetime()
            we = ws + timedelta(minutes=window_minutes)

            params_base = [str(row["source"]), str(row["service"]), str(row["src_ip_hash"]), ws, we]

            # 1) liczniki
            c = con.execute(sql_counts, params_base).fetchone()
            if c:
                df.at[i, "events_in_window"] = int(c[0] or 0)
                df.at[i, "login_fail_like"] = int(c[1] or 0)
                df.at[i, "login_success"] = int(c[2] or 0)

            # 2) top user/pass
            tu = con.execute(sql_top_users, params_base + [top_k]).fetchall()
            tp = con.execute(sql_top_passwords, params_base + [top_k]).fetchall()
            df.at[i, "top_usernames"] = format_top_counts(tu)
            df.at[i, "top_passwords"] = format_top_counts(tp)

            # 3) przykłady eventów (krótko — żeby dało się czytać)
            ex = con.execute(sql_examples, params_base + [examples]).fetchall()
            # zrób z tego zwięzły string (1 linia na event)
            lines = []
            for (ts_utc, event_type, eventid, command, raw_json) in ex:
                cmd = (command or "").strip()
                if cmd:
                    lines.append(f"{ts_utc} | {event_type} | {eventid} | cmd={cmd}")
                else:
                    # jak nie ma cmd, weź eventid i skrócony raw_json
                    rj = (raw_json or "")
                    rj_short = (rj[:200] + "...") if len(rj) > 200 else rj
                    lines.append(f"{ts_utc} | {event_type} | {eventid} | raw={rj_short}")
            df.at[i, "example_events"] = "\n".join(lines)

        ensure_dir(out_csv.parent)
        df.to_csv(out_csv, index=False, encoding="utf-8")
        LOG.info("Wzbogacony plik -> %s (events_table=%s)", out_csv, table)

    finally:
        con.close()


# -----------------------------
# Use-case A: anomaly detection
# -----------------------------

def engineer_window_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Tworzy cechy do baseline + ML.
    Zakładamy kolumny jak z cleanHoneypots99836.py: attempts, unique_users, unique_passwords, success_count,
    pass_entropy_mean, mean_interarrival_s, min_interarrival_s.
    """
    out = df.copy()

    if "window_start" in out.columns:
        out["window_start"] = pd.to_datetime(out["window_start"], errors="coerce", utc=True)

    for col in ["attempts", "unique_users", "unique_passwords", "success_count"]:
        out[col] = pd.to_numeric(out.get(col, 0), errors="coerce").fillna(0).astype(int)

    for col in ["pass_entropy_mean", "mean_interarrival_s", "min_interarrival_s"]:
        out[col] = pd.to_numeric(out.get(col, np.nan), errors="coerce")

    # Pochodne
    out["users_per_attempt"] = np.where(out["attempts"] > 0, out["unique_users"] / out["attempts"], 0.0)
    out["passwords_per_attempt"] = np.where(out["attempts"] > 0, out["unique_passwords"] / out["attempts"], 0.0)
    out["success_rate"] = np.where(out["attempts"] > 0, out["success_count"] / out["attempts"], 0.0)

    out["log_attempts"] = np.log1p(out["attempts"].clip(lower=0))
    out["log_unique_users"] = np.log1p(out["unique_users"].clip(lower=0))
    out["log_unique_passwords"] = np.log1p(out["unique_passwords"].clip(lower=0))

    # Uzupełnianie braków medianą (per service, jeśli jest)
    if "service" in out.columns:
        for col in ["mean_interarrival_s", "min_interarrival_s", "pass_entropy_mean"]:
            out[col] = out.groupby("service")[col].transform(lambda s: s.fillna(s.median()))
    else:
        for col in ["mean_interarrival_s", "min_interarrival_s", "pass_entropy_mean"]:
            out[col] = out[col].fillna(out[col].median())

    out = out.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return out


def baseline_alerts(
    df: pd.DataFrame,
    attempts_ge: int = 20,
    unique_users_ge: int = 10,
    unique_passwords_ge: int = 10,
    max_mean_interarrival_s: Optional[float] = 2.0,
) -> pd.Series:
    """
    Prosty baseline:
      - dużo prób w oknie
      - oraz sygnał spraying (dużo userów) lub bruteforce (dużo haseł)
      - opcjonalnie bardzo krótki interarrival (automatyzacja)
    """
    cond = df["attempts"] >= attempts_ge
    cond = cond & ((df["unique_users"] >= unique_users_ge) | (df["unique_passwords"] >= unique_passwords_ge))

    if max_mean_interarrival_s is not None:
        cond = cond | ((df["attempts"] >= attempts_ge) & (df["mean_interarrival_s"] <= max_mean_interarrival_s))

    return cond.astype(int)


def run_isolation_forest(df: pd.DataFrame, contamination: float = 0.01, random_state: int = 42) -> pd.DataFrame:
    IsolationForest, _, _, _ = optional_sklearn()

    feats = [
        "log_attempts",
        "log_unique_users",
        "log_unique_passwords",
        "users_per_attempt",
        "passwords_per_attempt",
        "pass_entropy_mean",
        "mean_interarrival_s",
        "min_interarrival_s",
        "success_rate",
    ]
    X = df[feats].to_numpy(dtype=float)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X)

    pred = model.predict(X)  # -1 anomaly, 1 normal
    score = model.decision_function(X)  # wyższe = bardziej normalne
    out = df.copy()
    out["if_pred"] = (pred == -1).astype(int)
    out["if_score"] = score
    return out


def export_label_sample(df: pd.DataFrame, out_csv: Path, n: int = 80, seed: int = 42) -> None:
    ensure_dir(out_csv.parent)

    # 1) podejrzane: baseline lub IF
    suspicious = df[(df["baseline_alert"] == 1) | (df["if_pred"] == 1)].copy()

    # 2) normalne: reszta
    normal = df[(df["baseline_alert"] == 0) & (df["if_pred"] == 0)].copy()

    n_susp = min(len(suspicious), n // 2)
    n_norm = min(len(normal), n - n_susp)

    sample = pd.concat([
        suspicious.sample(n=n_susp, random_state=seed) if n_susp > 0 else suspicious.head(0),
        normal.sample(n=n_norm, random_state=seed) if n_norm > 0 else normal.head(0),
    ], ignore_index=True).sample(frac=1.0, random_state=seed)  # shuffle

    cols = [
        "window_start", "source", "service", "src_ip_hash", "src_ip_masked",
        "attempts", "unique_users", "unique_passwords", "success_count",
        "mean_interarrival_s", "min_interarrival_s", "pass_entropy_mean",
        "baseline_alert", "if_pred", "if_score",
    ]
    sample = sample[[c for c in cols if c in sample.columns]].copy()
    sample.insert(0, "label", "")
    sample.to_csv(out_csv, index=False, encoding="utf-8")
    LOG.info("Próbka do etykietowania -> %s (n=%d, suspicious=%d, normal=%d)", out_csv, len(sample), n_susp, n_norm)


def anomaly_pipeline(
    inputs: Inputs,
    out_dir: Path,
    prefer_source: str,
    filter_service: Optional[str],
    contamination: float,
    attempts_ge: int,
    unique_users_ge: int,
    unique_passwords_ge: int,
    max_mean_interarrival_s: Optional[float],
    export_sample_n: int,
    seed: int,
) -> None:
    ensure_dir(out_dir)

    LOG.info("Ładuję ip_windows_5m (%s)", prefer_source)
    df = load_ip_windows(inputs, prefer=prefer_source)

    if filter_service:
        df = df[df["service"].astype(str) == filter_service].copy()
        LOG.info("Filtr service=%s -> %d wierszy", filter_service, len(df))

    if len(df) == 0:
        raise RuntimeError("Brak danych po filtrach.")

    df = engineer_window_features(df)
    df["baseline_alert"] = baseline_alerts(
        df,
        attempts_ge=attempts_ge,
        unique_users_ge=unique_users_ge,
        unique_passwords_ge=unique_passwords_ge,
        max_mean_interarrival_s=max_mean_interarrival_s,
    )

    # ML (IF) opcjonalnie
    try:
        df = run_isolation_forest(df, contamination=contamination, random_state=seed)
    except RuntimeError as e:
        LOG.warning("Pomijam IsolationForest (brak sklearn): %s", e)
        df["if_pred"] = 0
        df["if_score"] = np.nan

    top_if = df.sort_values("if_score", ascending=True).head(200)
    top_baseline = df[df["baseline_alert"] == 1].sort_values(
        ["attempts", "unique_users", "unique_passwords"], ascending=False
    ).head(200)

    out_parquet = out_dir / "anomaly_windows.parquet"
    out_csv_top_if = out_dir / "top_if_anomalies.csv"
    out_csv_top_baseline = out_dir / "top_baseline_alerts.csv"
    out_json = out_dir / "anomaly_summary.json"

    df.to_parquet(out_parquet, index=False)
    top_if.to_csv(out_csv_top_if, index=False, encoding="utf-8")
    top_baseline.to_csv(out_csv_top_baseline, index=False, encoding="utf-8")

    summary = {
        "generated_at_utc": now_utc_iso(),
        "rows_total": int(len(df)),
        "baseline": {
            "attempts_ge": attempts_ge,
            "unique_users_ge": unique_users_ge,
            "unique_passwords_ge": unique_passwords_ge,
            "max_mean_interarrival_s": max_mean_interarrival_s,
            "alerts_count": int(df["baseline_alert"].sum()),
        },
        "isolation_forest": {
            "contamination": contamination,
            "anomalies_count": int(df["if_pred"].sum()) if "if_pred" in df.columns else None,
        },
        "outputs": {
            "parquet": out_parquet.as_posix(),
            "top_if_csv": out_csv_top_if.as_posix(),
            "top_baseline_csv": out_csv_top_baseline.as_posix(),
        }
    }
    out_json.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    LOG.info("Zapisano: %s", out_parquet)
    LOG.info("Zapisano: %s", out_csv_top_if)
    LOG.info("Zapisano: %s", out_csv_top_baseline)
    LOG.info("Zapisano: %s", out_json)

    if export_sample_n > 0:
        export_label_sample(df, out_dir / "label_sample.csv", n=export_sample_n, seed=seed)


# -----------------------------
# Eval: precision/recall
# -----------------------------

def eval_predictions(labeled_csv: Path, pred_col: str, out_json: Optional[Path]) -> Dict[str, Any]:
    df = pd.read_csv(labeled_csv)
    if "label" not in df.columns:
        raise ValueError("Brak kolumny 'label' w pliku z etykietami.")
    if pred_col not in df.columns:
        raise ValueError(f"Brak kolumny predykcji '{pred_col}' w pliku z etykietami.")

    y_true = pd.to_numeric(df["label"], errors="coerce")
    y_pred = pd.to_numeric(df[pred_col], errors="coerce").fillna(0)

    mask = y_true.notna()
    if int(mask.sum()) == 0:
        raise ValueError(
            "Brak uzupełnionych etykiet w kolumnie 'label'. "
            "Wpisz 0/1 w pliku CSV i uruchom eval ponownie."
        )
    
    y_true = y_true[mask].astype(int).to_numpy()
    y_pred = y_pred[mask].astype(int).to_numpy()

    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * precision * recall / (precision + recall)) if (precision is not None and recall is not None and (precision + recall)) else None

    res = {
        "evaluated_at_utc": now_utc_iso(),
        "n": int(len(y_true)),
        "pred_col": pred_col,
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "metrics": {"precision": precision, "recall": recall, "f1": f1},
    }

    if out_json:
        ensure_dir(out_json.parent)
        out_json.write_text(json.dumps(res, indent=2, ensure_ascii=False), encoding="utf-8")

    return res


# -----------------------------
# Use-case B: clustering Cowrie sessions
# -----------------------------

def command_tokens_from_seq(seq: Any) -> str:
    if seq is None:
        return ""
    if isinstance(seq, str):
        lines = [seq]
    else:
        try:
            lines = list(seq)
        except Exception:
            return ""

    tokens = []
    for line in lines:
        if not isinstance(line, str):
            continue
        line = line.strip().lower()
        if not line:
            continue
        cmd = line.split()[0]
        if len(cmd) < 2:
            continue
        tokens.append(cmd)
    return " ".join(tokens)


def cluster_pipeline(
    inputs: Inputs,
    out_dir: Path,
    prefer_source: str,
    k: int,
    min_commands: int,
    seed: int,
) -> None:
    ensure_dir(out_dir)

    _, TfidfVectorizer, KMeans, PCA = optional_sklearn()

    LOG.info("Ładuję cowrie_sessions (%s)", prefer_source)
    df = load_sessions(inputs, prefer=prefer_source)

    if len(df) == 0:
        raise RuntimeError("Brak danych sesji.")

    if "num_commands" in df.columns:
        df = df[pd.to_numeric(df["num_commands"], errors="coerce").fillna(0) >= min_commands].copy()
    LOG.info("Sesje po filtrze min_commands=%d -> %d", min_commands, len(df))

    if len(df) == 0:
        raise RuntimeError("Brak sesji po filtrze min_commands.")

    tqdm.pandas(desc="Tokenizacja sesji")
    df["doc"] = df["commands_seq"].progress_apply(command_tokens_from_seq)

    vectorizer = TfidfVectorizer(
        lowercase=True,
        token_pattern=r"(?u)\b[a-zA-Z0-9_\-]{2,}\b",
        min_df=2,
        max_df=0.8,
        ngram_range=(1, 2),
    )
    X = vectorizer.fit_transform(df["doc"].fillna(""))

    km = KMeans(n_clusters=k, random_state=seed, n_init="auto")
    labels = km.fit_predict(X)
    df["cluster"] = labels.astype(int)

    # Top tokeny per klaster (na centroidach)
    terms = np.array(vectorizer.get_feature_names_out())
    rows = []
    for c in range(k):
        idx = np.where(labels == c)[0]
        if len(idx) == 0:
            continue
        centroid = X[idx].mean(axis=0).A1
        top_idx = np.argsort(centroid)[::-1][:15]
        top_terms = terms[top_idx].tolist()
        rows.append({"cluster": int(c), "n_sessions": int(len(idx)), "top_terms": ", ".join(top_terms)})

    summary = pd.DataFrame(rows).sort_values("n_sessions", ascending=False)

    # 2D PCA współrzędne (CSV do wykresów)
    n_for_coords = min(20000, X.shape[0])
    pca = PCA(n_components=2, random_state=seed)
    coords = pca.fit_transform(X[:n_for_coords].toarray())
    coords_df = pd.DataFrame(coords, columns=["x", "y"])
    coords_df["cluster"] = labels[:n_for_coords]

    out_parquet = out_dir / "session_clusters.parquet"
    out_summary_csv = out_dir / "cluster_summary.csv"
    out_coords_csv = out_dir / "cluster_coords_2d.csv"

    df.drop(columns=["doc"], errors="ignore").to_parquet(out_parquet, index=False)
    summary.to_csv(out_summary_csv, index=False, encoding="utf-8")
    coords_df.to_csv(out_coords_csv, index=False, encoding="utf-8")

    LOG.info("Zapisano: %s", out_parquet)
    LOG.info("Zapisano: %s", out_summary_csv)
    LOG.info("Zapisano: %s", out_coords_csv)


# -----------------------------
# CLI
# -----------------------------

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Analiza danych po cleanHoneypots99836.py (anomalia/klastry/ewaluacja).")
    ap.add_argument("--data-dir", default="data", help="Katalog bazowy z raw/processed/curated (domyślnie: ./data)")
    ap.add_argument("--duckdb-path", default=None, help="Ścieżka do logs.duckdb (domyślnie: data/processed/logs.duckdb)")
    ap.add_argument("--prefer", choices=["duckdb", "parquet"], default="duckdb", help="Preferowane źródło danych")
    ap.add_argument("--verbose", action="store_true", help="Więcej logów")

    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_a = sub.add_parser("anomaly", help="Wykrywanie automatyzacji logowań na ip_windows (baseline + IF)")
    ap_a.add_argument("--out-dir", default=None, help="Katalog wyjściowy (domyślnie: data/curated/analysis/anomaly)")
    ap_a.add_argument("--service", default=None, help="Filtr: tylko dana usługa (np. ssh, ftp, mysql, rdp)")
    ap_a.add_argument("--contamination", type=float, default=0.01, help="IsolationForest contamination (domyślnie 0.01)")
    ap_a.add_argument("--baseline-attempts", type=int, default=20, help="Baseline: attempts >= N (domyślnie 20)")
    ap_a.add_argument("--baseline-unique-users", type=int, default=10, help="Baseline: unique_users >= U (domyślnie 10)")
    ap_a.add_argument("--baseline-unique-passwords", type=int, default=10, help="Baseline: unique_passwords >= P (domyślnie 10)")
    ap_a.add_argument("--baseline-max-mean-interarrival", type=float, default=2.0, help="Baseline: mean_interarrival_s <= T (domyślnie 2.0). Ustaw -1 aby wyłączyć.")
    ap_a.add_argument("--export-sample-n", type=int, default=80, help="Eksport próbki do etykietowania (0 = off). Domyślnie 80.")
    ap_a.add_argument("--seed", type=int, default=42)

    ap_e = sub.add_parser("eval", help="Ewaluacja predykcji na ręcznie oznaczonej próbce")
    ap_e.add_argument("--labeled-csv", required=True, help="CSV z kolumną label oraz predykcjami (np. label_sample.csv po uzupełnieniu label)")
    ap_e.add_argument("--pred-col", default="if_pred", help="Kolumna predykcji do oceny (if_pred albo baseline_alert)")
    ap_e.add_argument("--out-json", default=None, help="Gdzie zapisać JSON z metrykami (opcjonalnie)")

    ap_c = sub.add_parser("cluster", help="Klastrowanie sesji Cowrie (TF-IDF + KMeans)")
    ap_c.add_argument("--out-dir", default=None, help="Katalog wyjściowy (domyślnie: data/curated/analysis/cluster)")
    ap_c.add_argument("--k", type=int, default=8, help="Liczba klastrów KMeans (domyślnie 8)")
    ap_c.add_argument("--min-commands", type=int, default=3, help="Minimalna liczba komend w sesji (domyślnie 3)")
    ap_c.add_argument("--seed", type=int, default=42)

    ap_l = sub.add_parser("labelprep", help="Wzbogacenie label_sample.csv o kontekst z events/events_raw (top users/pass + przykłady)")
    ap_l.add_argument("--sample-csv", required=True, help="Wejściowy CSV (np. data/curated/analysis/anomaly/label_sample.csv)")
    ap_l.add_argument("--out-csv", default=None, help="Wyjściowy CSV (domyślnie: *_enriched.csv)")
    ap_l.add_argument("--events-table", default=None, help="Tabela eventów w DuckDB: events lub events_raw (domyślnie auto)")
    ap_l.add_argument("--window-minutes", type=int, default=5, help="Rozmiar okna w minutach (domyślnie 5)")
    ap_l.add_argument("--top-k", type=int, default=5, help="Ile top user/pass zwrócić (domyślnie 5)")
    ap_l.add_argument("--examples", type=int, default=3, help="Ile przykładowych eventów dołączyć (domyślnie 3)")

    return ap.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)

    inputs = resolve_inputs(Path(args.data_dir), Path(args.duckdb_path) if args.duckdb_path else None)

    if args.cmd == "anomaly":
        out_dir = Path(args.out_dir) if args.out_dir else (inputs.data_dir / "curated" / "analysis" / "anomaly")
        max_interarrival = float(args.baseline_max_mean_interarrival)
        if max_interarrival < 0:
            max_interarrival = None

        anomaly_pipeline(
            inputs=inputs,
            out_dir=out_dir,
            prefer_source=args.prefer,
            filter_service=args.service,
            contamination=float(args.contamination),
            attempts_ge=int(args.baseline_attempts),
            unique_users_ge=int(args.baseline_unique_users),
            unique_passwords_ge=int(args.baseline_unique_passwords),
            max_mean_interarrival_s=max_interarrival,
            export_sample_n=int(args.export_sample_n),
            seed=int(args.seed),
        )
        return

    if args.cmd == "eval":
        out_json = Path(args.out_json) if args.out_json else None
        res = eval_predictions(Path(args.labeled_csv), pred_col=args.pred_col, out_json=out_json)
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return

    if args.cmd == "cluster":
        out_dir = Path(args.out_dir) if args.out_dir else (inputs.data_dir / "curated" / "analysis" / "cluster")
        cluster_pipeline(
            inputs=inputs,
            out_dir=out_dir,
            prefer_source=args.prefer,
            k=int(args.k),
            min_commands=int(args.min_commands),
            seed=int(args.seed),
        )
        return
    
    if args.cmd == "labelprep":
        sample_csv = Path(args.sample_csv)
        out_csv = Path(args.out_csv) if args.out_csv else sample_csv.with_name(sample_csv.stem + "_enriched.csv")
        enrich_label_sample(
            duckdb_path=inputs.duckdb_path,
            sample_csv=sample_csv,
            out_csv=out_csv,
            events_table=args.events_table,
            window_minutes=int(args.window_minutes),
            top_k=int(args.top_k),
            examples=int(args.examples),
        )
        return


if __name__ == "__main__":
    main()
