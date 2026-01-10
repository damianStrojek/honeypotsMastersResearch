#!/usr/bin/env python3
# 99836 Damian Strojek
# 2026
"""
clean_honeypots.py

Pipeline czyszczenia/normalizacji logów z honeypotów:
- Cowrie (SSH) JSON lines: data/raw/cowrie/cowrie.json*
- OpenCanary JSON lines: data/raw/opencanary/opencanary.log

Wyjście:
- DuckDB: data/processed/logs.duckdb (events_raw, events, cowrie_sessions, ip_windows_5m)
- Parquet: data/curated/sessions/cowrie_sessions.parquet
          data/curated/ip_windows/ip_windows_5m.parquet
          data/curated/events/events_clean.parquet
- Raport QC: data/curated/reports/cleaning_report.json
- Odrzucone linie: data/processed/rejects/*.jsonl

Wymagania:
  pip install duckdb python-dateutil tqdm --break-system-packages
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from tqdm import tqdm

import duckdb
from dateutil import parser as dtparser


# --------------------------
# Konfiguracja i narzędzia
# --------------------------

LOG = logging.getLogger("clean_honeypots")


@dataclass
class Paths:
    raw_cowrie_dir: Path
    raw_opencanary_file: Path
    processed_dir: Path
    curated_dir: Path
    duckdb_path: Path
    rejects_dir: Path


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def ensure_dirs(*dirs: Path) -> None:
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()


def normalize_ip(ip: Optional[str]) -> Optional[str]:
    """Normalizuje IP (obsługa ::ffff:1.2.3.4, walidacja)."""
    if not ip:
        return None
    ip = ip.strip()
    if ip.startswith("::ffff:"):
        ip = ip.replace("::ffff:", "")
    try:
        obj = ipaddress.ip_address(ip)
        return str(obj)
    except ValueError:
        return None


def mask_ip(ip: Optional[str]) -> Optional[str]:
    """Maskowanie pod prezentacje/curated: IPv4 -> /24, IPv6 -> /64 (uproszczone)."""
    if not ip:
        return None
    try:
        obj = ipaddress.ip_address(ip)
        if obj.version == 4:
            net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
        else:
            net = ipaddress.ip_network(f"{ip}/64", strict=False)
            return str(net)
    except ValueError:
        return None


def hash_ip(ip: Optional[str], salt: str) -> Optional[str]:
    if not ip:
        return None
    return sha256_hex(salt + "|" + ip)[:16]  # krótszy identyfikator, wystarczy do analizy


def iter_jsonl_limited(paths: List[Path], max_lines: Optional[int] = None) -> Iterable[Tuple[Path, int, str]]:
    """
    Jak iter_jsonl, ale kończy po max_lines (liczone jako linie fizyczne z pliku).
    """
    seen = 0
    for p, line_no, line in iter_jsonl(paths):
        yield p, line_no, line
        seen += 1
        if max_lines is not None and seen >= max_lines:
            return


def shannon_entropy(s: Optional[str]) -> Optional[float]:
    if not s:
        return None
    s = s.strip()
    if not s:
        return None
    # Shannon entropy w bitach na znak (klasyczne)
    from math import log2

    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    ent = 0.0
    for c in freq.values():
        p = c / n
        ent -= p * log2(p)
    return float(ent)


def parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Parsuje timestamp do aware datetime UTC.
    Jeśli timestamp jest "naive" -> zakładamy UTC (bez zgadywania lokalnej strefy).
    """
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            # epoch seconds
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
            return dt
        if isinstance(value, str):
            dt = dtparser.parse(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
    except Exception:
        return None
    return None


def as_lower_str(v: Any) -> str:
    """Bezpiecznie zamienia na lowercase string (obsługuje int/dict/None)."""
    if v is None:
        return ""
    try:
        return str(v).lower()
    except Exception:
        return ""


def safe_int(x: Any) -> Optional[int]:
    try:
        if x is None:
            return None
        return int(x)
    except Exception:
        return None


def clean_command(cmd: Optional[str], max_len: int = 8000) -> Tuple[Optional[str], bool]:
    if cmd is None:
        return None, False
    # usuń kontrolne znaki
    cleaned = "".join(ch for ch in cmd if ch == "\n" or ch == "\t" or ord(ch) >= 32)
    cleaned = cleaned.strip()
    if len(cleaned) > max_len:
        return cleaned[:max_len], True
    return cleaned, False


def count_lines_fast(path: Path, chunk_size: int = 8 * 1024 * 1024) -> int:
    """
    Szybkie liczenie liczby linii w pliku (zliczanie znaków '\n' w trybie binarnym).
    Działa dobrze dla dużych plików.
    """
    if not path.exists() or not path.is_file():
        return 0
    n = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            n += chunk.count(b"\n")
    return n


# --------------------------
# Czytanie JSONL
# --------------------------

def iter_jsonl(paths: List[Path]) -> Iterable[Tuple[Path, int, str]]:
    """
    Yield: (path, line_no, raw_line)
    Celowo NIE pomijamy pustych linii tutaj, żeby progress bar był zgodny z liczbą linii.
    """
    for p in paths:
        if not p.exists():
            continue
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f, start=1):
                yield p, i, line.rstrip("\n")


def parse_json_line(line: str) -> Optional[dict]:
    try:
        return json.loads(line)
    except Exception:
        return None


# --------------------------
# Normalizacja Cowrie
# --------------------------

def normalize_cowrie(rec: dict, salt: str, keep_secrets: bool) -> Optional[Dict[str, Any]]:
    eventid = rec.get("eventid") or rec.get("event_id") or rec.get("event")
    ts = parse_timestamp(rec.get("timestamp") or rec.get("time") or rec.get("ts"))
    if ts is None:
        return None

    src_ip_raw = normalize_ip(rec.get("src_ip") or rec.get("src_host") or rec.get("src") or rec.get("ip"))
    src_port = safe_int(rec.get("src_port"))
    dst_port = safe_int(rec.get("dst_port") or rec.get("port"))  # cowrie zwykle nie ma, ale zostawiamy

    session_id = rec.get("session") or rec.get("session_id")

    # mapowanie event_type
    event_type = "other"
    if isinstance(eventid, str):
        if eventid.endswith("login.failed") or eventid == "cowrie.login.failed":
            event_type = "login_fail"
        elif eventid.endswith("login.success") or eventid == "cowrie.login.success":
            event_type = "login_success"
        elif eventid.endswith("command.input") or eventid == "cowrie.command.input":
            event_type = "command"
        elif eventid.endswith("session.connect") or eventid == "cowrie.session.connect":
            event_type = "connect"
        elif eventid.endswith("session.closed") or eventid == "cowrie.session.closed":
            event_type = "disconnect"
        elif "file_download" in eventid or eventid.endswith("session.file_download"):
            event_type = "download"

    username = rec.get("username")
    password = rec.get("password")

    cmd_raw = rec.get("input") or rec.get("command") or rec.get("message")
    command, truncated = clean_command(cmd_raw)

    url = rec.get("url")
    filename = rec.get("outfile") or rec.get("filename") or rec.get("destfile")
    file_hash = rec.get("sha256") or rec.get("shasum") or rec.get("hash")

    username_hash = sha256_hex(salt + "|u|" + str(username))[:16] if username else None
    password_hash = sha256_hex(salt + "|p|" + str(password))[:16] if password else None
    pass_entropy = shannon_entropy(password) if password else None
    pass_len = len(password) if isinstance(password, str) else None

    src_ip_hash = hash_ip(src_ip_raw, salt)
    src_ip_masked = mask_ip(src_ip_raw)

    base: Dict[str, Any] = {
        "ts_utc": ts.isoformat(),
        "source": "cowrie",
        "service": "ssh",
        "event_type": event_type,
        "eventid": str(eventid) if eventid is not None else None,
        "src_ip": src_ip_raw if keep_secrets else None,  # surowe IP tylko opcjonalnie
        "src_ip_hash": src_ip_hash,
        "src_ip_masked": src_ip_masked,
        "src_port": src_port,
        "dst_port": dst_port,
        "session_id": str(session_id) if session_id is not None else None,
        "username": str(username) if (keep_secrets and username is not None) else None,
        "username_hash": username_hash,
        "password": str(password) if (keep_secrets and password is not None) else None,
        "password_hash": password_hash,
        "pass_len": pass_len,
        "pass_entropy": pass_entropy,
        "command": command,
        "command_truncated": truncated,
        "url": str(url) if url is not None else None,
        "filename": str(filename) if filename is not None else None,
        "file_hash": str(file_hash) if file_hash is not None else None,
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }

    # event_hash do deduplikacji
    dedup_key = "|".join(
        [
            base["source"] or "",
            base["service"] or "",
            base["event_type"] or "",
            base["eventid"] or "",
            base["ts_utc"] or "",
            base["src_ip_hash"] or "",
            base["session_id"] or "",
            base["username_hash"] or "",
            base["password_hash"] or "",
            (base["command"] or "")[:200],
            base["url"] or "",
            base["filename"] or "",
        ]
    )
    base["event_hash"] = sha256_hex(dedup_key)

    return base


# --------------------------
# Normalizacja OpenCanary
# --------------------------

def guess_service_from_opencanary(rec: dict) -> Optional[str]:
    # Najczęściej: logtype zawiera nazwę usługi (ftp, ssh, rdp, mysql, http, smb…)
    logtype_val = rec.get("logtype") or rec.get("type") or rec.get("logger")
    logtype = as_lower_str(logtype_val)

    if "ftp" in logtype:
        return "ftp"
    if "mysql" in logtype:
        return "mysql"
    if "rdp" in logtype:
        return "rdp"
    if "ssh" in logtype:
        return "ssh"
    if "smb" in logtype:
        return "smb"
    if "http" in logtype:
        return "http"

    # fallback na port
    dst_port = safe_int(rec.get("dst_port") or rec.get("port"))
    port_map = {21: "ftp", 22: "ssh", 80: "http", 443: "http", 3389: "rdp", 3306: "mysql", 445: "smb"}
    if dst_port in port_map:
        return port_map[dst_port]
    return "unknown"


def guess_event_type_from_opencanary(rec: dict) -> str:
    logtype_val = rec.get("logtype") or rec.get("type")
    logtype = as_lower_str(logtype_val)

    if "login" in logtype and ("fail" in logtype or "failed" in logtype):
        return "login_fail"
    if "login" in logtype and ("success" in logtype or "successful" in logtype):
        return "login_success"
    if "login" in logtype:
        return "login_attempt"
    if "connection" in logtype or "connect" in logtype:
        return "connect"
    return "other"


def normalize_opencanary(rec: dict, salt: str, keep_secrets: bool) -> Optional[Dict[str, Any]]:
    # OpenCanary bywa: {"local_time": "...", "utc_time": "...", "logtype": "...", "src_host": "...", "dst_port": ... , "logdata": {...}}
    logdata = rec.get("logdata")
    if isinstance(logdata, dict):
        # spłaszcz logdata na wierzch (bez nadpisywania głównych)
        for k, v in logdata.items():
            rec.setdefault(k, v)

    ts = parse_timestamp(rec.get("utc_time") or rec.get("timestamp") or rec.get("time") or rec.get("local_time"))
    if ts is None:
        return None

    src_ip_raw = normalize_ip(rec.get("src_host") or rec.get("src_ip") or rec.get("src") or rec.get("ip"))
    src_port = safe_int(rec.get("src_port"))
    dst_port = safe_int(rec.get("dst_port") or rec.get("port"))

    service = guess_service_from_opencanary(rec)
    event_type = guess_event_type_from_opencanary(rec)
    logtype = rec.get("logtype") or rec.get("type")

    username = rec.get("username") or rec.get("user")
    password = rec.get("password") or rec.get("pass")

    username_hash = sha256_hex(salt + "|u|" + str(username))[:16] if username else None
    password_hash = sha256_hex(salt + "|p|" + str(password))[:16] if password else None
    pass_entropy = shannon_entropy(password) if password else None
    pass_len = len(password) if isinstance(password, str) else None

    src_ip_hash = hash_ip(src_ip_raw, salt)
    src_ip_masked = mask_ip(src_ip_raw)

    base: Dict[str, Any] = {
        "ts_utc": ts.isoformat(),
        "source": "opencanary",
        "service": service,
        "event_type": event_type,
        "eventid": str(logtype) if logtype is not None else None,
        "src_ip": src_ip_raw if keep_secrets else None,
        "src_ip_hash": src_ip_hash,
        "src_ip_masked": src_ip_masked,
        "src_port": src_port,
        "dst_port": dst_port,
        "session_id": None,  # OpenCanary zwykle nie ma sesji wprost
        "username": str(username) if (keep_secrets and username is not None) else None,
        "username_hash": username_hash,
        "password": str(password) if (keep_secrets and password is not None) else None,
        "password_hash": password_hash,
        "pass_len": pass_len,
        "pass_entropy": pass_entropy,
        "command": None,
        "command_truncated": False,
        "url": None,
        "filename": None,
        "file_hash": None,
        "raw_json": json.dumps(rec, ensure_ascii=False),
    }

    dedup_key = "|".join(
        [
            base["source"] or "",
            base["service"] or "",
            base["event_type"] or "",
            base["eventid"] or "",
            base["ts_utc"] or "",
            base["src_ip_hash"] or "",
            base["username_hash"] or "",
            base["password_hash"] or "",
            str(base["dst_port"] or ""),
        ]
    )
    base["event_hash"] = sha256_hex(dedup_key)

    return base


# --------------------------
# DuckDB: schema i insert
# --------------------------

EVENTS_COLUMNS = [
    "ts_utc",
    "source",
    "service",
    "event_type",
    "eventid",
    "src_ip",
    "src_ip_hash",
    "src_ip_masked",
    "src_port",
    "dst_port",
    "session_id",
    "username",
    "username_hash",
    "password",
    "password_hash",
    "pass_len",
    "pass_entropy",
    "command",
    "command_truncated",
    "url",
    "filename",
    "file_hash",
    "raw_json",
    "event_hash",
]

CREATE_EVENTS_RAW_SQL = f"""
CREATE TABLE IF NOT EXISTS events_raw (
    ts_utc TIMESTAMP,
    source VARCHAR,
    service VARCHAR,
    event_type VARCHAR,
    eventid VARCHAR,
    src_ip VARCHAR,
    src_ip_hash VARCHAR,
    src_ip_masked VARCHAR,
    src_port INTEGER,
    dst_port INTEGER,
    session_id VARCHAR,
    username VARCHAR,
    username_hash VARCHAR,
    password VARCHAR,
    password_hash VARCHAR,
    pass_len INTEGER,
    pass_entropy DOUBLE,
    command VARCHAR,
    command_truncated BOOLEAN,
    url VARCHAR,
    filename VARCHAR,
    file_hash VARCHAR,
    raw_json VARCHAR,
    event_hash VARCHAR
);
"""


def dict_to_row(d: Dict[str, Any]) -> Tuple[Any, ...]:
    # DuckDB przyjmie ISO string w TIMESTAMP? Bezpieczniej: przekazać string i rzutować w insert.
    return tuple(d.get(col) for col in EVENTS_COLUMNS)


def insert_batch(conn: duckdb.DuckDBPyConnection, rows: List[Tuple[Any, ...]]) -> None:
    if not rows:
        return
    placeholders = ",".join(["?"] * len(EVENTS_COLUMNS))
    sql = f"INSERT INTO events_raw VALUES ({placeholders})"
    conn.executemany(sql, rows)


# --------------------------
# Budowa tabel curated
# --------------------------

def build_dedup_and_curated(conn: duckdb.DuckDBPyConnection, window_minutes: int) -> None:
    # Deduplikacja po event_hash (pierwszy rekord wg ts_utc)
    conn.execute("DROP TABLE IF EXISTS events;")
    conn.execute(
        """
        CREATE TABLE events AS
        SELECT * EXCLUDE (rn)
        FROM (
          SELECT *,
                 row_number() OVER (PARTITION BY event_hash ORDER BY ts_utc) AS rn
          FROM events_raw
        )
        WHERE rn = 1;
        """
    )

    # Sesje Cowrie
    conn.execute("DROP TABLE IF EXISTS cowrie_sessions;")
    conn.execute(
        """
        CREATE TABLE cowrie_sessions AS
        SELECT
            session_id,
            min(ts_utc) AS start_ts_utc,
            max(ts_utc) AS end_ts_utc,
            datediff('second', min(ts_utc), max(ts_utc)) AS duration_s,
            any_value(src_ip_hash) AS src_ip_hash,
            any_value(src_ip_masked) AS src_ip_masked,
            (sum(CASE WHEN event_type = 'login_success' THEN 1 ELSE 0 END) > 0) AS has_success,
            list(command ORDER BY ts_utc) FILTER (WHERE event_type = 'command' AND command IS NOT NULL) AS commands_seq,
            count(*) FILTER (WHERE event_type = 'command') AS num_commands,
            list(url ORDER BY ts_utc) FILTER (WHERE event_type = 'download' AND url IS NOT NULL) AS download_urls,
            count(*) FILTER (WHERE event_type = 'download') AS num_downloads
        FROM events
        WHERE source = 'cowrie' AND session_id IS NOT NULL
        GROUP BY session_id;
        """
    )

    # Okna czasowe per IP/usługa dla prób logowania
    window_s = window_minutes * 60
    conn.execute("DROP TABLE IF EXISTS ip_windows_5m;")
    conn.execute(
        f"""
        CREATE TABLE ip_windows_5m AS
        WITH login_events AS (
            SELECT
                *,
                to_timestamp(floor(epoch(ts_utc) / {window_s}) * {window_s}) AS window_start
            FROM events
            WHERE event_type IN ('login_fail','login_success','login_attempt')
              AND src_ip_hash IS NOT NULL
        ),
        login_events_with_lag AS (
            SELECT
                *,
                (epoch(ts_utc) - epoch(lag(ts_utc) OVER (PARTITION BY src_ip_hash, service ORDER BY ts_utc))) AS interarrival_s
            FROM login_events
        )
        SELECT
            window_start,
            source,
            service,
            src_ip_hash,
            any_value(src_ip_masked) AS src_ip_masked,
            count(*) AS attempts,
            count(*) FILTER (WHERE event_type = 'login_success') AS success_count,
            count(DISTINCT username_hash) AS unique_users,
            count(DISTINCT password_hash) AS unique_passwords,
            avg(pass_entropy) AS pass_entropy_mean,
            avg(interarrival_s) AS mean_interarrival_s,
            min(interarrival_s) AS min_interarrival_s
        FROM login_events_with_lag
        GROUP BY window_start, source, service, src_ip_hash;
        """
    )


def export_parquets(conn: duckdb.DuckDBPyConnection, curated_dir: Path) -> Dict[str, Path]:
    out_events = curated_dir / "events" / "events_clean.parquet"
    out_sessions = curated_dir / "sessions" / "cowrie_sessions.parquet"
    out_windows = curated_dir / "ip_windows" / "ip_windows_5m.parquet"

    ensure_dirs(out_events.parent, out_sessions.parent, out_windows.parent)

    conn.execute(f"COPY (SELECT * FROM events) TO '{out_events.as_posix()}' (FORMAT PARQUET);")
    conn.execute(f"COPY (SELECT * FROM cowrie_sessions) TO '{out_sessions.as_posix()}' (FORMAT PARQUET);")
    conn.execute(f"COPY (SELECT * FROM ip_windows_5m) TO '{out_windows.as_posix()}' (FORMAT PARQUET);")

    return {"events": out_events, "sessions": out_sessions, "ip_windows": out_windows}


def write_qc_report(
    conn: duckdb.DuckDBPyConnection,
    report_path: Path,
    rejects_summary: Dict[str, Any],
) -> None:
    ensure_dirs(report_path.parent)

    def q(sql: str) -> Any:
        return conn.execute(sql).fetchall()

    report: Dict[str, Any] = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "events_raw": q("SELECT count(*) FROM events_raw;")[0][0],
            "events_dedup": q("SELECT count(*) FROM events;")[0][0],
            "cowrie_sessions": q("SELECT count(*) FROM cowrie_sessions;")[0][0],
            "ip_windows_5m": q("SELECT count(*) FROM ip_windows_5m;")[0][0],
        },
        "time_range": {
            "min_ts_utc": q("SELECT min(ts_utc) FROM events;")[0][0],
            "max_ts_utc": q("SELECT max(ts_utc) FROM events;")[0][0],
        },
        "top_event_types": q(
            """
            SELECT source, service, event_type, count(*) AS c
            FROM events
            GROUP BY source, service, event_type
            ORDER BY c DESC
            LIMIT 30;
            """
        ),
        "null_rates": {
            "src_ip_hash_null": q("SELECT sum(CASE WHEN src_ip_hash IS NULL THEN 1 ELSE 0 END) FROM events;")[0][0],
            "ts_null": q("SELECT sum(CASE WHEN ts_utc IS NULL THEN 1 ELSE 0 END) FROM events;")[0][0],
        },
        "rejects": rejects_summary,
    }

    with report_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)


# --------------------------
# Main pipeline
# --------------------------

def discover_cowrie_files(raw_cowrie_dir: Path) -> List[Path]:
    # cowrie.json + cowrie.json.YYYY-MM-DD itd.
    files = sorted(raw_cowrie_dir.glob("cowrie.json*"))
    return [p for p in files if p.is_file()]


def run_pipeline(paths: Paths, salt: str, window_minutes: int, keep_secrets: bool, batch_size: int,
                 ingest: str = "both", opencanary_first: bool = False,
                 parse_selected: bool = False, opencanary_max_lines: int = 5_000_000, cowrie_max_files: int = 50) -> None:
    ensure_dirs(paths.processed_dir, paths.curated_dir, paths.rejects_dir)

    do_cowrie = ingest in ("both", "cowrie")
    do_opencanary = ingest in ("both", "opencanary")

    # Odkrywaj pliki tylko dla tych etapów, które faktycznie robisz
    cowrie_files: List[Path] = discover_cowrie_files(paths.raw_cowrie_dir) if do_cowrie else []
    opencanary_files: List[Path] = [paths.raw_opencanary_file] if (do_opencanary and paths.raw_opencanary_file.exists()) else []

    if do_cowrie and not cowrie_files:
        raise FileNotFoundError(f"Nie znaleziono plików Cowrie w: {paths.raw_cowrie_dir}")

    if do_opencanary and not opencanary_files:
        raise FileNotFoundError(f"Brak opencanary.log pod: {paths.raw_opencanary_file}")

    # --- Tryb parsowania wybranych fragmentów danych (dev mode) ---
    if parse_selected:
        if cowrie_files:
            original = len(cowrie_files)
            cowrie_files = cowrie_files[:max(0, cowrie_max_files)]
            LOG.warning("Tryb --parse-selected: Cowrie ograniczone do %d/%d plików.", len(cowrie_files), original)

        if opencanary_files:
            LOG.warning("Tryb --parse-selected: OpenCanary ograniczone do pierwszych %d linii.", opencanary_max_lines)

    if do_cowrie:
        LOG.info("Cowrie files: %d", len(cowrie_files))
    if do_opencanary:
        if opencanary_files:
            LOG.info("OpenCanary file: %s", paths.raw_opencanary_file)
        else:
            raise FileNotFoundError(f"Brak opencanary.log pod: {paths.raw_opencanary_file}")

    if not do_cowrie and not do_opencanary:
        LOG.info("Ingest pominięty (--ingest none). Używam istniejących danych w DuckDB.")

    conn = duckdb.connect(paths.duckdb_path.as_posix())
    conn.execute("PRAGMA threads=8;")
    conn.execute(CREATE_EVENTS_RAW_SQL)

    # reject files
    cowrie_rejects = paths.rejects_dir / "cowrie_rejects.jsonl"
    opencanary_rejects = paths.rejects_dir / "opencanary_rejects.jsonl"

    rejects_summary = {
        "cowrie": {"bad_json": 0, "bad_ts": 0, "other": 0, "reject_file": cowrie_rejects.as_posix()},
        "opencanary": {"bad_json": 0, "bad_ts": 0, "other": 0, "reject_file": opencanary_rejects.as_posix()},
    }

    def write_reject(out_path: Path, payload: Dict[str, Any]) -> None:
        with out_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def ingest_cowrie() -> None:
        LOG.info("Ingest: Cowrie")
        cowrie_total = sum(count_lines_fast(fp) for fp in cowrie_files)
        batch: List[Tuple[Any, ...]] = []

        with tqdm(total=cowrie_total, desc="Ingest Cowrie", unit="line", smoothing=0.05) as pbar:
            for p, line_no, line in iter_jsonl(cowrie_files):
                pbar.update(1)
                line = line.strip()
                if not line:
                    continue

                rec = parse_json_line(line)
                if not isinstance(rec, dict):
                    rejects_summary["cowrie"]["other"] += 1
                    write_reject(cowrie_rejects, {"file": p.as_posix(), "line": line_no, "reason": "not_dict_or_bad_json", "raw": line[:500]})
                    continue

                norm = normalize_cowrie(rec, salt=salt, keep_secrets=keep_secrets)
                if norm is None:
                    rejects_summary["cowrie"]["bad_ts"] += 1
                    write_reject(cowrie_rejects, {"file": p.as_posix(), "line": line_no, "reason": "bad_ts", "raw": line[:500]})
                    continue

                batch.append(dict_to_row(norm))
                if len(batch) >= batch_size:
                    insert_batch(conn, batch)
                    batch.clear()

            if batch:
                insert_batch(conn, batch)
                batch.clear()

    def ingest_opencanary() -> None:
        LOG.info("Ingest: OpenCanary")

        # Jeśli parse_selected -> nie skanujemy całego pliku dla count_lines_fast (to kosztowne przy 100M+ linii)
        if parse_selected:
            total_for_bar = opencanary_max_lines
            iterator = iter_jsonl_limited(opencanary_files, max_lines=opencanary_max_lines)
        else:
            total_for_bar = sum(count_lines_fast(fp) for fp in opencanary_files)
            iterator = iter_jsonl(opencanary_files)

        batch: List[Tuple[Any, ...]] = []
        with tqdm(total=total_for_bar, desc="Ingest OpenCanary", unit="line", smoothing=0.05) as pbar:
            for p, line_no, line in iterator:
                pbar.update(1)

                line = line.strip()
                if not line:
                    continue

                rec = parse_json_line(line)
                if not isinstance(rec, dict):
                    rejects_summary["opencanary"]["other"] += 1
                    write_reject(opencanary_rejects, {"file": p.as_posix(), "line": line_no, "reason": "not_dict_or_bad_json", "raw": line[:500]})
                    continue

                norm = normalize_opencanary(rec, salt=salt, keep_secrets=keep_secrets)
                if norm is None:
                    rejects_summary["opencanary"]["bad_ts"] += 1
                    write_reject(opencanary_rejects, {"file": p.as_posix(), "line": line_no, "reason": "bad_ts", "raw": line[:500]})
                    continue

                batch.append(dict_to_row(norm))
                if len(batch) >= batch_size:
                    insert_batch(conn, batch)
                    batch.clear()

            if batch:
                insert_batch(conn, batch)
                batch.clear()

    # Kolejność ingestu
    if do_cowrie or do_opencanary:
        if ingest == "both" and opencanary_first:
            if do_opencanary:
                ingest_opencanary()
            if do_cowrie:
                ingest_cowrie()
        else:
            # domyślnie: cowrie -> opencanary, a jeśli --ingest opencanary to i tak poleci tylko opencanary
            if do_cowrie:
                ingest_cowrie()
            if do_opencanary:
                ingest_opencanary()

    LOG.info("Zapisano events_raw: %s", paths.duckdb_path)

    # Build curated tables
    with tqdm(total=3, desc="Build & Export", unit="step") as stage:
        LOG.info("Buduję: events (dedup), cowrie_sessions, ip_windows_5m")
        build_dedup_and_curated(conn, window_minutes=window_minutes)
        stage.update(1)

        LOG.info("Eksportuję Parquet do curated/")
        exported = export_parquets(conn, paths.curated_dir)
        stage.update(1)

        LOG.info("Tworzę QC report")
        report_path = paths.curated_dir / "reports" / "cleaning_report.json"
        write_qc_report(conn, report_path, rejects_summary=rejects_summary)
        stage.update(1)

    LOG.info("QC report -> %s", report_path)

    conn.close()
    LOG.info("Done.")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Czyszczenie/normalizacja logów Cowrie + OpenCanary do DuckDB + curated Parquet.")
    ap.add_argument("--data-dir", default="data", help="Katalog bazowy z raw/processed/curated (domyślnie: ./data)")
    ap.add_argument("--cowrie-raw-dir", default=None, help="Nadpisz ścieżkę do data/raw/cowrie")
    ap.add_argument("--opencanary-raw-file", default=None, help="Nadpisz ścieżkę do data/raw/opencanary/opencanary.log")

    ap.add_argument("--duckdb-path", default=None, help="Nadpisz ścieżkę do data/processed/logs.duckdb")
    ap.add_argument("--window-minutes", type=int, default=5, help="Rozmiar okna czasowego do ip_windows (minuty), domyślnie 5")
    ap.add_argument("--batch-size", type=int, default=5000, help="Batch insert do DuckDB, domyślnie 5000")

    ap.add_argument("--salt", default=None, help="Sól do hashy (IP/user/pass). Jeśli brak -> weź z ENV HONEYPOT_SALT albo 'dev-salt'.")
    ap.add_argument("--keep-secrets", action="store_true", help="Jeśli ustawione: zapisuj surowe IP/username/password w events_raw/events.")
    ap.add_argument("--verbose", action="store_true", help="Więcej logów.")

    ap.add_argument("--ingest", choices=["both", "cowrie", "opencanary", "none"], default="both", help="Co wczytywać do events_raw. 'none' = nie ingestuj nic, tylko buduj curated z istniejących danych w DuckDB.")
    ap.add_argument("--opencanary-first", action="store_true", help="Gdy --ingest both: wczytaj OpenCanary przed Cowrie.")

    ap.add_argument("--parse-selected", action="store_true", help="Tryb deweloperski: parsuj tylko ograniczony fragment danych (szybsze testy).")
    ap.add_argument("--opencanary-max-lines", type=int, default=5_000_000, help="Gdy --parse-selected: ile pierwszych linii z opencanary.log wczytać (domyślnie 5000000).")
    ap.add_argument("--cowrie-max-files", type=int, default=50, help="Gdy --parse-selected: ile pierwszych plików cowrie.json* wczytać (domyślnie 50).")

    return ap.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)

    data_dir = Path(args.data_dir).resolve()
    raw_cowrie_dir = Path(args.cowrie_raw_dir).resolve() if args.cowrie_raw_dir else (data_dir / "raw" / "cowrie")
    raw_opencanary_file = Path(args.opencanary_raw_file).resolve() if args.opencanary_raw_file else (data_dir / "raw" / "opencanary" / "opencanary.log")

    processed_dir = data_dir / "processed"
    curated_dir = data_dir / "curated"
    duckdb_path = Path(args.duckdb_path).resolve() if args.duckdb_path else (processed_dir / "logs.duckdb")
    rejects_dir = processed_dir / "rejects"

    salt = args.salt or os.environ.get("HONEYPOT_SALT") or "dev-salt"
    if salt == "dev-salt":
        LOG.warning("Używasz domyślnej soli 'dev-salt'. Do pracy ustaw --salt albo ENV HONEYPOT_SALT.")

    paths = Paths(
        raw_cowrie_dir=raw_cowrie_dir,
        raw_opencanary_file=raw_opencanary_file,
        processed_dir=processed_dir,
        curated_dir=curated_dir,
        duckdb_path=duckdb_path,
        rejects_dir=rejects_dir,
    )

    run_pipeline(
        paths=paths,
        salt=salt,
        window_minutes=args.window_minutes,
        keep_secrets=args.keep_secrets,
        batch_size=args.batch_size,
        ingest=args.ingest,
        opencanary_first=args.opencanary_first,
        parse_selected=args.parse_selected,
        opencanary_max_lines=args.opencanary_max_lines,
        cowrie_max_files=args.cowrie_max_files,
    )


if __name__ == "__main__":
    main()
