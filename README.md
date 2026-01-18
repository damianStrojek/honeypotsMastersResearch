# Honeypots Masters Research — narzędzia do przygotowania i analizy danych

Repozytorium zawiera zestaw narzędzi do **zbierania, czyszczenia, normalizacji i analizy** danych z honeypotów (m.in. **Cowrie** oraz **OpenCanary**) na potrzeby pracy magisterskiej.

Pipeline jest podzielony na dwa etapy:

1) **Ingest + przygotowanie danych** (`cleanHoneypots99836.py`)  
2) **Analiza i eksperymenty** (`analyzeHoneypots99836.py` + narzędzia pomocnicze do wykresów i tuningu)

## Zawartość repozytorium

- **`cleanHoneypots99836.py`** — pipeline czyszczenia/normalizacji logów → **DuckDB + Parquet** (warstwy `raw → processed → curated`).
- **`analyzeHoneypots99836.py`** — drugi etap strumienia badawczego, pracujący wyłącznie na danych wygenerowanych przez `cleanHoneypots99836.py` (DuckDB + Parquet w `data/curated/`).
- **`plotBaseline.py`** — generowanie wykresów/podsumowań dla wyników baseline (reguły) na bazie artefaktów z `analyzeHoneypots99836.py`.
- **`plotIsolationForest.py`** — generowanie wykresów/podsumowań dla wyników Isolation Forest (anomalia) na bazie artefaktów z `analyzeHoneypots99836.py`.
- **`tuneDetection99836.py`** — pomocnicze narzędzie do strojenia parametrów detekcji (np. progi baseline / ustawienia modelu), bazujące na wcześniej przygotowanych danych i (opcjonalnie) ręcznie oznaczonych próbkach.

## Wymagania

- Python **3.10+** (rekomendowane 3.11/3.12)
- Pakiety (minimum):
  ```bash
  pip install duckdb python-dateutil tqdm pandas numpy scikit-learn matplotlib
  ```

> W praktyce najwygodniej używać virtualenv/venv.

## Struktura danych

### Dane wejściowe (`data/raw/`)

W katalogu `data/raw/` powinny znaleźć się surowe logi z honeypotów:

```text
data/
  raw/
    cowrie/
      cowrie.json
      cowrie.json.2025-06-08
      ...
    opencanary/
      opencanary.log
```

### Dane wyjściowe (generowane)

Po uruchomieniu `cleanHoneypots99836.py` powstają m.in.:

```text
data/
  processed/
    logs.duckdb
    rejects/
      cowrie_rejects.jsonl
      opencanary_rejects.jsonl
  curated/
    events/
      events_clean.parquet
    sessions/
      cowrie_sessions.parquet
    ip_windows/
      ip_windows_5m.parquet
    reports/
      cleaning_report.json
```

## cleanHoneypots99836.py

### Uruchomienie

1) Standardowe przetworzenie (Cowrie + OpenCanary)
```bash
python3 cleanHoneypots99836.py --data-dir ./data
```

2) Podejrzenie utworzonej bazy DuckDB:
```bash
duckdb ./data/processed/logs.duckdb
```

### Pseudonimizacja i dane wrażliwe

- Skrypt wspiera **pseudonimizację** (np. IP / user / pass) poprzez stabilny hash z solą.
- Dla powtarzalności wyników ustaw stałą sól (rekomendowane):

**Linux/macOS:**
```bash
export HONEYPOT_SALT="dlugi-losowy-ciag"
python3 cleanHoneypots99836.py --data-dir ./data
```

**Windows (PowerShell):**
```powershell
$env:HONEYPOT_SALT="dlugi-losowy-ciag"
python3 .\cleanHoneypots99836.py --data-dir .\data
```

Domyślnie skrypt może **nie zapisywać jawnych** `username` i `password` (ustawia je na `NULL`) — zamiast tego przechowuje m.in.:
- `username_hash`, `password_hash`
- `pass_len`, `pass_entropy`
- `src_ip_hash`, `src_ip_masked`

Jeśli chcesz zachować jawne dane (np. wyłącznie do lokalnej analizy), użyj:
```bash
python3 cleanHoneypots99836.py --data-dir ./data --keep-secrets
```

### Okna czasowe (agregacja pod detekcję)

Domyślnie `ip_windows` budowane są w oknach 5 minut. Możesz zmienić rozmiar okna:
```bash
python3 cleanHoneypots99836.py --data-dir ./data --window-minutes 10
```

### Duże logi i wydajność

Dla bardzo dużych plików (np. OpenCanary 100M+ linii) zwiększ batch:
```bash
python3 cleanHoneypots99836.py --data-dir ./data --batch-size 20000
```

### Tryby ingestu (pomijanie etapów)

Jeśli Twoja wersja skryptu obsługuje flagę `--ingest`, możesz sterować etapami ingestu:

- `--ingest both` — (domyślnie) wczytaj Cowrie i OpenCanary
- `--ingest cowrie` — tylko Cowrie
- `--ingest opencanary` — tylko OpenCanary
- `--ingest none` — nie ingestuj nic, tylko przebuduj warstwy curated z istniejącego `events_raw`

Przykłady:

**Tylko OpenCanary (Cowrie już wcześniej wczytane):**
```bash
python3 cleanHoneypots99836.py --data-dir ./data --ingest opencanary
```

**Tylko przebudowa curated bez ponownego czytania logów:**
```bash
python3 cleanHoneypots99836.py --data-dir ./data --ingest none
```

> Jeśli nie widzisz tych opcji w `--help`, Twoja kopia skryptu może być starsza — zaktualizuj kod zgodnie z bieżącą wersją w repozytorium.

## analyzeHoneypots99836.py

Celem narzędzia jest analiza zdarzeń z honeypotów z wykorzystaniem metod regułowych oraz uczenia maszynowego, w szczególności:
- wykrywanie automatyzacji ataków logowania (brute force, password spraying),
- ewaluacja skuteczności metod detekcji na ręcznie oznaczonej próbce,
- klastrowanie zachowań atakujących w sesjach Cowrie.

Skrypt realizuje powyższe zadania w postaci subkomend CLI, umożliwiając modularne prowadzenie eksperymentów.

### Use-case A: wykrywanie automatyzacji logowań (anomalia)

Analiza wykonywana jest na zbiorze zagregowanych okien czasowych per adres IP i usługa (`ip_windows_5m`).

```bash
python3 analyzeHoneypots99836.py --data-dir ./data anomaly
```

Efekty (przykładowo) trafiają do:
```text
data/curated/analysis/anomaly/
  anomaly_windows.parquet
  top_if_anomalies.csv
  top_baseline_alerts.csv
  anomaly_summary.json
  label_sample.csv
```

### Wzbogacanie próbki do ręcznego etykietowania (labelprep)

Tryb `labelprep` wzbogaca próbkę o kontekst z tabel `events` / `events_raw` w DuckDB.

```bash
python3 analyzeHoneypots99836.py --data-dir ./data labelprep \
  --sample-csv data/curated/analysis/anomaly/label_sample.csv
```

Efektem jest plik `label_sample_enriched.csv` przeznaczony do ręcznego uzupełnienia kolumny `label`.

### Ewaluacja skuteczności metod (eval)

```bash
python3 analyzeHoneypots99836.py --data-dir ./data eval \
  --labeled-csv data/curated/analysis/anomaly/label_sample_enriched_labeled.csv \
  --pred-col baseline_alert
```

Analogicznie możesz oceniać predykcje modelu (np. `if_pred`), jeśli są obecne w pliku z etykietami.

### Use-case B: klastrowanie sesji Cowrie (cluster)

```bash
python3 analyzeHoneypots99836.py --data-dir ./data cluster --k 8 --min-commands 3
```

Efekty (przykładowo):
```text
data/curated/analysis/cluster/
  session_clusters.parquet
  cluster_summary.csv
  cluster_coords_2d.csv
```

> Uwaga: jeśli po filtrze `--min-commands` zostaje bardzo mało sesji, KMeans może wymagać mniejszego `--k`.

## Wykresy i raportowanie wyników

### plotBaseline.py

Skrypt służy do wizualizacji wyników baseline (reguły) wygenerowanych przez `analyzeHoneypots99836.py`.
Przykładowe uruchomienie (jeśli skrypt obsługuje `--help`, kieruj się nim):

```bash
python3 plotBaseline.py --data-dir ./data
```

### plotIsolationForest.py

Skrypt służy do wizualizacji wyników detekcji anomalii (Isolation Forest) wygenerowanych przez `analyzeHoneypots99836.py`.

```bash
python3 plotIsolationForest.py --data-dir ./data
```

> Te narzędzia są celowo lekkie: mają szybko generować wykresy/obrazki do rozdziału wyników (np. rozkłady alarmów, top anomalie, porównania z baseline).

---

## Strojenie detekcji (tuneDetection99836.py)

Narzędzie wspiera iteracyjne strojenie parametrów (np. progów baseline / ustawień modelu) na podstawie:
- `ip_windows_5m` / artefaktów z `analyzeHoneypots99836.py`,
- opcjonalnie ręcznie oznaczonej próbki (CSV z etykietą).

```bash
python3 tuneDetection99836.py --data-dir ./data --help
```

## Minimalny workflow (end-to-end)

```bash
# 1) przygotowanie danych (DuckDB + Parquet)
python3 cleanHoneypots99836.py --data-dir ./data

# 2) detekcja (baseline + IF) + próbka do etykiet
python3 analyzeHoneypots99836.py --data-dir ./data anomaly

# 3) wzbogacenie próbki do ręcznej oceny
python3 analyzeHoneypots99836.py --data-dir ./data labelprep \
  --sample-csv data/curated/analysis/anomaly/label_sample.csv

# 4) ewaluacja (po uzupełnieniu etykiet)
python3 analyzeHoneypots99836.py --data-dir ./data eval \
  --labeled-csv data/curated/analysis/anomaly/label_sample_enriched_labeled.csv \
  --pred-col baseline_alert

# 5) klastrowanie sesji (opcjonalnie)
python3 analyzeHoneypots99836.py --data-dir ./data cluster --k 8 --min-commands 3
```

## Uwagi

- Narzędzia są projektowane tak, aby **nie wymagać pełnego etykietowania całego zbioru** — do wiarygodnej ewaluacji wystarczy niewielka próbka.
- W repozytorium nie należy publikować surowych logów ani danych wrażliwych. Do wyników rekomendowane są **maskowanie i hashe**.
