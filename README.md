# Honeypots Masters Research — Narzędzia do przygotowania danych

Repozytorium zawiera zestaw narzędzi do zbierania, czyszczenia i przygotowania danych z honeypotów (m.in. **Cowrie** i **OpenCanary**) pod dalszą analizę (baseline, ML, klastrowanie zachowań, generowanie raportów/IOC).

Narzędzia:
- **`cleanHoneypots99836.py`** — strumień czyszczenia/normalizacji logów, który generuje **DuckDB + Parquet** (warstwy `raw → processed → curated`).
- **`analyzeHoneypots99836.py`** - drugi etap strumienia badawczego pracujący wyłącznie na danych uprzednio przygotowanych przez narzędzie `cleanHoneypots99836.py` (pliki `logs.duckdb` oraz zestawy Parquet w katalogu `data/curated/`).

## cleanHoneypots99836.py

### Wymagania

1. Pliki logów znajdują się w folderze `data/raw/...`
2. Zainstalowane są poniższe zależności:
   ```bash
   pip install duckdb python-dateutil tqdm
   ```
3. Sposób uruchomienia:
   ```bash
   python3 cleanHoneypots99836.py --data-dir ./data
   ```
4. Podejrzenie utworzonej bazy danych:
   ```bash
   duckdb ./data/processed/logs.duckdb
   ```

Oczekiwana struktura katalogów:

```text
data/
  raw/
    cowrie/
      cowrie.json
      cowrie.json.2025-06-08
      ...
    opencanary/
      opencanary.log
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

### Uruchamianie `cleanHoneypots99836.py`

1) Standardowe przetworzenie (Cowrie + OpenCanary)
    ```bash
    python3 cleanHoneypots99836.py --data-dir ./data
    ```

2) Ustawienie stałej soli do pseudonimizacji - Sól stabilizuje hashe (IP/user/pass) między uruchomieniami — ważne dla powtarzalności wyników.

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

    > Jeśli nie ustawisz soli, skrypt może ostrzegać i użyć wartości domyślnej (niezalecane dla wersji produkcyjnej).

3) Okna czasowe dla `ip_windows` (domyślnie 5 minut)
    ```bash
    python3 cleanHoneypots99836.py --data-dir ./data --window-minutes 10
    ```

4) Duże logi i wydajność
    Dla bardzo dużych plików (np. OpenCanary 100M+ linii) zwiększ batch:
    ```bash
    python3 cleanHoneypots99836.py --data-dir ./data --batch-size 20000
    ```

### Tryby ingestu (pomijanie etapów)

Jeśli Twoja wersja skryptu obsługuje flagę `--ingest`, możesz sterować etapami ingestu:

- `--ingest both` — (domyślnie) wczytaj Cowrie i OpenCanary
- `--ingest cowrie` — tylko Cowrie
- `--ingest opencanary` — tylko OpenCanary
- `--ingest none` — **nie ingestuj nic**, tylko zbuduj `events/sessions/ip_windows` z istniejącego `events_raw`

Przykłady:

**Tylko OpenCanary (Cowrie już wcześniej wczytane):**
```bash
python3 cleanHoneypots99836.py --data-dir ./data --ingest opencanary
```

**Tylko przebudowa tabel curated bez ponownego czytania logów:**
```bash
python3 cleanHoneypots99836.py --data-dir ./data --ingest none
```

**OpenCanary przed Cowrie (jeśli jest `--opencanary-first`):**
```bash
python3 cleanHoneypots99836.py --data-dir ./data --ingest both --opencanary-first
```

> Jeśli nie widzisz tych opcji w `--help`, Twoja kopia skryptu może być starsza — zaktualizuj kod zgodnie z ostatnimi zmianami.

### Dane wrażliwe (username/password/IP)

Domyślnie skrypt może **nie zapisywać jawnych** `username` i `password` (ustawia je na `NULL`) ze względów bezpieczeństwa i łatwości publikacji wyników. Zamiast tego trzyma:
- `username_hash`, `password_hash`
- `pass_len`, `pass_entropy`
- `src_ip_hash`, `src_ip_masked`

Jeśli chcesz **zachować jawne** dane (np. do lokalnej analizy), użyj:
```bash
python3 cleanHoneypots99836.py --data-dir ./data --keep-secrets
```

> Uwaga: do pracy i publicznego repozytorium zalecane są hashe/maskowanie, a nie jawne dane.

### Co dokładnie powstaje po uruchomieniu

`data/processed/logs.duckdb` Zawiera m.in. tabele:
- `events_raw` — staging (wszystko po normalizacji, przed deduplikacją)
- `events` — deduplikacja po `event_hash`
- `cowrie_sessions` — agregacja sesji Cowrie + sekwencje komend
- `ip_windows_5m` — okna czasowe per IP/usługa (próby logowania)

`data/curated/*` (Parquet)
- `curated/events/events_clean.parquet` — „czyste” eventy
- `curated/sessions/cowrie_sessions.parquet` — sesje (pod klastrowanie/LLM)
- `curated/ip_windows/ip_windows_5m.parquet` — okna IP (pod baseline/ML)

`data/processed/rejects/*.jsonl`
- linie odrzucone (np. uszkodzony JSON, brak timestamp)

`data/curated/reports/cleaning_report.json`
- szybkie QC: liczności, zakres czasu, top eventy, statystyki odrzuceń

## analyzeHoneypots99836.py

Celem narzędzia jest analiza zdarzeń z honeypotów z wykorzystaniem metod regułowych oraz uczenia maszynowego, w szczególności:
- wykrywanie automatyzacji ataków logowania (brute force, password spraying),
- ewaluacja skuteczności metod detekcji na ręcznie oznaczonej próbce,
- klastrowanie zachowań atakujących w sesjach Cowrie.

Skrypt realizuje powyższe zadania w postaci kilku trybów pracy
(subkomend CLI), umożliwiając modularne prowadzenie eksperymentów.

### Wymagania

```bash
pip install duckdb pandas numpy tqdm scikit-learn
```

### Use-case A: wykrywanie automatyzacji logowań (anomalia)

Analiza wykonywana jest na zbiorze zagregowanych **okien czasowych per adres IP i usługa**
(`ip_windows_5m`), zawierających m.in.:
- liczbę prób logowania,
- liczbę unikalnych nazw użytkowników i haseł,
- liczbę udanych logowań,
- statystyki czasowe (interarrival time),
- entropię haseł.

```bash
python3 analyzeHoneypots99836.py --data-dir ./data anomaly
```

### Wzbogacanie próbki do ręcznego etykietowania (labelprep)

Tryb **`labelprep`** umożliwia wzbogacenie próbki do etykietowania o kontekst z tabel `events` / `events_raw` w DuckDB.

```bash
python3 analyzeHoneypots99836.py --data-dir ./data labelprep   --sample-csv data/curated/analysis/anomaly/label_sample.csv
```

Efektem jest plik `label_sample_enriched.csv`, przeznaczony do ręcznego uzupełnienia kolumny `label`.

### Ewaluacja skuteczności metod (eval)

```bash
python3 analyzeHoneypots99836.py --data-dir ./data eval   --labeled-csv data/curated/analysis/anomaly/label_sample_enriched_labeled.csv   --pred-col baseline_alert
```

### Use-case B: klastrowanie sesji Cowrie

```bash
python3 analyzeHoneypots99836.py --data-dir ./data cluster --k 8 --min-commands 3
```

### Uwagi metodologiczne

- Skrypt nie modyfikuje danych wejściowych.
- Metody regułowe pełnią rolę baseline’u, a ML stanowi uzupełnienie.
- Ręczne etykietowanie niewielkiej próbki pozwala na wiarygodną ewaluację.