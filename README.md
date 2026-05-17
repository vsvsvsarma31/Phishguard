# PhishGuard 🛡️
> AI-Powered Phishing URL Detection with Cyber Threat Intelligence

## Overview

PhishGuard is an end-to-end phishing URL detection system that combines machine learning, cyber threat intelligence, URL obfuscation checks, typosquatting analysis, and DNS/WHOIS enrichment. It includes a FastAPI backend for scanning URLs, a React dashboard for investigation and reporting, and a Chrome extension that automatically checks pages as you browse. The ML pipeline trains on phishing URL datasets such as ISCX URL 2016 or PhishTank-style malicious URL exports. The project is designed for local development, security demos, and rapid experimentation with phishing detection workflows.

```powershell
git clone https://github.com/vsvsvsarma31/Phishguard.git
cd phishguard
```

## Architecture Diagram

```text
+-------------------+        +-------------------+        +----------------------+
| Chrome Extension  | -----> | FastAPI Backend   | -----> | ML Detection Pipeline|
| Auto page scanner |        | /analyze endpoint |        | preprocess + train   |
+-------------------+        +---------+---------+        +----------+-----------+
                                      |                             |
                                      v                             v
+-------------------+        +-------------------+        +----------------------+
| React Dashboard   | <----- | Scan History API  |        | model.pkl + features |
| Reports + charts  |        | stats + history   |        | generated locally    |
+-------------------+        +---------+---------+        +----------------------+
                                      |
                                      v
                           +----------------------+
                           | Threat Intelligence  |
                           | VT + DNS + WHOIS     |
                           +----------------------+
```

## Features

- ML-based URL classification for phishing, malware, defacement, benign, and suspicious URLs.
- FastAPI backend with health checks, URL analysis, scan history, and statistics endpoints.
- React dashboard with scanner UI, risk visualizations, history, reports, and PDF export.
- Chrome extension that auto-scans visited pages and provides browser-level warnings.
- Cyber threat intelligence enrichment with VirusTotal-ready configuration.
- URL obfuscation, typosquatting, DNS, and WHOIS analysis helpers.
- Reproducible local training workflow using ignored dataset and model artifacts.

```powershell
git status
```

## Tech Stack

| Component | Technology |
| --- | --- |
| Backend API | Python 3.11+, FastAPI, Uvicorn |
| ML Pipeline | scikit-learn, NumPy, pandas, joblib |
| Threat Intelligence | VirusTotal API, DNS, WHOIS helpers |
| Dashboard | React, Vite, JavaScript, CSS |
| Extension | Chrome Extension Manifest V3, JavaScript |
| Testing | pytest, JavaScript extension tests |
| Version Control | Git, GitHub |

```powershell
python --version
node --version
git --version
```

## Prerequisites

- Python 3.11+: download from https://www.python.org/downloads/
- Node.js 18+: download from https://nodejs.org/en/download
- Chrome browser: download from https://www.google.com/chrome/
- Git: download from https://git-scm.com/downloads

```powershell
python --version
node --version
npm --version
git --version
```

## Quick Start

### 1. Clone the repo

```powershell
git clone https://github.com/vsvsvsarma31/Phishguard.git
cd phishguard
```

Expected output: Git downloads the repository and creates a local `phishguard` folder.

### 2. Train the ML Model

Download `malicious_phish.csv` from Kaggle, using an ISCX URL 2016 dataset export or a PhishTank-style malicious URL dataset. Place `malicious_phish.csv` in the project root beside `README.md`.

```powershell
cd phishguard
python -m pip install -r backend/requirements.txt
python -m ml.preprocess
python -m ml.train
```

Expected output: preprocessing creates local training arrays, and training creates model artifacts such as `model.pkl`. The full preprocessing and training flow can take about 15 minutes depending on your CPU and dataset size.

### 3. Configure Environment

```powershell
cp .env.example .env
notepad .env
```

Environment variables:

| Variable | Description |
| --- | --- |
| `VIRUSTOTAL_API_KEY` | Optional VirusTotal API key for threat intelligence enrichment. Get a free key at https://www.virustotal.com/. |

```powershell
Get-Content .env
```

### 4. Start Backend

```powershell
cd phishguard
python -m pip install -r backend/requirements.txt
python -m uvicorn backend.main:app --reload --port 8000
```

Verify the backend in a second PowerShell window:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"ok"}
```

You can also open http://127.0.0.1:8000/health in your browser and confirm it returns `{"status":"ok"}`.

### 5. Start Dashboard

```powershell
cd phishguard\dashboard
npm install
npm run dev
```

Open the dashboard:

```powershell
Start-Process http://localhost:5173
```

Expected output: Vite starts a local development server and prints a `Local:` URL for the React dashboard.

### 6. Load Chrome Extension

```powershell
Start-Process chrome://extensions
```

1. Enable Developer Mode.
2. Click Load Unpacked.
3. Select `phishguard\extension\`.
4. Pin PhishGuard to the toolbar.

Expected result: the PhishGuard extension appears in Chrome and can scan the current tab.

## Usage

- Paste any URL in the dashboard and click Analyze.
- Let the extension auto-scan every page you visit.
- Go to the Reports tab, select scans, and export a PDF report.

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/analyze -ContentType "application/json" -Body '{"url":"https://example.com"}'
Invoke-RestMethod http://127.0.0.1:8000/history
Invoke-RestMethod http://127.0.0.1:8000/stats
```

## API Endpoints

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/analyze` | Analyze a URL |
| GET | `/history` | Get scan history |
| GET | `/stats` | Get statistics |
| GET | `/health` | Health check |

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
```

## Model Performance

| Metric | Score |
| --- | --- |
| Overall Accuracy | 92.2% |
| Defacement F1 | 98.3% |
| Malware F1 | 93.9% |
| Inference Time | ~2ms |

```powershell
python -m pytest tests/test_model.py
```

## Common Issues

| Error | Fix |
| --- | --- |
| `ModuleNotFoundError` | Install backend dependencies with `python -m pip install -r backend/requirements.txt` from the project root. |
| CORS error in dashboard | Confirm the backend is running on `http://127.0.0.1:8000` and restart `npm run dev` in `dashboard`. |
| `uvicorn` not found | Use `python -m uvicorn backend.main:app --reload --port 8000` after installing requirements. |
| `model.pkl` missing | Download `malicious_phish.csv`, place it in the project root, then run `python -m ml.preprocess` and `python -m ml.train`. |

```powershell
python -m pip install -r backend/requirements.txt
python -m ml.preprocess
python -m ml.train
python -m uvicorn backend.main:app --reload --port 8000
```

## Project Structure

```text
phishguard/
|-- backend/
|   |-- main.py
|   |-- models.py
|   |-- cti.py
|   |-- obfuscation.py
|   |-- typosquat.py
|   |-- whois_dns.py
|   `-- requirements.txt
|-- dashboard/
|   |-- package.json
|   |-- vite.config.js
|   `-- src/
|       |-- App.jsx
|       |-- api/
|       |   `-- client.js
|       `-- components/
|           |-- RiskChart.jsx
|           |-- ScanHistory.jsx
|           |-- StatsBar.jsx
|           |-- ThreatReport.jsx
|           `-- URLScanner.jsx
|-- extension/
|   |-- manifest.json
|   |-- background.js
|   |-- content.js
|   |-- icons/
|   `-- popup/
|       |-- popup.html
|       |-- popup.css
|       `-- popup.js
|-- ml/
|   |-- features.py
|   |-- preprocess.py
|   |-- train.py
|   |-- predict.py
|   `-- tune.py
|-- tests/
|   |-- test_api.py
|   |-- test_cti.py
|   |-- test_extension.js
|   |-- test_features.py
|   |-- test_model.py
|   `-- test_whois.py
|-- .env.example
|-- .gitignore
|-- docker-compose.yml
|-- BEGINNER_GUIDE.md
|-- README.md
`-- LICENSE
```

```powershell
Get-ChildItem -Recurse -File | Where-Object { $_.FullName -notmatch "node_modules|__pycache__|\.git" }
```

## License

MIT

```powershell
Get-Content LICENSE
```
