# PhishGuard Beginner Guide

## 1. What is PhishGuard

PhishGuard is a security project that checks URLs and warns you when a link looks suspicious or dangerous. It uses a machine learning model, threat intelligence, WHOIS, DNS, and browser tools to help detect phishing, malware, defacement, and safe links.

You can use PhishGuard from a web dashboard or from a Chrome extension.

## 2. What you need to install first

Before you start, install these tools on Windows:

| Tool | Why you need it | Download link |
| --- | --- | --- |
| Python 3.11+ | Runs the backend API and trains the ML model. | [https://www.python.org/downloads/](https://www.python.org/downloads/) |
| Node.js 18+ | Runs the React dashboard. | [https://nodejs.org/](https://nodejs.org/) |
| Git | Downloads the project files from GitHub. | [https://git-scm.com/download/win](https://git-scm.com/download/win) |
| VS Code | Recommended code editor. | [https://code.visualstudio.com/](https://code.visualstudio.com/) |
| Chrome browser | Runs the PhishGuard browser extension. | [https://www.google.com/chrome/](https://www.google.com/chrome/) |

After installing Python, open PowerShell and check it:

```powershell
python --version
```

Expected output:

```text
Python 3.11.x
```

After installing Node.js, check it:

```powershell
node --version
```

Expected output:

```text
v18.x.x
```

Check npm too. npm is installed with Node.js:

```powershell
npm --version
```

Expected output:

```text
9.x.x
```

Check Git:

```powershell
git --version
```

Expected output:

```text
git version 2.x.x
```

## 3. How to get the project files

You can get the project files in either of these two ways.

### Option A: Use Git clone

1. Open PowerShell.

2. Go to the folder where you keep projects:

```powershell
cd $HOME\Desktop
```

3. Clone the project:

```powershell
$ProjectGitUrl = Read-Host "Paste the project Git URL"
git clone $ProjectGitUrl phishguard
```

PowerShell will ask you to paste the project Git URL. Paste the URL, then press Enter.

Expected output:

```text
Cloning into 'phishguard'...
Receiving objects: 100%
Resolving deltas: 100%
```

4. Go into the project folder:

```powershell
cd phishguard
```

### Option B: Download ZIP

1. Open the project page in your browser.

2. Click the green **Code** button.

3. Click **Download ZIP**.

4. Extract the ZIP file.

5. Open PowerShell in the extracted folder.

6. If the extracted folder contains another folder named `phishguard`, go into it:

```powershell
cd phishguard
```

You are in the correct folder when this command shows folders like `backend`, `dashboard`, `extension`, and `ml`:

```powershell
Get-ChildItem
```

Expected output:

```text
backend
dashboard
extension
ml
tests
```

In the rest of this guide, this folder is called the project root.

## 4. Folder structure explained

| Folder or file | What it does |
| --- | --- |
| `backend` | FastAPI server that receives URLs and returns analysis results. |
| `dashboard` | React web dashboard where you paste URLs, view results, and export PDF reports. |
| `extension` | Chrome extension that scans the current browser tab. |
| `ml` | Machine learning code for feature extraction, preprocessing, training, and prediction. |
| `tests` | Automated tests for the API, model, features, CTI, WHOIS, and extension logic. |
| `malicious_phish.csv` | Dataset used to train the ML model. |
| `X_train.npy`, `X_test.npy`, `y_train.npy`, `y_test.npy` | Processed training and testing files created by preprocessing. |
| `feature_names.json` | List of URL features used by the model. |
| `.env.example` | Example environment file for API keys. |

## 5. Setting up the ML model

The ML model is the part of PhishGuard that learns patterns from URLs.

1. Open PowerShell in the project root folder.

The project root is the folder that contains `backend`, `dashboard`, `extension`, and `ml`.

2. Make sure `malicious_phish.csv` is in the project root:

```powershell
Test-Path .\malicious_phish.csv
```

Expected output:

```text
True
```

If the output is `False`, copy `malicious_phish.csv` into the project root before continuing.

3. Create a Python virtual environment:

```powershell
python -m venv .venv
```

Expected output:

```text

```

No output usually means it worked.

4. Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Expected output:

```text
(.venv) PS C:\path\to\phishguard>
```

If PowerShell blocks the activation script, run this command once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

Then activate the virtual environment again:

```powershell
.\.venv\Scripts\Activate.ps1
```

5. Install the backend and ML Python packages:

```powershell
pip install -r .\backend\requirements.txt
```

Expected output:

```text
Successfully installed fastapi uvicorn ...
```

6. Run preprocessing:

```powershell
python .\ml\preprocess.py
```

Expected output snippet:

```text
Loading dataset from ...
Dropping nulls and duplicates...
Normalizing URLs...
Extracting features (this may take a few minutes)...
Performing stratified 80/20 split...
Saving processed data...
Preprocessing complete.
```

This creates or updates these files:

```text
X_train.npy
X_test.npy
y_train.npy
y_test.npy
feature_names.json
ml\label_encoder.pkl
```

7. Run training:

```powershell
python .\ml\train.py --skip-preprocess
```

Expected output snippet:

```text
[train] Loading pre-processed artefacts ...
[train] Running GridSearchCV ...
[train] Test accuracy : 0.92...
[train] Saved model -> ...\ml\model.pkl
[train] Saved encoder -> ...\ml\label_encoder.pkl
```

Training can take a while because the project tries several model settings.

8. Check that the model file exists:

```powershell
Test-Path .\ml\model.pkl
```

Expected output:

```text
True
```

`model.pkl` is the saved ML model. The backend loads this file when it starts, so it can classify URLs without training again.

## 6. Setting up the backend

The backend is the local API server. The dashboard and Chrome extension call this server.

1. Open PowerShell in the project root folder.

2. Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Expected output:

```text
(.venv) PS C:\path\to\phishguard>
```

3. Install requirements if you have not already done it:

```powershell
pip install -r .\backend\requirements.txt
```

Expected output:

```text
Requirement already satisfied ...
```

or:

```text
Successfully installed ...
```

4. Create a `.env` file from `.env.example`:

```powershell
Copy-Item .\.env.example .\.env
```

Expected output:

```text

```

No output usually means it worked.

5. Open `.env` in VS Code:

```powershell
code .\.env
```

6. Put your VirusTotal API key in the file if you have one:

```text
VT_API_KEY=your_real_virustotal_api_key_here
```

If you do not have a VirusTotal key yet, you can leave the example value in place. The app can still run, but VirusTotal CTI results may be missing.

7. Start the backend server from the project root folder:

```powershell
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Expected output snippet:

```text
INFO:     Uvicorn running on http://127.0.0.1:8000
INFO:     Application startup complete.
[startup] Model loaded
```

If you see this instead:

```text
[startup] Model not found ... run train.py first.
```

Go back to section 5 and train the model.

8. Verify the backend works by opening this URL in Chrome:

```text
http://127.0.0.1:8000/health
```

Expected browser output:

```json
{
  "status": "ok",
  "ml_ready": true,
  "timestamp": "..."
}
```

If `ml_ready` is `false`, the server is running but the ML model was not loaded. Check that `ml\model.pkl` and `ml\label_encoder.pkl` exist.

## 7. Setting up the dashboard

The dashboard is the web page where you scan URLs and export PDF reports.

1. Open a second PowerShell window.

Keep the backend server running in the first PowerShell window.

2. Go to the project root folder.

If your PowerShell is in the parent folder, run:

```powershell
cd .\phishguard
```

3. Go to the dashboard folder:

```powershell
cd .\dashboard
```

4. Install dashboard packages:

```powershell
npm install
```

Expected output snippet:

```text
added ... packages
```

or:

```text
up to date
```

5. Start the dashboard:

```powershell
npm run dev
```

Expected output:

```text
VITE v5.x.x  ready
Local:   http://localhost:5173/
```

6. Open this URL in Chrome:

```text
http://localhost:5173/
```

The PhishGuard dashboard should appear.

## 8. Loading the Chrome extension

The Chrome extension scans the page you are visiting and shows the result in a popup.

1. Make sure the backend server is still running at:

```text
http://127.0.0.1:8000
```

2. Open Chrome.

3. Type this in the Chrome address bar:

```text
chrome://extensions
```

4. Press Enter.

Screenshot description: You should see the Chrome Extensions page. The page title says **Extensions**.

5. Turn on **Developer mode**.

Screenshot description: The **Developer mode** switch is usually in the top-right corner. After you turn it on, buttons like **Load unpacked** appear.

6. Click **Load unpacked**.

Screenshot description: A file picker window opens and asks you to choose a folder.

7. Select the `extension` folder inside the PhishGuard project.

Example folder:

```text
C:\path\to\phishguard\extension
```

8. Click **Select Folder**.

Screenshot description: A new extension card named **PhishGuard** appears on the Extensions page.

9. Pin the extension if you want quick access.

Screenshot description: Click the puzzle-piece icon near the Chrome address bar, then click the pin icon next to PhishGuard.

## 9. How to use PhishGuard

This section walks through a full demo from dashboard scan to extension popup.

1. Start the backend from the project root:

```powershell
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

Expected output:

```text
INFO:     Uvicorn running on http://127.0.0.1:8000
```

2. Start the dashboard in a second PowerShell window:

```powershell
cd .\phishguard
cd .\dashboard
npm run dev
```

Expected output:

```text
Local:   http://localhost:5173/
```

3. Open the dashboard:

```text
http://localhost:5173/
```

4. Paste a URL into the **Analyze URL** box.

Example:

```text
https://www.google.com
```

5. Click **Analyze**.

6. Read the result.

The result contains:

| Result field | Meaning |
| --- | --- |
| `label` | The category predicted by the model. Common labels are `benign`, `phishing`, `malware`, and `defacement`. |
| `confidence` | How sure the model is about its label. For example, `94.0%` means the model is very sure. |
| `risk score` | A 0 to 100 score that combines ML confidence, CTI hits, domain age, and typosquatting signs. Higher means more risky. |

7. Generate a PDF report.

First, scan at least one URL. Then scroll to the report/history area, select one or more scan rows, and click **Export PDF**.

Expected result:

```text
A PDF file named like phishguard-report-XXXXXXXXXXXXX.pdf is downloaded.
```

8. Use the extension popup.

Open any normal website, then click the PhishGuard extension icon in Chrome.

The popup shows:

| Popup field | Meaning |
| --- | --- |
| Current URL | The page URL being scanned. |
| Label | The model result, such as `BENIGN` or `PHISHING`. |
| Confidence | How sure the model is. |
| Risk Score | Overall danger score out of 100. |
| Features | A few important URL features found during analysis. |
| Recent scans | The last few extension scans saved in Chrome storage. |

If you click **View Report**, the extension opens the dashboard at:

```text
http://localhost:5173
```

## 10. Common errors and fixes

| Error | Cause | Fix |
| --- | --- | --- |
| `ModuleNotFoundError` | A Python package is missing, or the virtual environment is not active. | Run `.\.venv\Scripts\Activate.ps1`, then run `pip install -r .\backend\requirements.txt`. |
| CORS error in browser console | The dashboard cannot call the backend, or the backend is not running. | Start the backend with `python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000`, then refresh the dashboard. |
| `uvicorn` not found | Uvicorn is not installed in the active Python environment. | Activate `.venv`, then run `pip install -r .\backend\requirements.txt`. You can also start with `python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000`. |
| `model.pkl` missing | The ML model has not been trained yet. | Run `python .\ml\preprocess.py`, then run `python .\ml\train.py --skip-preprocess`. |
| `npm` not found | Node.js is not installed, or PowerShell was opened before Node.js was installed. | Install Node.js 18+ from [https://nodejs.org/](https://nodejs.org/), close PowerShell, open a new PowerShell window, then run `npm --version`. |

## 11. How the ML model works

The ML model looks at a URL and turns it into simple signals called features. A feature is one measurable thing about the URL.

PhishGuard looks at features like:

1. How long the URL is.

2. How many dots, slashes, hyphens, digits, and special characters it has.

3. Whether it uses HTTPS.

4. Whether the hostname is an IP address instead of a normal domain name.

5. Whether the URL contains words like `login`, `verify`, `secure`, `account`, or `password`.

6. Whether the domain looks similar to a famous brand.

7. Whether the URL uses suspicious top-level domains like `.xyz`, `.top`, or `.click`.

8. Whether the URL contains redirects, encoded text, or many subdomains.

The model learns from many labeled examples in `malicious_phish.csv`. Each example tells the model whether a URL is benign, phishing, malware, or defacement.

Around 92% accuracy is useful for a beginner security tool because phishing URLs often share visible patterns. It is not perfect, so you should treat the result as a warning signal, not as a final legal or security decision.

CTI integration adds extra real-world threat information on top of the ML model. For example, if VirusTotal or URLHaus has already seen a URL behaving badly, PhishGuard can raise the risk score even if the ML model is uncertain.

## 12. Glossary

| Term | Meaning |
| --- | --- |
| Phishing | A scam that tricks people into giving passwords, money, or private information. |
| URL | A web address, such as `https://example.com/login`. |
| ML model | A saved program that learned patterns from data and can make predictions. |
| API | A way for one program to talk to another program. The dashboard talks to the backend API. |
| CORS | A browser safety rule that controls which websites can call an API. |
| CTI | Cyber Threat Intelligence. It means outside information about known threats. |
| WHOIS | Public domain registration information, such as registrar and creation date. |
| DNS | The system that turns domain names like `example.com` into server addresses. |
| Typosquatting | Making a fake domain that looks like a real brand, such as a misspelled company name. |
| Obfuscation | Hiding the real meaning of a URL by using tricks like encoded characters or confusing redirects. |
