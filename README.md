# SecureAI X — AI-Assisted PHP Vulnerability Scanner

A full SAST (Static Application Security Testing) tool:
- **Backend** (Python/FastAPI): real regex/heuristic PHP vulnerability scanner,
  risk scoring engine, plain-English AI explanation layer, attack simulator,
  and PDF report generator.
- **Frontend** (HTML/CSS/JS + Three.js): a fully interactive interface styled
  as a live VS Code window, with a real 3D animated vulnerability graph.

No build tools required. No React, no npm install for the frontend — just a
browser. The backend needs Python.

---

## 0. What you need installed

- **Python 3.9+** — check with `python3 --version`
- **VS Code** (you already have this)
- Any modern browser (Chrome/Edge/Firefox)

---

## 1. Get the project into VS Code

1. Unzip the `secureai-x.zip` file you downloaded, anywhere you like
   (e.g. `Desktop/secureai-x`).
2. Open VS Code → `File > Open Folder...` → select the unzipped `secureai-x`
   folder.
3. You should see this structure in the Explorer sidebar:

```
secureai-x/
├── backend/
│   ├── main.py
│   ├── scanner.py
│   ├── risk_engine.py
│   ├── ai_explainer.py
│   ├── attack_simulator.py
│   ├── report_generator.py
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── style.css
│   ├── app.js
│   └── hero3d.js
└── README.md   ← you are here
```

Nothing else needs to be created — every file is already in place.

---

## 2. Start the backend (the scanner API)

Open a terminal in VS Code: `Terminal > New Terminal` (or `` Ctrl+` ``).

```bash
cd backend

# create an isolated environment (recommended)
python3 -m venv venv

# activate it
source venv/bin/activate        # macOS / Linux
venv\Scripts\activate           # Windows (PowerShell: venv\Scripts\Activate.ps1)

# install dependencies
pip install -r requirements.txt

# run the API
uvicorn main:app --reload --port 8000
```

You should see:

```
Uvicorn running on http://127.0.0.1:8000
```

Leave this terminal running. Test it worked by opening
`http://localhost:8000/api/health` in your browser — it should show
`{"status":"ok","service":"SecureAI X"}`.

> **Optional — real AI explanations instead of the built-in templates:**
> set an environment variable before starting uvicorn:
> `export ANTHROPIC_API_KEY=sk-ant-...` (macOS/Linux) or
> `$env:ANTHROPIC_API_KEY="sk-ant-..."` (PowerShell). Without it, the app
> still works perfectly using curated offline explanations.

---

## 3. Start the frontend

Open a **second** terminal in VS Code (click the `+` in the terminal panel,
so the backend keeps running in the first one).

**Easiest way — VS Code's "Live Server" extension:**
1. Install the extension: Extensions panel (`Ctrl+Shift+X`) → search
   `Live Server` by Ritwick Dey → Install.
2. Right-click `frontend/index.html` in the Explorer → **"Open with Live
   Server"**.
3. It opens automatically at something like `http://127.0.0.1:5500`.

**Or, no extension needed — Python's built-in server:**

```bash
cd frontend
python3 -m http.server 5500
```

Then open `http://localhost:5500` in your browser.

---

## 4. Use it

1. The **welcome.php** tab shows the animated 3D vulnerability graph and
   headline stats.
2. Click **Launch Scanner** (or the search icon in the left activity bar).
3. Click **"Choose file"** to upload a `.php` file, or paste code directly
   into the editor, or click **"Try a sample file"** on the welcome tab for
   an instant deliberately-vulnerable demo file.
4. Click **Run Scan** — watch the integrated terminal at the bottom stream
   the scan live, then review findings (line numbers, CWE ID, plain-English
   explanation, and the fix) in the Problems panel on the right.
5. Open the **Attack Simulator** tab to see example payloads and impact for
   each vulnerability class that was found.
6. Open the **Reports** tab and click **Download PDF Report** for a
   polished, shareable security report.

---

## 5. How the scanner actually works (for your write-up / viva)

`backend/scanner.py` runs a rule set of regex-based detectors against PHP
source, line by line:

| Class | CWE | Example trigger |
|---|---|---|
| SQL Injection | CWE-89 | `$_GET`/`$_POST` reaching `mysqli_query`, `->query`, string-concatenated SQL |
| Cross-Site Scripting | CWE-79 | `echo`/`print` of unescaped request data |
| Hardcoded Credentials | CWE-798 | `$password = "literal"` patterns |
| Insecure File Inclusion | CWE-98 | `include`/`require` fed by request data |
| Weak Cryptographic Hash | CWE-327 | `md5()` / `sha1()` |
| Insecure Deserialization | CWE-502 | `unserialize()` on request data |
| Code Injection | CWE-95 | `eval()` |
| Command Injection | CWE-78 | `system`/`exec`/`shell_exec` fed by request data |
| Missing CSRF Protection | CWE-352 | POST forms with no nearby CSRF token |

`risk_engine.py` converts findings into a 0–100 score with diminishing
penalties (so 5 lows don't overwhelm 1 critical unfairly).
`ai_explainer.py` turns each finding into a beginner-friendly explanation
(optionally using the real Claude API if you set `ANTHROPIC_API_KEY`).
`attack_simulator.py` returns illustrative (non-executing) payloads and
impact chains per vulnerability class, purely for education.
`report_generator.py` builds the downloadable PDF using ReportLab.

---

## 6. Extending it (Phase 2 ideas already scoped)

- Multi-file / ZIP project scanning — loop `scan_php_source` over every
  `.php` file in an extracted archive and merge findings.
- Confidence scores — already returned per finding (`f.confidence`); surface
  it more prominently in the UI.
- Multi-language support — add new rule modules (`scanner_js.py`,
  `scanner_python.py`) and route by file extension in `main.py`.
- GitHub repo scanning — clone with `gitpython`, walk the tree, reuse the
  same scan pipeline.
- AI auto-remediation — extend `ai_explainer.py` to also request a rewritten,
  safe version of the flagged line from Claude.

---

## Notes

- This is a **static heuristic scanner** for learning/portfolio purposes —
  not a replacement for a commercial SAST tool or a real penetration test.
- The Attack Simulator only *displays* example payloads and impact — it
  never executes anything against a real target.
