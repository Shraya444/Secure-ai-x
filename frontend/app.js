/* ============================================================
   SecureAI X — Frontend application logic
   Talks to the FastAPI backend at API_BASE.
   ============================================================ */

const API_BASE = "http://localhost:8000";

let sessionScans = 0;
let lastResult = null;

const SAMPLE_PHP = `<?php
$conn = mysqli_connect("localhost", "root", "admin123");
$password = "SuperSecret123";

$result = mysqli_query($conn, "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'");

echo "Welcome " . $_GET['name'];

if (isset($_POST['file'])) {
    include($_POST['file']);
}

$hashed = md5($password);
$data = unserialize($_POST['payload']);

eval($_GET['cmd']);
system($_GET['host']);
?>
<form method="POST" action="/transfer">
  <input type="text" name="amount">
  <button>Send</button>
</form>
`;

/* ------------------------- nav active-state on scroll ------------------------- */

const navLinks = document.querySelectorAll(".nav-link");
const sections = document.querySelectorAll("main > .section");

const observer = new IntersectionObserver(
  (entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        navLinks.forEach((l) => l.classList.toggle("active", l.getAttribute("href") === "#" + entry.target.id));
      }
    });
  },
  { rootMargin: "-45% 0px -45% 0px" }
);
sections.forEach((s) => observer.observe(s));

document.getElementById("btn-view-sample").addEventListener("click", () => {
  document.getElementById("code-input").value = SAMPLE_PHP;
  document.getElementById("current-filename").textContent = "sample.php";
  document.getElementById("scanner").scrollIntoView({ behavior: "smooth" });
});

/* ------------------------- mini console (typewriter log) ------------------------- */

const consoleBox = document.getElementById("mini-console");

function consoleLine(html, cls) {
  const div = document.createElement("div");
  div.className = "console-line" + (cls ? " " + cls : "");
  div.innerHTML = html;
  consoleBox.appendChild(div);
  consoleBox.scrollTop = consoleBox.scrollHeight;
}
function clearConsole() { consoleBox.innerHTML = ""; }
async function typeLine(html, cls, delay = 90) {
  return new Promise((resolve) => {
    consoleLine(html, cls);
    setTimeout(resolve, delay);
  });
}

/* ------------------------- file upload ------------------------- */

document.getElementById("file-input").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    document.getElementById("code-input").value = reader.result;
    document.getElementById("current-filename").textContent = file.name;
  };
  reader.readAsText(file);
});

/* ------------------------- scan pipeline ------------------------- */

document.getElementById("btn-run-scan").addEventListener("click", runScan);

async function runScan() {
  const code = document.getElementById("code-input").value;
  const filename = document.getElementById("current-filename").textContent || "snippet.php";
  if (!code.trim()) {
    alert("Paste or upload some PHP code first.");
    return;
  }

  const btn = document.getElementById("btn-run-scan");
  btn.disabled = true;
  btn.innerHTML = '<span class="run-icon">…</span> Scanning';

  clearConsole();
  await typeLine(`$ python3 scan.py ${filename}`, "", 120);
  await typeLine(`[INFO] Loading rule set: SQLi, XSS, secrets, LFI, deserialization, eval, exec, weak-hash, CSRF…`, "", 220);
  await typeLine(`[INFO] Parsing ${code.split("\\n").length} lines…`, "", 260);

  let data;
  try {
    const res = await fetch(`${API_BASE}/api/scan/text`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, filename }),
    });
    if (!res.ok) throw new Error(`API returned ${res.status}`);
    data = await res.json();
  } catch (err) {
    await typeLine(`[ERROR] Could not reach backend at ${API_BASE} — is uvicorn running?`, "c-crit");
    await typeLine(`[HINT] cd backend && uvicorn main:app --reload --port 8000`, "c-warn");
    btn.disabled = false;
    btn.innerHTML = '<span class="run-icon">▶</span> Run Scan';
    return;
  }

  for (const f of data.findings) {
    const cls = f.severity === "critical" || f.severity === "high" ? "c-crit"
      : f.severity === "medium" ? "c-warn" : "";
    await typeLine(`[${f.severity.toUpperCase()}] line ${f.line} — ${f.type} (${f.cwe})`, cls, 80);
  }
  await typeLine(`[DONE] Score ${data.risk.score}/100 — ${data.risk.label}. ${data.risk.total_findings} finding(s).`, "c-ok", 100);
  await typeLine(`$ <span class="c-blink">▍</span>`, "");

  lastResult = data;
  sessionScans += 1;

  renderResults(data);
  renderSimulations(data);
  renderReportSummary(data);
  renderAnalytics(data);
  updateHeroStats(data);

  btn.disabled = false;
  btn.innerHTML = '<span class="run-icon">▶</span> Run Scan';
}

/* ------------------------- render: results ------------------------- */

function renderResults(data) {
  const list = document.getElementById("results-list");
  const empty = document.getElementById("results-empty");
  const pill = document.getElementById("score-pill");

  list.innerHTML = "";
  if (data.findings.length === 0) {
    empty.style.display = "block";
    empty.textContent = "No issues found by the current rule set. Nice and clean.";
  } else {
    empty.style.display = "none";
    data.findings.forEach((f) => {
      const item = document.createElement("div");
      item.className = "finding-item";
      item.innerHTML = `
        <div class="finding-head">
          <span class="sev-badge sev-${f.severity}">${f.severity}</span>
          <span class="finding-type">${f.type}</span>
          <span class="finding-meta">Ln ${f.line} · ${f.cwe} · ${f.confidence}%</span>
        </div>
        <div class="finding-snippet">${escapeHtml(f.snippet)}</div>
        <div class="finding-desc">${escapeHtml(f.explanation || f.description)}</div>
        <div class="finding-fix"><b>Fix:</b> ${escapeHtml(f.recommendation)}</div>
      `;
      list.appendChild(item);
    });
  }

  pill.textContent = `SCORE ${data.risk.score}`;
  pill.className = "score-pill " + (data.risk.score >= 90 ? "safe" : data.risk.score >= 50 ? "moderate" : "high");
}

/* ------------------------- render: analytics ------------------------- */

function renderAnalytics(data) {
  const c = data.risk.counts;
  document.getElementById("cnt-critical").textContent = c.critical;
  document.getElementById("cnt-high").textContent = c.high;
  document.getElementById("cnt-medium").textContent = c.medium;
  document.getElementById("cnt-low").textContent = c.low;
  document.getElementById("gauge-score").textContent = data.risk.score;

  const circumference = 377; // 2 * PI * 60, matches SVG r=60
  const offset = circumference - (data.risk.score / 100) * circumference;
  const fill = document.getElementById("gauge-fill");
  fill.style.strokeDashoffset = offset;
  fill.style.stroke = data.risk.score >= 90 ? "#00e08a" : data.risk.score >= 50 ? "#ffb020" : "#ff4d4d";

  if (window.updateAnalyticsShape) window.updateAnalyticsShape(c);
}

/* ------------------------- render: simulator ------------------------- */

function renderSimulations(data) {
  const list = document.getElementById("sim-list");
  const empty = document.getElementById("sim-empty");
  list.innerHTML = "";

  const types = Object.keys(data.simulations || {});
  if (types.length === 0) {
    empty.style.display = "block";
    return;
  }
  empty.style.display = "none";

  types.forEach((type) => {
    const sim = data.simulations[type];
    const card = document.createElement("div");
    card.className = "sim-card";
    card.innerHTML = `
      <div class="sim-card-title">⚔ ${type}</div>
      <div class="sim-payload">${escapeHtml(sim.payload)}</div>
      <ol class="sim-steps">${sim.steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>
      <div class="sim-impact">${sim.impact.map((i) => `<span class="impact-tag">${escapeHtml(i)}</span>`).join("")}</div>
    `;
    list.appendChild(card);
  });
}

/* ------------------------- render: report ------------------------- */

function renderReportSummary(data) {
  const summary = document.getElementById("report-summary");
  const btn = document.getElementById("btn-download-report");
  const c = data.risk.counts;
  summary.textContent =
    `file:      ${data.filename}\n` +
    `score:     ${data.risk.score}/100 (${data.risk.label})\n` +
    `critical:  ${c.critical}\n` +
    `high:      ${c.high}\n` +
    `medium:    ${c.medium}\n` +
    `low:       ${c.low}`;
  btn.disabled = false;
}

document.getElementById("btn-download-report").addEventListener("click", async () => {
  if (!lastResult) return;
  const btn = document.getElementById("btn-download-report");
  btn.disabled = true;
  const original = btn.innerHTML;
  btn.textContent = "Generating…";
  try {
    const res = await fetch(`${API_BASE}/api/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        filename: lastResult.filename,
        risk: lastResult.risk,
        findings: lastResult.findings,
      }),
    });
    if (!res.ok) throw new Error("report generation failed");
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "secureai-x-report.pdf";
    a.click();
    URL.revokeObjectURL(url);
  } catch (err) {
    alert("Could not generate the report. Is the backend running?");
  } finally {
    btn.disabled = false;
    btn.innerHTML = original;
  }
});

/* ------------------------- hero stats ------------------------- */

function updateHeroStats(data) {
  document.getElementById("stat-score").textContent = `${data.risk.score}/100`;
  document.getElementById("stat-score-sub").textContent = data.risk.label.toLowerCase();
  document.getElementById("stat-findings").textContent = data.risk.total_findings;
  document.getElementById("stat-risk").textContent =
    data.risk.score >= 90 ? "Low" : data.risk.score >= 50 ? "Moderate" : "High";
  document.getElementById("stat-scans").textContent = sessionScans;
}

/* ------------------------- utils ------------------------- */

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/* ------------------------- API health check ------------------------- */

(async function checkApi() {
  const el = document.getElementById("stat-api");
  try {
    const res = await fetch(`${API_BASE}/api/health`);
    if (!res.ok) throw new Error();
    el.textContent = "online";
  } catch {
    el.textContent = "offline";
    el.classList.remove("status-ok");
  }
})();
