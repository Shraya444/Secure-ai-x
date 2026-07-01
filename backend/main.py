"""
SecureAI X — Backend API
Run with:  uvicorn main:app --reload --port 8000
"""

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from typing import Optional

from scanner import scan_php_source, findings_to_dicts
from risk_engine import calculate_risk
from ai_explainer import explain
from attack_simulator import simulate_all
from report_generator import build_report_pdf

app = FastAPI(title="SecureAI X API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten this in production
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanTextRequest(BaseModel):
    code: str
    filename: Optional[str] = "snippet.php"


class ReportRequest(BaseModel):
    filename: str
    risk: dict
    findings: list


def _run_pipeline(code: str, filename: str) -> dict:
    findings = findings_to_dicts(scan_php_source(code, filename))
    for f in findings:
        f["explanation"] = explain(f)

    risk = calculate_risk(findings)
    simulations = simulate_all([f["type"] for f in findings])

    return {
        "filename": filename,
        "risk": risk,
        "findings": findings,
        "simulations": simulations,
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "SecureAI X"}


@app.post("/api/scan/text")
def scan_text(req: ScanTextRequest):
    if not req.code or not req.code.strip():
        raise HTTPException(status_code=400, detail="No code provided.")
    return _run_pipeline(req.code, req.filename or "snippet.php")


@app.post("/api/scan/file")
async def scan_file(file: UploadFile = File(...)):
    raw = await file.read()
    try:
        code = raw.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Could not read file as text.")
    return _run_pipeline(code, file.filename or "uploaded.php")


@app.post("/api/report")
def report(req: ReportRequest):
    pdf_bytes = build_report_pdf(req.filename, req.risk, req.findings)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="secureai-x-report.pdf"'},
    )
