"""
FastAPI Entrypoint & REST API for QuantumShield CBOM & Compliance Engine
"""

import json
import re
from pathlib import Path
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.constants import APP_NAME, APP_VERSION
from app.scanner.tls_scanner import TLSScanner
from app.engine.hndl_estimator import HNDLEstimator
from app.engine.compliance_scorer import ComplianceScorer
from app.engine.cbom_generator import CBOMGenerator
from app.reporting.pdf_generator import AuditPDFGenerator

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    description="Enterprise Cryptography Bill of Materials & DORA/NIS2/PQC Audit Platform"
)

# Template path
TEMPLATES_DIR = Path(__file__).resolve().parent / "web" / "templates"

class ScanRequest(BaseModel):
    target: str = Field(..., example="cloudflare.com", description="Domain or IP with optional port")

@app.get("/", response_class=HTMLResponse)
async def get_dashboard():
    """Serves the interactive web audit dashboard."""
    index_file = TEMPLATES_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=500, detail="Dashboard template not found.")
    return HTMLResponse(content=index_file.read_text(encoding="utf-8"))

@app.get("/api/health")
async def health_check():
    """Healthcheck endpoint."""
    return {"status": "ok", "service": APP_NAME, "version": APP_VERSION}

@app.post("/api/scan")
async def perform_scan(request: ScanRequest) -> Dict[str, Any]:
    """
    Executes complete end-to-end cryptographic and compliance audit.
    1. Runs TLS and PQC scan
    2. Computes HNDL and DORA/NIS2 compliance scores
    3. Generates CycloneDX 1.6 CBOM (JSON)
    4. Generates C-Level executive PDF audit report
    """
    target = request.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="A célpont nem lehet üres.")

    # 1. Execute Scan
    try:
        scan_result = TLSScanner.scan_target(target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Váratlan hiba a vizsgálat közben: {str(e)}")

    if not scan_result.get("success"):
        error_msg = "; ".join(scan_result.get("errors", ["Sikertelen kapcsolat."]))
        raise HTTPException(status_code=502, detail=f"Nem sikerült csatlakozni a célponthoz: {error_msg}")

    # 2. Risk & Compliance Evaluation
    hndl_info = HNDLEstimator.calculate_hndl_risk(
        scan_result["tls_info"],
        scan_result["certificate_info"],
        scan_result["pqc_info"]
    )
    compliance_result = ComplianceScorer.evaluate(scan_result, hndl_info)

    # 3. CycloneDX 1.6 CBOM Generation
    cbom_document = CBOMGenerator.generate(scan_result, compliance_result)

    # Sanitize hostname for filenames
    safe_hostname = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', scan_result["hostname"])
    cbom_filename = f"cbom_{safe_hostname}.json"
    pdf_filename = f"audit_report_{safe_hostname}.pdf"

    cbom_file_path = settings.reports_dir / cbom_filename
    pdf_file_path = settings.reports_dir / pdf_filename

    # Save CBOM JSON
    with open(cbom_file_path, "w", encoding="utf-8") as f:
        json.dump(cbom_document, f, indent=2, ensure_ascii=False)

    # Generate Executive PDF Report
    AuditPDFGenerator.generate_report(scan_result, compliance_result, pdf_file_path)

    return {
        "success": True,
        "target": target,
        "scan": scan_result,
        "compliance": compliance_result,
        "cbom": cbom_document,
        "report_filename": pdf_filename,
        "cbom_filename": cbom_filename
    }

@app.get("/api/reports/{filename}")
async def download_report(filename: str):
    """Downloads the generated PDF audit report."""
    # Prevent path traversal
    safe_name = Path(filename).name
    file_path = settings.reports_dir / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="A kért PDF riport nem található.")
    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=safe_name
    )

@app.get("/api/cbom/{filename}")
async def download_cbom(filename: str):
    """Downloads the generated CycloneDX 1.6 CBOM JSON document."""
    safe_name = Path(filename).name
    file_path = settings.reports_dir / safe_name
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="A kért CBOM dokumentum nem található.")
    return FileResponse(
        path=file_path,
        media_type="application/json",
        filename=safe_name
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=settings.debug)
