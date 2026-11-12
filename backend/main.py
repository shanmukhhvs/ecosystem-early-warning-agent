import os
import asyncio
import logging
from pathlib import Path
from datetime import date
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env", override=True)

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

import httpx

from scanner import parse_dependencies
from intelligence import analyze_packages_batch, detect_namespace_clusters
from synthesizer import synthesize_all, chat_response
from oss_index import catalog_stats, threats_count_for_days, differentiator_stats

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

app = FastAPI(title="Ecosystem Early Warning Agent")


@app.on_event("startup")
def _startup_check():
    """Best-effort reachability of the public sources. Never blocks startup."""
    try:
        r = httpx.get("https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q", timeout=5)
        if r.status_code == 200:
            log.info("OSV.dev reachable — live vulnerability intelligence active.")
        else:
            log.warning("OSV.dev returned %s — degraded mode.", r.status_code)
    except Exception as e:
        log.warning("OSV.dev unreachable (%s) — running on local catalog only.", e)
    if not os.getenv("NVD_API_KEY", "").strip():
        log.info("NVD_API_KEY not set — keyless NVD rate (5 req/30s). Set it for 50 req/30s.")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_FRONTEND_DIR = Path(__file__).parent.parent / "frontend"
if _FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(_FRONTEND_DIR)), name="static")


@app.get("/")
def index():
    index_file = _FRONTEND_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return {"status": "ok", "service": "ecosystem-early-warning-agent"}


@app.get("/health")
def health():
    stats = catalog_stats()
    return {"status": "ok", "catalog": stats}


@app.get("/stats")
def stats():
    """Live differentiator stats — powers the 'Why we are different' panel."""
    return differentiator_stats()


@app.get("/pulse")
def pulse(days: int = 1):
    """Ecosystem pulse — new CVEs published to NVD.

    days: lookback window (1=today, 7=last week, 30=last month, etc.)
    """
    if days == 1:
        stats = catalog_stats()
        count = stats.get("new_threats_today")
    else:
        count = threats_count_for_days(days)
    if count is None:
        raise HTTPException(status_code=503, detail="NVD unreachable — pulse unavailable.")
    return {"new_threats_count": count, "days": days, "source": "nvd"}


@app.get("/trends")
def trends(days: int = 30):
    """Time-series trend data for charts."""
    from oss_index import trends_data
    return trends_data(days)


_MAX_UPLOAD_BYTES = 512 * 1024  # 512 KB — large enough for any real dependency file


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    raw = await file.read()
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large ({len(raw) // 1024} KB). Maximum allowed is {_MAX_UPLOAD_BYTES // 1024} KB.",
        )
    content = raw.decode("utf-8", errors="replace")
    filename = file.filename or "unknown"

    deps = parse_dependencies(filename, content)
    if not deps:
        raise HTTPException(status_code=400, detail="No dependencies found in file. Supported: package.json, pom.xml, requirements.txt")

    # Intelligence analysis — local catalog + OSV.dev (batch)
    loop = asyncio.get_event_loop()
    packages = await loop.run_in_executor(None, analyze_packages_batch, deps)

    # Only synthesize non-green packages to save LLM calls + time
    risky = [p for p in packages if p["traffic_light"] != "GREEN"]
    safe = [p for p in packages if p["traffic_light"] == "GREEN"]

    if risky:
        risky = await synthesize_all(risky)
    for p in safe:
        p["narrative"] = "No known threats detected across OSV.dev and NVD public vulnerability data."

    all_packages = risky + safe
    all_packages.sort(key=lambda p: p["risk_score"], reverse=True)

    ns_clusters = detect_namespace_clusters(all_packages)

    summary = {
        "total": len(all_packages),
        "red": sum(1 for p in all_packages if p["traffic_light"] == "RED"),
        "yellow": sum(1 for p in all_packages if p["traffic_light"] == "YELLOW"),
        "green": sum(1 for p in all_packages if p["traffic_light"] == "GREEN"),
    }

    return {"packages": all_packages, "summary": summary, "filename": filename, "namespace_clusters": ns_clusters}


class ChatRequest(BaseModel):
    question: str
    report_context: str = ""


@app.post("/chat")
async def chat(req: ChatRequest):
    if not req.question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty.")
    answer = await chat_response(req.question, req.report_context, {})
    return {"answer": answer}


class LeadRequest(BaseModel):
    email: str
    company: str = ""
    packages_scanned: int = 0
    red_count: int = 0


@app.post("/api/lead")
def capture_lead(req: LeadRequest):
    leads_file = Path(__file__).parent / "leads.log"
    with open(leads_file, "a") as f:
        f.write(f"{date.today()},{req.email},{req.company},{req.packages_scanned} packages,{req.red_count} RED\n")
    log.info("Lead captured: %s / %s", req.email, req.company)
    return {"status": "ok", "message": "You're on the early access list!"}
