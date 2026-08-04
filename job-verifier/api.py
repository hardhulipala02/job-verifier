"""Async FastAPI backend for the Job Scam Intelligence Network.

Front-ends:
  * a friendly web UI served at ``/`` (paste/upload an email -> readable report),
  * a Chrome extension that POSTs page text to ``/analyze/message``.

Endpoints:
  * ``GET  /health``          — liveness + which optional integrations are enabled.
  * ``POST /analyze``         — analyze a raw email string (JSON body).
  * ``POST /analyze/upload``  — analyze an uploaded ``.eml`` file (multipart).
  * ``POST /analyze/message`` — analyze a platform message (LinkedIn DM, etc.).

The heavy pipeline is synchronous and may do network I/O, so it runs in a worker
thread to keep the event loop async.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

import config
from main_graph import analyze_email, analyze_message
from schemas import ScamReport

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = FastAPI(
    title="Job Scam Intelligence Network",
    description="Detect malicious recruiter outreach from raw emails.",
    version="1.0.0",
)

# Allow the Chrome extension (and the local web UI) to call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class AnalyzeRequest(BaseModel):
    raw_email: str
    persist: bool = True
    use_llm: bool | None = None
    resolve_dns: bool = True


class MessageRequest(BaseModel):
    text: str
    sender_name: str | None = None
    platform: str | None = None
    persist: bool = True
    use_llm: bool | None = None


class HealthResponse(BaseModel):
    status: str = "ok"
    llm_enabled: bool
    neo4j_enabled: bool


@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        llm_enabled=config.llm_enabled(),
        neo4j_enabled=config.neo4j_enabled(),
    )


@app.post("/analyze", response_model=ScamReport)
async def analyze(request: AnalyzeRequest) -> ScamReport:
    if not request.raw_email.strip():
        raise HTTPException(status_code=400, detail="raw_email must not be empty")
    return await run_in_threadpool(
        analyze_email,
        request.raw_email,
        use_llm=request.use_llm,
        persist=request.persist,
        resolve_dns=request.resolve_dns,
    )


@app.post("/analyze/upload", response_model=ScamReport)
async def analyze_upload(
    file: UploadFile = File(...),
    persist: bool = True,
    use_llm: bool | None = None,
    resolve_dns: bool = True,
) -> ScamReport:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    return await run_in_threadpool(
        analyze_email,
        raw,
        use_llm=use_llm,
        persist=persist,
        resolve_dns=resolve_dns,
    )


@app.post("/analyze/message", response_model=ScamReport)
async def analyze_platform_message(request: MessageRequest) -> ScamReport:
    if not request.text.strip():
        raise HTTPException(status_code=400, detail="text must not be empty")
    return await run_in_threadpool(
        analyze_message,
        request.text,
        sender_name=request.sender_name,
        platform=request.platform,
        use_llm=request.use_llm,
        persist=request.persist,
    )


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# Serve the web UI assets (CSS/JS) under /static.
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
