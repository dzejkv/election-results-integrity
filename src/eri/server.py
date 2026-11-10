"""HTTP API and public dashboard.

Run with:  uvicorn --factory eri.server:create_app
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .config import Election, Settings, load_registry
from .metrics import Metrics
from .models import Envelope
from .service import ResultService
from .store import Store

STATIC_DIR = Path(__file__).parent / "static"

# Strict CSP for the public pages: no inline scripts, no third-party origins.
DASHBOARD_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    election = Election.load(settings.election_path)
    registry = load_registry(settings.registry_path)
    store = Store(settings.db_path)
    metrics = Metrics()
    service = ResultService(election, registry, store, metrics, settings)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        store.close()

    app = FastAPI(
        lifespan=lifespan,
        title="Election Results Integrity (fictional demo)",
        version=__version__,
        description="Signed result intake, reconciliation, tamper-evident audit log.",
    )
    app.state.service = service
    logging.getLogger("eri").info(
        "loaded election %s with %d stations and %d provisioned devices",
        election.election_id, len(election.stations), len(registry),
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        path = request.url.path
        if path == "/" or path.startswith("/static/"):
            response.headers["Content-Security-Policy"] = DASHBOARD_CSP
        if path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        if request.url.path == "/api/results":
            client = request.client.host if request.client else None
            service.record_malformed_request(client, len(exc.errors()))
        return JSONResponse(
            status_code=422,
            content={"status": "rejected", "reason": "rejected_malformed",
                     "message": "request body is not a valid envelope"},
        )

    # ---- intake ----

    @app.post("/api/results", tags=["intake"])
    def submit_result(envelope: Envelope, request: Request):
        client = request.client.host if request.client else None
        outcome = service.submit(envelope, client)
        return JSONResponse(status_code=outcome.status_code, content=outcome.body())

    # ---- public read API ----

    @app.get("/api/election", tags=["public"])
    def election_info():
        return election.public_view()

    @app.get("/api/totals", tags=["public"])
    def totals():
        return service.totals()

    @app.get("/api/stations", tags=["public"])
    def stations():
        return service.stations()

    @app.get("/api/audit/verify", tags=["public"])
    def audit_verify(expect_head: str | None = Query(default=None, pattern=r"^[0-9a-f]{64}$")):
        return service.verify_audit(expect_head).as_dict()

    # ---- operations ----

    @app.get("/healthz", tags=["ops"])
    def healthz():
        return {"status": "ok"}

    @app.get("/metrics", tags=["ops"], response_class=PlainTextResponse)
    def prometheus_metrics():
        t = service.totals()
        audit = service.verify_audit()
        return metrics.render({
            "eri_stations_total": ("Polling stations in this election.", t["stations_total"]),
            "eri_stations_reporting": ("Stations with an accepted result.", t["stations_reporting"]),
            "eri_results_under_review": ("Results waiting for human review.", t["results_under_review"]),
            "eri_devices_provisioned": ("Devices in the trusted registry.", len(registry)),
            "eri_audit_entries": ("Entries in the audit log.", audit.entries),
            "eri_audit_chain_valid": ("1 if the audit hash chain verifies, else 0.", 1 if audit.ok else 0),
        })

    # ---- dashboard ----

    @app.get("/", include_in_schema=False)
    def dashboard():
        return FileResponse(STATIC_DIR / "dashboard.html")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app
