"""API sloj izoliranog izvrsnog okruzenja.

Izlaze jedno sucelje za izvrsavanje koda i dvije dijagnosticke tocke.
Sloj namjerno ne sadrzi nikakvu logiku izolacije: ona je u cijelosti u
orkestratoru (executor.py), pa se API moze zamijeniti bez utjecaja na
sigurnosna svojstva sustava.
"""
from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .audit import AuditLog
from .config import settings
from .executor import InfrastructureError, SandboxExecutor
from .models import ExecuteRequest, ExecuteResponse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("sandbox.api")

app = FastAPI(
    title="Izolirano izvrsno okruzenje za AI agente",
    description="Sucelje za izvrsavanje nepouzdanog koda u efemernom, ocvrsnutom kontejneru.",
    version="0.1.0",
)

_executor: SandboxExecutor | None = None
_audit = AuditLog(settings.audit_log)


def get_executor() -> SandboxExecutor:
    global _executor
    if _executor is None:
        _executor = SandboxExecutor(settings)
    return _executor


@app.on_event("startup")
def _startup() -> None:
    settings.validate()
    log.info("pokretanje, profil izolacije: %s", settings.profile_name())


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "runtime": settings.runtime, "profile": settings.profile_name()}


@app.get("/config")
def config() -> dict:
    """Djelatna konfiguracija; biljezi se uz rezultate mjerenja radi ponovljivosti."""
    limits = settings.limits
    return {
        "runtime": settings.runtime,
        "profile": settings.profile_name(),
        "seccomp": settings.seccomp_profile or "docker-default",
        "network_mode": settings.network_mode,
        "read_only_rootfs": settings.read_only_rootfs,
        "drop_all_caps": settings.drop_all_caps,
        "no_new_privileges": settings.no_new_privileges,
        "run_as": settings.run_as,
        "limits": {
            "memory_mb": limits.memory_mb,
            "cpus": limits.cpus,
            "pids": limits.pids,
            "timeout_s": limits.timeout_s,
            "tmpfs_mb": limits.tmpfs_mb,
        },
    }


@app.post("/execute", response_model=ExecuteResponse)
def execute(request: ExecuteRequest) -> ExecuteResponse:
    if not request.code.strip():
        raise HTTPException(status_code=400, detail="prazan kod")

    try:
        response = get_executor().execute(request.code, request.timeout_s)
    except InfrastructureError as exc:
        log.error("kvar orkestratora: %s", exc)
        raise HTTPException(status_code=503, detail=f"orkestrator nedostupan: {exc}") from exc

    _audit.record(response, label=request.label, code_len=len(request.code))
    log.info(
        "izvrseno %s label=%s verdict=%s mehanizam=%s trajanje=%dms",
        response.execution_id, request.label, response.verdict.value,
        response.mechanism.value, response.duration_ms,
    )
    return response


@app.exception_handler(Exception)
def _unhandled(_, exc: Exception) -> JSONResponse:
    log.exception("neobradena iznimka")
    return JSONResponse(status_code=500, content={"detail": "unutarnja pogreska"})
