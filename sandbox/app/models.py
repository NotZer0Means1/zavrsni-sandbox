"""Podatkovni modeli zahtjeva i odgovora."""
from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Verdict(str, Enum):
    """Ishod izvrsavanja s gledista sigurnosnog vrednovanja."""

    OK = "ok"                      # kod se izvrsio do kraja
    ERROR = "error"                # kod je zavrsio s pogreskom
    TIMEOUT = "timeout"            # prekoraceno vrijeme izvrsavanja
    OOM = "oom"                    # prekoracena memorija, jezgra je ubila proces
    BLOCKED = "blocked"            # radnju je zaustavio mehanizam izolacije
    INFRA_ERROR = "infra_error"    # kvar samog sustava, ne i koda


class Mechanism(str, Enum):
    """Mehanizam koji je zaustavio radnju. Sluzi za odgovor na IP2."""

    SECCOMP = "seccomp"
    CAPABILITIES = "capabilities"
    READ_ONLY_FS = "read_only_fs"
    CGROUPS_MEMORY = "cgroups_memory"
    CGROUPS_PIDS = "cgroups_pids"
    NETWORK_POLICY = "network_policy"
    TIMEOUT = "timeout"
    NAMESPACE = "namespace"
    RUNTIME_KERNEL = "runtime_kernel"   # gVisor Sentry je odbio poziv
    NONE = "none"                       # nista nije zaustavilo radnju


class ExecuteRequest(BaseModel):
    code: str = Field(..., description="Python kod koji agent zeli izvrsiti")
    timeout_s: Optional[int] = Field(None, ge=1, le=120)
    label: Optional[str] = Field(None, description="Oznaka testnog slucaja, npr. S3-02")


class ExecuteResponse(BaseModel):
    verdict: Verdict
    mechanism: Mechanism
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_ms: int
    startup_ms: int
    runtime: str
    profile: str
    execution_id: str
