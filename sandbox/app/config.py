"""Konfiguracija izvrsnog okruzenja.

Sve vrijednosti mogu se nadjacati varijablama okruzenja, sto omogucuje da se
ista slika koristi za lokalni razvoj i za mjerenja na AWS-u bez izmjene koda.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
PROFILES_DIR = BASE_DIR / "profiles"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "da"}


@dataclass(frozen=True)
class Limits:
    """Ogranicenja resursa koja se primjenjuju na svako izvrsavanje."""

    memory_mb: int = _env_int("SBX_MEM_MB", 256)
    cpus: float = float(os.environ.get("SBX_CPUS", "0.5"))
    pids: int = _env_int("SBX_PIDS", 64)
    timeout_s: int = _env_int("SBX_TIMEOUT_S", 10)
    tmpfs_mb: int = _env_int("SBX_TMPFS_MB", 64)
    output_bytes: int = _env_int("SBX_OUTPUT_BYTES", 64_000)

    @property
    def nano_cpus(self) -> int:
        return int(self.cpus * 1_000_000_000)


@dataclass(frozen=True)
class Settings:
    """Postavke orkestratora."""

    # runc = obicno kontejnersko izvrsavanje, runsc = gVisor
    runtime: str = os.environ.get("SBX_RUNTIME", "runc")
    runner_image: str = os.environ.get("SBX_RUNNER_IMAGE", "sandbox-runner:latest")

    # mreza: "none" znaci potpuna izolacija, inace ime docker mreze s allowlistom
    network_mode: str = os.environ.get("SBX_NETWORK", "none")

    # seccomp profil; prazno = docker zadani profil (koristi se u kontrolnoj skupini)
    seccomp_profile: str = os.environ.get("SBX_SECCOMP", "seccomp-strict.json")

    read_only_rootfs: bool = _env_bool("SBX_READONLY", True)
    drop_all_caps: bool = _env_bool("SBX_DROP_CAPS", True)
    no_new_privileges: bool = _env_bool("SBX_NNP", True)

    # nobody:nogroup - izvrsavanje bez ovlasti nadkorisnika
    run_as: str = os.environ.get("SBX_USER", "65534:65534")

    audit_log: Path = Path(os.environ.get("SBX_AUDIT_LOG", "/var/log/sandbox/audit.jsonl"))
    limits: Limits = field(default_factory=Limits)

    ALLOWED_RUNTIMES = ("runc", "runsc")

    def validate(self) -> None:
        if self.runtime not in self.ALLOWED_RUNTIMES:
            raise ValueError(
                f"nepoznat runtime {self.runtime!r}; dopusteno: {self.ALLOWED_RUNTIMES}"
            )
        if self.seccomp_profile and not self.seccomp_path().exists():
            raise FileNotFoundError(f"seccomp profil nije pronaden: {self.seccomp_path()}")

    def seccomp_path(self) -> Path:
        return PROFILES_DIR / self.seccomp_profile

    def profile_name(self) -> str:
        """Kratka oznaka konfiguracije koja se biljezi uz svaki rezultat mjerenja."""
        parts = [self.runtime]
        parts.append("seccomp" if self.seccomp_profile else "seccomp-default")
        if self.read_only_rootfs:
            parts.append("ro")
        if self.drop_all_caps:
            parts.append("nocaps")
        parts.append(f"net-{self.network_mode}")
        return "+".join(parts)


settings = Settings()
