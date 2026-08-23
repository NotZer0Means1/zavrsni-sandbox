"""Klijent prema izoliranom izvrsnom okruzenju.

Agent nema drugog nacina izvrsavanja koda osim ovog klijenta. Time je osigurano
da sav kod koji agent proizvede prolazi kroz sandbox, a ne kroz stroj domacina.
Ovo je kljucna sigurnosna pretpostavka cijelog sustava: agent je nepouzdan i ne
smije imati izravan pristup izvrsavanju.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

import requests


@dataclass
class SandboxResult:
    verdict: str
    mechanism: str
    stdout: str
    stderr: str
    duration_ms: int

    @property
    def blocked(self) -> bool:
        return self.verdict in {"blocked", "timeout", "oom"} or (
            self.verdict == "error" and self.mechanism != "none"
        )


class SandboxClient:
    def __init__(self, base_url: str | None = None):
        self.base_url = base_url or os.environ.get("SANDBOX_API", "http://127.0.0.1:8000")

    def run(self, code: str, label: str | None = None) -> SandboxResult:
        r = requests.post(
            f"{self.base_url}/execute",
            json={"code": code, "label": label},
            timeout=180,
        )
        r.raise_for_status()
        b = r.json()
        return SandboxResult(
            verdict=b.get("verdict", "infra_error"),
            mechanism=b.get("mechanism", "none"),
            stdout=b.get("stdout", ""),
            stderr=b.get("stderr", ""),
            duration_ms=b.get("duration_ms", 0),
        )
