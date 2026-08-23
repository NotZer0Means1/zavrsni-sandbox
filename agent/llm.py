"""Sucelje prema jezicnom modelu s tri nacina rada.

Problem ponovljivosti: ako model pozivamo uzivo pri svakom pokretanju, svako
mjerenje daje drukcije rezultate i pokus nije ponovljiv. Rjesenje je obrazac
snimanja i reprodukcije (engl. record and replay):

  live    - poziva stvarni model, nista se ne biljezi
  record  - poziva stvarni model i sprema odgovore u "kasetu" (JSON datoteka)
  replay  - ne poziva model, nego cita odgovore iz kasete

Mjerenja u radu provode se u nacinu replay nad kasetom snimljenom jednom, cime
su rezultati u cijelosti ponovljivi i ne ovise o dostupnosti modela ni o
nedeterminizmu uzorkovanja.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import requests


@dataclass
class Message:
    role: str          # "system", "user" ili "assistant"
    content: str

    def as_dict(self) -> dict:
        return {"role": self.role, "content": self.content}


class CassetteMiss(RuntimeError):
    """Trazeni poziv nije pronaden u kaseti."""


def _key(messages: List[Message], model: str, temperature: float) -> str:
    """Determinirani kljuc poziva. Ista povijest razgovora daje isti kljuc."""
    payload = json.dumps(
        {"model": model, "temperature": temperature,
         "messages": [m.as_dict() for m in messages]},
        ensure_ascii=False, sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _default_model() -> str:
    """Zadani model ovisi o pruzatelju: OpenAI ili lokalna Ollama."""
    if os.environ.get("AGENT_MODEL"):
        return os.environ["AGENT_MODEL"]
    # Zadano llama3.1 (8B) jer stane u 8 GB RAM-a instance m7i.large i daje
    # kvalitetniji kod od manjih modela. Na manjoj instanci uzeti llama3.2:3b ili 1b.
    return "llama3.1" if os.environ.get("AGENT_PROVIDER") == "ollama" else "gpt-4o-mini"


def _default_api_base() -> str:
    if os.environ.get("AGENT_API_BASE"):
        return os.environ["AGENT_API_BASE"]
    # Ollama nudi sucelje uskladeno s OpenAI-jem na /v1
    if os.environ.get("AGENT_PROVIDER") == "ollama":
        return os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434") + "/v1"
    return "https://api.openai.com/v1"


@dataclass
class LLMClient:
    """Klijent jezicnog modela s podrskom za snimanje i reprodukciju.

    Podrzava dva pruzatelja, izabrana varijablom AGENT_PROVIDER:
      openai  - zahtijeva AGENT_API_KEY, placa se po pozivu (zadano)
      ollama  - lokalni model, bez kljuca i bez troska
    """

    provider: str = field(default_factory=lambda: os.environ.get("AGENT_PROVIDER", "openai"))
    mode: str = field(default_factory=lambda: os.environ.get("AGENT_LLM_MODE", "replay"))
    model: str = field(default_factory=_default_model)
    temperature: float = field(default_factory=lambda: float(os.environ.get("AGENT_TEMP", "0")))
    cassette_path: Path = field(
        default_factory=lambda: Path(os.environ.get("AGENT_CASSETTE", "agent/cassettes/default.json"))
    )
    api_base: str = field(default_factory=_default_api_base)
    api_key: Optional[str] = field(default_factory=lambda: os.environ.get("AGENT_API_KEY"))

    _cassette: dict = field(default_factory=dict, init=False)
    _dirty: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.mode not in {"live", "record", "replay"}:
            raise ValueError(f"nepoznat nacin rada: {self.mode}")
        if self.provider not in {"openai", "ollama"}:
            raise ValueError(f"nepoznat pruzatelj: {self.provider}")
        if self.mode in {"replay", "record"} and self.cassette_path.exists():
            self._cassette = json.loads(self.cassette_path.read_text(encoding="utf-8"))
        # Ollama ne treba kljuc; OpenAI ga zahtijeva za stvarni poziv.
        if self.mode in {"live", "record"} and self.provider == "openai" and not self.api_key:
            raise ValueError("AGENT_API_KEY nije postavljen, a pruzatelj openai zahtijeva kljuc")

    # ------------------------------------------------------------------ javno
    def complete(self, messages: List[Message]) -> str:
        k = _key(messages, self.model, self.temperature)

        if self.mode == "replay":
            if k not in self._cassette:
                raise CassetteMiss(
                    f"poziv {k} nije u kaseti {self.cassette_path}. "
                    f"Snimiti ga s AGENT_LLM_MODE=record."
                )
            return self._cassette[k]["response"]

        if self.mode == "record" and k in self._cassette:
            return self._cassette[k]["response"]

        response = self._call_api(messages)

        if self.mode == "record":
            self._cassette[k] = {
                "model": self.model,
                "temperature": self.temperature,
                "messages": [m.as_dict() for m in messages],
                "response": response,
            }
            self._dirty = True
            self.save()
        return response

    def save(self) -> None:
        if not self._dirty:
            return
        self.cassette_path.parent.mkdir(parents=True, exist_ok=True)
        self.cassette_path.write_text(
            json.dumps(self._cassette, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        self._dirty = False

    # ---------------------------------------------------------------- interno
    def _call_api(self, messages: List[Message]) -> str:
        """Poziv sucelja usklađenog s OpenAI Chat Completions.

        Isto sucelje koristi i OpenAI i Ollama (preko /v1), pa se kod poziva ne
        razlikuje osim po zaglavlju s kljucem koje Ollama ne trazi.
        """
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        # Ollama ucitava model tromo, pa prvi poziv zna potrajati.
        timeout = 600 if self.provider == "ollama" else 120
        r = requests.post(
            f"{self.api_base}/chat/completions",
            headers=headers,
            json={
                "model": self.model,
                "temperature": self.temperature,
                "messages": [m.as_dict() for m in messages],
            },
            timeout=timeout,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
