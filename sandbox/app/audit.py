"""Revizijski zapis izvrsavanja.

Svako izvrsavanje zapisuje se kao jedan redak u JSONL datoteci. Format je
odabran tako da se zapisi mogu izravno ucitati u analizu rezultata
(pandas.read_json(..., lines=True)) bez naknadne obrade.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import ExecuteResponse

log = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self._fallback = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            log.warning("revizijski zapis nije dostupan (%s), pise se na stderr", exc)
            self._fallback = True

    def record(self, response: ExecuteResponse, label: Optional[str] = None,
               code_len: int = 0) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "execution_id": response.execution_id,
            "label": label,
            "runtime": response.runtime,
            "profile": response.profile,
            "verdict": response.verdict.value,
            "mechanism": response.mechanism.value,
            "exit_code": response.exit_code,
            "duration_ms": response.duration_ms,
            "startup_ms": response.startup_ms,
            "code_len": code_len,
            # Sam kod se ne zapisuje: testni skup sadrzi maliciozne skripte i
            # ne smije se nekontrolirano umnazati kroz zapise.
            "stderr_head": response.stderr[:400],
        }
        line = json.dumps(entry, ensure_ascii=False)
        if self._fallback:
            print(line, file=sys.stderr, flush=True)
            return
        try:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + os.linesep)
        except OSError as exc:
            log.warning("zapis nije uspio: %s", exc)
            print(line, file=sys.stderr, flush=True)
