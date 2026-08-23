#!/usr/bin/env python3
"""Ispitni okvir: izvrsava cijeli testni skup i biljezi rezultate.

Za svaki testni slucaj poziva izvrsno okruzenje i usporeduje stvarni ishod s
ocekivanim. Rezultat svakog slucaja je jedno od:

  PASS_BLOCKED   - napad je ocekivano zaustavljen
  PASS_ALLOWED   - kontrolni slucaj se ocekivano izvrsio
  FAIL_LEAK      - napad NIJE zaustavljen (izolacija probijena) - kriticno
  FAIL_CONTROL   - dobrocudan kod je pogresno zaustavljen (prestroga izolacija)
  MECH_MISMATCH  - napad zaustavljen, ali drugim mehanizmom nego ocekivanim

Pokretanje:
    python3 run_corpus.py --api http://127.0.0.1:8000 --repeat 5 --out rezultati.jsonl

Rezultat se sprema u JSONL i ispisuje kao sazetak po scenariju. Svaki se slucaj
ponavlja vise puta, a mjerodavnim se uzima najlosiji ishod jer je u sigurnosnom
vrednovanju dovoljan jedan uspjesan napad da bi se izolacija smatrala probijenom.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from corpus.cases import CASES, AttackCase  # noqa: E402

# Rangiranje ishoda po ozbiljnosti; "najlosiji" je onaj s najvecim rangom.
SEVERITY = {
    "PASS_ALLOWED": 0,
    "PASS_BLOCKED": 0,
    "MECH_MISMATCH": 1,
    "FAIL_CONTROL": 2,
    "FAIL_LEAK": 3,
    "INFRA_ERROR": 4,
}


def evaluate(case: AttackCase, resp: dict) -> str:
    verdict = resp.get("verdict")
    mechanism = resp.get("mechanism")

    if verdict == "infra_error":
        return "INFRA_ERROR"

    # Napad se smatra zaustavljenim ako okruzenje nije izvrsilo kod do kraja.
    blocked = verdict in {"blocked", "timeout", "oom"} or (
        verdict == "error" and mechanism != "none"
    )

    if case.expect_blocked:
        if not blocked:
            return "FAIL_LEAK"
        if case.expected_mechanism and case.expected_mechanism != "none" \
                and mechanism != case.expected_mechanism:
            return "MECH_MISMATCH"
        return "PASS_BLOCKED"
    else:
        return "PASS_ALLOWED" if verdict in {"ok"} else "FAIL_CONTROL"


def worst(outcomes: list[str]) -> str:
    return max(outcomes, key=lambda o: SEVERITY.get(o, 0))


def run_case(api: str, case: AttackCase, repeat: int) -> dict:
    outcomes, mechs, durations, startups = [], [], [], []
    last = {}
    for _ in range(repeat):
        try:
            r = requests.post(
                f"{api}/execute",
                json={"code": case.code, "label": case.id},
                timeout=180,
            )
            r.raise_for_status()
            last = r.json()
        except requests.RequestException as exc:
            last = {"verdict": "infra_error", "mechanism": "none", "detail": str(exc)}
        outcomes.append(evaluate(case, last))
        mechs.append(last.get("mechanism"))
        durations.append(last.get("duration_ms"))
        startups.append(last.get("startup_ms"))

    return {
        "id": case.id,
        "scenario": case.scenario,
        "title": case.title,
        "expect_blocked": case.expect_blocked,
        "expected_mechanism": case.expected_mechanism,
        "outcome": worst(outcomes),
        "observed_mechanism": Counter(m for m in mechs if m).most_common(1)[0][0] if any(mechs) else None,
        "runtime": last.get("runtime"),
        "profile": last.get("profile"),
        "repeat": repeat,
        "duration_ms_med": _median(durations),
        "startup_ms_med": _median(startups),
    }


def _median(xs: list) -> float | None:
    vals = sorted(v for v in xs if isinstance(v, (int, float)))
    if not vals:
        return None
    n = len(vals)
    return vals[n // 2] if n % 2 else (vals[n // 2 - 1] + vals[n // 2]) / 2


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--out", type=Path, default=Path("rezultati.jsonl"))
    args = ap.parse_args()

    try:
        cfg = requests.get(f"{args.api}/config", timeout=10).json()
    except requests.RequestException as exc:
        print(f"API nije dostupan na {args.api}: {exc}", file=sys.stderr)
        return 2

    print(f"profil izolacije: {cfg.get('profile')}  |  {len(CASES)} slucajeva x {args.repeat}\n")

    rows = []
    with args.out.open("w", encoding="utf-8") as fh:
        for case in CASES:
            row = run_case(args.api, case, args.repeat)
            rows.append(row)
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
            mark = {"PASS_BLOCKED": "✓", "PASS_ALLOWED": "✓", "MECH_MISMATCH": "≈",
                    "FAIL_LEAK": "✗ PROBOJ", "FAIL_CONTROL": "✗ prestrogo",
                    "INFRA_ERROR": "! kvar"}[row["outcome"]]
            print(f"  {case.id:<7} {case.title:<44} {mark} "
                  f"({row['observed_mechanism']}, {row['duration_ms_med']} ms)")

    _summary(rows, cfg)
    leaks = [r for r in rows if r["outcome"] == "FAIL_LEAK"]
    return 1 if leaks else 0


def _summary(rows: list, cfg: dict) -> None:
    print("\n" + "=" * 60)
    print(f"SAZETAK  ({cfg.get('profile')})")
    by = Counter(r["outcome"] for r in rows)
    for k in ("PASS_BLOCKED", "PASS_ALLOWED", "MECH_MISMATCH", "FAIL_LEAK",
              "FAIL_CONTROL", "INFRA_ERROR"):
        if by.get(k):
            print(f"  {k:<16} {by[k]}")
    attacks = [r for r in rows if r["expect_blocked"]]
    stopped = [r for r in attacks if r["outcome"] in ("PASS_BLOCKED", "MECH_MISMATCH")]
    if attacks:
        print(f"\n  zaustavljeno napada: {len(stopped)}/{len(attacks)} "
              f"({100*len(stopped)//len(attacks)} %)")


if __name__ == "__main__":
    raise SystemExit(main())
