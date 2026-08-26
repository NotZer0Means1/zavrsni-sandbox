#!/usr/bin/env python3
"""Prilagodnik za RedCode benchmark.

RedCode (Guo et al., 2024) javno je mjerilo rizicnog izvrsavanja i generiranja
koda za kodne agente. Ovaj prilagodnik ucitava RedCode-Exec testne slucajeve i
provlaci ih kroz isto izvrsno okruzenje kao i vlastiti skup, cime se rezultati
ovog rada cine usporedivima s literaturom.

RedCode se ne ukljucuje u repozitorij zbog velicine i licencije; preuzima se
zasebno:
    git clone https://github.com/AI-secure/RedCode tests/redcode/RedCode

Ocekivani format ulaza je JSONL s poljima koja sadrze isjecak koda; buduci da se
struktura RedCode skupa s vremenom mijenja, ucitavanje je namjerno tolerantno i
trazi kod u nekoliko mogucih polja.

Pokretanje:
    python3 redcode_adapter.py --api http://127.0.0.1:8000 \
        --dataset tests/redcode/RedCode/dataset/RedCode-Exec --limit 100
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests

CODE_FIELDS = ("Code", "code", "script", "prompt_code", "input", "content")


def extract_code(obj: dict) -> str | None:
    for f in CODE_FIELDS:
        v = obj.get(f)
        if isinstance(v, str) and v.strip():
            return v
    return None


def load_dataset(path: Path, limit: int) -> list[dict]:
    cases: list[dict] = []
    files = sorted(path.rglob("*.json")) + sorted(path.rglob("*.jsonl"))
    for f in files:
        try:
            if f.suffix == ".jsonl":
                objs = [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
            else:
                loaded = json.loads(f.read_text(encoding="utf-8"))
                objs = loaded if isinstance(loaded, list) else [loaded]
        except (json.JSONDecodeError, OSError):
            continue
        for i, obj in enumerate(objs):
            if not isinstance(obj, dict):
                continue
            code = extract_code(obj)
            if code:
                idx = obj.get("Index") or obj.get("index") or ""
                cat = obj.get("category") or (str(idx).split("_")[0] if idx else f.parent.name)
                cases.append({"id": f"{obj.get('Index', f'{f.stem}-{i}')}", "code": code,
                              "category": cat})
            if len(cases) >= limit:
                return cases
    return cases


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--dataset", type=Path, required=True)
    ap.add_argument("--limit", type=int, default=100)
    ap.add_argument("--out", type=Path, default=Path("redcode-rezultati.jsonl"))
    args = ap.parse_args()

    if not args.dataset.exists():
        print(f"RedCode skup nije pronaden u {args.dataset}.\n"
              f"Preuzeti: git clone https://github.com/AI-secure/RedCode", file=sys.stderr)
        return 2

    cases = load_dataset(args.dataset, args.limit)
    if not cases:
        print("nije pronaden nijedan iskoristiv testni slucaj", file=sys.stderr)
        return 1

    try:
        cfg = requests.get(f"{args.api}/config", timeout=10).json()
    except requests.RequestException as exc:
        print(f"API nije dostupan: {exc}", file=sys.stderr)
        return 2

    print(f"RedCode: {len(cases)} slucajeva  |  profil {cfg.get('profile')}\n")

    blocked = executed = errors = 0
    with args.out.open("w", encoding="utf-8") as fh:
        for c in cases:
            try:
                r = requests.post(f"{args.api}/execute",
                                  json={"code": c["code"], "label": f"redcode-{c['id']}"},
                                  timeout=180)
                body = r.json()
            except requests.RequestException as exc:
                errors += 1
                body = {"verdict": "infra_error", "detail": str(exc)}

            verdict = body.get("verdict")
            is_blocked = verdict in {"blocked", "timeout", "oom"} or (
                verdict == "error" and body.get("mechanism") != "none")
            if is_blocked:
                blocked += 1
            elif verdict == "ok":
                executed += 1

            fh.write(json.dumps({
                "id": c["id"], "category": c["category"],
                "verdict": verdict, "mechanism": body.get("mechanism"),
                "profile": cfg.get("profile"),
            }, ensure_ascii=False) + "\n")

    n = len(cases)
    print(f"zaustavljeno: {blocked}/{n} ({100*blocked//n} %)")
    print(f"izvrseno do kraja: {executed}/{n}")
    if errors:
        print(f"kvarova: {errors}")
    print(f"\nrezultat u {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
