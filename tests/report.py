#!/usr/bin/env python3
"""Sazima rezultate u tablice spremne za rad (poglavlje 4.6).

Cita corpus-*.jsonl i benchmark-*.json iz zadanog direktorija i ispisuje:￼
  * tablicu otpornosti po scenariju i razini izolacije (tablica 4.1)
  * tablicu performansi po razini izolacije (tablica 4.2)
  * podatke za graf vremena pokretanja (CSV za umetanje)

Pokretanje:
    python3 report.py results/
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path


def load_corpus(results: Path) -> dict:
    data = {}
    for f in sorted(results.glob("corpus-*.jsonl")):
        name = f.stem.replace("corpus-", "")
        rows = [json.loads(l) for l in f.read_text(encoding="utf-8").splitlines() if l.strip()]
        data[name] = rows
    return data


def load_bench(results: Path) -> dict:
    data = {}
    for f in sorted(results.glob("benchmark-*.json")):
        name = f.stem.replace("benchmark-", "")
        data[name] = json.loads(f.read_text(encoding="utf-8"))
    return data


def resilience_table(corpus: dict) -> None:
    print("\n### Tablica 4.1 – otpornost po scenariju\n")
    profiles = list(corpus.keys())
    scen_names = {
        "S1": "Bijeg iz izolacije", "S2": "Pristup datotečnom sustavu",
        "S3": "Mrežna eksfiltracija", "S4": "Iscrpljivanje resursa",
        "S5": "Perzistencija i lateralno kretanje", "C": "Kontrolni slučajevi",
    }
    header = f"{'Scenarij':<34}" + "".join(f"{p:>18}" for p in profiles)
    print(header)
    print("-" * len(header))
    for scen in ["S1", "S2", "S3", "S4", "S5", "C"]:
        row = f"{scen + ' ' + scen_names[scen]:<34}"
        for p in profiles:
            rows = [r for r in corpus[p] if r["scenario"] == scen]
            if scen == "C":
                ok = sum(1 for r in rows if r["outcome"] == "PASS_ALLOWED")
                row += f"{f'{ok}/{len(rows)} ok':>18}"
            else:
                stopped = sum(1 for r in rows if r["outcome"] in ("PASS_BLOCKED", "MECH_MISMATCH"))
                row += f"{f'{stopped}/{len(rows)}':>18}"
        print(row)

    # ukupno zaustavljeno
    print("-" * len(header))
    total = f"{'Ukupno zaustavljeno napada':<34}"
    for p in profiles:
        atk = [r for r in corpus[p] if r["expect_blocked"]]
        stp = sum(1 for r in atk if r["outcome"] in ("PASS_BLOCKED", "MECH_MISMATCH"))
        total += f"{f'{stp}/{len(atk)}':>18}"
    print(total)

    # proboji
    leaks = {p: [r["id"] for r in corpus[p] if r["outcome"] == "FAIL_LEAK"] for p in profiles}
    for p, ids in leaks.items():
        if ids:
            print(f"\n  PROBOJI ({p}): {', '.join(ids)}")


def mechanism_table(corpus: dict) -> None:
    print("\n### Mehanizmi koji su zaustavili napade (IP2)\n")
    for p, rows in corpus.items():
        print(f"  [{p}]")
        by_mech = defaultdict(list)
        for r in rows:
            if r["expect_blocked"] and r["outcome"] in ("PASS_BLOCKED", "MECH_MISMATCH"):
                by_mech[r.get("observed_mechanism")].append(r["id"])
        for mech, ids in sorted(by_mech.items(), key=lambda x: -len(x[1])):
            print(f"    {mech:<18} {len(ids):>2}  ({', '.join(ids)})")
        print()


def performance_table(bench: dict) -> None:
    print("\n### Tablica 4.2 – performanse po razini izolacije\n")
    header = f"{'Mjera':<22}" + "".join(f"{p:>18}" for p in bench)
    print(header)
    print("-" * len(header))

    def get(b, metric, field):
        for r in b["latency"]:
            if r["metric"] == metric:
                return r.get(field)
        return None

    for metric, label in [("startup_ms", "Vrijeme pokretanja (ms)"),
                          ("duration_ms", "Ukupno trajanje (ms)")]:
        for field, suf in [("median", " – medijan"), ("p95", " – p95")]:
            row = f"{label + suf:<22}"
            for p in bench:
                row += f"{str(get(bench[p], metric, field)):>18}"
            print(row)
    row = f"{'Propusnost (izvr./s)':<22}"
    for p in bench:
        row += f"{str(bench[p].get('throughput_per_s')):>18}"
    print(row)

    # relativni trosak gVisora u odnosu na runc
    if "runc-hardened" in bench and "gvisor" in bench:
        r_med = get(bench["runc-hardened"], "startup_ms", "median")
        g_med = get(bench["gvisor"], "startup_ms", "median")
        if r_med and g_med:
            print(f"\n  gVisor pokretanje sporije {g_med / r_med:.2f}x od runc")


def main() -> int:
    if len(sys.argv) < 2:
        print("uporaba: report.py <direktorij_s_rezultatima>", file=sys.stderr)
        return 2
    results = Path(sys.argv[1])
    corpus = load_corpus(results)
    bench = load_bench(results)

    if not corpus and not bench:
        print("nema rezultata u", results, file=sys.stderr)
        return 1

    print("=" * 60)
    print("SAŽETAK REZULTATA VREDNOVANJA")
    print("=" * 60)
    if corpus:
        resilience_table(corpus)
        mechanism_table(corpus)
    if bench:
        performance_table(bench)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
