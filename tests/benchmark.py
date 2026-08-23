#!/usr/bin/env python3
"""Mjerenje performansi izvrsnog okruzenja.

Mjeri tri velicine za svaku razinu izolacije, nad istim skupom zadataka:

  * vrijeme pokretanja (startup_ms) - od pokretanja kontejnera do pocetka izvrsavanja
  * ukupno trajanje (duration_ms)   - od zahtjeva do rezultata
  * propusnost                      - broj izvrsavanja u sekundi pri zadanoj paralelnosti

Obrazac opterecenja odgovara agentskom: mnogo kratkih, medusobno neovisnih
izvrsavanja, kod kojih vrijeme pokretanja cini najveci dio ukupnog trajanja.
Zato se posebno izvjestava o startup_ms, koji je za ovaj slucaj mjerodavniji od
propusnosti na dugotrajnom opterecenju.

Pokretanje:
    python3 benchmark.py --api http://127.0.0.1:8000 --iterations 50 --concurrency 4
"""
from __future__ import annotations

import argparse
import json
import statistics as st
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests

# Referentni zadatak: kratak, deterministican, bez mrezne ili disk aktivnosti,
# kako bi se mjerila cijena samog okruzenja, a ne posla.
BENCH_CODE = "s=0\nfor i in range(50000):\n    s+=i*i\nprint(s)\n"


def percentile(xs: list[float], p: float) -> float:
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def one_call(api: str) -> dict | None:
    t0 = time.perf_counter()
    try:
        r = requests.post(f"{api}/execute", json={"code": BENCH_CODE, "label": "bench"}, timeout=180)
        r.raise_for_status()
        body = r.json()
        body["wall_ms"] = (time.perf_counter() - t0) * 1000
        return body
    except requests.RequestException as exc:
        print(f"  poziv nije uspio: {exc}", file=sys.stderr)
        return None


def measure_latency(api: str, iterations: int) -> dict:
    startups, durations, walls = [], [], []
    # zagrijavanje: prvi poziv povlaci sliku i puni predmemoriju, ne mjeri se
    one_call(api)
    for _ in range(iterations):
        b = one_call(api)
        if not b:
            continue
        startups.append(b.get("startup_ms", 0))
        durations.append(b.get("duration_ms", 0))
        walls.append(b.get("wall_ms", 0))
    return {"startup": startups, "duration": durations, "wall": walls}


def measure_throughput(api: str, iterations: int, concurrency: int) -> float:
    t0 = time.perf_counter()
    done = 0
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = [ex.submit(one_call, api) for _ in range(iterations)]
        for f in as_completed(futs):
            if f.result():
                done += 1
    elapsed = time.perf_counter() - t0
    return done / elapsed if elapsed else 0.0


def summarize(name: str, xs: list[float]) -> dict:
    if not xs:
        return {"metric": name, "n": 0}
    return {
        "metric": name,
        "n": len(xs),
        "min": round(min(xs), 1),
        "median": round(st.median(xs), 1),
        "mean": round(st.mean(xs), 1),
        "p95": round(percentile(xs, 0.95), 1),
        "max": round(max(xs), 1),
        "stdev": round(st.pstdev(xs), 1),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--iterations", type=int, default=50)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--out", type=Path, default=Path("benchmark.json"))
    args = ap.parse_args()

    try:
        cfg = requests.get(f"{args.api}/config", timeout=10).json()
    except requests.RequestException as exc:
        print(f"API nije dostupan: {exc}", file=sys.stderr)
        return 2

    profile = cfg.get("profile")
    print(f"profil: {profile}  |  {args.iterations} iteracija, paralelnost {args.concurrency}\n")

    lat = measure_latency(args.api, args.iterations)
    tput = measure_throughput(args.api, args.iterations, args.concurrency)

    rows = [summarize("startup_ms", lat["startup"]),
            summarize("duration_ms", lat["duration"]),
            summarize("wall_ms", lat["wall"])]

    print(f"{'mjera':<14}{'medijan':>10}{'p95':>10}{'sr.vr.':>10}{'std':>10}")
    for r in rows:
        if r.get("n"):
            print(f"{r['metric']:<14}{r['median']:>10}{r['p95']:>10}{r['mean']:>10}{r['stdev']:>10}")
    print(f"\npropusnost: {tput:.1f} izvrsavanja/s  (paralelnost {args.concurrency})")

    result = {
        "profile": profile,
        "runtime": cfg.get("runtime"),
        "config": cfg,
        "iterations": args.iterations,
        "concurrency": args.concurrency,
        "latency": rows,
        "throughput_per_s": round(tput, 2),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with args.out.open("w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print(f"\nrezultat spremljen u {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
