#!/usr/bin/env bash
# Pokrece cijelo vrednovanje za obje razine izolacije (runc i gVisor) i sprema
# rezultate razvrstane po profilu. Pretpostavlja da je slika izvrsnog okruzenja
# vec izgradena (docker build -f Dockerfile.runner -t sandbox-runner:latest .).
#
# Za svaku razinu izolacije: pokrece API, ceka spremnost, izvrsi testni skup i
# mjerenje performansi, zatim gasi API.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS="${ROOT}/results"
mkdir -p "${RESULTS}"

run_profile() {
  local runtime="$1"
  local name="$2"
  echo "=============================================================="
  echo "  razina izolacije: ${name}  (runtime=${runtime})"
  echo "=============================================================="

  SBX_RUNTIME="${runtime}" \
  SBX_AUDIT_LOG="${RESULTS}/audit-${name}.jsonl" \
    uvicorn app.main:app --host 127.0.0.1 --port 8000 \
    --app-dir "${ROOT}/sandbox" >"${RESULTS}/api-${name}.log" 2>&1 &
  local api_pid=$!

  # cekaj spremnost
  for _ in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1; then break; fi
    sleep 1
  done

  python3 "${ROOT}/tests/run_corpus.py" \
    --api http://127.0.0.1:8000 --repeat 5 \
    --out "${RESULTS}/corpus-${name}.jsonl" || true

  python3 "${ROOT}/tests/benchmark.py" \
    --api http://127.0.0.1:8000 --iterations 50 --concurrency 4 \
    --out "${RESULTS}/benchmark-${name}.json" || true

  kill "${api_pid}" 2>/dev/null || true
  wait "${api_pid}" 2>/dev/null || true
  echo
}

run_profile runc  "runc-hardened"
run_profile runsc "gvisor"

echo "gotovo. rezultati u ${RESULTS}/"
python3 "${ROOT}/tests/report.py" "${RESULTS}" || true
