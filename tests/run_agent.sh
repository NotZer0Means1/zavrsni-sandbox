#!/usr/bin/env bash
# Pokrece pokus S6 (autonomni agent + posredno ubacivanje uputa) za obje razine
# izolacije. Model se poziva preko lokalne Ollame, bez API kljuca.
#
# Prvi put snima kasetu (poziva model), zatim je reproducira za drugu razinu
# izolacije, cime su rezultati ponovljivi.
#
# Preduvjeti: Docker, gVisor, Ollama s povucenim modelom, izgradena slika
#             sandbox-runner:latest, instalirane ovisnosti iz requirements.txt.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS="${ROOT}/results"
CASSETTE="${ROOT}/agent/cassettes/injection.json"
MODEL="${AGENT_MODEL:-llama3.1}"
mkdir -p "${RESULTS}" "$(dirname "${CASSETTE}")"

export AGENT_PROVIDER="${AGENT_PROVIDER:-ollama}"
export AGENT_MODEL="${MODEL}"

# provjeri da je Ollama dostupna i da je model povucen
if ! curl -sf "http://127.0.0.1:11434/api/tags" >/dev/null; then
  echo "Ollama nije dostupna na 127.0.0.1:11434. Pokreni: systemctl start ollama" >&2
  exit 1
fi
if ! curl -s "http://127.0.0.1:11434/api/tags" | grep -q "${MODEL%%:*}"; then
  echo "Model ${MODEL} nije povucen. Pokreni: ollama pull ${MODEL}" >&2
  exit 1
fi

run_profile() {
  local runtime="$1" name="$2" mode="$3"
  echo "=============================================================="
  echo "  S6  razina izolacije: ${name}  (runtime=${runtime}, LLM ${mode})"
  echo "=============================================================="

  SBX_RUNTIME="${runtime}" SBX_AUDIT_LOG="${RESULTS}/audit-agent-${name}.jsonl" \
    uvicorn app.main:app --app-dir "${ROOT}/sandbox" --host 127.0.0.1 --port 8000 \
    >"${RESULTS}/api-agent-${name}.log" 2>&1 &
  local api_pid=$!
  for _ in $(seq 1 30); do
    curl -sf http://127.0.0.1:8000/health >/dev/null 2>&1 && break; sleep 1
  done

  AGENT_LLM_MODE="${mode}" python3 -m agent.run_injection \
    --api http://127.0.0.1:8000 --cassette "${CASSETTE}" \
    --out "${RESULTS}/injection-${name}.jsonl" || true

  kill "${api_pid}" 2>/dev/null || true
  wait "${api_pid}" 2>/dev/null || true
  echo
}

# prvi prolaz snima kasetu (poziva model), drugi je reproducira
run_profile runc  "runc-hardened" "record"
run_profile runsc "gvisor"        "replay"

echo "gotovo. rezultati u ${RESULTS}/injection-*.jsonl"
