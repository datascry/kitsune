#!/usr/bin/env bash
# scripts/frontier — fast frontier-only loop: run ONLY the evaders that still beat per-session detection.
# Camoufox single (per-session frontier miss) + a Camoufox fleet (coordination catch); skips the known-caught.

# The full sweep (live_scoreboard.sh) re-detects 7 evaders we already catch with certainty — slow and
# uninformative. This runner targets the frontier: Camoufox is the only tool that evades every per-session
# rule, so it is the only one worth iterating on frequently. Run the full regression sweep sparsely instead.
set -euo pipefail
cd "$(dirname "$0")/.."
NET=kitsune_default
FLEET_N="${FLEET_N:-3}"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.agent.yml)

docker image inspect kitsune-camoufox >/dev/null 2>&1 || {
  echo "[!] kitsune-camoufox image missing — build it first: docker build -t kitsune-camoufox ./evaders/camoufox" >&2
  exit 1
}

echo "[*] bringing up detector+edge (reuse images)…"
"${COMPOSE[@]}" up -d detector edge >/dev/null 2>&1
for _ in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$("${COMPOSE[@]}" ps -q detector)" 2>/dev/null)" = healthy ] && break
  sleep 3
done

run_camoufox() { # $1 = output session-json path; captures one Camoufox session from the detector
  # KS_FAST=1 (default): detection-only capture — event-driven, ~3s faster, drops the behavioral layer
  # the frontier test does not score. KS_FAST=0 for a full capture (mouse simulation + behavioral).
  local out="$1" line sid
  line="$(docker run --rm --network "$NET" \
    -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 \
    -e KS_FAST="${KS_FAST:-1}" \
    kitsune-camoufox 2>/dev/null | sed -n 's/^__KS__//p' | tail -1 || true)"
  sid="$(printf '%s' "$line" | python3 -c "import json,sys;print(json.load(sys.stdin)['session_id'])" 2>/dev/null || true)"
  [ -n "$sid" ] || { echo "[!] camoufox produced no session" >&2; return 1; }
  curl -s "http://localhost:8090/session/$sid" -o "$out"
}

echo "[*] frontier: Camoufox single (per-session) → corpus/sessions/camoufox.json"
run_camoufox corpus/sessions/camoufox.json || true

echo "[*] frontier: Camoufox fleet ×$FLEET_N → corpus/fleet/cf*.json"
mkdir -p corpus/fleet
rm -f corpus/fleet/cf*.json # drop stale members so a failed capture can't pollute the cluster
for i in $(seq 1 "$FLEET_N"); do
  run_camoufox "corpus/fleet/cf$i.json" || true
done

echo "[*] per-session verdicts (frontier miss is expected — Camoufox is coherent):"
( cd harness && uv run python -m kitsune_harness.corpus ../corpus/sessions ) | grep -iE 'camoufox|label' || true

echo
echo "[*] coordination verdict (the frontier catch):"
( cd harness && uv run python -m kitsune_harness.coordination ../corpus/fleet )

echo "[*] done → coordination snapshot printed above + refreshed corpus/{sessions,fleet}/"
