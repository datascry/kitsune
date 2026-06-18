#!/usr/bin/env bash
# scripts/live_scoreboard — run the evader fleet against the live stack and render one scoreboard.
# Brings up detector+edge+browser, runs vanilla + stealth (+ agent if RUN_AGENT=1), writes docs/scoreboard.md.

set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$(mktemp -d)"
NET=kitsune_default
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.agent.yml)

echo "[*] bringing up the live stack…"
"${COMPOSE[@]}" up -d --build detector edge browser >/dev/null 2>&1
for _ in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$("${COMPOSE[@]}" ps -q detector)" 2>/dev/null)" = healthy ] && break
  sleep 3
done

echo "[*] vanilla…"
"${COMPOSE[@]}" run --rm -T --no-deps \
  -e KITSUNE_EDGE=https://edge:8443/healthz -e KITSUNE_DETECTOR=http://detector:8080 \
  vanilla 2>/dev/null >"$OUT/vanilla.json"

echo "[*] stealth (naive + patched)…"
docker run --rm --network "$NET" \
  -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 \
  -v "$PWD/evaders/stealth":/work -v "$OUT":/out -w /work \
  mcr.microsoft.com/playwright:v1.48.0-jammy \
  bash -c 'npm i -s playwright@1.48.0 >/dev/null 2>&1;
           node run.mjs >/out/stealth-naive.json 2>/dev/null;
           STEALTH=1 node run.mjs >/out/stealth-patched.json 2>/dev/null'

ARGS=("vanilla=$OUT/vanilla.json" "stealth-naive=$OUT/stealth-naive.json" "stealth-patched=$OUT/stealth-patched.json")

if [ "${RUN_AGENT:-0}" = 1 ]; then
  echo "[*] agent (claude -p — spends Claude usage)…"
  ( cd evaders/agent && uv sync -q &&
    KITSUNE_BROWSER_WS=http://localhost:9222 KITSUNE_EDGE=https://edge:8443/ \
    KITSUNE_DETECTOR=http://localhost:8090 uv run python -m kitsune_agent 2>/dev/null ) >"$OUT/agent.json"
  ARGS+=("agent=$OUT/agent.json")
fi

echo "[*] rendering scoreboard…"
( cd harness && uv run python -m kitsune_harness.liveboard "${ARGS[@]}" ) | tee docs/scoreboard.md

"${COMPOSE[@]}" --profile evaders down -v >/dev/null 2>&1
echo "[*] done → docs/scoreboard.md"
