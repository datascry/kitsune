#!/usr/bin/env bash
# scripts/live_scoreboard — run the evader fleet against the live stack and render one scoreboard.
# Brings up detector+edge+browser, runs vanilla + stealth (+ agent if RUN_AGENT=1), writes docs/scoreboard.md.

set -euo pipefail
cd "$(dirname "$0")/.."
OUT="$(mktemp -d)"
NET=kitsune_default
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.agent.yml)

echo "[*] bringing up the live stack…"
BUILD=()
[ "${KITSUNE_BUILD:-1}" = 1 ] && BUILD=(--build) # KITSUNE_BUILD=0 to reuse images (faster reruns)
"${COMPOSE[@]}" up -d "${BUILD[@]}" detector edge browser >/dev/null 2>&1
for _ in $(seq 1 40); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$("${COMPOSE[@]}" ps -q detector)" 2>/dev/null)" = healthy ] && break
  sleep 3
done

echo "[*] vanilla (httpx faking a browser UA — the scripted-flood case)…"
CHROME_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
"${COMPOSE[@]}" run --rm -T --no-deps \
  -e KITSUNE_EDGE=https://edge:8443/healthz -e KITSUNE_DETECTOR=http://detector:8080 -e KS_UA="$CHROME_UA" \
  vanilla 2>/dev/null >"$OUT/vanilla.json" || true

echo "[*] stealth (naive + patched + spoof-ua)…"
docker build -q -t kitsune-stealth ./evaders/stealth >/dev/null # Playwright baked in; cached
run_stealth() { # $1 = output file; remaining args = extra `docker run` env flags
  # A failing evader must NOT abort the run (set -e + pipefail) — it just yields an empty file.
  docker run --rm --network "$NET" \
    -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 \
    "${@:2}" kitsune-stealth 2>/dev/null | sed -n 's/^__KS__//p' | tail -1 >"$1" || true
  return 0
}
run_stealth "$OUT/stealth-naive.json"
run_stealth "$OUT/stealth-patched.json" -e STEALTH=1
run_stealth "$OUT/spoof-ua.json" -e SPOOF_UA="Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
run_stealth "$OUT/full-stealth.json" -e FULL=1
run_stealth "$OUT/floor-spoof.json" -e FLOOR_SPOOF=1 # red-team: fake the environment floor (voices/devices)
run_stealth "$OUT/patchright.json" -e PATCHRIGHT=1 || true # evaluate a real anti-detect tool

# Engine/tool evaders — use the prebuilt images if present (graceful skip otherwise).
run_tool() { # $1 image, $2 label
  docker image inspect "$1" >/dev/null 2>&1 || return 0
  echo "[*] $2…"
  docker run --rm --network "$NET" \
    -e KITSUNE_EDGE=https://edge:8443/ -e KITSUNE_DETECTOR=http://detector:8080 \
    "$1" 2>/dev/null | sed -n 's/^__KS__//p' | tail -1 >"$OUT/$2.json" || true
}
run_tool kitsune-camoufox camoufox
run_tool kitsune-nodriver nodriver
run_tool kitsune-zendriver zendriver
run_tool kitsune-selenium-driverless selenium-driverless
run_tool kitsune-pydoll pydoll
run_tool kitsune-curl-impersonate curl-impersonate
run_tool kitsune-h2-rapid-reset h2-rapid-reset

ARGS=(
  "vanilla=$OUT/vanilla.json"
  "stealth-naive=$OUT/stealth-naive.json"
  "stealth-patched=$OUT/stealth-patched.json"
  "spoof-ua=$OUT/spoof-ua.json"
  "full-stealth=$OUT/full-stealth.json"
)
[ -s "$OUT/patchright.json" ] && ARGS+=("patchright=$OUT/patchright.json")
[ -s "$OUT/camoufox.json" ] && ARGS+=("camoufox=$OUT/camoufox.json")
[ -s "$OUT/nodriver.json" ] && ARGS+=("nodriver=$OUT/nodriver.json")

if [ "${RUN_AGENT:-0}" = 1 ]; then
  echo "[*] agent (claude -p — spends Claude usage)…"
  ( cd evaders/agent && uv sync -q &&
    KITSUNE_BROWSER_WS=http://localhost:9222 KITSUNE_EDGE=https://edge:8443/ \
    KITSUNE_DETECTOR=http://localhost:8090 uv run python -m kitsune_agent 2>/dev/null ) >"$OUT/agent.json"
  ARGS+=("agent=$OUT/agent.json")
fi

echo "[*] rendering scoreboard…"
( cd harness && uv run python -m kitsune_harness.liveboard "${ARGS[@]}" ) | tee docs/scoreboard.md

echo "[*] refreshing the recorded-session corpus…"
mkdir -p corpus/sessions
for arg in "${ARGS[@]}"; do
  label="${arg%%=*}"
  sid="$(python3 -c "import json;print(json.load(open('${arg#*=}'))['session_id'])" 2>/dev/null)" || continue
  curl -s "http://localhost:8090/session/$sid" -o "corpus/sessions/$label.json"
done

echo "[*] rendering detection matrix…"
( cd harness && uv run python -m kitsune_harness.report ../corpus/sessions ) >docs/matrix.md

"${COMPOSE[@]}" --profile evaders down -v >/dev/null 2>&1
echo "[*] done → docs/scoreboard.md + docs/matrix.md + corpus/sessions/"
