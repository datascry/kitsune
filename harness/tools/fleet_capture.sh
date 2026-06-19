#!/usr/bin/env bash
# harness/tools/fleet_capture — capture a live coordination fleet: N concurrent evader instances → sessions.
# Runs one evader image N times CONCURRENTLY so each holds a distinct container IP, then pulls each /session.

# The live analog of the synthetic coordination scenarios: distinct simultaneous container IPs substitute for
# residential-proxy egress IPs, so the same image's deterministic fp_hash collides across distinct sources —
# the cloned-profile-behind-proxies shape the coordination detector convicts via _fp_collision. Concurrency is
# load-bearing: SEQUENTIAL runs reuse the freed bridge IP (one IP → benign "one machine, many sessions").
#
#   IMAGE=kitsune-stealth:latest N=3 ENV="-e STEALTH=1" OUT=corpus/fleet-cloned harness/tools/fleet_capture.sh
set -euo pipefail

IMAGE="${IMAGE:-kitsune-stealth:latest}"
N="${N:-3}"
NET="${NET:-kitsune_default}"
ENV_ARGS="${ENV:--e STEALTH=1}"
OUT="${OUT:-corpus/fleet-cloned}"
EDGE="${KITSUNE_EDGE:-https://edge:8443/}"
DETECTOR="${KITSUNE_DETECTOR:-http://detector:8080}"

tmp="$(mktemp -d)"
echo "launching $N concurrent $IMAGE instances on $NET ..."
for i in $(seq 1 "$N"); do
  # shellcheck disable=SC2086
  ( timeout 120 docker run --rm --name "fleet-node-$i" --network "$NET" \
      -e KITSUNE_EDGE="$EDGE" -e KITSUNE_DETECTOR="$DETECTOR" $ENV_ARGS "$IMAGE" \
      > "$tmp/node$i.out" 2>&1 ) &
done
wait

mkdir -p "$OUT"
for i in $(seq 1 "$N"); do
  sid="$(grep -o '__KS__.*' "$tmp/node$i.out" | sed 's/^__KS__//' \
        | python3 -c 'import json,sys;print(json.load(sys.stdin).get("session_id",""))' 2>/dev/null || true)"
  if [ -n "$sid" ]; then
    docker run --rm --network "$NET" curlimages/curl:latest -s "$DETECTOR/session/$sid" 2>/dev/null \
      | python3 -c "import json,sys;d=json.load(sys.stdin);open('$OUT/cn$i.json','w').write(json.dumps(d,indent=1))"
    echo "  node$i → $OUT/cn$i.json (sid ${sid:0:12})"
  else
    echo "  node$i: NO SESSION"; tail -3 "$tmp/node$i.out"
  fi
done
echo "grade with: cd harness && uv run python -m kitsune_harness.coordination ../$OUT"
