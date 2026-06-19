#!/usr/bin/env bash
# scripts/verify_deployed — check the LIVE detector matches the committed ruleset/prior (catch a stale deploy).
# Queries the running detector on the lab network and compares to the repo; exits non-zero if stale.
set -uo pipefail

NET="${KITSUNE_NET:-kitsune_default}"
DET="${KITSUNE_DETECTOR:-http://detector:8080}"
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
cd "$ROOT" || exit 2

committed_ver="$(grep -oE 'ruleset_version: "[0-9.]+"' contracts/rules/registry.yaml | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
committed_thr="$(python3 -c 'import json; print(round(json.load(open("detector/src/kitsune_detector/data/prevalence_prior.json"))["threshold"],4))')"

live="$(docker run --rm --network "$NET" curlimages/curl:latest -s "$DET/healthz" 2>/dev/null)"
live_ver="$(printf '%s' "$live" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("ruleset_version","?"))' 2>/dev/null || echo '?')"

stale=0
echo "ruleset_version:      committed=$committed_ver  live=$live_ver"
[ "$committed_ver" = "$live_ver" ] || { echo "  ↳ STALE: detector serves $live_ver but the repo is at $committed_ver"; stale=1; }

# Best-effort prior-threshold check (the v0.74.24 prevalence fix lived only in the prior data, not the version).
cid="$(docker ps -qf name=detector 2>/dev/null | head -1)"
if [ -n "$cid" ]; then
  live_thr="$(docker exec "$cid" python -c 'import json,glob; print(round(json.load(open(glob.glob("/app/**/prevalence_prior.json",recursive=True)[0]))["threshold"],4))' 2>/dev/null || echo '?')"
  echo "prevalence threshold: committed=$committed_thr  live=$live_thr"
  [ "$committed_thr" = "$live_thr" ] || { echo "  ↳ STALE: prior threshold differs (a prior-data change was not redeployed)"; stale=1; }
fi

if [ "$stale" -ne 0 ]; then
  echo "DEPLOY IS STALE — a committed fix is NOT in effect. Rebuild:" >&2
  echo "  docker compose build detector edge && docker compose up -d detector edge" >&2
  exit 1
fi
echo "OK: the deployed stack matches the committed source."
