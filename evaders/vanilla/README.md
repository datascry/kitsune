# evaders/vanilla — baseline evader (the control)

A plain HTTPS client with **no evasion**. It drives the live pipeline and establishes the detection
floor: with no browser/behavioral signals and an unpopulated JA4 hint table, nothing fires, so it
scores `human`. Everything else on the scoreboard is measured against this floor.

## Flow

```
vanilla ──HTTPS──▶ edge (captures ClientHello → JA3/JA4, mints ks_sid, forwards signals)
                     │
                     └─▶ detector  ──(verdict by ks_sid)──▶ vanilla prints it
```

## Run

Against the live stack (from the repo root):

```sh
docker compose up -d --build detector edge
docker compose --profile evaders run --rm vanilla   # prints the verdict JSON
```

Verified live: a real `session_id` threads socket → edge → detector → verdict; vanilla scores
`0.00 / human`.

`KS_UA=<ua>` fakes a browser User-Agent over plain httpx (no `Sec-Fetch-*` headers) — the classic
UA-spoofing scripted-flood client, caught by the edge's `net.sec_fetch_vs_ua` HTTP-layer tell. The
live scoreboard runs vanilla in this mode.

## Develop

```sh
uv sync && uv run pytest    # runner logic tested via httpx MockTransport (no real network)
uv run ruff check . && uv run mypy
```
