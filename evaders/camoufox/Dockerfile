# evaders/camoufox/Dockerfile — Camoufox evader image (engine-level anti-detect Firefox).
# Built on the Playwright/python base (browser system deps) + camoufox; fetches the browser at build.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
# camoufox fetches its own browser; the stock Playwright Firefox (KS_BASELINE control group) needs the
# Playwright-bundled binary matching the pip-pulled Playwright version, so install it explicitly.
RUN pip install --no-cache-dir "camoufox[geoip]" && python -m camoufox fetch \
    && python -m playwright install firefox
# numpy: the in-session matched-filter for the arena AUDIO gate (KS_ARENA_SOLVE=audio) — correlates the mounted
# FSDD templates over the minted clip to transcribe the spoken digits, so the coherent browser can PASS the gate.
RUN pip install --no-cache-dir numpy
# Camoufox's bundled macOS font list exposes 49 dot-prefixed INTERNAL system fonts (.Aqua Kana, .Apple Color
# Emoji UI, …) that a real Mac HIDES from web content — a font-enumeration leak that trips br.font_mac_internal
# under KS_MACOS. Strip them so the macOS profile's web-measurable font set matches a real Mac (the ~524 non-dot
# fonts remain, so font_os_vs_ua stays macOS-coherent). The faithful engine-bundled-font fix.
RUN python -c "import camoufox, os, json; p=os.path.join(os.path.dirname(camoufox.__file__),'fonts.json'); d=json.load(open(p)); d['mac']=[f for f in d['mac'] if not f.startswith('.')]; json.dump(d, open(p,'w'))"
# camoufox's webgl_data.db caps its Apple GPU entries' MAX_TEXTURE_SIZE at a BUGGY 8192 (a real Apple M1/M2/M3
# exposes 16384) — an "Apple M1" renderer @ 8192 is self-incoherent and trips br.webgl_renderer_caps_mismatch,
# blocking a coherent macOS morph. Correct the wrong data (backed by llvmpipe's real 16384 allocation).
COPY patch_webgl_db.py /patch_webgl_db.py
RUN python3 /patch_webgl_db.py
# xdotool = real XTEST input (KS_REAL_INPUT); pulseaudio/espeak-ng/speech-dispatcher/dbus = a provisioned
# ENVIRONMENT (KS_PROVISION: real audio devices + TTS voices) so the environment-floor tells go silent
# coherently — the "become a real desktop" evasion vs the JS spoof coherence catches. Base ships Xvfb.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      xdotool pulseaudio espeak-ng speech-dispatcher dbus \
    && rm -rf /var/lib/apt/lists/*
COPY run.py /run.py
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["sh", "/entrypoint.sh"]
