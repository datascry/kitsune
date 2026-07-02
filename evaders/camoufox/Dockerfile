# evaders/camoufox/Dockerfile — Camoufox evader image (engine-level anti-detect Firefox).
# Built on the Playwright/python base (browser system deps) + camoufox; fetches the browser at build.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
# camoufox fetches its own browser; the stock Playwright Firefox (KS_BASELINE control group) needs the
# Playwright-bundled binary matching the pip-pulled Playwright version, so install it explicitly.
RUN pip install --no-cache-dir "camoufox[geoip]" && python -m camoufox fetch \
    && python -m playwright install firefox
# xdotool = real XTEST input (KS_REAL_INPUT); pulseaudio/espeak-ng/speech-dispatcher/dbus = a provisioned
# ENVIRONMENT (KS_PROVISION: real audio devices + TTS voices) so the environment-floor tells go silent
# coherently — the "become a real desktop" evasion vs the JS spoof coherence catches. Base ships Xvfb.
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends \
      xdotool pulseaudio espeak-ng speech-dispatcher dbus \
    && rm -rf /var/lib/apt/lists/*
COPY run.py /run.py
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["sh", "/entrypoint.sh"]
