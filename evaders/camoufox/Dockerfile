# evaders/camoufox/Dockerfile — Camoufox evader image (engine-level anti-detect Firefox).
# Built on the Playwright/python base (browser system deps) + camoufox; fetches the browser at build.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
# camoufox fetches its own browser; the stock Playwright Firefox (KS_BASELINE control group) needs the
# Playwright-bundled binary matching the pip-pulled Playwright version, so install it explicitly.
RUN pip install --no-cache-dir "camoufox[geoip]" && python -m camoufox fetch \
    && python -m playwright install firefox
# xdotool injects real XTEST input for KS_REAL_INPUT (the behavioral terminus); xvfb-run gives it + a headful
# Camoufox a shared real X display. The base Playwright image already ships Xvfb (browsers need it).
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends xdotool \
    && rm -rf /var/lib/apt/lists/*
COPY run.py /run.py
# KS_REAL_INPUT runs headful Camoufox on a real Xvfb display so xdotool's XTEST motion lands in the window;
# every other mode runs Python directly (headless / Camoufox's own virtual display). Start Xvfb by hand on a
# fixed display (xvfb-run's readiness probe hangs on this base image) and export DISPLAY for camoufox + xdotool.
ENTRYPOINT ["sh", "-c", "if [ \"$KS_REAL_INPUT\" = \"1\" ]; then Xvfb :99 -screen 0 1280x1024x24 -nolisten tcp >/dev/null 2>&1 & sleep 2; export DISPLAY=:99; exec python /run.py; else exec python /run.py; fi"]
