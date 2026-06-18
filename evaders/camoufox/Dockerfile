# evaders/camoufox/Dockerfile — Camoufox evader image (engine-level anti-detect Firefox).
# Built on the Playwright/python base (browser system deps) + camoufox; fetches the browser at build.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
# camoufox fetches its own browser; the stock Playwright Firefox (KS_BASELINE control group) needs the
# Playwright-bundled binary matching the pip-pulled Playwright version, so install it explicitly.
RUN pip install --no-cache-dir "camoufox[geoip]" && python -m camoufox fetch \
    && python -m playwright install firefox
COPY run.py /run.py
ENTRYPOINT ["python", "/run.py"]
