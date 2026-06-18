# evaders/camoufox/Dockerfile — Camoufox evader image (engine-level anti-detect Firefox).
# Built on the Playwright/python base (browser system deps) + camoufox; fetches the browser at build.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
RUN pip install --no-cache-dir "camoufox[geoip]" && python -m camoufox fetch
COPY run.py /run.py
ENTRYPOINT ["python", "/run.py"]
