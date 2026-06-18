# evaders/zendriver/Dockerfile — zendriver evader (maintained nodriver successor, CDP-based, no webdriver).
# Playwright/python base (provides chromium + system deps) + zendriver.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
RUN pip install --no-cache-dir zendriver
COPY run.py /run.py
ENTRYPOINT ["python", "/run.py"]
