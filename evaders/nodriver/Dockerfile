# evaders/nodriver/Dockerfile — nodriver evader (CDP-based, no Selenium/webdriver).
# Playwright/python base (provides chromium + system deps) + nodriver.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
RUN pip install --no-cache-dir nodriver
COPY run.py /run.py
ENTRYPOINT ["python", "/run.py"]
