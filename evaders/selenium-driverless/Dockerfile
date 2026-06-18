# evaders/selenium-driverless/Dockerfile — selenium-driverless evader (CDP, no chromedriver/webdriver).
# Playwright/python base (chromium + system deps) + selenium-driverless, which runs scripts in isolated worlds.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
RUN pip install --no-cache-dir selenium-driverless
COPY run.py /run.py
ENTRYPOINT ["python", "/run.py"]
