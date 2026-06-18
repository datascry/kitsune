# evaders/pydoll/Dockerfile — pydoll evader (async CDP-native, no webdriver; markets Turnstile bypass).
# Playwright/python base (chromium + system deps) + pydoll-python.

FROM mcr.microsoft.com/playwright/python:v1.48.0-jammy
RUN pip install --no-cache-dir pydoll-python
COPY run.py /run.py
ENTRYPOINT ["python", "/run.py"]
