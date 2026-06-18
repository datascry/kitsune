# evaders/undetected/Dockerfile — undetected-chromedriver evader (the most popular anti-detect tool).
# Selenium + a patched chromedriver; UC auto-matches the driver to the installed Chrome at runtime.

FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      wget gnupg ca-certificates fonts-liberation libnss3 libxss1 libasound2 \
      libatk-bridge2.0-0 libgtk-3-0 libgbm1 libu2f-udev xdg-utils \
    && wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && (dpkg -i /tmp/chrome.deb || apt-get install -y -f) && rm /tmp/chrome.deb \
    && pip install --no-cache-dir undetected-chromedriver selenium \
    && rm -rf /var/lib/apt/lists/*
COPY run.py /run.py
ENTRYPOINT ["python", "/run.py"]
