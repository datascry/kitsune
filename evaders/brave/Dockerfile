# evaders/brave/Dockerfile — Brave evader (farbling: per-session canvas/audio noise injection).
# Playwright base (Chromium deps) + the Brave browser; driven via Playwright executablePath.

FROM mcr.microsoft.com/playwright:v1.48.0-jammy
RUN apt-get update && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
    && curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg \
         https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg arch=amd64] https://brave-browser-apt-release.s3.brave.com/ stable main" \
         > /etc/apt/sources.list.d/brave-browser-release.list \
    && apt-get update && apt-get install -y --no-install-recommends brave-browser \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN npm install --silent --no-audit --no-fund playwright@1.48.0
COPY run.mjs ./
ENTRYPOINT ["node", "run.mjs"]
