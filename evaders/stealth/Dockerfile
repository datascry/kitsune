# evaders/stealth/Dockerfile — prebuilt Playwright image so the live run skips per-run npm install.
# Playwright is baked into a layer; editing run.mjs only re-copies the last layer (fast rebuild).

FROM mcr.microsoft.com/playwright:v1.48.0-jammy
WORKDIR /app
COPY package.json ./
RUN npm install --silent --no-audit --no-fund playwright@1.48.0
COPY run.mjs ./
ENTRYPOINT ["node", "run.mjs"]
