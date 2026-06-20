# evaders/playwright-extra/Dockerfile — Playwright image + playwright-extra stealth toolchain.
# Bakes playwright + playwright-extra + the stealth plugin into a layer; editing run.mjs re-copies the last layer.

FROM mcr.microsoft.com/playwright:v1.55.1-jammy
WORKDIR /app
COPY package.json ./
# Pin to the base image's Chromium (playwright 1.52.0) so the stealth plugin drives the baked revision.
RUN npm install --silent --no-audit --no-fund \
      playwright@1.52.0 playwright-extra@4.3.6 puppeteer-extra-plugin-stealth@2.11.2 \
    && (npx playwright install chromium || true)
COPY run.mjs ./
ENTRYPOINT ["node", "run.mjs"]
