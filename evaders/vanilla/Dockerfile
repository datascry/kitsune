# evaders/vanilla/Dockerfile — one-shot container for the vanilla baseline evader.
# Runs python -m kitsune_vanilla against the live edge + detector.

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/uv
WORKDIR /app
COPY evaders/vanilla /app/vanilla
WORKDIR /app/vanilla
RUN uv sync --frozen --no-dev
CMD ["uv", "run", "python", "-m", "kitsune_vanilla"]
