# evaders/primp/Dockerfile — one-shot container for the primp impersonation evader.
# Runs python -m kitsune_primp against the live edge + detector.

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /bin/uv
WORKDIR /app
COPY evaders/primp /app/primp
WORKDIR /app/primp
RUN uv sync --frozen --no-dev
CMD ["uv", "run", "python", "-m", "kitsune_primp"]
