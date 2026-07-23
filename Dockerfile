FROM python:3.14.5-slim AS builder
WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    curl -LsSf https://astral.sh/uv/install.sh | sh && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --no-cache --prefix=/app/.local -e .

COPY . .

FROM python:3.14.5-slim
ENV PYTHONUNBUFFERED=1 \
    PATH=/app/.local/bin:$PATH
WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    curl -LsSf https://astral.sh/uv/install.sh | sh && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app /app

RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:80/config/warmup || exit 1

CMD ["uvicorn", "api.app:app", "--host", "0.0.0.0", "--port", "80", \
     "--workers", "2", "--proxy-headers"]