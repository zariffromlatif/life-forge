# Multi-stage production container for LIFE FORGE
FROM python:3.12-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY lifeforge/ ./lifeforge/

RUN pip install --no-cache-dir --upgrade pip && \
    pip wheel --no-cache-dir --no-deps --wheel-dir /app/wheels ".[all]"


FROM python:3.12-slim AS runner

WORKDIR /app

# Create non-root user for enterprise security
RUN groupadd -r lifeforge && useradd -r -g lifeforge -d /app -s /bin/bash lifeforge

COPY --from=builder /app/wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

COPY pyproject.toml README.md ./
COPY lifeforge/ ./lifeforge/
COPY examples/ ./examples/

RUN mkdir -p /app/results && chown -R lifeforge:lifeforge /app

USER lifeforge

EXPOSE 8000

VOLUME ["/app/results"]

ENTRYPOINT ["lifeforge"]
CMD ["ui", "--port", "8000", "--no-browser"]
