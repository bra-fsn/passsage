FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    less \
    procps \
    && ARCH=$(dpkg --print-architecture) \
    && case "$ARCH" in amd64) FDB_ARCH=amd64 ;; arm64) FDB_ARCH=aarch64 ;; *) echo "unsupported: $ARCH" && exit 1 ;; esac \
    && curl -fsSL "https://github.com/apple/foundationdb/releases/download/7.3.63/foundationdb-clients_7.3.63-1_${FDB_ARCH}.deb" -o /tmp/fdb-clients.deb \
    && dpkg -i /tmp/fdb-clients.deb \
    && rm /tmp/fdb-clients.deb \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (this layer is cached until pyproject.toml changes)
COPY pyproject.toml README.md ./
RUN mkdir -p src/passsage \
    && echo '__version__ = "0.0.0"' > src/passsage/__init__.py \
    && uv pip install --system --no-cache --link-mode=copy ".[ui]" \
    && rm -rf src/passsage

# Copy source and install package only (dependencies already satisfied)
COPY src/ ./src/
RUN uv pip install --system --no-cache --link-mode=copy --no-deps .

# Expose proxy port
EXPOSE 8080
# Health endpoint
EXPOSE 8082

# Default command
ENTRYPOINT ["passsage"]
