FROM python:3.14-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# Create non-root user with home
RUN useradd -r -u 10001 -g root -m -d /home/passsage passsage
ENV HOME=/home/passsage

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    less \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (this layer is cached until pyproject.toml changes)
COPY pyproject.toml README.md ./
RUN mkdir -p src/passsage && touch src/passsage/__init__.py \
    && uv pip install --system --no-cache ".[ui]" \
    && rm -rf src/passsage

# Copy source and install package only (dependencies already satisfied)
COPY src/ ./src/
RUN uv pip install --system --no-cache --no-deps .

# Run as non-root
USER 10001

# Expose proxy port
EXPOSE 8080
# Health endpoint
EXPOSE 8082

# Default command
ENTRYPOINT ["passsage"]
