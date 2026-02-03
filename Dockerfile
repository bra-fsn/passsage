FROM python:3.14-slim

WORKDIR /app

# Create non-root user with home
RUN useradd -r -u 10001 -g root -m -d /home/passsage passsage
ENV HOME=/home/passsage

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy and install package
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Run as non-root
USER 10001

# Expose proxy port
EXPOSE 8080
# Health endpoint
EXPOSE 8082

# Default command
ENTRYPOINT ["passsage"]
