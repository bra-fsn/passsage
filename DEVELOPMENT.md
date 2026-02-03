# Development Guide

This guide covers local development with Docker Compose.

## Quick Start

### Production-like setup (no code mounting)

```bash
docker compose up --build
```

This starts:
- **LocalStack** on port 4566 with S3 and a pre-configured `proxy-cache` bucket
- **Passsage** proxy on port 8080
- **Health endpoint** on port 8082 (`/health`)

### Development setup (with live code editing)

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

This starts LocalStack and passsage with your source code mounted. mitmproxy reloads the proxy when `proxy.py` (or other mounted files) change, so you can edit code and see changes without restarting the container.

## Development Workflow

### 1. Start the dev environment

```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

### 2. Edit code and test

Edit files in `src/passsage/`. mitmproxy reloads the proxy on change; no container restart needed.

### 3. Test the proxy

Configure your HTTP client to use `http://localhost:${PASSSAGE_PORT:-8080}` as a proxy:

```bash
# Using curl
curl -x http://localhost:${PASSSAGE_PORT:-8080} http://example.com

# Using wget
http_proxy=http://localhost:${PASSSAGE_PORT:-8080} wget http://example.com

# Using pip
pip install --proxy http://localhost:${PASSSAGE_PORT:-8080} requests
```

### 4. Check health

```bash
curl -f http://localhost:${HEALTH_PORT:-8082}/health
```

## Testing with LocalStack S3

The LocalStack container automatically creates the `proxy-cache` bucket with public read access. You can verify it's working:

```bash
# List buckets
docker compose exec localstack awslocal s3 ls

# List cached objects (after some proxy traffic)
docker compose exec localstack awslocal s3 ls s3://proxy-cache/ --recursive
```

## Useful Commands

```bash
# Start dev environment
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build

# Stop everything
docker compose down

# Stop and remove volumes (clean slate)
docker compose down -v

# View passsage logs
docker compose logs -f passsage

# View localstack logs
docker compose logs -f localstack

# Configure host port mappings
PROXY_PORT=9090 HEALTH_PORT=9092 docker compose up --build

# Rebuild the dev image (after Dockerfile.dev changes)
docker compose -f docker-compose.yml -f docker-compose.dev.yml build passsage

# Shell in the passsage container
docker compose exec passsage bash
```

## Architecture

```
┌─────────────────┐     ┌─────────────────┐
│   Your Client   │────▶│    Passsage     │
│  (curl, pip,    │     │   (port 8080)   │
│   browser, etc) │     └────────┬────────┘
└─────────────────┘              │
                                 │ Cache lookup/store
                                 ▼
                        ┌─────────────────┐
                        │   LocalStack    │
                        │   S3 Bucket     │
                        │  (port 4566)    │
                        └─────────────────┘
```

## Troubleshooting

### Proxy won't start

Check the logs:
```bash
docker compose logs passsage
```

### LocalStack not ready

The passsage container waits for LocalStack to be healthy. If it's stuck, check LocalStack logs:
```bash
docker compose logs localstack
```

### Permission errors on mounted volumes

On Linux, you may need to adjust permissions or run with your user ID:
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml run --user $(id -u):$(id -g) passsage
```

### Code changes not reflected

mitmproxy reloads the proxy when the script file changes. If changes don't appear, restart the container:
```bash
docker compose restart passsage
```

## Running Tests

```bash
# In the container
docker compose exec passsage pip install -e ".[dev]"
docker compose exec passsage pytest

# Or locally with the dev dependencies
pip install -e ".[dev]"
pytest
```

## Integration test notes

The integration suite relies on `X-Passsage-Policy` overrides. Enable them with
`PASSAGE_ALLOW_POLICY_HEADER=1` or `passsage --allow-policy-header`.

If the proxy runs in a container, ensure the host test server is reachable:

```bash
export PASSAGE_TEST_SERVER_BIND_HOST=0.0.0.0
export PASSAGE_TEST_SERVER_HOST=host.docker.internal
export PROXY_URL=http://localhost:${PASSSAGE_PORT:-8080}
pytest -m "not slow"
```
