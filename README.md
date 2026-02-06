# Passsage proxy

**Passsage** (or **Pas³age** to emphasize the backend choice) is named for the three S's in **S3**: it uses Amazon S3 or an
S3-compatible object store to persist its cached objects.

A caching HTTP(S) proxy built on [mitmproxy](https://mitmproxy.org/) that stores responses in S3 storage. Useful for caching package repositories, API responses, and other HTTP traffic for improved performance and offline access.

Mitmproxy is used so Passsage can terminate TLS, inspect HTTP responses, and cache HTTPS
content instead of blindly tunneling encrypted bytes. In explicit proxy mode, clients
connect to the proxy and issue `CONNECT` requests for HTTPS; mitmproxy completes the
upstream TLS handshake, generates a matching interception certificate signed by its
local CA, and then speaks TLS with the client so it can read and cache the HTTP payloads.
See https://docs.mitmproxy.org/stable/concepts/how-mitmproxy-works/ for the details.

## Features

- **S3-backed caching**: Store cached responses in AWS S3 or S3-compatible storage (MinIO, LocalStack, etc.)
- **Flexible caching policies**: Configure how different URLs are cached
  - `NoRefresh`: Serve from cache without revalidation; fetch on miss
  - `Standard`: RFC 9111 compliant caching and revalidation
  - `StaleIfError`: Serve stale cache on upstream failure (4xx/5xx/timeout)
  - `AlwaysUpstream`: Always fetch from upstream, cache as fallback
  - `NoCache`: Pass through without caching
  - Default policy when no rule matches: `Standard` (override with `--default-policy`)
- **Automatic failover**: Serve cached content when upstream is unavailable
- **Ban management**: Temporarily ban unresponsive upstreams to avoid timeouts

## Cache hits and misses

Passsage resolves each request to a cache policy, then uses S3 object metadata to decide
whether to serve from cache or go upstream. In brief:

- Cache hits are served by rewriting the request to the S3 object (Cache-Status is set to
  `hit` and `Age` is derived from the stored timestamp).
- Optionally, cache hits can be redirected to S3 (to avoid proxying bytes), using
  `--cache-redirect` or `PASSSAGE_CACHE_REDIRECT=1`. Signed URLs are the default for
  cache redirects and do not require a public bucket policy. Use
  `--cache-redirect-public` (or `PASSSAGE_CACHE_REDIRECT_SIGNED_URL=0`) to redirect
  to public S3 objects instead.
- When inspecting cached objects with `awslocal`, keys that start with `https://` are
  treated as URL parameters. Disable that behavior or pass the key via a file:

```bash
awslocal configure set cli_follow_urlparam false
awslocal s3api head-object --bucket proxy-cache --key "https://files.pythonhosted.org/..."
```

```bash
printf '%s' "https://files.pythonhosted.org/..." > /tmp/passsage-key.txt
awslocal s3api head-object --bucket proxy-cache --key file:///tmp/passsage-key.txt
```
- When `--cache-redirect` is enabled, clients must be able to fetch cached objects from
  S3 without AWS credentials. Configure a bucket policy to allow unauthenticated
  `s3:GetObject`/`s3:ListBucket` from your network:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "vpc_access",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-bucket/*",
        "arn:aws:s3:::your-bucket"
      ],
      "Condition": {
        "StringEquals": {
          "aws:SourceVpc": [
            "vpc-xxxxxxxx",
            "vpc-yyyyyyyy"
          ]
        }
      }
    },
    {
      "Sid": "ip_access",
      "Effect": "Allow",
      "Principal": {
        "AWS": "*"
      },
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-bucket/*",
        "arn:aws:s3:::your-bucket"
      ],
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": [
            "203.0.113.10/32",
            "198.51.100.42/32"
          ]
        }
      }
    }
  ]
}
```
- `NoRefresh` serves from cache immediately on a hit (no revalidation).
- `Standard` revalidates with an upstream `HEAD` when stale; if the cached `ETag`/`Last-Modified`
  matches, the cached object is served.
- `StaleIfError` serves stale cache on upstream failure, and `Standard` honors
  `stale-if-error` / `stale-while-revalidate` directives when present.
- `AlwaysUpstream` always fetches from upstream, even if cached.
- `NoCache` bypasses cache lookup for non-GET/HEAD or policy override.

`Standard` follows RFC 9111 HTTP caching semantics; `stale-if-error` and
`stale-while-revalidate` are supported when present.

On cache misses, Passsage fetches from upstream and streams the response to the client.
Responses are saved to S3 unless caching is disabled by policy or response headers
(`Cache-Control: no-store` or `private`, or `Vary: *`). When `Vary` is present, cache
keys include the `Vary` request headers so separate variants are stored and served.

## Installation

```bash
pip install passsage
```

For development:

```bash
pip install -e ".[dev]"
```

## Usage

### Basic Usage

```bash
# Run with default settings (uses AWS S3)
passsage

# Run on a specific port (CLI or env var)
PASSSAGE_PORT=9090 passsage
passsage -p 9090

# Bind to a specific interface (CLI or env var)
PASSSAGE_HOST=127.0.0.1 passsage
passsage --bind 127.0.0.1

# Run with web interface
passsage --web
```

### Client Setup (Certificate + Proxy Env Vars)

Passsage runs on mitmproxy, so clients must trust the mitmproxy CA certificate to avoid
TLS errors. Mitmproxy exposes a magic domain, `mitm.it`, which serves the local
certificate authority for download; see https://docs.mitmproxy.org/stable/concepts/certificates/.
The examples below assume a localhost proxy; if you deploy Passsage on an intranet host,
replace `localhost:8080` with the proxy hostname/IP.

1. Start Passsage (example on localhost):

```bash
PASSSAGE_PORT=8080 passsage
```

2. Run the proxy env script (it embeds the cert, installs it, and exports proxy env vars):

```bash
curl -x http://localhost:${PASSSAGE_PORT} http://mitm.it/proxy-env.sh -o /tmp/passsage-proxy-env.sh
. /tmp/passsage-proxy-env.sh
```

You can also source it in one line:

```bash
. <(curl -fsSL -x http://localhost:${PASSSAGE_PORT} http://mitm.it/proxy-env.sh)
```

It also tries to write `~/.passsage/proxy-env.sh` for reuse in other shells.

If the proxy is behind a load balancer or deployed in Kubernetes, the internal
listen address (e.g. `0.0.0.0:8080`) is not reachable by clients. Set
`--public-proxy-url` to the externally reachable address so the onboarding
script exports the correct `HTTP_PROXY`/`HTTPS_PROXY` values:

```bash
passsage --public-proxy-url http://proxy.example.com:3128
```

You can also set it via the environment variable:

```bash
export PASSSAGE_PUBLIC_PROXY_URL=http://proxy.example.com:3128
passsage
```

### With LocalStack (Local Development)

Start LocalStack:

```bash
docker run --rm -p 4566:4566 localstack/localstack
```

Create and configure the bucket:

```bash
# Using awslocal (pip install awscli-local)
awslocal s3 mb s3://proxy-cache
awslocal s3api put-bucket-policy --bucket proxy-cache --policy '{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject", "s3:HeadObject"],
    "Resource": "arn:aws:s3:::proxy-cache/*"
  }]
}'
```

Run Passsage:

```bash
passsage --s3-endpoint http://localhost:4566 --s3-bucket proxy-cache
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PASSSAGE_PORT` | Proxy listen port | `8080` |
| `PASSSAGE_HOST` | Proxy bind host | `0.0.0.0` |
| `S3_BUCKET` | S3 bucket name for cache storage | `364189071156-ds-proxy-us-west-2` (AWS) or `proxy-cache` (custom endpoint) |
| `S3_ENDPOINT_URL` | Custom S3 endpoint URL | None (uses AWS) |
| `PASSSAGE_PUBLIC_PROXY_URL` | Externally reachable proxy URL for the onboarding script (e.g. `http://proxy.example.com:3128`). Required behind a load balancer or in Kubernetes. | None |
| `PASSSAGE_ACCESS_LOGS` | Enable Parquet access logs | `0` |
| `PASSSAGE_ACCESS_LOG_PREFIX` | S3 prefix for access logs | `__passsage_logs__` |
| `PASSSAGE_ACCESS_LOG_DIR` | Local spool dir for access logs | `/tmp/passsage-logs` |
| `PASSSAGE_ACCESS_LOG_FLUSH_SECONDS` | Flush interval in seconds | `30` |
| `PASSSAGE_ACCESS_LOG_FLUSH_BYTES` | Flush size threshold | `1G` |
| `PASSSAGE_ACCESS_LOG_HEADERS` | Headers to include in access logs | `accept,accept-encoding,cache-control,content-type,content-encoding,etag,last-modified,range,user-agent,via,x-cache,x-cache-lookup,x-amz-request-id` |
| `PASSSAGE_ERROR_LOGS` | Enable Parquet error logs | `0` |
| `PASSSAGE_ERROR_LOG_PREFIX` | S3 prefix for error logs | `__passsage_error_logs__` |
| `PASSSAGE_ERROR_LOG_DIR` | Local spool dir for error logs | `/tmp/passsage-errors` |
| `PASSSAGE_ERROR_LOG_FLUSH_SECONDS` | Flush interval in seconds | `30` |
| `PASSSAGE_ERROR_LOG_FLUSH_BYTES` | Flush size threshold | `256M` |

### CLI Options

```
Usage: passsage [OPTIONS]

Options:
  -p, --port INTEGER              Port to listen on (env: PASSSAGE_PORT, default: 8080)
  -b, --bind TEXT                 Address to bind to (env: PASSSAGE_HOST, default: 0.0.0.0)
  --s3-bucket TEXT                S3 bucket for cache storage
  --s3-endpoint TEXT              S3 endpoint URL for S3-compatible services
  --test                          Run in test mode
  -m, --mode [regular|transparent|wireguard|upstream]
                                  Proxy mode (default: regular)
  -v, --verbose                   Enable verbose logging
  --public-proxy-url TEXT         Externally reachable proxy URL for client onboarding
                                  (env: PASSSAGE_PUBLIC_PROXY_URL)
  --cache-redirect                Redirect cache hits to S3 instead of streaming through the proxy
  --access-logs                   Enable S3 access logs in Parquet format
  --access-log-prefix TEXT        S3 prefix for access logs (env: PASSSAGE_ACCESS_LOG_PREFIX)
  --access-log-dir TEXT           Local spool directory for access logs
  --access-log-flush-seconds TEXT Flush interval in seconds for access logs
  --access-log-flush-bytes TEXT   Flush size threshold for access logs
  --access-log-headers TEXT       Headers to include in access logs
  --error-logs                    Enable S3 error logs in Parquet format
  --error-log-prefix TEXT         S3 prefix for error logs (env: PASSSAGE_ERROR_LOG_PREFIX)
  --error-log-dir TEXT            Local spool directory for error logs
  --error-log-flush-seconds TEXT  Flush interval in seconds for error logs
  --error-log-flush-bytes TEXT    Flush size threshold for error logs
  --health-port INTEGER           Health endpoint port (env: PASSSAGE_HEALTH_PORT, 0 disables)
  --health-host TEXT              Health endpoint bind host (env: PASSSAGE_HEALTH_HOST)
  --web                           Enable mitmproxy web interface
  --version                       Show the version and exit.
  --help                          Show this message and exit.
```

### Access Logs

Passsage can emit structured access logs to S3 as Parquet for diagnostics and performance analysis.

S3 layout:

```
s3://<bucket>/__passsage_logs__/date=YYYY-MM-DD/hour=HH/<file>.parquet
```

Enable logging:

```bash
passsage --access-logs
```

Log UI:

```bash
pip install "passsage[ui]"
passsage logs --start-date 2026-02-01 --end-date 2026-02-02
```

### Error Logs

S3 layout:

```
s3://<bucket>/__passsage_error_logs__/date=YYYY-MM-DD/hour=HH/<file>.parquet
```

Enable error logging:

```bash
passsage --error-logs
```

Error UI:

```bash
pip install "passsage[ui]"
passsage errors --start-date 2026-02-01 --end-date 2026-02-02
```

### As a mitmproxy Script

You can also use Passsage directly as a mitmproxy script:

```bash
mitmproxy -s $(python -c "import passsage; print(passsage.get_proxy_path())")
```

## Docker Development

The easiest way to develop and test Passsage is with Docker Compose, which sets up LocalStack S3 automatically.

### Quick Start

```bash
# Production-like setup
docker compose up --build

# Development setup (with live code editing; mitmproxy reloads proxy on change)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

This starts:
- **LocalStack** S3 on port 4566 with pre-configured `proxy-cache` bucket
- **Passsage** proxy on port 8080
- **Health endpoint** on port 8082 (`/health`)

### Development Workflow

1. Start dev environment: `docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build`
2. Edit code in `src/passsage/`; mitmproxy reloads the proxy on change

See [DEVELOPMENT.md](DEVELOPMENT.md) for the full guide.

## Building and Publishing

### Build the Package

```bash
pip install build
python -m build
```

This creates `dist/passsage-*.whl` and `dist/passsage-*.tar.gz`.

### Publish to PyPI

```bash
pip install twine

# Upload to Test PyPI first
twine upload --repository testpypi dist/*

# Upload to PyPI
twine upload dist/*
```

### Publish to Private PyPI (CodeArtifact, etc.)

```bash
# Configure your repository in ~/.pypirc or use environment variables
twine upload --repository your-repo dist/*
```

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run linter
ruff check src/

# Format code
ruff format src/
```

### Integration tests with Docker Compose

The integration suite expects a running proxy that allows `X-Passsage-Policy` overrides.
Start Passsage with `--allow-policy-header` or set `PASSSAGE_ALLOW_POLICY_HEADER=1`.

```bash
# Default port 8080 and health port 8082
PASSSAGE_ALLOW_POLICY_HEADER=1 docker compose up --build

# Override the host port mappings
PROXY_PORT=9090 HEALTH_PORT=9092 PASSSAGE_ALLOW_POLICY_HEADER=1 docker compose up --build
```

When the proxy runs in a container, the test server must be reachable by Passsage.
On Linux, set the bind host and public host so the proxy can reach the test server:

```bash
export PASSSAGE_TEST_SERVER_BIND_HOST=0.0.0.0
export PASSSAGE_TEST_SERVER_HOST=host.docker.internal
export PROXY_URL=http://localhost:9090
pytest -m "not slow"
```

### Health endpoint

Passsage starts a lightweight HTTP server for health checks on a separate port.

```bash
curl -f http://localhost:8082/health
```

Configure it via environment variables:

```bash
export PASSSAGE_HEALTH_PORT=8082
export PASSSAGE_HEALTH_HOST=0.0.0.0
```

## Policy Overrides

You can override caching policies by pointing Passsage at a Python file. The file
can define a `RULES` list, a `get_rules()` function, or a `get_resolver()` function.
These are evaluated in this order:

1. `get_resolver()` -> return a `PolicyResolver`
2. `get_rules()` -> return a list of rules
3. `RULES` -> a list of rules

The file is loaded at runtime and does not need to be installed as a package.

### Header-based policy override (client-side)

You can force a policy per request by sending the `X-Passsage-Policy` header.
This override is disabled by default and must be enabled on the proxy.

```bash
passsage --allow-policy-header
```

```bash
curl -x http://localhost:8080 \
  -H "X-Passsage-Policy: NoRefresh" \
  http://example.com/data.csv
```

Supported values: `NoRefresh`, `Standard`, `StaleIfError`, `AlwaysUpstream`, `NoCache`.

Security note: this allows clients to bypass normal policy rules. A malicious or
misconfigured client could force caching of sensitive responses or disable caching
to increase upstream load. Only expose the proxy to trusted clients if you rely
on header overrides.

### Use a custom policy file

```bash
passsage --policy-file /path/to/policies.py
```

You can also set the environment variable:

```bash
export PASSSAGE_POLICY_FILE=/path/to/policies.py
passsage
```

### Example: simple rules list

```python
# /path/to/policies.py
from passsage.policy import NoCache, NoRefresh, PathContainsRule, RegexRule

RULES = [
    PathContainsRule("/assets/", NoRefresh),
    RegexRule(r".*\\.csv$", NoRefresh),
    PathContainsRule("/api/private", NoCache),
]
```

### Example: programmatic rules with defaults

```python
# /path/to/policies.py
from passsage.default_policies import default_rules
from passsage.policy import AlwaysUpstream, PathContainsRule

def get_rules():
    rules = default_rules()
    rules.insert(0, PathContainsRule("/debug/", AlwaysUpstream))
    return rules
```

### Example: full resolver with custom default policy

```python
# /path/to/policies.py
from passsage.default_policies import default_rules
from passsage.policy import PolicyResolver, Standard

def get_resolver():
    return PolicyResolver(rules=default_rules(), default_policy=Standard)
```

### Example: dynamic rule based on headers

```python
# /path/to/policies.py
from passsage.policy import CallableRule, Context, NoCache, NoRefresh

def choose_policy(ctx: Context):
    for key, value in (ctx.headers or []):
        if key.lower() == "x-no-cache" and value == "1":
            return NoCache
    return NoRefresh

RULES = [
    CallableRule(choose_policy),
]
```

## License

See `LICENSE` and `NOTICE` for copyright and attribution details.

MIT License - see [LICENSE](LICENSE) for details.
