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
  - Default policy when no rule matches: `Standard` (override via a policy file)
- **Automatic failover**: Serve cached content when upstream is unavailable
- **Presigned URL normalization**: Strip ephemeral signing parameters from cache keys so differently-signed requests share a single cache entry

## Cache hits and misses

Passsage resolves each request to a cache policy, then uses Elasticsearch metadata
and xs3lerator to decide whether to serve from cache or go upstream. In brief:

- GET requests are routed through [xs3lerator](https://github.com/bra-fsn/xs3lerator), which handles
  parallel downloads from both S3 (cache hits) and upstream HTTP servers (cache
  misses), and simultaneously uploads data to S3 on miss. Passsage manages
  metadata only (Elasticsearch indexes, vary indexes).
- HEAD requests are served synthetically from Elasticsearch metadata when fresh,
  or forwarded to xs3lerator otherwise.
- Object metadata is stored in Elasticsearch (`passsage_meta` index) for fast
  real-time lookups by document `_id`. The data objects themselves are immutable
  content-addressed chunks in S3.
- Elasticsearch document `_id` format is `<scheme>/<host>/<sha224>` (or
  `<scheme>/<host>/<sha224>+<vary_sha224>` for vary-aware keys).
  Vary index documents use `<scheme>/<host>/_vary/<sha224>`.
- S3 data keys use hash-prefixed format
  `data/<h>/<a>/<s>/<h>/<sha256>` for content-addressed chunks.
- `NoRefresh` serves from cache immediately on a hit (no revalidation).
- `Standard` revalidates via conditional GET through xs3lerator when stale; if the
  upstream returns 304, the cached object is served. If the content changed, xs3lerator
  fetches and caches the new version.
- `StaleIfError` serves stale cache on upstream failure, and `Standard` honors
  `stale-if-error` / `stale-while-revalidate` directives when present.
- `AlwaysUpstream` always fetches from upstream, even if cached.
- `NoCache` bypasses cache lookup for non-GET/HEAD or policy override.

`Standard` follows RFC 9111 HTTP caching semantics; `stale-if-error` and
`stale-while-revalidate` are supported when present.

On cache misses, the response is fetched from upstream and streamed to the client.
Data fetching and S3 upload is handled by xs3lerator; Passsage only saves metadata
(`.meta` and vary index).
Responses are saved to S3 unless caching is disabled by policy or response headers
(`Cache-Control: no-store` or `private`, or `Vary: *`). When `Vary` is present, cache
keys include the `Vary` request headers so separate variants are stored and served.

## Architecture

A typical deployment uses Passsage as the TLS-terminating policy engine with
xs3lerator handling all data transfer. On a cache hit, Passsage rewrites the
GET request to xs3lerator, which serves the data from S3 using parallel
range-GETs. On a cache miss, xs3lerator fetches from the real upstream with
adaptive parallel downloads and simultaneously uploads to S3. Clients point
`HTTP_PROXY`/`HTTPS_PROXY` at Passsage.

```
┌──────────────┐     ┌──────────────┐     ┌────────────┐
│   Client     │────▶│   Passsage   │────▶│  Upstream   │
│ (pip, curl,  │◀────│ (policy +    │◀────│  Servers    │
│  docker...)  │     │  metadata)   │     │ (PyPI etc)  │
└──────────────┘     └──────┬───────┘     └────────────┘
                            │
                  GET       │   metadata
                  requests  │   read/write
                            ▼
                     ┌──────────────┐        ┌───────────────┐
                     │  xs3lerator  │◀──────▶│    AWS S3     │
                     │ (data plane) │        │   (cache)     │
                     └──────────────┘        └───────────────┘
                                                    ▲
                     ┌──────────────┐               │
                     │Elasticsearch │◀──────────────┘
                     │(passsage_meta│  metadata index
                     │  index)      │
                     └──────────────┘
```

Both `--elasticsearch-url` and `--xs3lerator-url` are required.

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
# Run with required services (Elasticsearch + xs3lerator must be running)
passsage --elasticsearch-url http://localhost:9200 \
    --xs3lerator-url http://localhost:8888

# Run on a specific port
passsage -p 9090 --elasticsearch-url http://localhost:9200 \
    --xs3lerator-url http://localhost:8888

# Run with web interface
passsage --web --elasticsearch-url http://localhost:9200 \
    --xs3lerator-url http://localhost:8888
```

The easiest way to get started is with Docker Compose, which starts all
required services (see [Docker Development](#docker-development)).

### Client Setup (Certificate + Proxy Env Vars)

Passsage runs on mitmproxy, so clients must trust the mitmproxy CA certificate to avoid
TLS errors. Mitmproxy exposes a magic domain, `mitm.it`, which serves the local
certificate authority for download; see https://docs.mitmproxy.org/stable/concepts/certificates/.
The examples below assume a localhost proxy; if you deploy Passsage on an intranet host,
replace `localhost:8080` with the proxy hostname/IP.

1. Start Passsage (example on localhost):

```bash
docker compose up --build
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

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PASSSAGE_PORT` | Proxy listen port | `8080` |
| `PASSSAGE_HOST` | Proxy bind host | `0.0.0.0` |
| `S3_BUCKET` | S3 bucket name for cache storage | `proxy-cache` |
| `S3_ENDPOINT_URL` | Custom S3 endpoint URL | None (uses AWS) |
| `PASSSAGE_MODE` | Proxy mode: `regular`, `transparent`, `wireguard`, or `upstream` | `regular` |
| `PASSSAGE_PUBLIC_PROXY_URL` | Externally reachable proxy URL for the onboarding script (e.g. `http://proxy.example.com:3128`). Required behind a load balancer or in Kubernetes. | None |
| `PASSSAGE_NO_PROXY_EXTRA` | Extra comma-separated hosts to add to `NO_PROXY` in the onboarding script | None |
| `PASSSAGE_ELASTICSEARCH_URL` | Elasticsearch URL for metadata storage (required) | (required) |
| `PASSSAGE_ELASTICSEARCH_META_INDEX` | Elasticsearch index for metadata | `passsage_meta` |
| `PASSSAGE_ELASTICSEARCH_REPLICAS` | Number of ES index replicas | `1` |
| `PASSSAGE_ELASTICSEARCH_SHARDS` | Number of ES index shards | `9` |
| `PASSSAGE_ELASTICSEARCH_FLUSH_INTERVAL` | Interval for batched last_access updates (seconds) | `30` |
| `PASSSAGE_XS3LERATOR_URL` | xs3lerator base URL (required). All GET requests are routed through xs3lerator for parallel downloads and S3 caching. | (required) |
| `PASSSAGE_ACCESS_LOGS` | Enable Parquet access logs | `1` (enabled) |
| `PASSSAGE_ACCESS_LOG_PREFIX` | S3 prefix for access logs | `__passsage_logs__` |
| `PASSSAGE_ACCESS_LOG_DIR` | Local spool dir for access logs | `/tmp/passsage-logs` |
| `PASSSAGE_ACCESS_LOG_FLUSH_SECONDS` | Flush interval in seconds | `30` |
| `PASSSAGE_ACCESS_LOG_FLUSH_BYTES` | Flush size threshold | `1G` |
| `PASSSAGE_ACCESS_LOG_HEADERS` | Headers to include in access logs | `accept,accept-encoding,cache-control,content-type,content-encoding,etag,last-modified,range,user-agent,via,x-cache,x-cache-lookup,x-amz-request-id` |
| `PASSSAGE_ERROR_LOGS` | Enable Parquet error logs | `1` (enabled) |
| `PASSSAGE_ERROR_LOG_PREFIX` | S3 prefix for error logs | `__passsage_error_logs__` |
| `PASSSAGE_ERROR_LOG_DIR` | Local spool dir for error logs | `/tmp/passsage-errors` |
| `PASSSAGE_ERROR_LOG_FLUSH_SECONDS` | Flush interval in seconds | `30` |
| `PASSSAGE_ERROR_LOG_FLUSH_BYTES` | Flush size threshold | `256M` |
| `PASSSAGE_CONNECTION_STRATEGY` | Mitmproxy connection strategy: `lazy` (default) or `eager` | `lazy` |
| `PASSSAGE_MITM_CA_CERT` | mitmproxy CA certificate (PEM file path or inline PEM). Written to `~/.mitmproxy/mitmproxy-ca-cert.pem` before startup. | None |
| `PASSSAGE_MITM_CA` | mitmproxy CA key+cert bundle (PEM file path or inline PEM). Written to `~/.mitmproxy/mitmproxy-ca.pem` before startup. | None |
| `PASSSAGE_VERBOSE` | Enable verbose logging | `0` |
| `PASSSAGE_DEBUG` | Enable debug logging for proxy internals | `0` |
| `PASSSAGE_DEBUG_PROXY` | Enable debug logging for passsage proxy only | `0` |
| `PASSSAGE_WEB` | Enable mitmproxy web interface | `0` |
| `PASSSAGE_POLICY_FILE` | Path to Python file defining policy overrides | None |
| `PASSSAGE_ALLOW_POLICY_HEADER` | Allow client policy override via `X-Passsage-Policy` header | `0` |
| `PASSSAGE_S3_HASH_PREFIX_DEPTH` | Number of hash characters to use as S3 path prefix segments (e.g. 4 produces `f/f/3/0/hash...`). Distributes objects across prefixes to avoid S3 throttling. | `4` |

### CLI Options

```
Usage: passsage [OPTIONS] COMMAND [ARGS]...

  Passsage (Pas³age) - S3-backed caching proxy.

Options:
  -p, --port INTEGER              Port to listen on (env: PASSSAGE_PORT, default: 8080)
  -b, --bind TEXT                 Address to bind to (env: PASSSAGE_HOST, default: 0.0.0.0)
  --s3-bucket TEXT                S3 bucket for cache storage (env: S3_BUCKET)
  --s3-endpoint TEXT              S3 endpoint URL for S3-compatible services (env: S3_ENDPOINT_URL)
  -m, --mode [regular|transparent|wireguard|upstream]
                                  Proxy mode (env: PASSSAGE_MODE, default: regular)
  -v, --verbose                   Enable verbose logging (env: PASSSAGE_VERBOSE)
  --debug                         Enable debug logging for proxy internals (env: PASSSAGE_DEBUG)
  --debug-proxy                   Enable debug logging for passsage proxy only
                                  (env: PASSSAGE_DEBUG_PROXY)
  --web                           Enable mitmproxy web interface (env: PASSSAGE_WEB)
  --policy-file TEXT              Path to Python file defining policy overrides
                                  (env: PASSSAGE_POLICY_FILE)
  --allow-policy-header           Allow client policy override via X-Passsage-Policy
                                  (env: PASSSAGE_ALLOW_POLICY_HEADER)
  --public-proxy-url TEXT         Public proxy URL embedded in mitm.it/proxy-env responses
                                  (env: PASSSAGE_PUBLIC_PROXY_URL)
  --no-proxy-extra TEXT           Extra comma-separated hosts to add to NO_PROXY in
                                  mitm.it/proxy-env responses (env: PASSSAGE_NO_PROXY_EXTRA)
  --access-logs / --no-access-logs
                                  Enable S3 access logs in Parquet format (default: enabled)
                                  (env: PASSSAGE_ACCESS_LOGS)
  --access-log-prefix TEXT        S3 prefix for access logs (env: PASSSAGE_ACCESS_LOG_PREFIX)
  --access-log-dir TEXT           Local spool directory for access logs
  --access-log-flush-seconds TEXT Flush interval in seconds for access logs
  --access-log-flush-bytes TEXT   Flush size threshold for access logs
  --access-log-headers TEXT       Headers to include in access logs
  --error-logs / --no-error-logs  Enable S3 error logs in Parquet format (default: enabled)
                                  (env: PASSSAGE_ERROR_LOGS)
  --error-log-prefix TEXT         S3 prefix for error logs (env: PASSSAGE_ERROR_LOG_PREFIX)
  --error-log-dir TEXT            Local spool directory for error logs
  --error-log-flush-seconds TEXT  Flush interval in seconds for error logs
  --error-log-flush-bytes TEXT    Flush size threshold for error logs
  --health-port INTEGER           Health endpoint port (env: PASSSAGE_HEALTH_PORT, 0 disables)
  --health-host TEXT              Health endpoint bind host (env: PASSSAGE_HEALTH_HOST)
  --connection-strategy [lazy|eager]
                                  Upstream TLS connection strategy (default: lazy)
  --mitm-ca-cert TEXT             mitmproxy CA certificate (PEM path or inline)
                                  (env: PASSSAGE_MITM_CA_CERT)
  --mitm-ca TEXT                  mitmproxy CA key+cert bundle (PEM path or inline)
                                  (env: PASSSAGE_MITM_CA)
  --elasticsearch-url TEXT        Elasticsearch URL for metadata (required)
                                  (env: PASSSAGE_ELASTICSEARCH_URL)
  --elasticsearch-meta-index TEXT ES index name (default: passsage_meta)
                                  (env: PASSSAGE_ELASTICSEARCH_META_INDEX)
  --elasticsearch-replicas INT    Number of ES replicas (default: 1)
                                  (env: PASSSAGE_ELASTICSEARCH_REPLICAS)
  --elasticsearch-shards INT      Number of ES shards (default: 9)
                                  (env: PASSSAGE_ELASTICSEARCH_SHARDS)
  --elasticsearch-flush-interval FLOAT
                                  Batch flush interval seconds (default: 30)
                                  (env: PASSSAGE_ELASTICSEARCH_FLUSH_INTERVAL)
  --xs3lerator-url TEXT           xs3lerator base URL (required). All GET requests are routed
                                  through xs3lerator for parallel downloads and S3 caching.
                                  (env: PASSSAGE_XS3LERATOR_URL)
  --s3-hash-prefix-depth INT      Hash prefix depth for S3 key partitioning (default: 4)
                                  (env: PASSSAGE_S3_HASH_PREFIX_DEPTH)
  --version                       Show the version and exit.
  --help                          Show this message and exit.

Commands:
  cache-keys  Detect query parameters that fragment the cache.
  errors      Browse or export error logs.
  logs        Browse or export access logs.
```

### Access Logs

Passsage can emit structured access logs to S3 as Parquet for diagnostics and performance analysis.

S3 layout:

```
s3://<bucket>/__passsage_logs__/date=YYYY-MM-DD/hour=HH/<file>.parquet
```

Enable logging:

```bash
# Access and error logs are enabled by default. To disable:
passsage --no-access-logs
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
# Error logs are enabled by default. To disable:
passsage --no-error-logs
```

Error UI:

```bash
pip install "passsage[ui]"
passsage errors --start-date 2026-02-01 --end-date 2026-02-02
```

### Cache Key Analysis

The `cache-keys` subcommand scans access logs for query parameters that fragment
the cache and cause unnecessary misses. It identifies parameters with many
distinct values appearing across multiple URL paths — strong candidates for
cache key stripping (e.g. tracking IDs, session tokens, cache-busters).

```bash
pip install "passsage[ui]"

# Analyze today's logs
passsage cache-keys --s3-bucket my-proxy-cache

# Analyze a date range with stricter thresholds
passsage cache-keys --start-date 2026-02-01 --end-date 2026-02-10 \
    --min-distinct 50 --min-misses 500
```

### Health and Debug Endpoints

Passsage starts a lightweight HTTP server for health checks and diagnostics on
a separate port (default 8082).

| Endpoint | Description |
|---|---|
| `/health` | S3 bucket connectivity check. Returns 200 if healthy, 503 otherwise. |
| `/debug/threads` | Dumps all Python thread tracebacks. |
| `/debug/connections` | Dumps TCP connections from `/proc/net/tcp`. |
| `/debug/memory` | GC object type profiling and RSS info. Append `?tracemalloc` for a tracemalloc snapshot. |

```bash
curl -f http://localhost:8082/health
curl http://localhost:8082/debug/threads
curl http://localhost:8082/debug/memory
```

Configure via environment variables:

```bash
export PASSSAGE_HEALTH_PORT=8082   # set to 0 to disable
export PASSSAGE_HEALTH_HOST=0.0.0.0
```

### As a mitmproxy Script

You can also use Passsage directly as a mitmproxy script:

```bash
mitmproxy -s $(python -c "import passsage; print(passsage.get_proxy_path())")
```

## Docker Development

The easiest way to develop and test Passsage is with Docker Compose, which sets up all required services automatically.

### Quick Start

```bash
# Production-like setup
docker compose up --build

# Development setup (with live code editing; mitmproxy reloads proxy on change)
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

This starts:
- **LocalStack** S3 on port 4566 with pre-configured `proxy-cache` bucket
- **Elasticsearch** on port 9200 (single-node, metadata storage)
- **xs3lerator** on port 8888 (data plane: parallel downloads + S3 caching)
- **Passsage** proxy on port 8080, health endpoint on port 8082

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

## Content Delivery Services

Passsage ships with built-in handling for common content delivery and object
storage services. Two mechanisms work together to make caching effective:
**URL normalization** removes ephemeral query parameters so that different
signed URLs for the same object produce a single cache entry, and **default
caching policies** assign a sensible policy to well-known hosts.

### Presigned URL normalization

Object storage services authenticate access through _presigned URLs_ — URLs
that embed short-lived credentials, timestamps, and signatures as query
parameters. Each request for the same object carries a different set of
parameters, which would produce a unique cache key and defeat caching entirely.

Passsage normalizes presigned URLs by stripping the signature-related query
parameters _before_ computing the cache key. The original URL (with all
parameters intact) is still used when talking to the upstream server, so
authentication continues to work. Only the cache key sees the stripped version.

Signing parameters are stripped from **all URLs** regardless of host, since the
parameter names are unambiguous credentials/signatures:

| Signing scheme | Stripped parameters |
|---|---|
| AWS Signature V4 (S3, R2, HuggingFace xethub, etc.) | All `X-Amz-*` params (Algorithm, Credential, Date, Expires, Signature, Security-Token, SignedHeaders, ...) |
| AWS CloudFront signed URLs | `Expires`, `Policy`, `Signature`, `Key-Pair-Id` |
| Azure SAS tokens (GitHub Container Registry, Azure Blob, etc.) | `se`, `sig`, `sp`, `spr`, `sr`, `sv`, `ske`, `skoid`, `sks`, `skt`, `sktid`, `skv`, `hmac` |

After stripping, any remaining query parameters are sorted by key to avoid
cache misses from different parameter orderings.

**Why this matters for CI/CD pipelines**: build jobs typically depend on
artifacts hosted on these services — container base images, Python packages,
Debian packages, pre-built binaries. During high-load periods (e.g. security
patch rollouts, popular release days), upstream registries can become slow or
return transient errors. Because Passsage collapses all presigned variants of
the same object into one cache entry, a single successful fetch serves every
subsequent build. Combined with the `StaleIfError` policy, pipelines keep
running from cache even while the upstream is struggling.

### Default caching policies

Passsage assigns caching policies to known hosts and URL patterns out of the
box. These defaults can be overridden with a policy file (see _Policy
Overrides_ below).

| Pattern | Policy | Rationale |
|---|---|---|
| `*.files.pythonhosted.org` | `StaleIfError` | PyPI package files are immutable once published |
| `pypi.org/simple/*` | `StaleIfError` + forced SWR (24h) | Simple index pages; stale index is better than a build failure. Background revalidation keeps the index fresh without blocking requests. |
| `*.deb`, `/Packages`, `/Packages.gz`, `/Packages.xz`, `/InRelease`, APT by-hash paths | `StaleIfError` | Debian/Ubuntu repository metadata and packages |
| `mran.microsoft.com/snapshot/*` | `StaleIfError` | MRAN R package snapshots |
| `*.amazonaws.com` (except CodeArtifact) | `NoCache` | S3 API calls, STS tokens — must not be cached |
| Cloud metadata endpoints (`169.254.169.*`, `169.254.170.*`, `100.100.100.*`, Azure/GCP metadata) | `NoCache` | Instance metadata must always be live |
| `/mitm.it/*` | `NoCache` | mitmproxy's own certificate distribution page |

### Extending normalization rules

Add custom cache key rules via a policy file (the same file used for policy
overrides):

```python
# /path/to/policies.py
from passsage.cache_key import CallableRule

def strip_my_cdn_token(ctx):
    if ctx.host and "cdn.example.com" in ctx.host:
        return ctx.url.split("?", 1)[0]
    return None

def get_cache_key_rules():
    return [CallableRule(strip_my_cdn_token)]
```

Export one of `get_cache_key_rules()`, `CACHE_KEY_RULES`,
`get_cache_key_resolver()`, or `CACHE_KEY_RESOLVER` from the file. See
`default_cache_keys.py` for the full built-in implementation.

## Important: Do Not Use S3 Object Expiration

**Never enable S3 lifecycle expiration rules on the whole cache bucket (you can expire the logs though).** Passsage
stores each cached response as an S3 object with associated metadata: a vary
index object (`_vary/` prefix). S3 lifecycle rules delete objects
independently — an expiration rule could remove the vary index but leave
the content object (or vice versa). This leads to cache corruption: stale
metadata pointing to missing content, or orphaned content with no metadata.

If you need to control cache size, use a cleanup script that deletes all
related objects atomically (content + vary index), or use
S3 Intelligent-Tiering to move cold objects to cheaper storage without
deleting them.

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

### Upstream Timeout Overrides

When Passsage is deployed with xs3lerator, you can configure per-rule upstream
timeouts. These override xs3lerator's server-wide defaults (`--upstream-connect-timeout`
and `--upstream-read-timeout`) on a per-request basis.

xs3lerator defaults to a 30 s connect timeout and a 300 s (5 min) read timeout,
matching common HTTP clients like pip and curl. Rules can tighten or relax these
as needed.

Timeouts are specified with `TimeoutConfig` and attached to any rule type via
the `timeouts` keyword argument:

```python
# /path/to/policies.py
from passsage.default_policies import default_rules
from passsage.policy import (
    HostContainsRule,
    PolicyResolver,
    StaleIfError,
    Standard,
    SuffixRule,
    TimeoutConfig,
)

def get_rules():
    rules = default_rules()

    # Large ML model files: allow up to 15 min read timeout
    rules.insert(0, SuffixRule(
        ".safetensors",
        StaleIfError,
        timeouts=TimeoutConfig(read_timeout=900),
    ))

    # Slow internal registry: longer connect + read timeouts
    rules.insert(0, HostContainsRule(
        "registry.internal.example.com",
        StaleIfError,
        timeouts=TimeoutConfig(connect_timeout=60, read_timeout=600),
    ))

    # Fast API that should fail quickly
    rules.insert(0, HostContainsRule(
        "api.example.com",
        Standard,
        timeouts=TimeoutConfig(connect_timeout=5, read_timeout=30),
    ))

    return rules
```

`TimeoutConfig` fields:

| Field | Type | Meaning |
|---|---|---|
| `connect_timeout` | `float \| None` | TCP/TLS handshake timeout in seconds. `None` = use xs3lerator default (30 s). |
| `read_timeout` | `float \| None` | Idle time between data chunks in seconds. `None` = use xs3lerator default (300 s). `0` = no timeout. |

Under the hood, Passsage sends `X-Xs3lerator-Connect-Timeout` and
`X-Xs3lerator-Read-Timeout` headers on the rewritten request. xs3lerator
creates (or reuses) an HTTP client configured with those timeouts. The
headers are stripped from client responses.

## License

See `LICENSE` and `NOTICE` for copyright and attribution details.

MIT License - see [LICENSE](LICENSE) for details.
