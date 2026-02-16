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

- **With xs3lerator** (`--xs3lerator-url`): GET requests are routed through
  [xs3lerator](../xs3lerator/), which handles parallel downloads from both S3
  (cache hits) and upstream HTTP servers (cache misses), and simultaneously
  uploads data to S3 on miss. Passsage manages metadata only (`.meta` JSON,
  vary indexes, memcached). HEAD requests are served synthetically from
  memcached metadata when fresh, or via direct upstream HEAD otherwise.
- **Without xs3lerator** (legacy mode): cache hits are fetched from an HTTP
  object store (`--object-store-url`, required). Passsage uploads data to S3
  on cache miss.
- Object metadata is stored in separate `.meta` JSON objects in S3 and cached in
  memcached for fast lookups. The data objects themselves are immutable.
- S3 cache keys use hash-prefixed format
  `<scheme>/<host>/<h>/<a>/<s>/<h>/<sha224>[.<ext>]`
  (e.g. `https/ftp.bme.hu/f/f/3/0/ff30f95e...56.iso`). The hash prefix depth
  is configurable (`--s3-hash-prefix-depth`, default 4) and distributes objects
  across 65,536 S3 prefixes to avoid per-prefix throttling. Metadata lives at
  `<key>.meta`. Vary-aware keys append `+<sha224-of-vary-values>`.
  Vary index objects live under `<scheme>/<host>/_vary/<h>/<a>/<s>/<h>/`.
  Memcached keys remain unprefixed.
- `NoRefresh` serves from cache immediately on a hit (no revalidation).
- `Standard` revalidates with an upstream `HEAD` when stale; if the cached `ETag`/`Last-Modified`
  matches, the cached object is served.
- `StaleIfError` serves stale cache on upstream failure, and `Standard` honors
  `stale-if-error` / `stale-while-revalidate` directives when present.
- `AlwaysUpstream` always fetches from upstream, even if cached.
- `NoCache` bypasses cache lookup for non-GET/HEAD or policy override.

`Standard` follows RFC 9111 HTTP caching semantics; `stale-if-error` and
`stale-while-revalidate` are supported when present.

On cache misses, the response is fetched from upstream and streamed to the client.
With xs3lerator enabled, data fetching and S3 upload is handled by xs3lerator;
Passsage only saves metadata (`.meta` and vary index). Without xs3lerator,
Passsage uploads the data to S3 itself.
Responses are saved to S3 unless caching is disabled by policy or response headers
(`Cache-Control: no-store` or `private`, or `Vary: *`). When `Vary` is present, cache
keys include the `Vary` request headers so separate variants are stored and served.

## Example production setup

A typical deployment uses Passsage as the TLS-terminating policy engine with
xs3lerator handling all data transfer. On a cache hit, Passsage rewrites the
GET request to xs3lerator, which serves the data from S3 using parallel
range-GETs. On a cache miss, xs3lerator fetches from the real upstream with
adaptive parallel downloads and simultaneously uploads to S3. Clients point
`HTTP_PROXY`/`HTTPS_PROXY` at Passsage.

```
                                             ┌────────────┐
                                        ┌───▶│  Upstream  │
                                        │ ◀──│  Servers   │
                                        │    │ (PyPI etc) │
┌──────────────┐     ┌──────────────┐   │    └────────────┘
│   Client     │────▶│   Passsage   │   │
│ (pip, curl,  │◀────│ (policy +    │   │
│  docker...)  │     │  metadata)   │   │
└──────────────┘     └──────┬───────┘   │
                            │           │
                  GET       │           │
                  requests  │           │
                            ▼           │
                     ┌──────────────┐   │    ┌──────────┐
                     │  xs3lerator  │───┘    │  AWS S3  │
                     │ (data plane) │◀──────▶│ (cache)  │
                     └──────────────┘        └──────────┘
                            │
                   metadata │  .meta JSON
                   only     │  vary index
                            │  memcached
                            ▼
                     ┌──────────────┐
                     │  Passsage    │
                     │ (writes meta │
                     │  to S3 +    │
                     │  memcached)  │
                     └──────────────┘
```

For deployments without xs3lerator (legacy mode), Passsage can still use an
HTTP object store directly:

```
┌──────────────┐     ┌──────────────────────┐     ┌────────────┐
│   Client     │────▶│   Passsage           │────▶│  Upstream  │
│ (pip, curl,  │◀────│   (caching proxy)    │◀────│  Servers   │
│  docker...)  │     │   :3128              │     │ (PyPI etc) │
└──────────────┘     └──────┬──────┬────────┘     └────────────┘
                            │      │
                   fetches  │      │  writes cached objects +
                   cached   │      │  .meta JSON + vary index
                   objects  │      │
                            │      ▼
                            │  ┌──────────┐
                            │  │  AWS S3  │
                            │  │ (cache)  │
                            │  └──────────┘
                            │
                            ▼
                     ┌──────────────────────┐
                     │   Object Store HTTP  │
                     │  (S3 public bucket,  │
                     │   nginx, or similar) │
                     └──────────────────────┘
```

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
passsage --s3-endpoint http://localhost:4566 --s3-bucket proxy-cache \
    --object-store-url http://localhost:4566/proxy-cache
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PASSSAGE_PORT` | Proxy listen port | `8080` |
| `PASSSAGE_HOST` | Proxy bind host | `0.0.0.0` |
| `S3_BUCKET` | S3 bucket name for cache storage | `364189071156-ds-proxy-us-west-2` (AWS) or `proxy-cache` (custom endpoint) |
| `S3_ENDPOINT_URL` | Custom S3 endpoint URL | None (uses AWS) |
| `PASSSAGE_PUBLIC_PROXY_URL` | Externally reachable proxy URL for the onboarding script (e.g. `http://proxy.example.com:3128`). Required behind a load balancer or in Kubernetes. | None |
| `PASSSAGE_OBJECT_STORE_URL` | HTTP URL of the object store exposing the S3 cache namespace (required). Cache hits are fetched from this URL. | (required) |
| `PASSSAGE_MEMCACHED_SERVERS` | Comma-separated memcached servers (host:port) for metadata caching. | None |
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
| `PASSSAGE_CONNECTION_STRATEGY` | Mitmproxy connection strategy: `lazy` (default) or `eager` | `lazy` |
| `PASSSAGE_MITM_CA_CERT` | mitmproxy CA certificate (PEM file path or inline PEM). Written to `~/.mitmproxy/mitmproxy-ca-cert.pem` before startup. | None |
| `PASSSAGE_MITM_CA` | mitmproxy CA key+cert bundle (PEM file path or inline PEM). Written to `~/.mitmproxy/mitmproxy-ca.pem` before startup. | None |
| `PASSSAGE_XS3LERATOR_URL` | xs3lerator base URL (e.g. `http://localhost:8080`). When set, GET requests are routed through xs3lerator for parallel download and S3 caching. | None (disabled) |
| `PASSSAGE_S3_HASH_PREFIX_DEPTH` | Number of hash characters to use as S3 path prefix segments (e.g. 4 produces `f/f/3/0/hash...`). Distributes objects across prefixes to avoid S3 throttling. | `4` |

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
  --object-store-url TEXT         HTTP URL of the object store (required)
                                  (env: PASSSAGE_OBJECT_STORE_URL)
  --memcached-servers TEXT        Comma-separated memcached servers (host:port)
                                  (env: PASSSAGE_MEMCACHED_SERVERS)
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
  --connection-strategy [lazy|eager]
                                  Upstream TLS connection strategy (default: lazy)
  --xs3lerator-url TEXT          xs3lerator base URL for parallel GET downloads and S3 caching
                                  (env: PASSSAGE_XS3LERATOR_URL)
  --s3-hash-prefix-depth INT    Hash prefix depth for S3 key partitioning (default: 4)
                                  (env: PASSSAGE_S3_HASH_PREFIX_DEPTH)
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

Normalization rules are applied based on the request hostname using a suffix
trie for fast matching. The built-in rules cover:

| Service / host suffix | Stripped parameters |
|---|---|
| `*.amazonaws.com` (S3, CloudFront signed URLs) | All `X-Amz-*` params (Algorithm, Credential, Date, Expires, Signature, Security-Token, SignedHeaders, …) |
| `*.r2.cloudflarestorage.com` (Cloudflare R2) | All `X-Amz-*` params (R2 uses S3-compatible signing) |
| `*.production.cloudflare.docker.com` (Cloudflare Docker registry) | `expires`, `signature`, `version` |
| `*.pkg-containers.githubusercontent.com` (GitHub Container Registry blobs) | Azure SAS token params: `se`, `sig`, `sp`, `spr`, `sr`, `sv`, `ske`, `skoid`, `sks`, `skt`, `sktid`, `skv`, `hmac` |

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
| `pypi.org/simple/*` | `StaleIfError` | Simple index pages; stale index is better than a build failure |
| `*.deb`, `/Packages`, `/Packages.gz`, `/Packages.xz`, `/InRelease`, APT by-hash paths | `StaleIfError` | Debian/Ubuntu repository metadata and packages |
| `mran.microsoft.com/snapshot/*` | `StaleIfError` | MRAN R package snapshots |
| `*.amazonaws.com` (except CodeArtifact) | `NoCache` | S3 API calls, STS tokens — must not be cached |
| Cloud metadata endpoints (`169.254.169.*`, `169.254.170.*`, Azure/GCP metadata) | `NoCache` | Instance metadata must always be live |
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

## License

See `LICENSE` and `NOTICE` for copyright and attribution details.

MIT License - see [LICENSE](LICENSE) for details.
