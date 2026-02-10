"""Command-line interface for Passsage."""

import logging
import os
import sys
from datetime import date
from pathlib import Path

import click


@click.group(invoke_without_command=True)
@click.option(
    "-p", "--port",
    default=8080,
    type=int,
    envvar="PASSSAGE_PORT",
    show_default=True,
    help="Port to listen on (env: PASSSAGE_PORT, default: 8080)"
)
@click.option(
    "-b", "--bind",
    default="0.0.0.0",
    envvar="PASSSAGE_HOST",
    show_default=True,
    help="Address to bind to (env: PASSSAGE_HOST, default: 0.0.0.0)"
)
@click.option(
    "--s3-bucket",
    envvar="S3_BUCKET",
    show_default=True,
    help="S3 bucket for cache storage (env: S3_BUCKET)"
)
@click.option(
    "--s3-endpoint",
    envvar="S3_ENDPOINT_URL",
    show_default=True,
    help="S3 endpoint URL for S3-compatible services (env: S3_ENDPOINT_URL)"
)
@click.option(
    "--test",
    is_flag=True,
    default=False,
    envvar="PASSSAGE_TEST",
    show_default=True,
    help="Run in test mode (banned sites are not released) (env: PASSSAGE_TEST)"
)
@click.option(
    "-m", "--mode",
    type=click.Choice(["regular", "transparent", "wireguard", "upstream"]),
    default="regular",
    envvar="PASSSAGE_MODE",
    show_default=True,
    help="Proxy mode (default: regular) (env: PASSSAGE_MODE)"
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    envvar="PASSSAGE_VERBOSE",
    show_default=True,
    help="Enable verbose logging (env: PASSSAGE_VERBOSE)"
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    envvar="PASSSAGE_DEBUG",
    show_default=True,
    help="Enable debug logging for proxy internals (env: PASSSAGE_DEBUG)"
)
@click.option(
    "--debug-proxy",
    is_flag=True,
    default=False,
    show_default=True,
    envvar="PASSSAGE_DEBUG_PROXY",
    help="Enable debug logging for passsage proxy only (env: PASSSAGE_DEBUG_PROXY)"
)
@click.option(
    "--web",
    is_flag=True,
    default=False,
    envvar="PASSSAGE_WEB",
    show_default=True,
    help="Enable mitmproxy web interface (env: PASSSAGE_WEB)"
)
@click.option(
    "--policy-file",
    envvar="PASSSAGE_POLICY_FILE",
    show_default=True,
    help="Path to Python file defining policy overrides (env: PASSSAGE_POLICY_FILE)"
)
@click.option(
    "--allow-policy-header",
    is_flag=True,
    default=False,
    envvar="PASSSAGE_ALLOW_POLICY_HEADER",
    show_default=True,
    help="Allow client policy override via X-Passsage-Policy (env: PASSSAGE_ALLOW_POLICY_HEADER)"
)
@click.option(
    "--cache-redirect",
    is_flag=True,
    default=False,
    envvar="PASSSAGE_CACHE_REDIRECT",
    show_default=True,
    help="Redirect cache hits to S3 instead of streaming through the proxy (env: PASSSAGE_CACHE_REDIRECT)"
)
@click.option(
    "--s3-proxy-url",
    envvar="PASSSAGE_S3_PROXY_URL",
    default="",
    show_default=True,
    help="On cache hit, redirect to this S3 proxy URL instead of S3 directly. "
    "Requires --cache-redirect. (env: PASSSAGE_S3_PROXY_URL)"
)
@click.option(
    "--no-redirect-user-agents",
    envvar="PASSSAGE_NO_REDIRECT_USER_AGENTS",
    default="pip/",
    show_default=True,
    help="Comma-separated list of User-Agent prefixes that should not receive "
    "cache-hit redirects. Matching clients are served through the proxy instead. "
    "Useful for clients like pip that ignore NO_PROXY. "
    "(env: PASSSAGE_NO_REDIRECT_USER_AGENTS)"
)
@click.option(
    "--cache-redirect-signed-url/--cache-redirect-public",
    envvar="PASSSAGE_CACHE_REDIRECT_SIGNED_URL",
    default=True,
    show_default=True,
    help="Redirect cache hits to signed S3 URLs (env: PASSSAGE_CACHE_REDIRECT_SIGNED_URL)"
)
@click.option(
    "--cache-redirect-signed-url-expires",
    type=int,
    default=3600,
    envvar="PASSSAGE_CACHE_REDIRECT_SIGNED_URL_EXPIRES",
    show_default=True,
    help="Presigned URL expiration in seconds (env: PASSSAGE_CACHE_REDIRECT_SIGNED_URL_EXPIRES)",
)
@click.option(
    "--presigned-url-cache-maxsize",
    type=int,
    default=10000,
    envvar="PASSSAGE_PRESIGNED_URL_CACHE_MAXSIZE",
    show_default=True,
    help="Max entries for presigned URL TTL cache (env: PASSSAGE_PRESIGNED_URL_CACHE_MAXSIZE)",
)
@click.option(
    "--public-proxy-url",
    envvar="PASSSAGE_PUBLIC_PROXY_URL",
    default="",
    show_default=True,
    help="Public proxy URL embedded in mitm.it/proxy-env responses (env: PASSSAGE_PUBLIC_PROXY_URL)"
)
@click.option(
    "--access-logs",
    is_flag=True,
    default=True,
    envvar="PASSSAGE_ACCESS_LOGS",
    show_default=True,
    help="Enable S3 access logs in Parquet format (env: PASSSAGE_ACCESS_LOGS)"
)
@click.option(
    "--access-log-prefix",
    envvar="PASSSAGE_ACCESS_LOG_PREFIX",
    default="__passsage_logs__",
    show_default=True,
    help="S3 prefix for access logs (env: PASSSAGE_ACCESS_LOG_PREFIX)",
)
@click.option(
    "--access-log-dir",
    envvar="PASSSAGE_ACCESS_LOG_DIR",
    default="/tmp/passsage-logs",
    show_default=True,
    help="Local spool directory for access logs (env: PASSSAGE_ACCESS_LOG_DIR)",
)
@click.option(
    "--access-log-flush-seconds",
    envvar="PASSSAGE_ACCESS_LOG_FLUSH_SECONDS",
    default="30",
    show_default=True,
    help="Flush interval in seconds for access logs (env: PASSSAGE_ACCESS_LOG_FLUSH_SECONDS)",
)
@click.option(
    "--access-log-flush-bytes",
    envvar="PASSSAGE_ACCESS_LOG_FLUSH_BYTES",
    default="1G",
    show_default=True,
    help="Flush size threshold for access logs (env: PASSSAGE_ACCESS_LOG_FLUSH_BYTES)",
)
@click.option(
    "--access-log-headers",
    envvar="PASSSAGE_ACCESS_LOG_HEADERS",
    default="accept,accept-encoding,cache-control,content-type,content-encoding,"
    "etag,last-modified,range,user-agent,via,x-cache,x-cache-lookup,x-amz-request-id",
    show_default=True,
    help="Headers to include in access logs (env: PASSSAGE_ACCESS_LOG_HEADERS)",
)
@click.option(
    "--error-logs",
    is_flag=True,
    default=True,
    envvar="PASSSAGE_ERROR_LOGS",
    show_default=True,
    help="Enable S3 error logs with tracebacks in Parquet format (env: PASSSAGE_ERROR_LOGS)",
)
@click.option(
    "--error-log-prefix",
    envvar="PASSSAGE_ERROR_LOG_PREFIX",
    default="__passsage_error_logs__",
    show_default=True,
    help="S3 prefix for error logs (env: PASSSAGE_ERROR_LOG_PREFIX)",
)
@click.option(
    "--error-log-dir",
    envvar="PASSSAGE_ERROR_LOG_DIR",
    default="/tmp/passsage-errors",
    show_default=True,
    help="Local spool directory for error logs (env: PASSSAGE_ERROR_LOG_DIR)",
)
@click.option(
    "--error-log-flush-seconds",
    envvar="PASSSAGE_ERROR_LOG_FLUSH_SECONDS",
    default="30",
    show_default=True,
    help="Flush interval in seconds for error logs (env: PASSSAGE_ERROR_LOG_FLUSH_SECONDS)",
)
@click.option(
    "--error-log-flush-bytes",
    envvar="PASSSAGE_ERROR_LOG_FLUSH_BYTES",
    default="256M",
    show_default=True,
    help="Flush size threshold for error logs (env: PASSSAGE_ERROR_LOG_FLUSH_BYTES)",
)
@click.option(
    "--health-port",
    envvar="PASSSAGE_HEALTH_PORT",
    type=int,
    default=8082,
    show_default=True,
    help="Health endpoint port (env: PASSSAGE_HEALTH_PORT, 0 disables)"
)
@click.option(
    "--health-host",
    envvar="PASSSAGE_HEALTH_HOST",
    default="0.0.0.0",
    show_default=True,
    help="Health endpoint bind host (env: PASSSAGE_HEALTH_HOST)"
)
@click.option(
    "--mitm-ca-cert",
    envvar="PASSSAGE_MITM_CA_CERT",
    default=None,
    help="mitmproxy CA certificate (PEM file path or inline PEM). "
    "Written to ~/.mitmproxy/mitmproxy-ca-cert.pem before startup. "
    "(env: PASSSAGE_MITM_CA_CERT)"
)
@click.option(
    "--mitm-ca",
    envvar="PASSSAGE_MITM_CA",
    default=None,
    help="mitmproxy CA key+cert bundle (PEM file path or inline PEM). "
    "Written to ~/.mitmproxy/mitmproxy-ca.pem before startup. "
    "(env: PASSSAGE_MITM_CA)"
)
@click.version_option()
@click.pass_context
def main(
    ctx,
    port,
    bind,
    s3_bucket,
    s3_endpoint,
    test,
    mode,
    verbose,
    debug,
    debug_proxy,
    web,
    policy_file,
    allow_policy_header,
    cache_redirect,
    s3_proxy_url,
    no_redirect_user_agents,
    cache_redirect_signed_url,
    cache_redirect_signed_url_expires,
    presigned_url_cache_maxsize,
    public_proxy_url,
    access_logs,
    access_log_prefix,
    access_log_dir,
    access_log_flush_seconds,
    access_log_flush_bytes,
    access_log_headers,
    error_logs,
    error_log_prefix,
    error_log_dir,
    error_log_flush_seconds,
    error_log_flush_bytes,
    health_port,
    health_host,
    mitm_ca_cert,
    mitm_ca,
):
    """
    Passsage (Pas³age) - S3-backed caching proxy.

    A caching HTTP proxy that stores responses in S3 or S3-compatible storage.
    Objects are cached based on configurable policies (NoRefresh, Standard,
    StaleIfError, AlwaysUpstream, NoCache).

    \b
    Examples:
        # Run with default settings (uses AWS S3)
        passsage

        # Run with LocalStack
        passsage --s3-endpoint http://localhost:4566 --s3-bucket proxy-cache

        # Run with web interface on custom port
        passsage -p 9090 --web

        # Run in transparent mode
        passsage -m transparent
    """
    if ctx.invoked_subcommand is None:
        if s3_proxy_url and not cache_redirect:
            raise click.UsageError(
                "--s3-proxy-url requires --cache-redirect"
            )
        run_proxy(
            port,
            bind,
            s3_bucket,
            s3_endpoint,
            test,
            mode,
            verbose,
            debug,
            debug_proxy,
            web,
            policy_file,
            allow_policy_header,
            cache_redirect,
            s3_proxy_url,
            no_redirect_user_agents,
            cache_redirect_signed_url,
            cache_redirect_signed_url_expires,
            presigned_url_cache_maxsize,
            public_proxy_url,
            access_logs,
            access_log_prefix,
            access_log_dir,
            access_log_flush_seconds,
            access_log_flush_bytes,
            access_log_headers,
            error_logs,
            error_log_prefix,
            error_log_dir,
            error_log_flush_seconds,
            error_log_flush_bytes,
            health_port,
            health_host,
            mitm_ca_cert,
            mitm_ca,
        )


def _read_pem_value(value):
    """Read PEM content from a file path or return inline PEM directly."""
    if value.lstrip().startswith("-----BEGIN"):
        return value
    return Path(os.path.expanduser(value)).read_text()


_MITM_CERT_FILES = {
    "mitm_ca_cert": "mitmproxy-ca-cert.pem",
    "mitm_ca": "mitmproxy-ca.pem",
}


def _install_mitm_certs(mitm_ca_cert, mitm_ca):
    """Write mitmproxy CA files to ~/.mitmproxy/ before mitmproxy starts."""
    mitm_dir = Path("~/.mitmproxy").expanduser()
    mitm_dir.mkdir(parents=True, exist_ok=True)
    values = {"mitm_ca_cert": mitm_ca_cert, "mitm_ca": mitm_ca}
    for key, filename in _MITM_CERT_FILES.items():
        if values[key]:
            (mitm_dir / filename).write_text(_read_pem_value(values[key]))


def run_proxy(
    port,
    bind,
    s3_bucket,
    s3_endpoint,
    test,
    mode,
    verbose,
    debug,
    debug_proxy,
    web,
    policy_file,
    allow_policy_header,
    cache_redirect,
    s3_proxy_url,
    no_redirect_user_agents,
    cache_redirect_signed_url,
    cache_redirect_signed_url_expires,
    presigned_url_cache_maxsize,
    public_proxy_url,
    access_logs,
    access_log_prefix,
    access_log_dir,
    access_log_flush_seconds,
    access_log_flush_bytes,
    access_log_headers,
    error_logs,
    error_log_prefix,
    error_log_dir,
    error_log_flush_seconds,
    error_log_flush_bytes,
    health_port,
    health_host,
    mitm_ca_cert=None,
    mitm_ca=None,
):
    if mitm_ca_cert or mitm_ca:
        _install_mitm_certs(mitm_ca_cert, mitm_ca)

    if s3_bucket:
        os.environ["S3_BUCKET"] = s3_bucket
    if s3_endpoint:
        os.environ["S3_ENDPOINT_URL"] = s3_endpoint
    if policy_file:
        os.environ["PASSSAGE_POLICY_FILE"] = policy_file
    if allow_policy_header:
        os.environ["PASSSAGE_ALLOW_POLICY_HEADER"] = "1"
    if cache_redirect:
        os.environ["PASSSAGE_CACHE_REDIRECT"] = "1"
    if s3_proxy_url:
        os.environ["PASSSAGE_S3_PROXY_URL"] = s3_proxy_url
    if no_redirect_user_agents:
        os.environ["PASSSAGE_NO_REDIRECT_USER_AGENTS"] = no_redirect_user_agents
    os.environ["PASSSAGE_CACHE_REDIRECT_SIGNED_URL"] = "1" if cache_redirect_signed_url else "0"
    os.environ["PASSSAGE_CACHE_REDIRECT_SIGNED_URL_EXPIRES"] = str(cache_redirect_signed_url_expires)
    os.environ["PASSSAGE_PRESIGNED_URL_CACHE_MAXSIZE"] = str(presigned_url_cache_maxsize)
    if public_proxy_url:
        os.environ["PASSSAGE_PUBLIC_PROXY_URL"] = public_proxy_url
    if access_logs:
        os.environ["PASSSAGE_ACCESS_LOGS"] = "1"
    if access_log_prefix:
        os.environ["PASSSAGE_ACCESS_LOG_PREFIX"] = access_log_prefix
    if access_log_dir:
        os.environ["PASSSAGE_ACCESS_LOG_DIR"] = access_log_dir
    if access_log_flush_seconds:
        os.environ["PASSSAGE_ACCESS_LOG_FLUSH_SECONDS"] = str(access_log_flush_seconds)
    if access_log_flush_bytes:
        os.environ["PASSSAGE_ACCESS_LOG_FLUSH_BYTES"] = str(access_log_flush_bytes)
    if access_log_headers:
        os.environ["PASSSAGE_ACCESS_LOG_HEADERS"] = access_log_headers
    if error_logs:
        os.environ["PASSSAGE_ERROR_LOGS"] = "1"
    if error_log_prefix:
        os.environ["PASSSAGE_ERROR_LOG_PREFIX"] = error_log_prefix
    if error_log_dir:
        os.environ["PASSSAGE_ERROR_LOG_DIR"] = error_log_dir
    if error_log_flush_seconds:
        os.environ["PASSSAGE_ERROR_LOG_FLUSH_SECONDS"] = str(error_log_flush_seconds)
    if error_log_flush_bytes:
        os.environ["PASSSAGE_ERROR_LOG_FLUSH_BYTES"] = str(error_log_flush_bytes)
    if health_port is not None:
        os.environ["PASSSAGE_HEALTH_PORT"] = str(health_port)
    if health_host:
        os.environ["PASSSAGE_HEALTH_HOST"] = health_host

    if debug:
        logging.basicConfig(level=logging.DEBUG)
        logging.getLogger().setLevel(logging.DEBUG)
    if debug_proxy:
        proxy_logger = logging.getLogger("passsage.proxy")
        proxy_logger.setLevel(logging.DEBUG)
        if not proxy_logger.handlers:
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            handler.setFormatter(logging.Formatter("DEBUG:passsage.proxy:%(message)s"))
            proxy_logger.addHandler(handler)
        proxy_logger.propagate = False

    proxy_path = os.path.join(os.path.dirname(__file__), "proxy.py")

    args = [
        "mitmdump" if not web else "mitmweb",
        "-s", proxy_path,
        "--listen-host", bind,
        "--listen-port", str(port),
    ]

    if test:
        args.extend(["--set", "test=true"])

    if mode != "regular":
        args.extend(["--mode", mode])
    if policy_file:
        args.extend(["--set", f"policy_file={policy_file}"])
    if allow_policy_header:
        args.extend(["--set", "allow_policy_header=true"])
    if cache_redirect:
        args.extend(["--set", "cache_redirect=true"])
    if s3_proxy_url:
        args.extend(["--set", f"s3_proxy_url={s3_proxy_url}"])
    if no_redirect_user_agents:
        for ua_prefix in no_redirect_user_agents.split(","):
            ua_prefix = ua_prefix.strip()
            if ua_prefix:
                args.extend(["--set", f"no_redirect_user_agents={ua_prefix}"])
    if cache_redirect_signed_url:
        args.extend(["--set", "cache_redirect_signed_url=true"])
    args.extend(["--set", f"cache_redirect_signed_url_expires={cache_redirect_signed_url_expires}"])
    args.extend(["--set", f"presigned_url_cache_maxsize={presigned_url_cache_maxsize}"])
    if public_proxy_url:
        args.extend(["--set", f"public_proxy_url={public_proxy_url}"])

    if verbose:
        args.extend(["-v"])
    if debug:
        args.extend(["--set", "termlog_verbosity=debug"])

    from mitmproxy.tools.main import mitmdump, mitmweb

    sys.argv = args
    if web:
        mitmweb()
    else:
        mitmdump()


@main.command("logs")
@click.option(
    "--start-date",
    default=date.today().isoformat(),
    show_default=True,
    help="Start date/time (YYYY-MM-DD, YYYY-MM-DDTHH, or YYYY-MM-DDTHH:MM)",
)
@click.option(
    "--end-date",
    default=date.today().isoformat(),
    show_default=True,
    help="End date/time (YYYY-MM-DD, YYYY-MM-DDTHH, or YYYY-MM-DDTHH:MM)",
)
@click.option(
    "--limit",
    type=int,
    default=5000,
    show_default=True,
    help="Maximum number of rows to load",
)
@click.option(
    "--s3-bucket",
    envvar="S3_BUCKET",
    default="",
    show_default=True,
    help="S3 bucket for access logs (env: S3_BUCKET)",
)
@click.option(
    "--access-log-prefix",
    envvar="PASSSAGE_ACCESS_LOG_PREFIX",
    default="__passsage_logs__",
    show_default=True,
    help="S3 prefix for access logs (env: PASSSAGE_ACCESS_LOG_PREFIX)",
)
@click.option(
    "-g", "--grep",
    default=None,
    help="Regex to match against all fields (keeps only matching rows)",
)
@click.option(
    "-f", "--filter",
    "filters",
    multiple=True,
    help="Per-field regex filter as field=regex (repeatable, all must match). "
    "Example: -f host=pypi -f 'status_code=^5'",
)
def logs(start_date, end_date, limit, s3_bucket, access_log_prefix, grep, filters):
    from passsage.logs_ui import run_logs_ui

    bucket = s3_bucket or os.environ.get("S3_BUCKET", "")
    if not bucket:
        raise click.ClickException("S3 bucket is required (set S3_BUCKET or --s3-bucket).")
    run_logs_ui(
        bucket, access_log_prefix, start_date, end_date, limit,
        grep=grep, filters=list(filters) or None,
    )


@main.command("errors")
@click.option(
    "--start-date",
    default=date.today().isoformat(),
    show_default=True,
    help="Start date/time (YYYY-MM-DD, YYYY-MM-DDTHH, or YYYY-MM-DDTHH:MM)",
)
@click.option(
    "--end-date",
    default=date.today().isoformat(),
    show_default=True,
    help="End date/time (YYYY-MM-DD, YYYY-MM-DDTHH, or YYYY-MM-DDTHH:MM)",
)
@click.option(
    "--limit",
    type=int,
    default=5000,
    show_default=True,
    help="Maximum number of rows to load",
)
@click.option(
    "--s3-bucket",
    envvar="S3_BUCKET",
    default="",
    show_default=True,
    help="S3 bucket for error logs (env: S3_BUCKET)",
)
@click.option(
    "--error-log-prefix",
    envvar="PASSSAGE_ERROR_LOG_PREFIX",
    default="__passsage_error_logs__",
    show_default=True,
    help="S3 prefix for error logs (env: PASSSAGE_ERROR_LOG_PREFIX)",
)
@click.option(
    "-g", "--grep",
    default=None,
    help="Regex to match against all fields (keeps only matching rows)",
)
@click.option(
    "-f", "--filter",
    "filters",
    multiple=True,
    help="Per-field regex filter as field=regex (repeatable, all must match). "
    "Example: -f error_type=Timeout -f 'host=pypi'",
)
def errors(start_date, end_date, limit, s3_bucket, error_log_prefix, grep, filters):
    from passsage.logs_ui import run_errors_ui

    bucket = s3_bucket or os.environ.get("S3_BUCKET", "")
    if not bucket:
        raise click.ClickException("S3 bucket is required (set S3_BUCKET or --s3-bucket).")
    run_errors_ui(
        bucket, error_log_prefix, start_date, end_date, limit,
        grep=grep, filters=list(filters) or None,
    )


@main.command("cache-keys")
@click.option(
    "--start-date",
    default=date.today().isoformat(),
    show_default=True,
    help="Start date (YYYY-MM-DD)",
)
@click.option(
    "--end-date",
    default=date.today().isoformat(),
    show_default=True,
    help="End date (YYYY-MM-DD)",
)
@click.option(
    "--s3-bucket",
    envvar="S3_BUCKET",
    default="",
    show_default=True,
    help="S3 bucket for access logs (env: S3_BUCKET)",
)
@click.option(
    "--access-log-prefix",
    envvar="PASSSAGE_ACCESS_LOG_PREFIX",
    default="__passsage_logs__",
    show_default=True,
    help="S3 prefix for access logs (env: PASSSAGE_ACCESS_LOG_PREFIX)",
)
@click.option(
    "--db-path",
    default="/tmp/passsage-cache-key-audit.sqlite",
    show_default=True,
    help="SQLite file used for aggregation",
)
@click.option(
    "--batch-size",
    type=int,
    default=5000,
    show_default=True,
    help="Rows per parquet batch to scan",
)
@click.option(
    "--min-distinct",
    type=int,
    default=10,
    show_default=True,
    help="Minimum distinct values per param",
)
@click.option(
    "--min-paths",
    type=int,
    default=2,
    show_default=True,
    help="Minimum distinct paths per param",
)
@click.option(
    "--min-misses",
    type=int,
    default=50,
    show_default=True,
    help="Minimum cache-miss count per param",
)
@click.option(
    "--top",
    type=int,
    default=50,
    show_default=True,
    help="Maximum number of candidates to show",
)
@click.option(
    "--reset-db",
    is_flag=True,
    default=False,
    show_default=True,
    help="Delete the SQLite file before scanning",
)
def cache_keys(
    start_date,
    end_date,
    s3_bucket,
    access_log_prefix,
    db_path,
    batch_size,
    min_distinct,
    min_paths,
    min_misses,
    top,
    reset_db,
):
    from passsage.log_analysis import analyze_cache_fragmentation

    bucket = s3_bucket or os.environ.get("S3_BUCKET", "")
    if not bucket:
        raise click.ClickException("S3 bucket is required (set S3_BUCKET or --s3-bucket).")
    candidates = analyze_cache_fragmentation(
        bucket=bucket,
        prefix=access_log_prefix,
        start_date=start_date,
        end_date=end_date,
        db_path=db_path,
        batch_size=batch_size,
        min_distinct=min_distinct,
        min_paths=min_paths,
        min_misses=min_misses,
        top=top,
        reset_db=reset_db,
    )
    if not candidates:
        click.echo("No candidates found.")
        return
    click.echo("host\tparam\tdistinct_values\tpaths\tmisses")
    for entry in candidates:
        click.echo(
            f"{entry.host}\t{entry.param}\t{entry.distinct_values}\t{entry.paths}\t{entry.misses}"
        )


if __name__ == "__main__":
    main()
