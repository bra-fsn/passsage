"""Command-line interface for Passsage."""

import logging
import os
import sys
from datetime import date

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
    show_default=True,
    help="Run in test mode (banned sites are not released)"
)
@click.option(
    "-m", "--mode",
    type=click.Choice(["regular", "transparent", "wireguard", "upstream"]),
    default="regular",
    show_default=True,
    help="Proxy mode (default: regular)"
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    show_default=True,
    help="Enable verbose logging"
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    show_default=True,
    help="Enable debug logging for proxy internals"
)
@click.option(
    "--debug-proxy",
    is_flag=True,
    default=False,
    show_default=True,
    help="Enable debug logging for passsage proxy only"
)
@click.option(
    "--web",
    is_flag=True,
    default=False,
    show_default=True,
    help="Enable mitmproxy web interface"
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
    show_default=True,
    help="Allow client policy override via X-Passsage-Policy"
)
@click.option(
    "--cache-redirect",
    is_flag=True,
    default=False,
    show_default=True,
    help="Redirect cache hits to S3 instead of streaming through the proxy"
)
@click.option(
    "--cache-redirect-signed-url/--cache-redirect-public",
    envvar="PASSSAGE_CACHE_REDIRECT_SIGNED_URL",
    default=True,
    show_default=True,
    help="Redirect cache hits to signed S3 URLs (env: PASSSAGE_CACHE_REDIRECT_SIGNED_URL)"
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
    cache_redirect_signed_url,
    public_proxy_url,
    access_logs,
    access_log_prefix,
    access_log_dir,
    access_log_flush_seconds,
    access_log_flush_bytes,
    access_log_headers,
    health_port,
    health_host,
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
            cache_redirect_signed_url,
            public_proxy_url,
            access_logs,
            access_log_prefix,
            access_log_dir,
            access_log_flush_seconds,
            access_log_flush_bytes,
            access_log_headers,
            health_port,
            health_host,
        )


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
    cache_redirect_signed_url,
    public_proxy_url,
    access_logs,
    access_log_prefix,
    access_log_dir,
    access_log_flush_seconds,
    access_log_flush_bytes,
    access_log_headers,
    health_port,
    health_host,
):
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
    os.environ["PASSSAGE_CACHE_REDIRECT_SIGNED_URL"] = "1" if cache_redirect_signed_url else "0"
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
    if cache_redirect_signed_url:
        args.extend(["--set", "cache_redirect_signed_url=true"])
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
    help="Start date (YYYY-MM-DD)",
)
@click.option(
    "--end-date",
    default=date.today().isoformat(),
    show_default=True,
    help="End date (YYYY-MM-DD)",
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
def logs(start_date, end_date, limit, s3_bucket, access_log_prefix):
    from passsage.logs_ui import run_logs_ui

    bucket = s3_bucket or os.environ.get("S3_BUCKET", "")
    if not bucket:
        raise click.ClickException("S3 bucket is required (set S3_BUCKET or --s3-bucket).")
    run_logs_ui(bucket, access_log_prefix, start_date, end_date, limit)


if __name__ == "__main__":
    main()
