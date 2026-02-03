"""Command-line interface for Passsage."""

import logging
import os
import sys

import click


@click.command()
@click.option(
    "-p", "--port",
    default=8080,
    type=int,
    envvar="PASSSAGE_PORT",
    help="Port to listen on (env: PASSSAGE_PORT, default: 8080)"
)
@click.option(
    "-b", "--bind",
    default="0.0.0.0",
    envvar="PASSSAGE_HOST",
    help="Address to bind to (env: PASSSAGE_HOST, default: 0.0.0.0)"
)
@click.option(
    "--s3-bucket",
    envvar="S3_BUCKET",
    help="S3 bucket for cache storage (env: S3_BUCKET)"
)
@click.option(
    "--s3-endpoint",
    envvar="S3_ENDPOINT_URL",
    help="S3 endpoint URL for S3-compatible services (env: S3_ENDPOINT_URL)"
)
@click.option(
    "--test",
    is_flag=True,
    default=False,
    help="Run in test mode (banned sites are not released)"
)
@click.option(
    "-m", "--mode",
    type=click.Choice(["regular", "transparent", "wireguard", "upstream"]),
    default="regular",
    help="Proxy mode (default: regular)"
)
@click.option(
    "-v", "--verbose",
    is_flag=True,
    default=False,
    help="Enable verbose logging"
)
@click.option(
    "--debug",
    is_flag=True,
    default=False,
    help="Enable debug logging for proxy internals"
)
@click.option(
    "--debug-proxy",
    is_flag=True,
    default=False,
    help="Enable debug logging for passsage proxy only"
)
@click.option(
    "--web",
    is_flag=True,
    default=False,
    help="Enable mitmproxy web interface"
)
@click.option(
    "--policy-file",
    envvar="PASSSAGE_POLICY_FILE",
    help="Path to Python file defining policy overrides (env: PASSSAGE_POLICY_FILE)"
)
@click.option(
    "--allow-policy-header",
    is_flag=True,
    default=False,
    help="Allow client policy override via X-Passsage-Policy"
)
@click.option(
    "--cache-redirect",
    is_flag=True,
    default=False,
    help="Redirect cache hits to S3 instead of streaming through the proxy"
)
@click.option(
    "--public-proxy-url",
    envvar="PASSSAGE_PUBLIC_PROXY_URL",
    default="",
    help="Public proxy URL embedded in mitm.it/proxy-env responses (env: PASSSAGE_PUBLIC_PROXY_URL)"
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
def main(
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
    public_proxy_url,
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
    if public_proxy_url:
        os.environ["PASSSAGE_PUBLIC_PROXY_URL"] = public_proxy_url
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


if __name__ == "__main__":
    main()
