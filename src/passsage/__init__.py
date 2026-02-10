"""
Passsage (Pas³age) - S3-backed caching proxy for mitmproxy.

The three S's in "Passsage" represent S3: this proxy uses Amazon S3 or an
S3-compatible object store to cache HTTP responses.

Note: Do NOT import from proxy at module level - the @concurrent decorator
requires mitmproxy's hooks to be registered first, which only happens when
mitmproxy loads the proxy script.
"""

__version__ = "0.2.0"

from passsage.policy import (
    AlwaysUpstream,
    CallableRule,
    Context,
    HostContainsRule,
    HostPrefixRule,
    NoRefresh,
    NoCache,
    PathContainsRule,
    Policy,
    PolicyResolver,
    PrefixRule,
    RegexRule,
    StaleIfError,
    Standard,
    SuffixRule,
    default_rules,
    get_default_resolver,
    policy_from_name,
    resolve_policy,
    set_default_resolver,
)


def get_proxy_path() -> str:
    """Return the path to the proxy.py file for use with mitmproxy -s."""
    import os
    return os.path.join(os.path.dirname(__file__), "proxy.py")


__all__ = [
    "__version__",
    "get_proxy_path",
    "Policy",
    "NoCache",
    "NoRefresh",
    "StaleIfError",
    "Standard",
    "AlwaysUpstream",
    "Context",
    "PolicyResolver",
    "PrefixRule",
    "SuffixRule",
    "HostPrefixRule",
    "HostContainsRule",
    "PathContainsRule",
    "RegexRule",
    "CallableRule",
    "default_rules",
    "get_default_resolver",
    "set_default_resolver",
    "resolve_policy",
    "policy_from_name",
]
