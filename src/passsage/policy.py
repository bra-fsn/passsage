"""Cache policy names and flexible, high-performance rule resolution for the proxy.

Rule types (evaluated in order; first match wins):
- Fast: PrefixRule, SuffixRule, HostPrefixRule, HostContainsRule, PathContainsRule
- Complex: RegexRule
- Dynamic: CallableRule(ctx) -> Policy | None

Use default_rules() for built-in behaviour, or pass custom rules to PolicyResolver(rules=...).
Override globally before starting the proxy: set_default_resolver(PolicyResolver(my_rules)).

Forced Stale-While-Revalidate (SWR)
------------------------------------
Any rule can set ``forced_swr_seconds`` to enable proxy-side stale-while-revalidate,
independent of origin Cache-Control headers.  When a cached response is stale but
younger than ``forced_swr_seconds``, the proxy serves the cached body immediately
and asks xs3lerator to revalidate with the origin in the background.  If the origin
returns 304 Not Modified, xs3lerator refreshes the ``stored_at`` timestamp in
Elasticsearch so the entry appears fresh again.  If the origin returns new content,
xs3lerator downloads and stores it normally — subsequent requests will see the update.

This eliminates the latency of foreground conditional revalidation for origins that
rarely change (e.g. PyPI simple index pages), while still keeping the cache
eventually consistent.  Responses older than the configured window fall back to
normal foreground revalidation.

Only applies to Standard and StaleIfError policies, and only when the cached response
carries validators (ETag or Last-Modified) so a conditional GET is possible.
Client-forced revalidation (``Cache-Control: no-cache``) bypasses this.
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence
from urllib.parse import urlparse

from passsage.default_policies import default_rules


@dataclass(frozen=True)
class TimeoutConfig:
    """Per-request upstream timeout overrides sent to xs3lerator.

    Values are in seconds. None means "use xs3lerator's server default".
    0 means "no timeout" (disable the timeout).
    """

    connect_timeout: Optional[float] = None
    read_timeout: Optional[float] = None


class Policy:
    pass


class NoCache(Policy):
    pass


class NoRefresh(Policy):
    """Serve from cache without revalidation; fetch from upstream only on miss."""

    pass


class StaleIfError(Policy):
    """Revalidate when stale; serve cached content on upstream errors (including 404/5xx/timeout)."""

    pass


class Standard(Policy):
    """RFC 9111 compliant caching and revalidation; serve errors if upstream fails."""

    pass


class AlwaysUpstream(Policy):
    """Always fetch from upstream; use cache only as fallback."""

    pass


@dataclass(frozen=True)
class ResolvedPolicy:
    """Policy plus optional timeout overrides resolved for a request."""

    policy: type[Policy]
    timeouts: Optional[TimeoutConfig] = None
    forced_swr_seconds: Optional[int] = None
    """Proxy-side stale-while-revalidate window in seconds (None = disabled).

    When set, stale cached responses younger than this many seconds are served
    immediately while xs3lerator revalidates with the origin in the background.
    Responses older than this window undergo normal foreground revalidation.
    See module docstring for full details.
    """


@dataclass(frozen=True)
class Context:
    """Request context passed to rules and dynamic callables."""

    url: str
    method: str = "GET"
    host: Optional[str] = field(default=None)
    headers: Optional[Sequence[tuple[str, str]]] = None

    def __post_init__(self) -> None:
        if self.host is None and self.url:
            obj = urlparse(self.url)
            object.__setattr__(self, "host", (obj.hostname or "").lower())

    @property
    def url_lower(self) -> str:
        return self.url.lower()


class Rule(Protocol):
    """Protocol for policy rules. First rule to return a non-None policy wins."""

    def match(self, ctx: Context) -> Optional[Policy]:
        ...


class PrefixRule:
    """Fast: match URL prefix (case-insensitive). Longest prefix wins if multiple match."""

    __slots__ = ("prefix", "policy", "timeouts", "forced_swr_seconds", "_prefix_lower")

    def __init__(
        self,
        prefix: str,
        policy: type[Policy],
        *,
        timeouts: Optional[TimeoutConfig] = None,
        forced_swr_seconds: Optional[int] = None,
    ) -> None:
        self.prefix = prefix
        self.policy = policy
        self.timeouts = timeouts
        self.forced_swr_seconds = forced_swr_seconds
        self._prefix_lower = prefix.lower()

    def match(self, ctx: Context) -> Optional[Policy]:
        if ctx.url_lower.startswith(self._prefix_lower):
            return self.policy
        return None


class SuffixRule:
    """Fast: match URL suffix (e.g. .deb)."""

    __slots__ = ("suffix", "policy", "timeouts", "forced_swr_seconds", "_suffix_lower")

    def __init__(
        self,
        suffix: str,
        policy: type[Policy],
        *,
        timeouts: Optional[TimeoutConfig] = None,
        forced_swr_seconds: Optional[int] = None,
    ) -> None:
        self.suffix = suffix
        self.policy = policy
        self.timeouts = timeouts
        self.forced_swr_seconds = forced_swr_seconds
        self._suffix_lower = suffix.lower()

    def match(self, ctx: Context) -> Optional[Policy]:
        if ctx.url_lower.endswith(self._suffix_lower):
            return self.policy
        return None


class HostPrefixRule:
    """Fast: match host prefix (e.g. 169.254.169. for link-local)."""

    __slots__ = ("prefix", "policy", "timeouts", "forced_swr_seconds", "_prefix_lower")

    def __init__(
        self,
        prefix: str,
        policy: type[Policy],
        *,
        timeouts: Optional[TimeoutConfig] = None,
        forced_swr_seconds: Optional[int] = None,
    ) -> None:
        self.prefix = prefix
        self.policy = policy
        self.timeouts = timeouts
        self.forced_swr_seconds = forced_swr_seconds
        self._prefix_lower = prefix.lower()

    def match(self, ctx: Context) -> Optional[Policy]:
        if ctx.host and ctx.host.startswith(self._prefix_lower):
            return self.policy
        return None


class HostContainsRule:
    """Fast: match substring in host (e.g. amazonaws.com, then exclude codeartifact)."""

    __slots__ = (
        "contains", "policy", "timeouts", "forced_swr_seconds",
        "exclude", "_contains_lower", "_exclude_lower",
    )

    def __init__(
        self,
        contains: str,
        policy: type[Policy],
        *,
        exclude: Optional[str] = None,
        timeouts: Optional[TimeoutConfig] = None,
        forced_swr_seconds: Optional[int] = None,
    ) -> None:
        self.contains = contains
        self.policy = policy
        self.timeouts = timeouts
        self.forced_swr_seconds = forced_swr_seconds
        self.exclude = exclude
        self._contains_lower = contains.lower()
        self._exclude_lower = exclude.lower() if exclude else None

    def match(self, ctx: Context) -> Optional[Policy]:
        if not ctx.host:
            return None
        h = ctx.host
        if self._contains_lower not in h:
            return None
        if self._exclude_lower is not None and self._exclude_lower in h:
            return None
        return self.policy


class PathContainsRule:
    """Fast: match substring in URL path (e.g. /mitm.it/)."""

    __slots__ = ("contains", "policy", "timeouts", "forced_swr_seconds", "_contains_lower")

    def __init__(
        self,
        contains: str,
        policy: type[Policy],
        *,
        timeouts: Optional[TimeoutConfig] = None,
        forced_swr_seconds: Optional[int] = None,
    ) -> None:
        self.contains = contains
        self.policy = policy
        self.timeouts = timeouts
        self.forced_swr_seconds = forced_swr_seconds
        self._contains_lower = contains.lower()

    def match(self, ctx: Context) -> Optional[Policy]:
        if self._contains_lower in ctx.url_lower:
            return self.policy
        return None


class RegexRule:
    """Complex: match URL with a compiled regex."""

    __slots__ = ("pattern", "policy", "timeouts", "forced_swr_seconds", "_compiled")

    def __init__(
        self,
        pattern: str | re.Pattern[str],
        policy: type[Policy],
        *,
        timeouts: Optional[TimeoutConfig] = None,
        forced_swr_seconds: Optional[int] = None,
    ) -> None:
        self.pattern = pattern
        self.policy = policy
        self.timeouts = timeouts
        self.forced_swr_seconds = forced_swr_seconds
        self._compiled = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern

    def match(self, ctx: Context) -> Optional[Policy]:
        if self._compiled.search(ctx.url):
            return self.policy
        return None


class CallableRule:
    """Dynamic: user callable(ctx) -> Policy | None."""

    __slots__ = ("func", "timeouts", "forced_swr_seconds")

    def __init__(
        self,
        func: Callable[[Context], Optional[Policy]],
        *,
        timeouts: Optional[TimeoutConfig] = None,
        forced_swr_seconds: Optional[int] = None,
    ) -> None:
        self.func = func
        self.timeouts = timeouts
        self.forced_swr_seconds = forced_swr_seconds

    def match(self, ctx: Context) -> Optional[Policy]:
        return self.func(ctx)


class PolicyResolver:
    """Resolves context to a policy by evaluating rules in order. First match wins."""

    __slots__ = ("_rules", "_prefix_rules", "_default_policy")

    def __init__(
        self,
        rules: Optional[Sequence[Rule]] = None,
        *,
        default_policy: type[Policy] = Standard,
    ) -> None:
        if rules is None:
            rules = default_rules()
        self._rules = list(rules)
        prefix_rules = [r for r in self._rules if isinstance(r, PrefixRule)]
        self._prefix_rules = sorted(prefix_rules, key=lambda r: len(r.prefix), reverse=True)
        self._default_policy = default_policy

    def resolve(self, ctx: Context) -> ResolvedPolicy:
        for rule in self._prefix_rules:
            p = rule.match(ctx)
            if p is not None:
                return ResolvedPolicy(
                    policy=p,
                    timeouts=getattr(rule, "timeouts", None),
                    forced_swr_seconds=getattr(rule, "forced_swr_seconds", None),
                )
        for rule in self._rules:
            if isinstance(rule, PrefixRule):
                continue
            p = rule.match(ctx)
            if p is not None:
                return ResolvedPolicy(
                    policy=p,
                    timeouts=getattr(rule, "timeouts", None),
                    forced_swr_seconds=getattr(rule, "forced_swr_seconds", None),
                )
        return ResolvedPolicy(policy=self._default_policy)

    def add_rule(self, rule: Rule, index: int = 0) -> None:
        """Insert a rule (default at front) for programmatic overrides."""
        self._rules.insert(index, rule)
        if isinstance(rule, PrefixRule):
            self._prefix_rules.insert(0, rule)
            self._prefix_rules.sort(key=lambda r: len(r.prefix), reverse=True)

    def set_default_policy(self, policy: type[Policy]) -> None:
        self._default_policy = policy


_default_resolver: Optional[PolicyResolver] = None


def get_default_resolver() -> PolicyResolver:
    """Return the default resolver (built-in rules). Use set_default_resolver() to override."""
    global _default_resolver
    if _default_resolver is None:
        _default_resolver = PolicyResolver()
    return _default_resolver


def set_default_resolver(resolver: PolicyResolver) -> None:
    """Set the global resolver (e.g. custom rules). Call before starting the proxy."""
    global _default_resolver
    _default_resolver = resolver


def resolve_policy(
    url: str, method: str = "GET", headers: Optional[Sequence[tuple[str, str]]] = None
) -> ResolvedPolicy:
    """Resolve policy for a request. Uses default resolver unless overridden."""
    ctx = Context(url=url, method=method, headers=headers)
    return get_default_resolver().resolve(ctx)


POLICY_BY_NAME = {
    "nocache": NoCache,
    "norefresh": NoRefresh,
    "staleiferror": StaleIfError,
    "standard": Standard,
    "alwaysupstream": AlwaysUpstream,
}


def policy_from_name(name: str, *, default: type[Policy] = Standard) -> type[Policy]:
    return POLICY_BY_NAME.get(name.strip().lower(), default)
