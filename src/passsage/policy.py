"""Cache policy names and flexible, high-performance rule resolution for the proxy.

Rule types (evaluated in order; first match wins):
- Fast: PrefixRule, SuffixRule, HostPrefixRule, HostContainsRule, PathContainsRule
- Complex: RegexRule
- Dynamic: CallableRule(ctx) -> Policy | None

Use default_rules() for built-in behaviour, or pass custom rules to PolicyResolver(rules=...).
Override globally before starting the proxy: set_default_resolver(PolicyResolver(my_rules)).
"""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence
from urllib.parse import urlparse

from passsage.default_policies import default_rules


class Policy:
    pass


class NoCache(Policy):
    pass


class AlwaysCached(Policy):
    """Serve from cache without checking upstream; if missing, fetch from upstream."""

    pass


class MissingCached(Policy):
    """HEAD first; if upstream returns any kind of failure (404, 500, timeout etc.), serve from cache."""

    pass


class Modified(Policy):
    """HEAD first; compare last-modified with cache; if unchanged, serve from cache."""

    pass


class AlwaysUpstream(Policy):
    """Always fetch from upstream; use cache only as fallback."""

    pass


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

    __slots__ = ("prefix", "policy", "_prefix_lower")

    def __init__(self, prefix: str, policy: type[Policy]) -> None:
        self.prefix = prefix
        self.policy = policy
        self._prefix_lower = prefix.lower()

    def match(self, ctx: Context) -> Optional[Policy]:
        if ctx.url_lower.startswith(self._prefix_lower):
            return self.policy
        return None


class SuffixRule:
    """Fast: match URL suffix (e.g. .deb)."""

    __slots__ = ("suffix", "policy", "_suffix_lower")

    def __init__(self, suffix: str, policy: type[Policy]) -> None:
        self.suffix = suffix
        self.policy = policy
        self._suffix_lower = suffix.lower()

    def match(self, ctx: Context) -> Optional[Policy]:
        if ctx.url_lower.endswith(self._suffix_lower):
            return self.policy
        return None


class HostPrefixRule:
    """Fast: match host prefix (e.g. 169.254.169. for link-local)."""

    __slots__ = ("prefix", "policy", "_prefix_lower")

    def __init__(self, prefix: str, policy: type[Policy]) -> None:
        self.prefix = prefix
        self.policy = policy
        self._prefix_lower = prefix.lower()

    def match(self, ctx: Context) -> Optional[Policy]:
        if ctx.host and ctx.host.startswith(self._prefix_lower):
            return self.policy
        return None


class HostContainsRule:
    """Fast: match substring in host (e.g. amazonaws.com, then exclude codeartifact)."""

    __slots__ = ("contains", "policy", "exclude", "_contains_lower", "_exclude_lower")

    def __init__(
        self,
        contains: str,
        policy: type[Policy],
        *,
        exclude: Optional[str] = None,
    ) -> None:
        self.contains = contains
        self.policy = policy
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

    __slots__ = ("contains", "policy", "_contains_lower")

    def __init__(self, contains: str, policy: type[Policy]) -> None:
        self.contains = contains
        self.policy = policy
        self._contains_lower = contains.lower()

    def match(self, ctx: Context) -> Optional[Policy]:
        if self._contains_lower in ctx.url_lower:
            return self.policy
        return None


class RegexRule:
    """Complex: match URL with a compiled regex."""

    __slots__ = ("pattern", "policy", "_compiled")

    def __init__(self, pattern: str | re.Pattern[str], policy: type[Policy]) -> None:
        self.pattern = pattern
        self.policy = policy
        self._compiled = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern

    def match(self, ctx: Context) -> Optional[Policy]:
        if self._compiled.search(ctx.url):
            return self.policy
        return None


class CallableRule:
    """Dynamic: user callable(ctx) -> Policy | None."""

    __slots__ = ("func",)

    def __init__(self, func: Callable[[Context], Optional[Policy]]) -> None:
        self.func = func

    def match(self, ctx: Context) -> Optional[Policy]:
        return self.func(ctx)


class PolicyResolver:
    """Resolves context to a policy by evaluating rules in order. First match wins."""

    __slots__ = ("_rules", "_prefix_rules", "_default_policy")

    def __init__(
        self,
        rules: Optional[Sequence[Rule]] = None,
        *,
        default_policy: type[Policy] = MissingCached,
    ) -> None:
        if rules is None:
            rules = default_rules()
        self._rules = list(rules)
        prefix_rules = [r for r in self._rules if isinstance(r, PrefixRule)]
        self._prefix_rules = sorted(prefix_rules, key=lambda r: len(r.prefix), reverse=True)
        self._default_policy = default_policy

    def resolve(self, ctx: Context) -> Policy:
        for rule in self._prefix_rules:
            p = rule.match(ctx)
            if p is not None:
                return p
        for rule in self._rules:
            if isinstance(rule, PrefixRule):
                continue
            p = rule.match(ctx)
            if p is not None:
                return p
        return self._default_policy

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
) -> Policy:
    """Resolve policy for a request. Uses default resolver unless overridden."""
    ctx = Context(url=url, method=method, headers=headers)
    return get_default_resolver().resolve(ctx)


POLICY_BY_NAME = {
    "nocache": NoCache,
    "alwayscached": AlwaysCached,
    "missingcached": MissingCached,
    "modified": Modified,
    "alwaysupstream": AlwaysUpstream,
}


def policy_from_name(name: str, *, default: type[Policy] = MissingCached) -> type[Policy]:
    return POLICY_BY_NAME.get(name.strip().lower(), default)
