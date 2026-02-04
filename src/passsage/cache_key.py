"""Cache key normalization and rule-based rewriting for proxy storage keys."""

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, Sequence
from urllib.parse import urlparse

from passsage.default_cache_keys import default_rules


@dataclass(frozen=True)
class Context:
    """Request context passed to cache-key rules."""

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
    """Protocol for cache-key rules. First rule to return a value wins."""

    def match(self, ctx: Context) -> Optional[str]:
        ...


class PrefixRule:
    """Fast: match URL prefix (case-insensitive)."""

    __slots__ = ("prefix", "rewriter", "_prefix_lower")

    def __init__(self, prefix: str, rewriter: Callable[[Context], str]) -> None:
        self.prefix = prefix
        self.rewriter = rewriter
        self._prefix_lower = prefix.lower()

    def match(self, ctx: Context) -> Optional[str]:
        if ctx.url_lower.startswith(self._prefix_lower):
            return self.rewriter(ctx)
        return None


class HostContainsRule:
    """Fast: match substring in host."""

    __slots__ = ("contains", "rewriter", "_contains_lower")

    def __init__(self, contains: str, rewriter: Callable[[Context], str]) -> None:
        self.contains = contains
        self.rewriter = rewriter
        self._contains_lower = contains.lower()

    def match(self, ctx: Context) -> Optional[str]:
        if ctx.host and self._contains_lower in ctx.host:
            return self.rewriter(ctx)
        return None


class PathContainsRule:
    """Fast: match substring in URL path."""

    __slots__ = ("contains", "rewriter", "_contains_lower")

    def __init__(self, contains: str, rewriter: Callable[[Context], str]) -> None:
        self.contains = contains
        self.rewriter = rewriter
        self._contains_lower = contains.lower()

    def match(self, ctx: Context) -> Optional[str]:
        if self._contains_lower in ctx.url_lower:
            return self.rewriter(ctx)
        return None


class RegexRule:
    """Complex: match URL with a compiled regex."""

    __slots__ = ("pattern", "rewriter", "_compiled")

    def __init__(self, pattern: str | re.Pattern[str], rewriter: Callable[[Context], str]) -> None:
        self.pattern = pattern
        self.rewriter = rewriter
        self._compiled = re.compile(pattern, re.IGNORECASE) if isinstance(pattern, str) else pattern

    def match(self, ctx: Context) -> Optional[str]:
        if self._compiled.search(ctx.url):
            return self.rewriter(ctx)
        return None


class CallableRule:
    """Dynamic: user callable(ctx) -> url | None."""

    __slots__ = ("func",)

    def __init__(self, func: Callable[[Context], Optional[str]]) -> None:
        self.func = func

    def match(self, ctx: Context) -> Optional[str]:
        return self.func(ctx)


class CacheKeyResolver:
    """Resolves context to a cache key by evaluating rules in order."""

    __slots__ = ("_rules", "_prefix_rules")

    def __init__(self, rules: Optional[Sequence[Rule]] = None) -> None:
        if rules is None:
            rules = default_rules()
        self._rules = list(rules)
        prefix_rules = [r for r in self._rules if isinstance(r, PrefixRule)]
        self._prefix_rules = sorted(prefix_rules, key=lambda r: len(r.prefix), reverse=True)

    def resolve(self, ctx: Context) -> str:
        for rule in self._prefix_rules:
            value = rule.match(ctx)
            if value:
                return value
        for rule in self._rules:
            if isinstance(rule, PrefixRule):
                continue
            value = rule.match(ctx)
            if value:
                return value
        return ctx.url

    def add_rule(self, rule: Rule, index: int = 0) -> None:
        self._rules.insert(index, rule)
        if isinstance(rule, PrefixRule):
            self._prefix_rules.insert(0, rule)
            self._prefix_rules.sort(key=lambda r: len(r.prefix), reverse=True)


_DEFAULT_RESOLVER = CacheKeyResolver()


def get_default_cache_key_resolver() -> CacheKeyResolver:
    return _DEFAULT_RESOLVER


def set_default_cache_key_resolver(resolver: CacheKeyResolver) -> None:
    global _DEFAULT_RESOLVER
    _DEFAULT_RESOLVER = resolver
