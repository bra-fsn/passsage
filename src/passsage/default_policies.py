"""Default policy rules for Passsage."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from passsage.policy import Rule


def default_rules() -> list["Rule"]:
    """Return built-in policy rules.

    Imports are local to avoid a circular import with passsage.policy.
    """
    from passsage.policy import (
        AlwaysCached,
        HostContainsRule,
        HostPrefixRule,
        MissingCached,
        NoCache,
        PathContainsRule,
        RegexRule,
        SuffixRule,
    )

    return [
        SuffixRule(".deb", AlwaysCached),
        SuffixRule("/Packages", MissingCached),
        SuffixRule("/Packages.gz", MissingCached),
        SuffixRule("/Packages.xz", MissingCached),
        HostPrefixRule("169.254.169.", NoCache),
        SuffixRule("/InRelease", MissingCached),
        HostContainsRule("amazonaws.com", NoCache, exclude="codeartifact"),
        PathContainsRule("/mitm.it/", NoCache),
        PathContainsRule("mran.microsoft.com/snapshot/", AlwaysCached),
        RegexRule(r".*by-hash/[A-Z0-9]+/[a-f0-9]+$", AlwaysCached),
    ]
