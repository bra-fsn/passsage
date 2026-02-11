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
        HostContainsRule,
        HostPrefixRule,
        NoCache,
        NoRefresh,
        PathContainsRule,
        RegexRule,
        StaleIfError,
        SuffixRule,
    )

    return [
        PathContainsRule("/mitm.it/", NoCache),
        # Debian based mirrors
        SuffixRule(".deb", StaleIfError),
        SuffixRule("/Packages", StaleIfError),
        SuffixRule("/Packages.gz", StaleIfError),
        SuffixRule("/Packages.xz", StaleIfError),
        SuffixRule("/InRelease", StaleIfError),
        RegexRule(r".*by-hash/[A-Z0-9]+/[a-f0-9]+$", NoRefresh),
        # Python hosted packages (immutable content-addressed archives)
        HostContainsRule("files.pythonhosted.org", NoRefresh),
        # Python package index (mutable, new versions appear)
        PathContainsRule("pypi.org/simple", StaleIfError),
        # cloud metadata endpoints
        HostPrefixRule("169.254.169.", NoCache),
        HostPrefixRule("169.254.170.", NoCache),
        HostPrefixRule("100.100.100.", NoCache),
        HostContainsRule("metadata.azure.internal", NoCache),
        HostContainsRule("metadata.google.internal", NoCache),
        HostContainsRule("amazonaws.com", NoCache, exclude="codeartifact"),
        # MRAN mirror
        PathContainsRule("mran.microsoft.com/snapshot/", StaleIfError),
    ]
