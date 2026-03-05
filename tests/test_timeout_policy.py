"""Unit tests for timeout configuration in the policy system."""

import pytest

from passsage.policy import (
    CallableRule,
    Context,
    HostContainsRule,
    NoCache,
    PathContainsRule,
    PolicyResolver,
    PrefixRule,
    RegexRule,
    ResolvedPolicy,
    StaleIfError,
    Standard,
    SuffixRule,
    TimeoutConfig,
)


class TestTimeoutConfig:
    def test_default_is_all_none(self):
        tc = TimeoutConfig()
        assert tc.connect_timeout is None
        assert tc.read_timeout is None

    def test_set_both(self):
        tc = TimeoutConfig(connect_timeout=10, read_timeout=300)
        assert tc.connect_timeout == 10
        assert tc.read_timeout == 300

    def test_zero_means_disable(self):
        tc = TimeoutConfig(connect_timeout=0, read_timeout=0)
        assert tc.connect_timeout == 0
        assert tc.read_timeout == 0

    def test_frozen(self):
        tc = TimeoutConfig(connect_timeout=5)
        with pytest.raises(AttributeError):
            tc.connect_timeout = 10


class TestResolvedPolicy:
    def test_default_no_timeouts(self):
        rp = ResolvedPolicy(policy=Standard)
        assert rp.policy is Standard
        assert rp.timeouts is None

    def test_with_timeouts(self):
        tc = TimeoutConfig(connect_timeout=15, read_timeout=600)
        rp = ResolvedPolicy(policy=StaleIfError, timeouts=tc)
        assert rp.policy is StaleIfError
        assert rp.timeouts.connect_timeout == 15
        assert rp.timeouts.read_timeout == 600


class TestRulesWithTimeouts:
    def test_suffix_rule_with_timeouts(self):
        tc = TimeoutConfig(connect_timeout=10, read_timeout=600)
        rule = SuffixRule(".whl", StaleIfError, timeouts=tc)
        ctx = Context(url="https://files.pythonhosted.org/torch-2.0.whl")
        assert rule.match(ctx) is StaleIfError
        assert rule.timeouts is tc

    def test_suffix_rule_without_timeouts(self):
        rule = SuffixRule(".deb", StaleIfError)
        assert rule.timeouts is None

    def test_prefix_rule_with_timeouts(self):
        tc = TimeoutConfig(read_timeout=120)
        rule = PrefixRule("https://slow.example.com/", Standard, timeouts=tc)
        ctx = Context(url="https://slow.example.com/big-file.tar.gz")
        assert rule.match(ctx) is Standard
        assert rule.timeouts.read_timeout == 120

    def test_host_contains_rule_with_timeouts(self):
        tc = TimeoutConfig(connect_timeout=5)
        rule = HostContainsRule("pypi.org", StaleIfError, timeouts=tc)
        ctx = Context(url="https://pypi.org/simple/requests/")
        assert rule.match(ctx) is StaleIfError
        assert rule.timeouts.connect_timeout == 5

    def test_host_contains_rule_exclude_still_works(self):
        tc = TimeoutConfig(read_timeout=60)
        rule = HostContainsRule("amazonaws.com", NoCache, exclude="codeartifact", timeouts=tc)
        ctx_excluded = Context(url="https://codeartifact.amazonaws.com/v1/pkg")
        ctx_matched = Context(url="https://s3.amazonaws.com/bucket/key")
        assert rule.match(ctx_excluded) is None
        assert rule.match(ctx_matched) is NoCache
        assert rule.timeouts.read_timeout == 60

    def test_path_contains_rule_with_timeouts(self):
        tc = TimeoutConfig(connect_timeout=3, read_timeout=30)
        rule = PathContainsRule("/api/v1/", Standard, timeouts=tc)
        ctx = Context(url="https://example.com/api/v1/data")
        assert rule.match(ctx) is Standard
        assert rule.timeouts == tc

    def test_regex_rule_with_timeouts(self):
        tc = TimeoutConfig(read_timeout=900)
        rule = RegexRule(r".*\.tar\.gz$", StaleIfError, timeouts=tc)
        ctx = Context(url="https://example.com/archive.tar.gz")
        assert rule.match(ctx) is StaleIfError
        assert rule.timeouts.read_timeout == 900

    def test_callable_rule_with_timeouts(self):
        tc = TimeoutConfig(connect_timeout=2)
        rule = CallableRule(lambda ctx: StaleIfError if "slow" in ctx.url else None, timeouts=tc)
        ctx_match = Context(url="https://slow.example.com/file")
        ctx_nomatch = Context(url="https://fast.example.com/file")
        assert rule.match(ctx_match) is StaleIfError
        assert rule.match(ctx_nomatch) is None
        assert rule.timeouts.connect_timeout == 2


class TestResolverWithTimeouts:
    def test_resolver_returns_timeout_from_matching_rule(self):
        tc = TimeoutConfig(connect_timeout=10, read_timeout=600)
        rules = [SuffixRule(".whl", StaleIfError, timeouts=tc)]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(Context(url="https://example.com/torch.whl"))
        assert isinstance(result, ResolvedPolicy)
        assert result.policy is StaleIfError
        assert result.timeouts is tc

    def test_resolver_returns_no_timeout_for_default_policy(self):
        rules = [SuffixRule(".deb", StaleIfError)]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(Context(url="https://example.com/unknown.zip"))
        assert result.policy is Standard
        assert result.timeouts is None

    def test_resolver_returns_no_timeout_when_rule_has_none(self):
        rules = [SuffixRule(".deb", StaleIfError)]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(Context(url="https://example.com/pkg.deb"))
        assert result.policy is StaleIfError
        assert result.timeouts is None

    def test_resolver_first_match_wins_for_timeouts(self):
        tc1 = TimeoutConfig(read_timeout=100)
        tc2 = TimeoutConfig(read_timeout=999)
        rules = [
            SuffixRule(".whl", StaleIfError, timeouts=tc1),
            HostContainsRule("pythonhosted.org", StaleIfError, timeouts=tc2),
        ]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(Context(url="https://files.pythonhosted.org/torch.whl"))
        assert result.timeouts is tc1

    def test_prefix_rules_longest_match_gets_timeout(self):
        tc_short = TimeoutConfig(read_timeout=30)
        tc_long = TimeoutConfig(read_timeout=600)
        rules = [
            PrefixRule("https://cdn.example.com/", Standard, timeouts=tc_short),
            PrefixRule("https://cdn.example.com/large/", Standard, timeouts=tc_long),
        ]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(Context(url="https://cdn.example.com/large/file.bin"))
        assert result.timeouts is tc_long

    def test_mixed_rules_with_and_without_timeouts(self):
        tc = TimeoutConfig(connect_timeout=5, read_timeout=120)
        rules = [
            SuffixRule(".deb", StaleIfError),
            SuffixRule(".whl", StaleIfError, timeouts=tc),
        ]
        resolver = PolicyResolver(rules=rules)

        deb = resolver.resolve(Context(url="https://example.com/pkg.deb"))
        assert deb.policy is StaleIfError
        assert deb.timeouts is None

        whl = resolver.resolve(Context(url="https://example.com/torch.whl"))
        assert whl.policy is StaleIfError
        assert whl.timeouts is tc

    def test_default_rules_have_no_timeouts(self):
        resolver = PolicyResolver()
        result = resolver.resolve(Context(url="https://files.pythonhosted.org/torch.whl"))
        assert result.policy is StaleIfError
        assert result.timeouts is None


class TestForcedSwrSeconds:
    def test_resolved_policy_default_no_forced_swr(self):
        rp = ResolvedPolicy(policy=Standard)
        assert rp.forced_swr_seconds is None

    def test_resolved_policy_with_forced_swr(self):
        rp = ResolvedPolicy(policy=StaleIfError, forced_swr_seconds=86400)
        assert rp.forced_swr_seconds == 86400

    def test_prefix_rule_with_forced_swr(self):
        rule = PrefixRule(
            "https://pypi.org/simple",
            StaleIfError,
            forced_swr_seconds=86400,
        )
        ctx = Context(url="https://pypi.org/simple/requests/")
        assert rule.match(ctx) is StaleIfError
        assert rule.forced_swr_seconds == 86400

    def test_suffix_rule_with_forced_swr(self):
        rule = SuffixRule(".deb", StaleIfError, forced_swr_seconds=3600)
        assert rule.forced_swr_seconds == 3600

    def test_host_contains_rule_with_forced_swr(self):
        rule = HostContainsRule(
            "pypi.org", StaleIfError, forced_swr_seconds=43200,
        )
        ctx = Context(url="https://pypi.org/simple/flask/")
        assert rule.match(ctx) is StaleIfError
        assert rule.forced_swr_seconds == 43200

    def test_path_contains_rule_with_forced_swr(self):
        rule = PathContainsRule(
            "pypi.org/simple", StaleIfError, forced_swr_seconds=86400,
        )
        ctx = Context(url="https://pypi.org/simple/flask/")
        assert rule.match(ctx) is StaleIfError
        assert rule.forced_swr_seconds == 86400

    def test_regex_rule_with_forced_swr(self):
        rule = RegexRule(
            r".*\.tar\.gz$", StaleIfError, forced_swr_seconds=7200,
        )
        assert rule.forced_swr_seconds == 7200

    def test_callable_rule_with_forced_swr(self):
        rule = CallableRule(
            lambda ctx: StaleIfError if "slow" in ctx.url else None,
            forced_swr_seconds=600,
        )
        assert rule.forced_swr_seconds == 600

    def test_rule_without_forced_swr_defaults_none(self):
        rule = PrefixRule("https://example.com/", Standard)
        assert rule.forced_swr_seconds is None

    def test_resolver_propagates_forced_swr(self):
        rules = [
            PathContainsRule(
                "pypi.org/simple", StaleIfError, forced_swr_seconds=86400,
            ),
        ]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(
            Context(url="https://pypi.org/simple/requests/")
        )
        assert result.policy is StaleIfError
        assert result.forced_swr_seconds == 86400

    def test_resolver_no_forced_swr_for_default_policy(self):
        rules = [
            PathContainsRule(
                "pypi.org/simple", StaleIfError, forced_swr_seconds=86400,
            ),
        ]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(
            Context(url="https://example.com/unknown")
        )
        assert result.policy is Standard
        assert result.forced_swr_seconds is None

    def test_resolver_no_forced_swr_when_rule_has_none(self):
        rules = [SuffixRule(".deb", StaleIfError)]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(Context(url="https://example.com/pkg.deb"))
        assert result.policy is StaleIfError
        assert result.forced_swr_seconds is None

    def test_default_rules_have_no_forced_swr(self):
        resolver = PolicyResolver()
        # pypi.org/simple now has forced SWR enabled by default
        result = resolver.resolve(
            Context(url="https://pypi.org/simple/requests/")
        )
        assert result.policy is StaleIfError
        assert result.forced_swr_seconds == 86400

        # other rules should not have forced SWR
        result = resolver.resolve(
            Context(url="https://files.pythonhosted.org/packages/foo.whl")
        )
        assert result.policy is StaleIfError
        assert result.forced_swr_seconds is None

    def test_forced_swr_combined_with_timeouts(self):
        tc = TimeoutConfig(connect_timeout=5, read_timeout=120)
        rule = PrefixRule(
            "https://pypi.org/simple",
            StaleIfError,
            timeouts=tc,
            forced_swr_seconds=86400,
        )
        rules = [rule]
        resolver = PolicyResolver(rules=rules)
        result = resolver.resolve(
            Context(url="https://pypi.org/simple/requests/")
        )
        assert result.policy is StaleIfError
        assert result.timeouts is tc
        assert result.forced_swr_seconds == 86400
