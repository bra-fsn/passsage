# """Tests for Passsage proxy."""

# import pytest

# from passsage.proxy import (
#     AlwaysCached,
#     AlwaysUpstream,
#     MissingCached,
#     Modified,
#     NoCache,
#     get_policy,
#     http_2xx,
# )


# class MockRequest:
#     def __init__(self, url):
#         self.url = url


# class MockFlow:
#     def __init__(self, url):
#         self.request = MockRequest(url)


# class TestPolicies:
#     def test_nocache_aws_api(self):
#         flow = MockFlow("https://ec2.amazonaws.com/some/path")
#         policy = get_policy(flow)
#         assert policy == NoCache

#     def test_nocache_link_local(self):
#         flow = MockFlow("http://169.254.169.254/latest/meta-data/")
#         policy = get_policy(flow)
#         assert policy == NoCache

#     def test_always_cached_deb(self):
#         flow = MockFlow("http://archive.ubuntu.com/pool/main/p/python3.10/python3.10_3.10.12.deb")
#         policy = get_policy(flow)
#         assert policy == AlwaysCached

#     def test_always_cached_mran(self):
#         flow = MockFlow("https://mran.microsoft.com/snapshot/2023-01-01/package.tar.gz")
#         policy = get_policy(flow)
#         assert policy == AlwaysCached

#     def test_modified_default(self):
#         flow = MockFlow("https://example.com/api/data")
#         policy = get_policy(flow)
#         assert policy == Modified


# class TestHttpStatus:
#     def test_2xx_200(self):
#         class MockResponse:
#             status_code = 200
#         assert http_2xx(MockResponse()) is True

#     def test_2xx_201(self):
#         class MockResponse:
#             status_code = 201
#         assert http_2xx(MockResponse()) is True

#     def test_2xx_299(self):
#         class MockResponse:
#             status_code = 299
#         assert http_2xx(MockResponse()) is True

#     def test_not_2xx_404(self):
#         class MockResponse:
#             status_code = 404
#         assert http_2xx(MockResponse()) is False

#     def test_not_2xx_500(self):
#         class MockResponse:
#             status_code = 500
#         assert http_2xx(MockResponse()) is False

#     def test_none_response(self):
#         assert http_2xx(None) is False
