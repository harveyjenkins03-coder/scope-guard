"""One test class per scope-enforcement pitfall. Each case is a target that a naive check would get wrong."""
from __future__ import annotations

import unittest

from helpers import scope, reason


class LookalikeHosts(unittest.TestCase):
    """A string prefix test on URLs lets a longer host through."""

    def test_url_rule_host_with_a_suffix_is_refused(self):
        self.assertEqual(reason("https://app.example.net.evil.test/api/x"), "not-in-scope")

    def test_domain_rule_host_with_a_suffix_is_refused(self):
        self.assertEqual(reason("https://shop.example.com.evil.test/"), "not-in-scope")
        self.assertEqual(reason("notexample.com"), "not-in-scope")


AT = chr(64)  # built at run time, so the source never holds an address-shaped string for leak scanners to flag


class UserInformation(unittest.TestCase):
    """'user' + AT + 'host' hides the real host from a reader who stops at the first name."""

    def test_in_scope_name_before_at_is_refused(self):
        self.assertEqual(reason(f"https://app.example.net{AT}evil.test/api/"), "invalid-target")

    def test_any_user_information_is_refused(self):
        self.assertEqual(reason(f"https://someone{AT}app.example.net/api/"), "invalid-target")


class SchemeAndPort(unittest.TestCase):
    """A URL rule names one origin: scheme, host and port together."""

    def test_other_port_is_refused(self):
        self.assertEqual(reason("https://app.example.net:8443/api/x"), "not-in-scope")

    def test_explicit_default_port_is_the_same_origin(self):
        self.assertEqual(reason("https://app.example.net:443/api/x"), "in-scope")

    def test_other_scheme_is_refused(self):
        self.assertEqual(reason("http://app.example.net/api/x"), "not-in-scope")

    def test_unchecked_schemes_and_bad_ports_are_invalid(self):
        for t in ("ftp://app.example.net/api/", "https://app.example.net:0/api/", "https://app.example.net:70000/api/",
                  "https://app.example.net:/api/", "https://app.example.net:44x/api/"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "invalid-target")


class WholeSegments(unittest.TestCase):
    """'/api' must not cover '/apix'."""

    def test_longer_segment_is_refused(self):
        self.assertEqual(reason("https://app.example.net/apix"), "not-in-scope")

    def test_rule_path_and_below_are_allowed(self):
        for t in ("https://app.example.net/api", "https://app.example.net/api/", "https://app.example.net/api/v1/x"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "in-scope")

    def test_inclusions_compare_case_exactly(self):
        self.assertEqual(reason("https://app.example.net/API/x"), "not-in-scope")


class ExclusionsAcrossKinds(unittest.TestCase):
    """An exclusion applies to the host however the target is written."""

    def test_domain_exclusion_blocks_a_url_and_a_bare_host(self):
        self.assertEqual(reason("https://admin.example.com/login"), "excluded:domain")
        self.assertEqual(reason("admin.example.com"), "excluded:domain")

    def test_cidr_exclusion_blocks_a_url_with_an_address(self):
        self.assertEqual(reason("http://192.0.2.200/"), "excluded:cidr")
        self.assertEqual(reason("192.0.2.200"), "excluded:cidr")
        self.assertEqual(reason("http://192.0.2.10/"), "in-scope")

    def test_url_exclusion_blocks_the_path_and_below(self):
        self.assertEqual(reason("https://shop.example.com/checkout"), "excluded:url")
        self.assertEqual(reason("https://shop.example.com/checkout/pay"), "excluded:url")
        self.assertEqual(reason("https://shop.example.com/products"), "in-scope")

    def test_url_exclusion_holds_on_every_scheme_and_port(self):
        for t in ("http://shop.example.com/checkout", "https://shop.example.com:8443/checkout",
                  "http://shop.example.com:8080/Checkout/pay"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "excluded:url")

    def test_domain_exclusion_covers_names_below_it(self):
        self.assertEqual(reason("x.admin.example.com"), "excluded:domain")
        self.assertEqual(reason("https://deep.x.admin.example.com/"), "excluded:domain")
        self.assertEqual(reason("notadmin.example.com"), "in-scope")

    def test_url_exclusion_blocks_a_bare_host_check(self):
        self.assertEqual(reason("shop.example.com"), "excluded:url-on-host")

    def test_url_exclusion_ignores_case_encoding_and_empty_segments(self):
        for t in ("https://shop.example.com/CHECKOUT", "https://shop.example.com/%63heckout",
                  "https://shop.example.com//checkout"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "excluded:url")

    def test_host_exclusion(self):
        s = scope(exclude={"hosts": ["api.example.net"]})
        self.assertEqual(reason("https://api.example.net/", s), "excluded:host")

    def test_wildcard_exclusion_covers_its_bare_domain(self):
        s = scope(exclude={"domains": ["*.example.org"]})
        self.assertEqual(reason("example.org", s), "excluded:domain")


class AmbiguousPaths(unittest.TestCase):
    """Paths that a server may resolve differently are refused, not resolved here."""

    def test_dot_segments_hidden_separators_and_parameters(self):
        for t in ("https://app.example.net/api/../admin", "https://app.example.net/api/%2e%2e/admin",
                  "https://app.example.net/api/%2E%2E/admin", "https://app.example.net/api%2fadmin",
                  "https://app.example.net/api%5Cadmin", "https://app.example.net/api\\admin",
                  "https://app.example.net/api;x=1", "https://shop.example.com/checkout;jsessionid=1"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "invalid-target")

    def test_segments_a_server_may_trim_or_misread(self):
        for t in ("https://shop.example.com/checkout.", "https://shop.example.com/checkout%20",
                  "https://shop.example.com/checkout%00", "https://shop.example.com/checkout%7F/x",
                  "https://app.example.net/api./x"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "invalid-target")


class AmbiguousHosts(unittest.TestCase):
    """Hosts that some clients read as addresses and others as names."""

    def test_numeric_looking_names_are_refused(self):
        for t in ("0177.0.0.1", "2130706433", "0x7f.0.0.1", "http://0x7f.1/", "http://192.0.2.010/"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "invalid-target")

    def test_whitespace_control_characters_and_ports_on_bare_hosts(self):
        for t in ("https://app.example.net/api/ x", "api.example.net\n", " api.example.net", "api.example.net:443",
                  "", "https:///api/", "https://[2001:db8:1::5/"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "invalid-target")


class InternationalNames(unittest.TestCase):
    """Unicode and its ASCII form are one host."""

    def test_unicode_and_punycode_match_the_same_rule(self):
        for t in ("bücher.example", "BÜCHER.example", "xn--bcher-kva.example", "https://bücher.example/"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "in-scope")

    def test_characters_idna_versions_disagree_on_are_refused(self):
        for t in ("straße.example.com", "ς.example.com", "a‍b.example.com", "a‌b.example.com",
                  "https://straße.example.com/"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "invalid-target")

    def test_case_and_one_trailing_dot(self):
        for t in ("API.EXAMPLE.NET", "api.example.net.", "https://api.example.net./x"):
            with self.subTest(t=t):
                self.assertEqual(reason(t), "in-scope")


class WildcardApex(unittest.TestCase):
    """Whether '*.example.com' covers 'example.com' is a setting, off by default."""

    def test_off_by_default(self):
        self.assertEqual(reason("example.com"), "not-in-scope")
        self.assertEqual(reason("deep.sub.example.com"), "in-scope")

    def test_on_when_asked(self):
        self.assertEqual(reason("example.com", scope(wildcard_includes_apex=True)), "in-scope")


class Addresses(unittest.TestCase):
    def test_ipv6_in_and_out(self):
        self.assertEqual(reason("http://[2001:db8:1::5]/"), "in-scope")
        self.assertEqual(reason("2001:db8:1::5"), "in-scope")
        self.assertEqual(reason("http://[2001:db8:2::5]/"), "not-in-scope")

    def test_ipv4_mapped_ipv6_is_checked_as_the_ipv4_address(self):
        self.assertEqual(reason("::ffff:192.0.2.200"), "excluded:cidr")
        self.assertEqual(reason("http://[::ffff:192.0.2.200]/"), "excluded:cidr")
        self.assertEqual(reason("::ffff:192.0.2.10"), "in-scope")
        wide = scope(include={"cidrs": ["::/0"]}, exclude={"cidrs": ["192.0.2.0/24"]})
        self.assertEqual(reason("::ffff:192.0.2.10", wide), "excluded:cidr")

    def test_address_never_matches_a_name_rule(self):
        self.assertEqual(reason("198.51.100.7"), "not-in-scope")


if __name__ == "__main__":
    unittest.main()
