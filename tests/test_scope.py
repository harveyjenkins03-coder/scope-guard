"""Loading, the activity window, decisions and the command line."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta

from helpers import BASE, NOW, REASONS, reason, scope

from scope_guard import OutOfScope, Scope, ScopeError
from scope_guard.__main__ import main


class Loading(unittest.TestCase):
    """A scope that cannot be read exactly as written is refused at load time, exclusions included."""

    def refused(self, **changes):
        with self.assertRaises(ScopeError):
            scope(**changes)

    def test_the_example_loads(self):
        self.assertIsInstance(scope(), Scope)

    def test_unknown_keys_are_refused(self):
        with self.assertRaises(ScopeError):
            Scope.from_dict({**BASE, "exlude": {"domains": ["example.com"]}})
        self.refused(include={"domain": ["example.com"]})
        self.refused(window={"start": "2026-11-01T00:00:00Z", "finish": "2026-12-01T00:00:00Z"})

    def test_bad_exclusions_are_refused_like_bad_inclusions(self):
        for section in ("include", "exclude"):
            for kind, value in (("cidrs", "192.0.2.300/24"), ("cidrs", "192.0.2.1/24"), ("cidrs", "not-a-net"),
                                ("domains", "*.*.example.com"), ("domains", "ex*ample.com"), ("domains", "a..b"),
                                ("domains", "straße.example.com"),
                                ("hosts", "192.0.2.1"), ("hosts", "*.example.com"),
                                ("urls", "https://example.com/?q=1"), ("urls", "https://example.com/#top"),
                                ("urls", "ftp://example.com/"), ("urls", "https://example.com/../x")):
                with self.subTest(section=section, kind=kind, value=value):
                    self.refused(**{section: {kind: [value]}})

    def test_wrong_types_are_refused(self):
        self.refused(include={"domains": "example.com"})
        self.refused(include={"domains": [1]})
        self.refused(include=["example.com"])
        self.refused(wildcard_includes_apex="yes")
        self.refused(revoked=1)
        with self.assertRaises(ScopeError):
            Scope.from_dict(["not", "an", "object"])

    def test_bad_windows_are_refused(self):
        self.refused(window={"end": "2026-13-01T00:00:00Z"})
        self.refused(window={"end": "next week"})
        self.refused(window={"end": "2026-12-01T00:00:00"})  # no time zone
        self.refused(window={"start": "2026-12-01T00:00:00Z", "end": "2026-11-01T00:00:00Z"})
        self.refused(window={"start": "2026-12-01T00:00:00Z", "end": "2026-12-01T00:00:00Z"})
        self.refused(window="2026-12-01")
        self.refused(window="")
        self.refused(window=False)
        self.refused(window=[])


class Window(unittest.TestCase):
    def test_before_during_and_after(self):
        s = scope()
        self.assertEqual(reason("api.example.net", s, datetime.fromisoformat("2026-10-31T23:59:59+00:00")),
                         "window-not-started")
        self.assertEqual(reason("api.example.net", s, datetime.fromisoformat("2026-11-01T00:00:00+00:00")),
                         "in-scope")
        self.assertEqual(reason("api.example.net", s, datetime.fromisoformat("2026-12-01T00:00:00+00:00")),
                         "window-ended")

    def test_other_time_zones_compare_correctly(self):
        late = datetime.fromisoformat("2026-12-01T00:30:00+01:00")  # 23:30 UTC on 30 November
        self.assertEqual(reason("api.example.net", scope(), late), "in-scope")

    def test_a_clock_without_a_time_zone_is_refused(self):
        self.assertEqual(reason("api.example.net", scope(), NOW.replace(tzinfo=None)), "clock-without-time-zone")

    def test_no_window_means_always(self):
        s = scope(window=None)
        self.assertEqual(reason("api.example.net", s, NOW + timedelta(days=3650)), "in-scope")


class Decisions(unittest.TestCase):
    def test_revoked_refuses_everything(self):
        self.assertEqual(reason("api.example.net", scope(revoked=True)), "revoked")

    def test_empty_scope_refuses_everything(self):
        s = Scope.from_dict({})
        self.assertEqual(reason("api.example.net", s), "not-in-scope")

    def test_non_strings_are_invalid(self):
        self.assertEqual(scope().check(None, NOW).reason, "invalid-target")  # type: ignore[arg-type]

    def test_reasons_are_fixed_codes(self):
        targets = ["https://app.example.net.evil.test/api/", "admin.example.com", "http://192.0.2.200/",
                   "shop.example.com", "https://shop.example.com/checkout", "198.51.100.7", "0177.0.0.1",
                   "https://app.example.net/apix", "api.example.net"]
        for t in targets:
            with self.subTest(t=t):
                self.assertIn(scope().check(t, NOW).reason, REASONS)

    def test_require_raises_with_the_decision(self):
        with self.assertRaises(OutOfScope) as caught:
            scope().require("admin.example.com", NOW)
        self.assertEqual(caught.exception.decision.reason, "excluded:domain")
        self.assertTrue(scope().require("api.example.net", NOW).allowed)

    def test_decisions_and_scopes_are_immutable(self):
        d = scope().check("api.example.net", NOW)
        with self.assertRaises(AttributeError):
            d.allowed = False  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            scope().revoked = True  # type: ignore[misc]


class CommandLine(unittest.TestCase):
    def run_cli(self, data, *targets) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "scope.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write(data if isinstance(data, str) else json.dumps(data))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main([path, *targets])
            return code, out.getvalue(), err.getvalue()

    def test_exit_codes(self):
        no_window = {k: v for k, v in BASE.items() if k != "window"}
        self.assertEqual(self.run_cli(no_window, "api.example.net")[0], 0)
        code, out, _ = self.run_cli(no_window, "api.example.net", "admin.example.com")
        self.assertEqual(code, 1)
        self.assertIn("REFUSE  excluded:domain", out)
        self.assertEqual(self.run_cli({"exlude": {}}, "api.example.net")[0], 2)
        self.assertEqual(self.run_cli("{not json", "api.example.net")[0], 2)

    def test_a_key_given_twice_is_refused(self):
        twice = '{"exclude": {"domains": ["admin.example.com"]}, "exclude": {}, "include": {"hosts": ["a.example.com"]}}'
        code, _, err = self.run_cli(twice, "admin.example.com")
        self.assertEqual(code, 2)
        self.assertIn("appears twice", err)

    def test_usage(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(main([]), 2)
        self.assertIn("usage:", err.getvalue())


if __name__ == "__main__":
    unittest.main()
