"""Mutation check: swap each guard in scope_guard for a naive version and confirm the test suite notices.

    python tools/mutation_check.py

Each mutant must make at least one test fail. Exit 1 if any mutant survives, which would mean a guard is untested.
"""
from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]

import scope_guard.scope as m  # noqa: E402

ORIGINAL = {name: getattr(m, name) for name in ("_url_hit", "_segments", "_domain_hit", "normalise_host", "_when",
                                               "_parse_ip")}


def url_prefix_without_segment_boundary(rule, t, broad):
    path, rule_path = "/" + "/".join(t.segments), "/" + "/".join(rule.segments)
    same = t.host == rule.host and (broad or (t.scheme, t.port) == (rule.scheme, rule.port))
    return same and path.startswith(rule_path)


def exclusion_keyed_on_full_origin(rule, t, broad):
    if broad and (t.scheme, t.port) != (rule.scheme, rule.port):
        return False
    return ORIGINAL["_url_hit"](rule, t, broad)


def exclusion_compares_case_exactly(rule, t, broad):
    if broad:
        return t.host == rule.host and t.segments[: len(rule.segments)] == rule.segments
    return ORIGINAL["_url_hit"](rule, t, broad)


def dot_segments_accepted(path):
    return tuple(unquote(p) for p in path.split("/") if p)


def trailing_dots_accepted(path):
    parts = tuple(unquote(p) for p in path.split("/") if p)
    if "\\" in path or ";" in path or any(p in (".", "..") for p in parts) or "%2f" in path.lower():
        raise ValueError("kept")
    return parts


def wildcard_inclusion_always_covers_apex(rule, host, apex, broad):
    return ORIGINAL["_domain_hit"](rule, host, True, broad)


def exclusion_is_exact(rule, host, apex, broad):
    return ORIGINAL["_domain_hit"](rule, host, apex, False)


def numeric_and_deviation_hosts_accepted(raw):
    host = raw[:-1] if raw.endswith(".") else raw
    if not host or any(c in host for c in "/\\@:% \t\r\n"):
        raise ValueError("kept")
    return host.encode("idna").decode("ascii").lower()


def malformed_dates_ignored(value, where):
    try:
        return ORIGINAL["_when"](value, where)
    except m.ScopeError:
        return None


def mapped_addresses_kept_as_ipv6(raw):
    import ipaddress
    text = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


MUTANTS = [
    ("URL rule matched by string prefix", "_url_hit", url_prefix_without_segment_boundary),
    ("URL exclusion keyed on scheme and port", "_url_hit", exclusion_keyed_on_full_origin),
    ("URL exclusion compares case exactly", "_url_hit", exclusion_compares_case_exactly),
    ("dot segments accepted", "_segments", dot_segments_accepted),
    ("trailing dots, spaces and control characters accepted", "_segments", trailing_dots_accepted),
    ("wildcard inclusion always covers the bare domain", "_domain_hit", wildcard_inclusion_always_covers_apex),
    ("domain exclusion matches the exact name only", "_domain_hit", exclusion_is_exact),
    ("numeric-looking and IDNA-deviation hosts accepted", "normalise_host", numeric_and_deviation_hosts_accepted),
    ("malformed window dates ignored", "_when", malformed_dates_ignored),
    ("IPv4-mapped IPv6 kept as IPv6", "_parse_ip", mapped_addresses_kept_as_ipv6),
]


def main() -> int:
    survivors = []
    for label, name, mutant in MUTANTS:
        setattr(m, name, mutant)
        try:
            suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests"))
            result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        finally:
            setattr(m, name, ORIGINAL[name])
        failing = len(result.failures) + len(result.errors)
        print(f"{'caught' if failing else 'SURVIVED':8} {failing:3d} failing tests  {label}")
        if not failing:
            survivors.append(label)
    print("every mutant was caught" if not survivors else f"survivors: {survivors}")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
