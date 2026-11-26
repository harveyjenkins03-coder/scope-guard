"""Shared fixtures. Every name is a reserved example name and every address comes from a documentation range
(RFC 2606 / RFC 6761 names, RFC 5737 and RFC 3849 addresses), so no test ever points at a real system."""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from scope_guard import Scope

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)

BASE = {
    "include": {
        "domains": ["*.example.com", "example.org", "bücher.example"],
        "hosts": ["api.example.net"],
        "cidrs": ["192.0.2.0/24", "2001:db8:1::/48"],
        "urls": ["https://app.example.net/api/"],
    },
    "exclude": {
        "domains": ["admin.example.com"],
        "cidrs": ["192.0.2.128/25"],
        "urls": ["https://shop.example.com/checkout"],
    },
    "window": {"start": "2026-11-01T00:00:00Z", "end": "2026-12-01T00:00:00Z"},
}

REASONS = {
    "in-scope", "revoked", "clock-without-time-zone", "window-not-started", "window-ended", "invalid-target",
    "excluded:cidr", "excluded:domain", "excluded:host", "excluded:url", "excluded:url-on-host", "not-in-scope",
}


def scope(**changes) -> Scope:
    data = copy.deepcopy(BASE)
    data.update(changes)
    return Scope.from_dict(data)


def reason(target: str, s: Scope | None = None, now: datetime = NOW) -> str:
    return (s or scope()).check(target, now).reason
