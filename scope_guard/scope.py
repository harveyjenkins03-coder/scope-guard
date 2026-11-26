"""The scope model and the one question it answers: may this target be touched under this engagement?

Everything here fails closed. A scope file that cannot be read exactly as written is refused when it is loaded, and a
target that cannot be read without guessing is refused when it is checked. Decisions carry a reason code, never the
rules themselves.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import unquote, urlsplit

KINDS = ("domains", "hosts", "cidrs", "urls")
TOP_KEYS = {"include", "exclude", "window", "wildcard_includes_apex", "revoked"}
SCHEMES = {"http": 80, "https": 443}
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_NUMERIC_LOOKING = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")
_IDNA_DEVIATIONS = "ßς‌‍"  # sharp s, final sigma, zero-width non-joiner and joiner


class ScopeError(ValueError):
    """The scope file is malformed. Nothing is checked against a scope that failed to load."""


class OutOfScope(PermissionError):
    """Raised by Scope.require when a target is refused."""

    def __init__(self, decision: "Decision"):
        super().__init__(f"refused: {decision.reason}")
        self.decision = decision


@dataclass(frozen=True)
class Decision:
    """The answer for one target. `reason` is a fixed code such as "excluded:domain"; it never quotes a rule."""

    allowed: bool
    reason: str


@dataclass(frozen=True)
class Target:
    """A target reduced to the facts the rules are matched against."""

    host: str                      # lower-case ASCII host name, or the address as text
    ip: IPAddress | None
    scheme: str | None = None      # set only for URL targets
    port: int | None = None
    segments: tuple[str, ...] = ()


@dataclass(frozen=True)
class UrlRule:
    scheme: str
    host: str
    port: int
    segments: tuple[str, ...]


@dataclass(frozen=True)
class Rules:
    domains: tuple[str, ...] = ()  # "example.com" or "*.example.com"
    hosts: tuple[str, ...] = ()
    cidrs: tuple[IPNetwork, ...] = ()
    urls: tuple[UrlRule, ...] = ()


# --------------------------------------------------------------------------------------------- normalising


def normalise_host(raw: str) -> str:
    """Lower-case ASCII form of a host name: IDNA-encoded, one trailing dot removed. Raises ValueError."""
    if not raw or raw != raw.strip() or any(c in raw for c in "/\\@:% \t\r\n"):
        raise ValueError("host has characters a host name cannot have")
    if any(c in raw for c in _IDNA_DEVIATIONS):
        # IDNA 2003 (Python's codec) and IDNA 2008 (most browsers) map these differently, so one name can be two hosts.
        raise ValueError("host has a character that IDNA versions disagree on")
    host = raw[:-1] if raw.endswith(".") else raw
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("host is not a valid international name") from exc
    labels = host.split(".")
    if len(host) > 253 or not all(_LABEL.match(label) for label in labels):
        raise ValueError("host is not a valid name")
    if _NUMERIC_LOOKING.match(labels[-1]):
        # "0177.0.0.1", "2130706433" and "0x7f.1" are read as addresses by some clients and as names by others.
        raise ValueError("host looks numeric but is not a plain address")
    return host


def _parse_ip(raw: str) -> IPAddress | None:
    text = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped  # "::ffff:192.0.2.9" reaches 192.0.2.9, so it is checked as that address
    return ip


def _host_or_ip(raw: str) -> tuple[str, IPAddress | None]:
    ip = _parse_ip(raw)
    if ip is not None:
        return ip.compressed, ip
    return normalise_host(raw), None


def _segments(path: str) -> tuple[str, ...]:
    """Split a URL path into decoded segments.

    Anything a server might read differently from this function is refused rather than guessed at: dot segments,
    encoded slashes or backslashes, backslashes, ';' path parameters, decoded control characters, and segments ending
    in a dot or a space (some servers drop those). Empty segments ("//") are dropped.
    """
    if "\\" in path or ";" in path or re.search(r"%(2f|5c)", path, re.I):
        raise ValueError("path hides a separator or a parameter")
    parts = tuple(unquote(p) for p in path.split("/") if p != "")
    if any(p in (".", "..") for p in parts):
        raise ValueError("path has a dot segment")
    if any(ord(c) < 32 or ord(c) == 127 for p in parts for c in p) or any(p[-1] in ". " for p in parts):
        raise ValueError("path has a segment a server may read differently")
    return parts


def _split_url(raw: str) -> tuple[str, str, IPAddress | None, int, tuple[str, ...], str, str]:
    if any(c.isspace() or ord(c) < 32 for c in raw):
        raise ValueError("URL has whitespace or control characters")
    url = urlsplit(raw)
    scheme = url.scheme.lower()
    if scheme not in SCHEMES:
        raise ValueError("only http and https URLs are checked")
    netloc = url.netloc
    if "@" in netloc:
        raise ValueError("URL carries user information")
    if netloc.startswith("["):
        close = netloc.find("]")
        if close < 0:
            raise ValueError("URL has an unclosed IPv6 address")
        host_text, rest = netloc[: close + 1], netloc[close + 1:]
    else:
        host_text, sep, port_text = netloc.partition(":")
        rest = sep + port_text
    if not host_text:
        raise ValueError("URL has no host")
    if rest and not re.fullmatch(r":[0-9]{1,5}", rest):
        raise ValueError("URL port is not a number")
    port = int(rest[1:]) if rest else SCHEMES[scheme]
    if not 1 <= port <= 65535:
        raise ValueError("URL port is out of range")
    host, ip = _host_or_ip(host_text)
    return scheme, host, ip, port, _segments(url.path), url.query, url.fragment


def parse_target(raw: str) -> Target:
    """A URL ("https://host/path") or a bare host name or address. Raises ValueError for anything ambiguous."""
    if not isinstance(raw, str) or not raw:
        raise ValueError("target must be a non-empty string")
    if "://" in raw:
        scheme, host, ip, port, segments, _, _ = _split_url(raw)
        return Target(host, ip, scheme, port, segments)
    host, ip = _host_or_ip(raw)
    return Target(host, ip)


# --------------------------------------------------------------------------------------------- loading


def _strings(value: Any, where: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ScopeError(f"{where} must be a list of strings")
    return value


def _rules(section: Any, where: str) -> Rules:
    if section is None:
        return Rules()
    if not isinstance(section, Mapping):
        raise ScopeError(f"{where} must be an object")
    unknown = set(section) - set(KINDS)
    if unknown:
        raise ScopeError(f"{where} has unknown keys: {sorted(unknown)}")
    domains, hosts, cidrs, urls = [], [], [], []
    for n, rule in enumerate(_strings(section.get("domains", []), f"{where}.domains")):
        wild = rule.startswith("*.")
        body = rule[2:] if wild else rule
        if "*" in body:
            raise ScopeError(f"{where}.domains[{n}]: a wildcard may only lead, as '*.'")
        try:
            domains.append(("*." if wild else "") + normalise_host(body))
        except ValueError as exc:
            raise ScopeError(f"{where}.domains[{n}]: {exc}") from None
    for n, rule in enumerate(_strings(section.get("hosts", []), f"{where}.hosts")):
        try:
            host, ip = _host_or_ip(rule)
        except ValueError as exc:
            raise ScopeError(f"{where}.hosts[{n}]: {exc}") from None
        if ip is not None:
            raise ScopeError(f"{where}.hosts[{n}]: put addresses under cidrs")
        hosts.append(host)
    for n, net_text in enumerate(_strings(section.get("cidrs", []), f"{where}.cidrs")):
        try:
            cidrs.append(ipaddress.ip_network(net_text, strict=True))  # host bits set is a typo, not a network
        except ValueError as exc:
            raise ScopeError(f"{where}.cidrs[{n}]: {exc}") from None
    for n, rule in enumerate(_strings(section.get("urls", []), f"{where}.urls")):
        try:
            scheme, host, _, port, segments, query, fragment = _split_url(rule)
        except ValueError as exc:
            raise ScopeError(f"{where}.urls[{n}]: {exc}") from None
        if query or fragment:
            raise ScopeError(f"{where}.urls[{n}]: a URL rule cannot have a query or fragment")
        urls.append(UrlRule(scheme, host, port, segments))
    return Rules(tuple(domains), tuple(hosts), tuple(cidrs), tuple(urls))


def _when(value: Any, where: str) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ScopeError(f"{where} must be an ISO 8601 string")
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value  # Python 3.10 has no 'Z' suffix
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        raise ScopeError(f"{where} is not an ISO 8601 date and time") from None
    if when.tzinfo is None:
        raise ScopeError(f"{where} needs a time zone, for example 'Z'")
    return when


# --------------------------------------------------------------------------------------------- matching


def _domain_hit(rule: str, host: str, apex: bool, broad: bool) -> bool:
    """Compare label lists, so "example.com" can only ever be matched as whole labels.

    Inclusions (broad=False): "example.com" is that name only; "*.example.com" is every name below it, and the bare
    name too only when `apex` is set. Exclusions (broad=True): either form covers the name and everything below it.
    """
    want, have = rule.split("."), host.split(".")
    wild = want[0] == "*"
    parent = want[1:] if wild else want
    below = len(have) > len(parent) and have[len(have) - len(parent):] == parent
    if broad:
        return have == parent or below
    if not wild:
        return have == want
    return below or (apex and have == parent)


def _url_hit(rule: UrlRule, t: Target, broad: bool) -> bool:
    """The rule's path segments lead the target's, whole segment by segment, on the rule's host.

    Inclusions (broad=False) also need the same scheme and port, and compare paths exactly. Exclusions (broad=True)
    cover the path on every scheme and port of that host, and compare without case, because some servers do.
    """
    if t.host != rule.host:
        return False
    head = t.segments[: len(rule.segments)]
    if broad:
        return [s.casefold() for s in head] == [s.casefold() for s in rule.segments]
    return (t.scheme, t.port) == (rule.scheme, rule.port) and head == rule.segments


def _host_hit(rules: Rules, t: Target, apex: bool, broad: bool) -> str | None:
    """The kind of host-level rule that matches, if any."""
    if t.ip is not None:
        return "cidr" if any(t.ip in net for net in rules.cidrs) else None
    if any(_domain_hit(r, t.host, apex, broad) for r in rules.domains):
        return "domain"
    if t.host in rules.hosts:
        return "host"
    return None


@dataclass(frozen=True)
class Scope:
    include: Rules
    exclude: Rules
    start: datetime | None = None
    end: datetime | None = None
    wildcard_includes_apex: bool = False
    revoked: bool = False

    @classmethod
    def from_dict(cls, data: Any) -> "Scope":
        if not isinstance(data, Mapping):
            raise ScopeError("scope must be an object")
        unknown = set(data) - TOP_KEYS
        if unknown:
            raise ScopeError(f"scope has unknown keys: {sorted(unknown)}")
        window = data.get("window")
        if window is None:
            window = {}
        if not isinstance(window, Mapping) or set(window) - {"start", "end"}:
            raise ScopeError("window must be an object with only 'start' and 'end'")
        start, end = _when(window.get("start"), "window.start"), _when(window.get("end"), "window.end")
        if start and end and end <= start:
            raise ScopeError("window.end must be after window.start")
        apex, revoked = data.get("wildcard_includes_apex", False), data.get("revoked", False)
        if not isinstance(apex, bool) or not isinstance(revoked, bool):
            raise ScopeError("wildcard_includes_apex and revoked must be true or false")
        return cls(_rules(data.get("include"), "include"), _rules(data.get("exclude"), "exclude"),
                   start, end, apex, revoked)

    def check(self, target: str, now: datetime | None = None) -> Decision:
        if self.revoked:
            return Decision(False, "revoked")
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            return Decision(False, "clock-without-time-zone")
        if self.start and now < self.start:
            return Decision(False, "window-not-started")
        if self.end and now >= self.end:
            return Decision(False, "window-ended")
        try:
            t = parse_target(target)
        except ValueError:
            return Decision(False, "invalid-target")

        # Exclusions first, matched against every fact the target gives, whatever kind the caller had in mind.
        # An exclusion is read broadly and an inclusion narrowly: when in doubt, the answer is no.
        hit = _host_hit(self.exclude, t, apex=True, broad=True)
        if hit:
            return Decision(False, f"excluded:{hit}")
        if t.scheme is not None and any(_url_hit(r, t, broad=True) for r in self.exclude.urls):
            return Decision(False, "excluded:url")
        if t.scheme is None and any(r.host == t.host for r in self.exclude.urls):
            return Decision(False, "excluded:url-on-host")  # a host-wide action could reach the excluded path

        if _host_hit(self.include, t, self.wildcard_includes_apex, broad=False):
            return Decision(True, "in-scope")
        if t.scheme is not None and any(_url_hit(r, t, broad=False) for r in self.include.urls):
            return Decision(True, "in-scope")
        return Decision(False, "not-in-scope")

    def require(self, target: str, now: datetime | None = None) -> Decision:
        decision = self.check(target, now)
        if not decision.allowed:
            raise OutOfScope(decision)
        return decision
