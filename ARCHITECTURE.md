# Architecture

One module, `scope_guard/scope.py`, with no dependencies beyond the standard library.

## Loading

`Scope.from_dict` reads a plain dictionary (for example, parsed JSON) and either returns a frozen `Scope` or raises
`ScopeError`. Nothing is checked against a scope that failed to load.

- Top-level keys: `include`, `exclude`, `window`, `wildcard_includes_apex`, `revoked`. Any other key is an error, so a
  misspelt `exclude` cannot be ignored.
- `include` and `exclude` take the same four lists, `domains`, `hosts`, `cidrs` and `urls`, and are validated by the
  same code.
- Domains may lead with one `*.` wildcard. Host names are IDNA-normalised. CIDRs must not have host bits set. URL
  rules must be `http` or `https`, with no user information, query or fragment, and a path that passes the same checks
  as a target's.
- The window's `start` and `end` must be ISO 8601 with a time zone, and `end` must be after `start`.

## Checking

`Scope.check(target, now=None)` returns a `Decision(allowed, reason)`. The order is fixed:

1. `revoked`, then the window (`window-not-started`, `window-ended`, or `clock-without-time-zone` for a naive `now`).
2. Parse the target into a host (or address), and for a URL its scheme, port and decoded path segments. Anything
   ambiguous gives `invalid-target`.
3. Exclusions, read broadly, against every fact the target has: the address against excluded CIDRs (an IPv4-mapped
   IPv6 address is checked as IPv4); the host against excluded domains, where either form covers the name and every
   name below it; the host against excluded hosts; the path against excluded URLs on that host, on any scheme and
   port, with case folded; and a bare host against any excluded URL on that host.
4. Inclusions: a host-level match (domain, host or CIDR) allows any path on that host; a URL rule allows its own
   origin and the path below it. A bare host is never allowed by a URL rule alone.
5. Otherwise `not-in-scope`.

`Scope.require` does the same and raises `OutOfScope`, carrying the decision, when the target is refused.

## Testing

`tests/test_pitfalls.py` has one class per pitfall in the README; `tests/test_scope.py` covers loading, the window,
decisions and the command line. `tools/mutation_check.py` replaces 10 guards with naive versions in turn and fails
if any replacement leaves the whole suite passing.

## Reason codes

`in-scope`, `revoked`, `window-not-started`, `window-ended`, `clock-without-time-zone`, `invalid-target`,
`excluded:cidr`, `excluded:domain`, `excluded:host`, `excluded:url`, `excluded:url-on-host`, `not-in-scope`.
