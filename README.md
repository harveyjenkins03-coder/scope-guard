# scope-guard

A small Python library that answers one question before an automated security test touches anything: is this target
inside the engagement's authorised scope, and if not, why not? It fails closed.

## At a glance

- **What it is.** A scope file (what is included, what is excluded, when the engagement runs) and a `check()` that
  takes a URL, a host name or an address and returns a decision with a fixed reason code. No network access, no DNS,
  nothing executed. Standard library only.
- **Why.** Scope checks look simple and are easy to get subtly wrong. A check that lets `app.example.net.evil.test`
  through because it starts with `app.example.net`, or skips an exclusion because the target was written as a URL
  instead of a host, gives an automated tool permission it was never given. This library is built around those
  mistakes, and each one has a regression test.
- **My part.** I chose the rules it enforces, the fail-closed defaults and the list of pitfalls it must defend against.
- **Stack.** Python 3.10 or later, standard library only, MIT licence.
- **Measured.** 50 tests pass on Python 3.10, 3.12 and 3.14 on Windows 11, each run under 0.1 s (2026-11-26,
  `python -m unittest discover -s tests`). [`tools/mutation_check.py`](tools/mutation_check.py) swaps each of 10
  guards for a naive version, and every one of those mutants makes between 1 and 15 tests fail. CI runs both on
  Ubuntu and Windows.

## Use

```python
from scope_guard import Scope

scope = Scope.from_dict({
    "include": {"domains": ["*.example.com"], "hosts": ["api.example.net"],
                "cidrs": ["192.0.2.0/24"], "urls": ["https://app.example.net/api/"]},
    "exclude": {"domains": ["admin.example.com"], "urls": ["https://shop.example.com/checkout"]},
})

scope.check("https://shop.example.com/products")   # Decision(allowed=True, reason='in-scope')
scope.check("https://admin.example.com/login")     # Decision(allowed=False, reason='excluded:domain')
scope.require("https://app.example.net/apix")      # raises OutOfScope (reason 'not-in-scope')
```

An engagement window is one more key, `"window": {"start": "2026-11-01T00:00:00Z", "end": "2026-12-01T00:00:00Z"}`,
and outside it every target is refused.

From the command line, with exit code 0 when every target is allowed, 1 when any is refused and 2 when the scope file
itself is refused:

```sh
python -m scope_guard examples/scope.json "https://api.example.net/v1" "shop.example.com"
```

## The pitfalls it is tested against

| Pitfall | What scope-guard does |
|---|---|
| Matching URLs by string prefix, so a longer look-alike host passes | Parses each URL and compares scheme, host and port exactly, then the path whole segment by segment: `/api` covers `/api/v1`, never `/apix` |
| A host hidden behind user information (`https://in-scope@elsewhere/`) | Refuses any URL with user information |
| Exclusions checked only for the kind of target the caller named | Checks every exclusion against the host, address and path the target gives, whatever its form. A URL exclusion also refuses a check of its bare host, since a host-wide action could reach the excluded path |
| Exclusions read as narrowly as inclusions | Reads exclusions broadly: a URL exclusion holds on every scheme and port of its host, and a domain exclusion covers every name below it |
| A typo in an exclusion that silently matches nothing | Validates every rule when the file loads, exclusions included: unknown keys, malformed or host-bit CIDRs, misplaced wildcards, URL rules with queries, a `window` that is not an object. The command line also refuses a JSON key given twice |
| A date that fails to parse and so never expires | Refuses a window that does not parse, has no time zone, or ends before it starts. A clock without a time zone is refused too |
| `*.example.com` quietly covering `example.com` | Makes it a setting, `wildcard_includes_apex`, off by default. A wildcard exclusion always covers its bare domain |
| Unicode and ASCII forms of one name treated as two hosts | Normalises host names to their IDNA ASCII form, lower case, one trailing dot removed, and refuses the characters that IDNA versions map differently (`ß`, `ς`, zero-width joiners) |
| Paths a server may read differently (`..`, `%2f`, `\`, `;params`, `checkout.`, `%00`, `%63heckout`) | Refuses dot segments, encoded separators, parameters, control characters and segments ending in a dot or space; decodes the rest before matching, and compares exclusions without case |
| Host names that some clients read as addresses (`0177.0.0.1`, `2130706433`) | Refuses them as ambiguous |
| An IPv4 address written as IPv6 (`::ffff:192.0.2.9`) | Checks it as the IPv4 address it reaches |
| Refusal messages that echo the allow list | Returns fixed reason codes only, never a rule |

## What it does not do

- It does not resolve names. An in-scope name can point at an address that is out of scope; a caller that cares must
  resolve the name and check the address too.
- It decides; it does not enforce. The caller has to ask before every request, including each redirect.
- It does not know what the scope should be. The file has to come from the programme's or client's written rules, and
  a scope file is not an authorisation.
- Paths are compared as text after decoding. It does not know how a particular server maps them.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the order of the checks.

## How this was made

I set the requirements and the pitfall list. Claude Code wrote the code and the tests in a new repository, from those
requirements; no code was carried over from earlier projects. A separate reviewer agent read it before release and
found gaps (a URL exclusion that held only on one scheme and port, among others); each was fixed with a regression
test and a mutant in the mutation check. I approved the release.

## Licence

MIT. See [LICENSE](LICENSE).
