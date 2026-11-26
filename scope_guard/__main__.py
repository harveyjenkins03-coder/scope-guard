"""Command line for scope-guard. See USAGE."""
from __future__ import annotations

import json
import sys

from .scope import Scope, ScopeError

USAGE = """usage: python -m scope_guard SCOPE.json TARGET [TARGET ...]

Prints one line per target. Exit 0 if every target is allowed, 1 if any is refused, 2 if the scope file is refused."""


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    """JSON allows a key twice and keeps the last one; a second "exclude" must not quietly replace the first."""
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ScopeError(f"key {key!r} appears twice")
        out[key] = value
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        with open(argv[0], encoding="utf-8") as f:
            scope = Scope.from_dict(json.load(f, object_pairs_hook=_no_duplicates))
    except (OSError, json.JSONDecodeError, ScopeError) as exc:
        print(f"scope refused: {exc}", file=sys.stderr)
        return 2
    worst = 0
    for target in argv[1:]:
        d = scope.check(target)
        print(f"{'ALLOW' if d.allowed else 'REFUSE':<6}  {d.reason:<22} {target}")
        worst = max(worst, 0 if d.allowed else 1)
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
