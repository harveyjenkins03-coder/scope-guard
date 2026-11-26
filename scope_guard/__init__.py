"""scope-guard: a fail-closed answer to "may this target be touched under this engagement, and if not, why not?"."""
from .scope import Decision, OutOfScope, Scope, ScopeError, parse_target

__all__ = ["Decision", "OutOfScope", "Scope", "ScopeError", "parse_target"]
__version__ = "0.1.0"
