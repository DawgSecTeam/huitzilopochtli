"""Box-side directive executor. See architecture.md §12.2."""
from agent.adversary.actions import ACTIONS
from common.schema import Directive


class UnknownDirectiveError(Exception):
    """The engine sent a directive whose action is not in the ACTIONS registry."""


def execute(directive: Directive, ctx: "agent.platform.base.PlatformContext") -> None:
    """Dispatch directive.action via the ACTIONS registry with directive.params.
    Unknown action -> UnknownDirectiveError (fail closed; never silently ignore
    a directive from the engine, but also never execute anything outside
    ACTIONS). Callers in the ranked loop catch this per-directive so one bad
    directive cannot stall the run (§9.1)."""
    if directive.action not in ACTIONS:
        raise UnknownDirectiveError(f"unknown adversary action: {directive.action!r}")
    action_fn = ACTIONS[directive.action]
    action_fn(directive.params, ctx)
