"""Box-side directive executor. See architecture.md §12.2.

PHASE 1 TASK: implement execute().
"""
from agent.adversary.actions import ACTIONS
from common.schema import Directive


def execute(directive: Directive, ctx: "agent.platform.base.PlatformContext") -> None:
    """Dispatch directive.action via the ACTIONS registry with directive.params.
    Unknown action -> raise (fail closed; never silently ignore a directive
    from the engine, but also never execute anything outside ACTIONS)."""
    if directive.action not in ACTIONS:
        raise KeyError(f"unknown adversary action: {directive.action!r}")
    action_fn = ACTIONS[directive.action]
    action_fn(directive.params, ctx)
