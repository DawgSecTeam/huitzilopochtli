"""Closed adversary action vocabulary. See architecture.md §12.2.

FROZEN registry mechanism. PHASE 1 TASK: implement the 3 allowlisted actions.

Hard constraint (§2.7): no action may open an outbound connection to any host
other than the engine. There is no network-egress primitive anywhere in this
module — that is a structural property, not a policy to be enforced at
runtime. Do not add a generic "run command" primitive.
"""
from typing import Callable

ACTIONS: dict[str, Callable] = {}


def register(name: str):
    def deco(fn):
        ACTIONS[name] = fn
        return fn
    return deco


# PHASE 1: implement each action, e.g.
#
# @register("flush_firewall")
# def _flush_firewall(params: dict, ctx: "agent.platform.base.PlatformContext") -> None:
#     raise NotImplementedError
#
# @register("kill_service")
# def _kill_service(params: dict, ctx) -> None:
#     raise NotImplementedError
#
# @register("drop_inert_artifact")
# def _drop_inert_artifact(params: dict, ctx) -> None:
#     """Writes a benign, inert marker file. Never an executable payload,
#     never a callback."""
#     raise NotImplementedError
