"""Registered check-type keys shared by authoring, agent, and tests.

Kept in ``common`` (stdlib-only) so the authoring toolchain can reject an
unknown/typo'd check type at compile time without importing the agent runtime.
``tests/unit/test_checks.py`` asserts this set and the live CHECKS registry
cannot drift.
"""

CHECK_TYPES = frozenset({
    "file_regex",
    "permission",
    "user_group",
    "service_state",
    "package",
    "process_state",
    "http_uptime",
    "db_query",
    "forensics_answer",
    "command_json",
    "powershell_json",
    "registry_value",
})
