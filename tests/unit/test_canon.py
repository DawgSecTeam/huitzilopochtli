"""Unit tests for common/canon.py canonicalize()."""
from common.canon import canonicalize


def test_key_order_independence():
    a = {"b": 1, "a": 2, "c": 3}
    b = {"c": 3, "a": 2, "b": 1}
    assert canonicalize(a) == canonicalize(b)


def test_nested_dict_key_order_independence():
    a = {"outer": {"z": 1, "y": {"n": 1, "m": 2}}, "top": 5}
    b = {"top": 5, "outer": {"y": {"m": 2, "n": 1}, "z": 1}}
    assert canonicalize(a) == canonicalize(b)


def test_nested_list_order_preserved_and_consistent():
    # Lists are ordered structures; canonicalize must not reorder list items,
    # but two equal structures (same list order) must canonicalize identically.
    a = {"items": [{"y": 1, "x": 2}, {"b": 3, "a": 4}]}
    b = {"items": [{"x": 2, "y": 1}, {"a": 4, "b": 3}]}
    assert canonicalize(a) == canonicalize(b)


def test_list_order_matters():
    a = {"items": [1, 2, 3]}
    b = {"items": [3, 2, 1]}
    assert canonicalize(a) != canonicalize(b)


def test_output_is_bytes():
    result = canonicalize({"a": 1})
    assert isinstance(result, bytes)


def test_no_trailing_newline():
    result = canonicalize({"a": 1})
    assert not result.endswith(b"\n")
    assert not result.endswith(b"\r\n")


def test_minimal_separators():
    # separators=(",", ":") means no spaces after ',' or ':'
    result = canonicalize({"a": 1, "b": 2})
    assert b", " not in result
    assert b": " not in result
    assert result == b'{"a":1,"b":2}'


def test_sorted_keys_in_output():
    result = canonicalize({"z": 1, "a": 2, "m": 3})
    assert result == b'{"a":2,"m":3,"z":1}'


def test_non_ascii_not_escaped():
    # ensure_ascii=False: non-ASCII characters should appear as literal UTF-8
    # bytes in the output, not as \uXXXX escape sequences.
    result = canonicalize({"name": "café"})
    assert "café".encode("utf-8") in result
    assert b"\\u" not in result


def test_non_ascii_round_trip_bytes():
    result = canonicalize({"emoji": "🔥"})
    assert "🔥".encode("utf-8") in result
    assert b"\\u" not in result
