"""Enumerate the data-carrying channels a tool call exposes.

A *channel* is one addressable string position inside a tool call's arguments
object: the dotted path from the arguments root to a leaf. Every channel is a
place a value can travel through, therefore a place data can leave through.

Channels are derived from the tool's *declared schema* (the JSON-Schema
``parameters`` object the model is shown), because that schema defines exactly
what the model is able to put data into.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Channel:
    """One addressable string position inside a tool call's arguments."""

    tool: str
    path: str

    @property
    def leaf(self) -> str:
        """The last path segment, used for applicability heuristics."""
        return self.path.split(".")[-1].rstrip("[]")

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.tool}.{self.path}"


# --------------------------------------------------------------------------- #
# Schema walking
# --------------------------------------------------------------------------- #

def leaf_string_paths(schema: dict, prefix: str = "") -> list[str]:
    """Return dotted paths of every string-ish leaf in a JSON-Schema subtree.

    Handles nested ``object`` (via ``properties``) and ``array`` (via ``items``,
    rendered as a ``name[]`` segment). A node with no ``type`` but with
    ``properties`` is treated as an object; a bare node is treated as a string
    leaf, which is the lenient reading and keeps unknown shapes probeable.

    ``prefix`` arrives with a trailing dot from the parent; it is normalised
    here so array markers attach directly (``labels[]``, never ``labels.[]``).
    """
    node_type = schema.get("type")
    properties = schema.get("properties")
    items = schema.get("items")
    base = prefix.rstrip(".")

    if node_type == "object" or (node_type is None and isinstance(properties, dict)):
        paths: list[str] = []
        for name, sub in (properties or {}).items():
            child = f"{base}.{name}" if base else name
            paths.extend(leaf_string_paths(sub, prefix=child))
        return paths

    if node_type == "array" or (node_type is None and isinstance(items, dict)):
        if not isinstance(items, dict):
            return [f"{base}[]"] if base and not base.endswith("[]") else ([base] if base else [])
        # An array of scalars becomes one channel; an array of objects recurses.
        sub_paths = leaf_string_paths(items, prefix=f"{base}[]")
        return sub_paths or ([base] if base else [])

    # string / number / integer / boolean / enum / unknown -> a single leaf
    return [base] if base else []


def tool_channels(tool_name: str, schema: dict) -> list[Channel]:
    """All channels a tool call exposes, in stable declaration order."""
    return [Channel(tool_name, p) for p in leaf_string_paths(schema)]


# --------------------------------------------------------------------------- #
# Dotted-path read / write over a plain nested dict
# --------------------------------------------------------------------------- #

def _segments(path: str) -> list[str]:
    return [s for s in path.split(".") if s]


def get_path(args: dict, path: str):
    """Read a dotted path. Array segments (``name[]``) read element 0."""
    current = args
    for segment in _segments(path):
        is_array = segment.endswith("[]")
        key = segment[:-2] if is_array else segment
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
        if is_array:
            if not isinstance(current, list) or not current:
                return None
            current = current[0]
    return current


def set_path(args: dict, path: str, value) -> None:
    """Write a dotted path, materialising intermediate dicts and 1-element lists."""
    segments = _segments(path)
    current = args
    for index, segment in enumerate(segments):
        is_array = segment.endswith("[]")
        key = segment[:-2] if is_array else segment
        last = index == len(segments) - 1

        if last:
            current[key] = [value] if is_array else value
            return

        if is_array:
            bucket = current.get(key)
            if not isinstance(bucket, list) or not bucket:
                bucket = [{}]
                current[key] = bucket
            current = bucket[0]
        else:
            bucket = current.get(key)
            if not isinstance(bucket, dict):
                bucket = {}
                current[key] = bucket
            current = bucket
