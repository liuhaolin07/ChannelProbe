"""Shared stdio worker loop.

A worker reads one JSON request per line and writes one JSON reply per line::

    -> {"tool": "...", "args": {...}}
    <- {"allowed": true, "reason": "...", "error": null}

stdout is the protocol channel, so a defense that prints must be wrapped in a
stdout redirect (see :func:`serve`). Getting that wrong corrupts the campaign
silently, which is the single easiest way to produce a meaningless report.
"""

from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from typing import Callable

DecideFn = Callable[[str, dict], tuple[bool, str]]


def respond(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def serve(decide: DecideFn, *, banner: str | None = None) -> int:
    """Run the JSONL request loop until stdin closes."""
    if banner:
        print(banner, file=sys.stderr, flush=True)

    sink = io.StringIO()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            respond({"allowed": None, "reason": "", "error": "bad request json"})
            continue

        tool = str(request.get("tool", ""))
        tool_args = request.get("args") or {}
        if not isinstance(tool_args, dict):
            respond({"allowed": None, "reason": "", "error": "args must be an object"})
            continue

        try:
            sink.seek(0)
            sink.truncate(0)
            with redirect_stdout(sink):
                allowed, reason = decide(tool, tool_args)
            respond({"allowed": bool(allowed), "reason": str(reason), "error": None})
        except Exception as exc:  # noqa: BLE001
            respond({
                "allowed": None,
                "reason": "",
                "error": f"{type(exc).__name__}: {exc}",
            })

    return 0
