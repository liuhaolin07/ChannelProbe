"""Bridge worker: answers ChannelProbe requests using AgentShield's middleware.

Run standalone::

    python -m channelprobe.workers.agentshield --root /path/to/AgentShield

Also usable as a harness for other projects: point ``--root`` at any checkout
that exposes ``security.middleware.check_tool_call(tool, args, ...)``.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile

from channelprobe.workers.base import respond, serve

AGENT_NAME = "channelprobe"


def make_decide(root: str, policy_path: str, audit_path: str):
    """Bind the AgentShield middleware into a ``decide(tool, args)`` callable."""
    sys.path.insert(0, root)
    from security.middleware import check_tool_call  # type: ignore[import-not-found]

    def decide(tool: str, args: dict) -> tuple[bool, str]:
        decision = check_tool_call(
            tool,
            args,
            agent=AGENT_NAME,
            policy_path=policy_path,
            audit_path=audit_path,
        )
        return bool(decision.allowed), decision.reason

    return decide


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ChannelProbe <-> AgentShield bridge")
    parser.add_argument("--root", required=True, help="AgentShield project root")
    parser.add_argument("--policy", default=None, help="path to policy.yaml")
    parser.add_argument("--audit", default=None, help="path to the audit jsonl")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        respond({"allowed": None, "reason": "", "error": f"root not found: {root}"})
        return 2

    policy_path = args.policy or os.path.join(root, "policy.yaml")
    audit_path = args.audit or os.path.join(
        tempfile.gettempdir(), "channelprobe_agentshield_audit.jsonl"
    )

    try:
        decide = make_decide(root, policy_path, audit_path)
    except Exception as exc:  # noqa: BLE001
        respond({
            "allowed": None,
            "reason": "",
            "error": f"cannot import middleware: {type(exc).__name__}: {exc}",
        })
        return 3

    return serve(decide, banner=f"ChannelProbe bridge -> {root}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
