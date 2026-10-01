"""Target specification and the probe campaign runner."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from channelprobe.adapters import Decision, DefenseAdapter
from channelprobe.canaries import Canary, canaries_for
from channelprobe.channels import Channel, get_path, set_path, tool_channels


# --------------------------------------------------------------------------- #
# Target specification
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ToolSpec:
    """One tool the agent can call, as the model sees it."""

    name: str
    schema: dict
    benign: dict
    target_tool: str | None = None  # name the defense expects, if it differs

    @property
    def request_tool(self) -> str:
        return self.target_tool or self.name


@dataclass(frozen=True)
class TargetSpec:
    name: str
    worker: str
    worker_args: dict[str, Any] = field(default_factory=dict)
    tools: tuple[ToolSpec, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict) -> "TargetSpec":
        target = raw["target"]
        tools = tuple(
            ToolSpec(
                name=t["name"],
                schema=t["schema"],
                benign=t.get("benign", {}),
                target_tool=t.get("target_tool"),
            )
            for t in raw.get("tools", [])
        )
        return cls(
            name=target.get("name", target["worker"]),
            worker=target["worker"],
            worker_args=target.get("worker_args", {}),
            tools=tools,
        )

    @classmethod
    def load(cls, path: str | Path) -> "TargetSpec":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- #
# Probes
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Probe:
    """One single-channel injection (or its benign control).

    ``canary`` is ``None`` for the untouched baseline probe, which is a harness
    sanity check rather than a measurement and is excluded from scoring.
    """

    tool: str
    request_tool: str
    channel: Channel
    canary: Canary | None
    kind: str          # "canary" | "control" | "baseline"
    args: dict

    @property
    def label(self) -> str:
        return f"{self.channel}.{self.canary.name if self.canary else '-'}.{self.kind}"


@dataclass(frozen=True)
class ProbeResult:
    probe: Probe
    decision: Decision

    @property
    def blocked(self) -> bool:
        return self.decision.allowed is False

    @property
    def errored(self) -> bool:
        return self.decision.error is not None


def build_probes(spec: TargetSpec) -> list[Probe]:
    """Enumerate the full probe matrix for a target.

    For every (channel, applicable canary) pair we emit two probes that differ
    *only* in the value written to that one channel: the canary itself, and its
    benign same-shape control. Everything else stays at its benign baseline, so
    any change in the verdict is attributable to that channel.
    """
    probes: list[Probe] = []

    for tool in spec.tools:
        channels = tool_channels(tool.name, tool.schema)
        if not channels:
            continue

        # Untouched baseline, used as a sanity check.
        baseline = copy.deepcopy(tool.benign)
        for channel in channels:
            if get_path(baseline, channel.path) is None:
                set_path(baseline, channel.path, "benchmark")
        probes.append(Probe(
            tool=tool.name, request_tool=tool.request_tool, channel=channels[0],
            canary=None, kind="baseline", args=baseline,
        ))

        for channel in channels:
            for canary in canaries_for(channel.leaf):
                for kind, value in (("canary", canary.value), ("control", canary.benign)):
                    args = copy.deepcopy(tool.benign)
                    set_path(args, channel.path, value)
                    probes.append(Probe(
                        tool=tool.name, request_tool=tool.request_tool,
                        channel=channel, canary=canary, kind=kind, args=args,
                    ))

    return probes


def run_campaign(adapter: DefenseAdapter, spec: TargetSpec) -> list[ProbeResult]:
    """Execute every probe against the defense, in order."""
    return [
        ProbeResult(probe, adapter.decide(probe.request_tool, probe.args))
        for probe in build_probes(spec)
    ]


def iter_tools(spec: TargetSpec) -> Iterator[ToolSpec]:
    return iter(spec.tools)
