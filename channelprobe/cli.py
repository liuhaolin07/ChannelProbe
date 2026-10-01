"""Command line entry point.

    python -m channelprobe.cli run --config configs/agentshield.json --out out/
    python -m channelprobe.cli channels --config configs/agentshield.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from channelprobe.adapters import WorkerAdapter
from channelprobe.campaign import TargetSpec, build_probes, run_campaign
from channelprobe.channels import tool_channels
from channelprobe.metrics import score
from channelprobe.report import render_json, render_markdown


def _cmd_channels(args: argparse.Namespace) -> int:
    spec = TargetSpec.load(args.config)
    print(f"target: {spec.name}  (worker: {spec.worker})")
    for tool in spec.tools:
        channels = tool_channels(tool.name, tool.schema)
        print(f"\n  {tool.name}  -> defense tool {tool.request_tool!r}")
        for channel in channels:
            print(f"    - {channel.path}   (leaf: {channel.leaf})")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    spec = TargetSpec.load(args.config)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    probes = build_probes(spec)
    print(f"[channelprobe] target={spec.name} probes={len(probes)}")

    adapter = WorkerAdapter(
        spec.worker, name=spec.name, worker_args=spec.worker_args, timeout=args.timeout
    )
    try:
        results = run_campaign(adapter, spec)
    finally:
        stderr_tail = adapter.stderr_tail(10)
        adapter.close()

    campaign = score(results, spec)
    if campaign.errored_probes:
        print(f"[channelprobe] WARNING: {campaign.errored_probes} probes errored")
        for line in stderr_tail:
            print(f"[worker stderr] {line}")

    (out / "report.md").write_text(render_markdown(campaign), encoding="utf-8")
    (out / "report.json").write_text(render_json(campaign), encoding="utf-8")

    iec = campaign.iec
    print(f"[channelprobe] IEC={iec if iec is None else round(iec, 4)}  "
          f"gaps={campaign.gap_pairs}/{campaign.detectable_pairs}  "
          f"over_blocks={campaign.over_blocks}")
    for tool in campaign.tools:
        for channel in tool.channels:
            if channel.tainted:
                print(f"[channelprobe]   LEAK {tool.tool}.{channel.channel}: "
                      f"{', '.join(channel.gaps)}")
    print(f"[channelprobe] wrote {out / 'report.md'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="channelprobe",
        description="Measure field-level enforcement coverage of an agent tool-call defense.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="run a probe campaign")
    p_run.add_argument("--config", required=True)
    p_run.add_argument("--out", default="out")
    p_run.add_argument("--timeout", type=float, default=30.0)
    p_run.set_defaults(func=_cmd_run)

    p_ch = sub.add_parser("channels", help="list the channels a config exposes")
    p_ch.add_argument("--config", required=True)
    p_ch.set_defaults(func=_cmd_channels)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
