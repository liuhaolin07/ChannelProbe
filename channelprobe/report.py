"""Render a campaign score as Markdown and JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from channelprobe.metrics import CampaignScore, ChannelScore


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def _verdict(channel: ChannelScore) -> str:
    if channel.errors and not channel.detectable:
        return "⚠️ probe error"
    if channel.applicable == 0:
        return "—"
    if channel.evaluable == 0:
        return "inconclusive (all confounded)"
    if channel.gap_rate is None:
        return "single-channel / no detectable canary"
    if channel.gap_rate == 0:
        return "✅ consistent"
    if channel.blind:
        return "🔴 BLIND"
    return "🟡 partial"


def render_markdown(campaign: CampaignScore, *, extra_intro: str = "") -> str:
    lines: list[str] = []
    add = lines.append

    add(f"# ChannelProbe report — {campaign.target}")
    add("")
    add(f"*Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')} · "
        f"{campaign.total_probes} probes · "
        f"{campaign.errored_probes} errored*")
    add("")
    if extra_intro:
        add(extra_intro)
        add("")

    # ---- headline -------------------------------------------------------- #
    add("## Headline")
    add("")
    iec = campaign.iec
    if iec is None:
        add("No canary was ever marker-detected, so **no coverage claim can be "
            "made**. Either the defense has no detector for this panel at all, or "
            "every channel confounded the probe.")
    else:
        add(f"- **Internal Enforcement Consistency (IEC): `{iec:.4f}`** — of "
            f"{campaign.detectable_pairs} evaluable (channel, canary) pairs the "
            f"defense demonstrably *can* stop, **{campaign.gap_pairs}** leave "
            f"through a channel it never inspected.")
        leaks = [c for t in campaign.tools for c in t.channels if c.tainted]
        add(f"- **Channels carrying a detectable leak: {len(leaks)}**")
        if leaks:
            for channel in leaks:
                add(f"  - `{channel.tool}.{channel.channel}` — "
                    f"{len(channel.gaps)}/{channel.detectable} "
                    f"({_pct(channel.gap_rate)})")
        add(f"- Confounded pairs (channel rejects the value with or without the "
            f"marker): {campaign.confounded_pairs} — no claim either way")
        add(f"- Over-blocks (control rejected while the canary passed): "
            f"{campaign.over_blocks}")
    add("")

    for tool in campaign.tools:
        if tool.baseline_blocked:
            add(f"> ⚠️ **`{tool.tool}`: the declared benign baseline is itself "
                f"rejected** (`{tool.baseline_reason}`). Either the config's benign "
                f"values are wrong or the defense over-blocks. Every number below "
                f"is suspect until this is resolved.")
            add("")

    # ---- per-tool tables ------------------------------------------------- #
    for tool in campaign.tools:
        add(f"## Tool `{tool.tool}`")
        add("")
        add("| Channel | applicable | evaluable | confounded | detectable | "
            "detected | gaps | CER | gap rate | verdict |")
        add("|---|---|---|---|---|---|---|---|---|---|")
        for channel in tool.channels:
            add(
                f"| `{channel.channel}` | {channel.applicable} | {channel.evaluable} | "
                f"{len(channel.confounded)} | {channel.detectable} | {channel.detected} | "
                f"{len(channel.gaps)} | {_pct(channel.cer)} | "
                f"{_pct(channel.gap_rate)} | {_verdict(channel)} |"
            )
        add("")

        for channel in tool.channels:
            if channel.gaps:
                add(f"**🔴 `{channel.channel}` leaks** — detectable, yet allowed here: "
                    f"{', '.join(f'`{g}`' for g in channel.gaps)}")
                add("")
            if channel.over_blocked:
                add(f"**⚠️ `{channel.channel}` over-blocks** — benign control "
                    f"rejected while the canary passed: "
                    f"{', '.join(f'`{o}`' for o in channel.over_blocked)}")
                add("")
            if channel.confounded:
                add(f"*`{channel.channel}` confounded* (no claim): "
                    f"{', '.join(f'`{c}`' for c in channel.confounded)}")
                add("")
            if channel.errors:
                add(f"**`{channel.channel}` probe errors**: {'; '.join(channel.errors[:3])}")
                add("")

        if tool.blind_spots:
            add(f"**Detector blind spots** — never marker-detected in any channel of "
                f"this tool (a policy-level finding, not a coverage defect): "
                f"{', '.join(f'`{b}`' for b in tool.blind_spots)}")
            add("")

    # ---- method ---------------------------------------------------------- #
    add("---")
    add("")
    add("## How to read this")
    add("")
    add("Every probe changes **exactly one** channel and leaves all others at their "
        "benign baseline, so a verdict change is attributable to that channel. Each "
        "canary injection is paired with a same-shape benign **control**.")
    add("")
    add("**Self-referential detectability.** No external oracle is needed to say what "
        "the right policy is. A canary counts as *detectable* once the defense stops "
        "it *somewhere* — the defense has demonstrated the capability itself. A "
        "detectable canary that a channel lets through is therefore a **coverage** "
        "defect: the check never reached the field. It is not a policy choice, and it "
        "cannot be argued to be one.")
    add("")
    add("**Control-gated detection.** A block is credited only when the canary was "
        "stopped *and* its control was not. Without this gate, a value any domain "
        "allowlist would reject for being malformed — a bare secret dropped into a "
        "URL field, say — would be miscounted as a detection, and the result would be "
        "an artifact of the probe rather than a property of the defense. Pairs the "
        "channel rejects either way are reported as **confounded** and excluded from "
        "both `evaluable` and `detectable`.")
    add("")
    add("| term | meaning |")
    add("|---|---|")
    add("| `applicable` | canaries whose role fits this channel |")
    add("| `confounded` | channel rejects the value with *and* without the marker |")
    add("| `evaluable` | `applicable - confounded`: cells where a claim is possible |")
    add("| `detectable` | canaries this defense demonstrably recognises, evaluable here |")
    add("| `detected` | ...and actually stopped here, marker-driven |")
    add("| `gaps` | `detectable - detected`: **the coverage number** |")
    add("| `CER` | `detected / evaluable` |")
    add("| `gap rate` | `gaps / detectable` |")
    add("")
    add("**Detector blind spots** are a different, policy-level finding: the defense "
        "has no detector for that family at all. They are not coverage defects and "
        "should be reported separately — they say the defense *cannot* see this, not "
        "that it *forgot* to look here.")
    add("")
    add("A tool with a single channel cannot exhibit an intra-tool inconsistency, so "
        "no gap claim is made for it. Its numbers are still useful as policy evidence.")
    add("")

    return "\n".join(lines)


def render_json(campaign: CampaignScore) -> str:
    payload = {
        "target": campaign.target,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_probes": campaign.total_probes,
        "errored_probes": campaign.errored_probes,
        "iec": campaign.iec,
        "detectable_pairs": campaign.detectable_pairs,
        "gap_pairs": campaign.gap_pairs,
        "confounded_pairs": campaign.confounded_pairs,
        "over_blocks": campaign.over_blocks,
        "tools": [
            {
                "tool": t.tool,
                "blind_spots": t.blind_spots,
                "baseline_blocked": t.baseline_blocked,
                "baseline_reason": t.baseline_reason,
                "channels": [
                    {
                        "channel": f"{c.tool}.{c.channel}",
                        "leaf": c.leaf,
                        "applicable": c.applicable,
                        "evaluable": c.evaluable,
                        "confounded": c.confounded,
                        "detectable": c.detectable,
                        "detected": c.detected,
                        "gaps": c.gaps,
                        "over_blocked": c.over_blocked,
                        "cer": c.cer,
                        "gap_rate": c.gap_rate,
                        "blind": c.blind,
                        "errors": c.errors,
                    }
                    for c in t.channels
                ],
            }
            for t in campaign.tools
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)
