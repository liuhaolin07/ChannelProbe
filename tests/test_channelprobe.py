"""Tests for ChannelProbe.

The point of these tests is that they do not depend on AgentShield: they pin the
*method*. The regression contract is

    a defense that inspects only one channel, while demonstrably recognising a
    canary, must be reported as leaking that canary through every other channel
    -- and must NOT be reported as leaking in the channel it does inspect.
"""

from __future__ import annotations

import base64
import unittest

from channelprobe.adapters import CallableAdapter
from channelprobe.campaign import TargetSpec, build_probes, run_campaign
from channelprobe.canaries import PANEL, by_name, canaries_for
from channelprobe.channels import Channel, get_path, leaf_string_paths, set_path, tool_channels
from channelprobe.metrics import score


# --------------------------------------------------------------------------- #
# Schema walking / path plumbing
# --------------------------------------------------------------------------- #

class ChannelTests(unittest.TestCase):
    def test_flat_object(self) -> None:
        schema = {"type": "object", "properties": {"a": {"type": "string"},
                                                   "b": {"type": "string"}}}
        self.assertEqual(sorted(leaf_string_paths(schema)), ["a", "b"])

    def test_nested_object(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "headers": {"type": "object",
                            "properties": {"Authorization": {"type": "string"}}},
            },
        }
        self.assertEqual(
            sorted(leaf_string_paths(schema)), ["endpoint", "headers.Authorization"]
        )

    def test_array_of_scalars_is_one_channel(self) -> None:
        schema = {"type": "object",
                  "properties": {"labels": {"type": "array", "items": {"type": "string"}}}}
        self.assertEqual(leaf_string_paths(schema), ["labels[]"])

    def test_array_of_objects(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "items": {"type": "array",
                          "items": {"type": "object",
                                    "properties": {"sku": {"type": "string"}}}},
            },
        }
        self.assertEqual(leaf_string_paths(schema), ["items[].sku"])

    def test_channel_leaf_strips_array_marker(self) -> None:
        self.assertEqual(Channel("t", "payload.labels[]").leaf, "labels")

    def test_set_and_get_round_trip(self) -> None:
        args: dict = {}
        set_path(args, "headers.Authorization", "Bearer x")
        self.assertEqual(get_path(args, "headers.Authorization"), "Bearer x")
        set_path(args, "labels[]", "routine")
        self.assertEqual(get_path(args, "labels[]"), "routine")
        self.assertEqual(args["labels"], ["routine"])
        set_path(args, "items[].sku", "A1")
        self.assertEqual(args["items"], [{"sku": "A1"}])

    def test_set_path_does_not_clobber_siblings(self) -> None:
        args = {"payload": {"body": "keep me"}}
        set_path(args, "payload.path", "/tmp/x")
        self.assertEqual(args["payload"]["body"], "keep me")


# --------------------------------------------------------------------------- #
# Canary applicability
# --------------------------------------------------------------------------- #

class CanaryTests(unittest.TestCase):
    def test_secrets_apply_to_every_field(self) -> None:
        for leaf in ("url", "data", "path", "notes", "Authorization"):
            names = {c.name for c in canaries_for(leaf)}
            self.assertIn("sk_api_key", names, leaf)
            self.assertIn("b64_secret", names, leaf)

    def test_destination_only_on_url_like_fields(self) -> None:
        self.assertIn("offpolicy_host", {c.name for c in canaries_for("url")})
        self.assertNotIn("offpolicy_host", {c.name for c in canaries_for("data")})

    def test_filesystem_only_on_path_like_fields(self) -> None:
        self.assertIn("blocked_dotenv", {c.name for c in canaries_for("path")})
        self.assertNotIn("blocked_dotenv", {c.name for c in canaries_for("body")})

    def test_every_canary_has_a_distinct_benign_control(self) -> None:
        for canary in PANEL:
            self.assertNotEqual(canary.value, canary.benign, canary.name)
            self.assertTrue(canary.benign, canary.name)

    def test_encoded_canaries_actually_encode_a_secret(self) -> None:
        secret = by_name("sk_api_key").value
        self.assertEqual(base64.b64decode(by_name("b64_secret").value).decode(), secret)
        self.assertEqual(bytes.fromhex(by_name("hex_secret").value).decode(), secret)


# --------------------------------------------------------------------------- #
# The method, on a synthetic partially-implemented defense
# --------------------------------------------------------------------------- #

class RecordedDefense:
    """Inspects the ``scanned`` channel only; treats everything else as clean.

    This is the pure form of the defect ChannelProbe exists to find: the policy
    logic is fine, the wiring is incomplete.
    """

    def __init__(self, tool: str, scanned: str, patterns: tuple[str, ...]) -> None:
        import re
        self.tool = tool
        self.scanned = scanned
        self.patterns = patterns
        self.re = re

    def __call__(self, tool: str, args: dict) -> tuple[bool, str]:
        if tool != self.tool:
            return False, "unsupported_tool"
        value = get_path(args, self.scanned)
        if isinstance(value, str) and any(
            self.re.search(p, value, flags=self.re.IGNORECASE) for p in self.patterns
        ):
            return False, "sensitive_data"
        return True, "policy_passed"


SECRET_PATTERNS = (
    r"sk-[a-zA-Z0-9]{8,}",
    r"\bak_[a-zA-Z0-9]{16,}\b",
    r"-----BEGIN OPENSSH PRIVATE KEY-----",
    r"AWS_SECRET",
    r"PASSWORD",
)

NESTED_SPEC = TargetSpec.from_dict({
    "target": {"name": "synthetic", "worker": "none"},
    "tools": [{
        "name": "submit_report",
        "schema": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "notes": {"type": "string"},
                "headers": {"type": "object",
                            "properties": {"Authorization": {"type": "string"}}},
                "payload": {
                    "type": "object",
                    "properties": {"body": {"type": "string"}, "path": {"type": "string"}},
                },
            },
        },
        "benign": {
            "endpoint": "https://example.com/ingest",
            "notes": "routine weekly report",
            "headers": {"Authorization": "Bearer demo-token"},
            "payload": {"body": "INFO service started successfully",
                        "path": "reports/weekly.log"},
        },
    }],
})


class MethodTests(unittest.TestCase):
    def _score(self, scanned: str):
        adapter = CallableAdapter(
            "synthetic", RecordedDefense("submit_report", scanned, SECRET_PATTERNS)
        )
        results = run_campaign(adapter, NESTED_SPEC)
        campaign = score(results, NESTED_SPEC)
        return campaign, campaign.tools[0]

    def test_channels_enumerated_including_nested(self) -> None:
        channels = {c.path for c in tool_channels("submit_report", NESTED_SPEC.tools[0].schema)}
        self.assertEqual(
            channels,
            {"endpoint", "notes", "headers.Authorization", "payload.body", "payload.path"},
        )

    def test_defense_blind_to_nested_channels_is_flagged(self) -> None:
        """Scanning only payload.body must leave every other channel leaking."""
        campaign, tool = self._score("payload.body")

        by_path = {c.channel: c for c in tool.channels}

        # The inspected channel is clean...
        self.assertEqual(by_path["payload.body"].gaps, [])
        self.assertEqual(by_path["payload.body"].gap_rate, 0.0)

        # ...and every other channel leaks the secret family.
        for path in ("endpoint", "notes", "headers.Authorization", "payload.path"):
            channel = by_path[path]
            self.assertTrue(channel.tainted, path)
            self.assertIn("sk_api_key", channel.gaps, path)
            self.assertEqual(channel.gap_rate, 1.0, path)
            self.assertTrue(channel.blind, path)

        self.assertLess(campaign.iec, 0.5)
        self.assertGreater(campaign.gap_pairs, 0)

    def test_fully_consistent_defense_scores_perfectly(self) -> None:
        """A defense that scans every channel yields IEC == 1.0 and no leaks."""
        import re
        patterns = SECRET_PATTERNS

        def decide(tool: str, args: dict) -> tuple[bool, str]:
            if tool != "submit_report":
                return False, "unsupported_tool"
            blob = str(args)
            if any(re.search(p, blob, flags=re.IGNORECASE) for p in patterns):
                return False, "sensitive_data"
            return True, "policy_passed"

        adapter = CallableAdapter("synthetic", decide)
        campaign = score(run_campaign(adapter, NESTED_SPEC), NESTED_SPEC)
        self.assertEqual(campaign.gap_pairs, 0)
        self.assertEqual(campaign.iec, 1.0)

    def test_undetected_family_is_a_blind_spot_not_a_gap(self) -> None:
        """A canary the defense can never see must not be counted as a gap."""
        _, tool = self._score("payload.body")
        # filesystem canaries live on `path`, which this defense never inspects,
        # and never inspects anywhere else either -> blind spot, not a gap.
        self.assertIn("blocked_dotenv", tool.blind_spots)
        for channel in tool.channels:
            self.assertNotIn("blocked_dotenv", channel.gaps)

    def test_benign_controls_are_not_flagged_as_over_block(self) -> None:
        campaign, tool = self._score("payload.body")
        self.assertEqual(campaign.over_blocks, 0)
        for channel in tool.channels:
            self.assertEqual(channel.over_blocked, [])

    def test_probe_matrix_pairs_every_canary_with_a_control(self) -> None:
        probes = build_probes(NESTED_SPEC)
        kinds: dict[tuple[str, str, str], set[str]] = {}
        for probe in probes:
            if probe.canary is None:  # baseline sanity probe
                continue
            key = (probe.tool, probe.channel.path, probe.canary.name)
            kinds.setdefault(key, set()).add(probe.kind)
        self.assertTrue(kinds)
        for key, seen in kinds.items():
            self.assertEqual(seen, {"canary", "control"}, key)

    def test_probes_differ_from_benign_in_exactly_one_channel(self) -> None:
        benign = NESTED_SPEC.tools[0].benign
        for probe in build_probes(NESTED_SPEC):
            if probe.kind == "baseline":
                continue
            differing = [
                c.path for c in tool_channels(probe.tool, NESTED_SPEC.tools[0].schema)
                if get_path(probe.args, c.path) != get_path(benign, c.path)
            ]
            self.assertEqual(differing, [probe.channel.path], probe.label)


if __name__ == "__main__":
    unittest.main()
