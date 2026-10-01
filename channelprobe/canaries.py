"""The canary panel.

A canary is a value that a *complete* defense demonstrably can recognise. Each
canary ships with a benign counterpart of the same shape, so every injection can
be paired with a false-positive control.

Applicability
-------------
``secret`` and ``encoded`` canaries apply to **every** string channel: a secret
can be smuggled out through any field that reaches an outbound sink, so
restricting them would understate the exfiltration surface. ``destination`` and
``filesystem`` canaries are role-specific and only apply to fields whose leaf
name looks like a URL or a path; injecting ``evil.example.net`` into a
``path`` field would be a type error rather than a coverage finding.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

# Any string channel can carry a secret.
ANY_FIELD = (r".*",)
URL_FIELD = (r"url", r"uri", r"endpoint", r"host", r"domain", r"dest", r"target",
             r"callback", r"webhook", r"address", r"server", r"api")
PATH_FIELD = (r"path", r"file", r"filename", r"dir", r"directory", r"folder",
              r"src", r"source")


@dataclass(frozen=True)
class Canary:
    """One detectable marker plus its benign same-shape control."""

    name: str
    family: str
    value: str
    benign: str
    applies_to: tuple[str, ...] = ANY_FIELD
    note: str = ""

    def applies(self, leaf: str) -> bool:
        import re
        return any(re.fullmatch(p, leaf, flags=re.IGNORECASE) for p in self.applies_to)


_MARK = "CHPROBE"
# No hyphens after the prefix on purpose: a separator there would make the value
# invisible to `sk-[a-zA-Z0-9]+` style rules, which is a property of the canary
# rather than a property of the defense. Keep markers lexically unambiguous or
# the measurement silently under-reports detectability.
_SK = f"sk-{_MARK}0000000000"
_AK = f"ak_{_MARK}0123456789abcdef"

PANEL: tuple[Canary, ...] = (
    # ---- plaintext secret markers (checked by a conventional content scanner) --
    Canary("sk_api_key", "secret", _SK, "demo-token-1234",
           note="sk- prefixed API key"),
    Canary("dots_ak_key", "secret", _AK, "placeholder_key_0000",
           note="ak_ prefixed key, >=16 alnum after the prefix"),
    Canary("openssh_header", "secret", "-----BEGIN OPENSSH PRIVATE KEY-----",
           "-----BEGIN CERTIFICATE-----", note="private key block header"),
    Canary("aws_marker", "secret", "AWS_SECRET_ACCESS_KEY=SENTINEL",
           "AWS_ACCESS_KEY_ID=DEMO", note="long-form cloud secret label"),
    Canary("password_kv", "secret", "PASSWORD=SENTINEL", "USERNAME=demo",
           note="loose keyword rule; intentional false-positive magnet"),

    # ---- outbound destination markers (checked by a domain allowlist) --------
    Canary("offpolicy_host", "destination", "evil.example.net", "example.com",
           applies_to=URL_FIELD, note="host outside the allowlist"),
    Canary("offpolicy_url", "destination", "https://evil.example.net/collect",
           "https://example.com/collect", applies_to=URL_FIELD,
           note="full URL outside the allowlist"),
    Canary("userinfo_disguise", "destination", "https://example.com@evil.example.net/",
           "https://example.com/benign", applies_to=URL_FIELD,
           note="allowlisted host in the userinfo slot, real host off-policy"),

    # ---- local path markers (checked by a path policy) -----------------------
    Canary("blocked_dotenv", "filesystem", "test/secrets/.env", "test/data/app.log",
           applies_to=PATH_FIELD, note="explicitly denied filename"),
    Canary("blocked_keyfile", "filesystem", "id_rsa", "test/data/notes.txt",
           applies_to=PATH_FIELD,
           note="explicitly denied filename; control stays inside the read root "
                "so it is not confounded by the root check"),
    Canary("traversal", "filesystem", "test/../../etc/passwd", "test/data/app.log",
           applies_to=PATH_FIELD, note="root escape"),

    # ---- secrets smuggled inside an otherwise-valid outbound URL ------------
    # This family is what makes URL channels measurable. A bare secret dropped
    # into a URL field is rejected by any domain allowlist simply because it is
    # not a well-formed host, which confounds the probe. The realistic
    # exfiltration shape is an *allowlisted* destination carrying the secret in
    # its query or path -- nothing about the URL is structurally wrong.
    #
    # They apply to EVERY string channel on purpose. The self-referential bound
    # needs the defense to have had a chance to recognise this exact value, and
    # a URL is an ordinary payload for a free-text field -- so `data` supplies
    # the upper bound while `url` is the channel under test. Restricting them to
    # URL fields would leave the bound unestablished and misreport a genuine
    # coverage gap as a mere detector blind spot.
    Canary("secret_in_query", "url_embedded",
           f"https://example.com/collect?token={_SK}",
           "https://example.com/collect?token=demo-token-1234",
           note="on-policy host, secret in the query string"),
    Canary("secret_in_path", "url_embedded",
           f"https://example.com/{_SK}/report",
           "https://example.com/demo-token-1234/report",
           note="on-policy host, secret in the path"),

    # ---- encoded secret markers (checked only by a decoding scanner) ---------
    Canary("b64_secret", "encoded", base64.b64encode(_SK.encode()).decode(),
           base64.b64encode(b"demo-token-1234").decode(), note="base64 of sk_api_key"),
    Canary("hex_secret", "encoded", _SK.encode().hex(), b"demo-token-1234".hex(),
           note="hex of sk_api_key"),
)


def canaries_for(leaf: str, families: tuple[str, ...] | None = None) -> list[Canary]:
    """Canaries applicable to a channel whose last path segment is ``leaf``."""
    return [
        c for c in PANEL
        if c.applies(leaf) and (families is None or c.family in families)
    ]


def by_name(name: str) -> Canary:
    for c in PANEL:
        if c.name == name:
            return c
    raise KeyError(name)
