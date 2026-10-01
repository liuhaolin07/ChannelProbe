"""ChannelProbe — field-level enforcement coverage measurement for agent tool-call defenses.

Method (see README.md): inject a single detectable canary into exactly one
data-carrying channel of a tool call, hold every other channel benign, and read
the defense's verdict. A canary that the defense blocks in one channel but not
in another reveals a *coverage* defect (the check never reached that field),
as opposed to a *policy* defect (the check reached it and chose to allow).

Stdlib only, deliberately: the method should be runnable on a fresh VM.
"""

__version__ = "0.1.0"
