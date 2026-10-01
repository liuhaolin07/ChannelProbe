"""Entry point so ``python -m channelprobe`` works like ``python -m channelprobe.cli``."""

from __future__ import annotations

from channelprobe.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
