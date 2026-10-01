"""Defense adapters.

A defense is probed through one method::

    decide(tool: str, args: dict) -> Decision

That is deliberately the same shape Ajar uses, so a defense wrapped for one
tool can be reused in the other.

``WorkerAdapter`` runs the defense in a **separate process** speaking JSON
Lines over stdio. Isolation matters here for three reasons:

1. many defenses print to stdout, which would corrupt an in-process protocol;
2. a defense that mutates global state (or is simply slow) must not take the
   prober down with it;
3. it is the shape of a real deployment, where the policy layer is a service.
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


@dataclass(frozen=True)
class Decision:
    """A defense's verdict on one tool call."""

    allowed: bool | None
    reason: str = ""
    error: str | None = None

    @property
    def blocked(self) -> bool:
        return self.allowed is False


class DefenseAdapter(Protocol):
    name: str

    def decide(self, tool: str, args: dict) -> Decision: ...

    def close(self) -> None: ...


# --------------------------------------------------------------------------- #
# Subprocess worker adapter
# --------------------------------------------------------------------------- #

class WorkerTimeout(RuntimeError):
    pass


class WorkerAdapter:
    """Drive a defense implemented as a JSONL stdio worker subprocess."""

    def __init__(
        self,
        worker_module: str,
        *,
        name: str | None = None,
        worker_args: dict[str, Any] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.name = name or worker_module.rsplit(".", 1)[-1]
        self.timeout = timeout

        package_root = str(Path(__file__).resolve().parents[1])
        env = dict(os.environ)
        # Pin PYTHONPATH to this project only. Inheriting the parent's
        # PYTHONPATH can shadow the target's own top-level packages (a project
        # with `agent/` and `tools/` dirs collides with anything else on the
        # path that ships a regular package of the same name).
        env["PYTHONPATH"] = package_root
        env["PYTHONIOENCODING"] = "utf-8"

        argv = [sys.executable, "-m", worker_module]
        for key, value in (worker_args or {}).items():
            argv.extend([f"--{key.replace('_', '-')}", str(value)])

        self._proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=env,
        )
        self._queue: queue.Queue[str | None] = queue.Queue()
        self._stderr: list[str] = []
        self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
        self._reader.start()
        self._err_reader = threading.Thread(target=self._pump_stderr, daemon=True)
        self._err_reader.start()

    # -- plumbing ---------------------------------------------------------- #
    def _pump_stdout(self) -> None:
        assert self._proc.stdout is not None
        for line in self._proc.stdout:
            self._queue.put(line)
        self._queue.put(None)

    def _pump_stderr(self) -> None:
        assert self._proc.stderr is not None
        for line in self._proc.stderr:
            self._stderr.append(line.rstrip())

    def stderr_tail(self, limit: int = 20) -> list[str]:
        return self._stderr[-limit:]

    # -- protocol ---------------------------------------------------------- #
    def decide(self, tool: str, args: dict) -> Decision:
        request = json.dumps({"tool": tool, "args": args}, ensure_ascii=False)
        try:
            assert self._proc.stdin is not None
            self._proc.stdin.write(request + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            return Decision(None, error=f"worker pipe closed: {exc}")

        try:
            line = self._queue.get(timeout=self.timeout)
        except queue.Empty:
            return Decision(None, error=f"worker timeout after {self.timeout}s")

        if line is None:
            tail = " | ".join(self.stderr_tail(5))
            return Decision(None, error=f"worker exited. stderr: {tail}")

        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            return Decision(None, error=f"malformed worker reply: {line[:200]!r}")

        return Decision(
            allowed=payload.get("allowed"),
            reason=str(payload.get("reason") or ""),
            error=payload.get("error"),
        )

    def close(self) -> None:
        try:
            if self._proc.stdin and not self._proc.stdin.closed:
                self._proc.stdin.close()
        except OSError:
            pass
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=5)

    def __enter__(self) -> "WorkerAdapter":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# --------------------------------------------------------------------------- #
# In-process adapter (for tests and for defenses that are already isolated)
# --------------------------------------------------------------------------- #

@dataclass
class CallableAdapter:
    """Wrap a plain ``fn(tool, args) -> (allowed, reason)`` callable."""

    name: str
    fn: Any
    calls: list[tuple[str, dict]] = field(default_factory=list)

    def decide(self, tool: str, args: dict) -> Decision:
        self.calls.append((tool, dict(args)))
        try:
            allowed, reason = self.fn(tool, args)
        except Exception as exc:  # noqa: BLE001 - surface as a probe error
            return Decision(None, error=f"{type(exc).__name__}: {exc}")
        return Decision(bool(allowed), str(reason))

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass
