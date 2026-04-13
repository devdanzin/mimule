"""Crash analysis and fingerprinting for mimule — minimal stub.

lafleur's analysis.py parses CPython tracebacks, ASan reports, and
fatal-error output to produce a stable crash fingerprint used for
deduplication across a fuzzing campaign. That logic is entirely
CPython-specific — the regular expressions target Python frame
strings, ``Fatal Python error``, ``Objects/*.c:NNN`` internal file
references, etc.

For mimule the equivalent will depend on what Henry's Monkey runtime
emits when it panics (presumably a node.js stack trace plus whatever
the Monkey interpreter's own assertion output looks like). Until we
have example crash traces to pattern-match against, this module
exposes just the class name the orchestrator constructs and hands to
``MimuleArtifactManager``.

``MimuleCrashFingerprinter.analyze`` currently returns a placeholder
``CrashSignature`` so the rest of the pipeline can run. No dedup is
performed — every crash looks unique to the downstream registry.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CrashSignature:
    """Structured description of a crash, used for dedup and classification.

    Minimal stub mirror of lafleur's shape. Full implementation will
    populate: crash_type (segfault / assertion / fatal_python_error / ...),
    normalized_top_frames, and a stable fingerprint hash derived from those.
    """

    crash_type: str = "unknown"
    fingerprint: str = ""
    top_frames: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "crash_type": self.crash_type,
            "fingerprint": self.fingerprint,
            "top_frames": list(self.top_frames),
        }


class MimuleCrashFingerprinter:
    """Classify and fingerprint a crash from exit code + log content.

    STUB: ``analyze`` returns an empty ``CrashSignature`` so the
    orchestrator can wire it through to ``MimuleArtifactManager``
    without branching. Once we see what Henry's Monkey runtime prints
    on panic, we'll port the regex pipeline from lafleur/analysis.py.
    """

    def analyze(self, returncode: int, log_content: str) -> CrashSignature:
        """Return a ``CrashSignature`` for this crash. STUB."""
        return CrashSignature()
