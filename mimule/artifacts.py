"""Crash, timeout, and divergence artifact management for mimule.

Minimal stub exposing only the surface area that scoring.py (and later
orchestrator.py) needs. Full implementation — actually writing crash
reproducers to disk, computing crash fingerprints, tracking telemetry,
crash-minimization — lands after we port the real scoring engine and
artifact.py from lafleur.

Stubbed interfaces:

    MimuleArtifactManager:
        check_for_crash(...)           returns False (no-op crash detection)
        save_divergence(...)           records to in-memory list
        last_crash_fingerprint         always None
"""

from pathlib import Path
from typing import Any


class MimuleArtifactManager:
    """Handles crash/timeout/divergence recording.

    Currently stubbed. When fully ported, this becomes the aggregator
    that writes crash reproducers to ``crashes/``, timeouts to
    ``timeouts/``, divergences to ``divergences/``, computes crash
    fingerprints via the analysis module, and tracks per-session
    telemetry via the health monitor.
    """

    def __init__(self) -> None:
        self.last_crash_fingerprint: str | None = None
        self.divergences: list[dict[str, Any]] = []
        self.crashes: list[dict[str, Any]] = []

    def check_for_crash(
        self,
        returncode: int,
        log_content: str,
        source_path: Path,
        log_path: Path,
        parent_path: Path | None = None,
        session_files: list[Path] | None = None,
        parent_id: str | None = None,
        mutation_info: dict[str, Any] | None = None,
        polluter_ids: list[str] | None = None,
    ) -> bool:
        """Return True if the run is a crash worth recording.

        STUB: always returns False. Full implementation will classify by
        exit code (segfault, assertion, ASan, Fatal Python error, etc.),
        compute a fingerprint via analysis.py, deduplicate against the
        crash registry, and write the reproducer to disk.
        """
        return False

    def save_divergence(
        self,
        source_path: Path,
        jit_output: str,
        nojit_output: str,
        reason: str,
    ) -> None:
        """Record a divergence between two execution modes.

        STUB: appends to an in-memory list. Full implementation will
        write the source, both outputs, and a metadata sidecar to
        ``divergences/``.
        """
        self.divergences.append({
            "source_path": source_path,
            "jit_output": jit_output,
            "nojit_output": nojit_output,
            "reason": reason,
        })
