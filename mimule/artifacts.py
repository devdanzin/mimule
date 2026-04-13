"""Crash, timeout, divergence, and telemetry management for mimule.

Minimal stub exposing only the surface area orchestrator.py needs. The
full implementation — writing crash reproducers, fingerprint-based dedup,
crash minimization, time-series telemetry, compressed log handling —
lands alongside the real analysis.py and execution.py ports, once we
know what Henry's Monkey runtime emits on panic.

Stubbed classes:

    MimuleArtifactManager: check_for_crash / save_divergence / save_regression
    MimuleTelemetryManager: update_and_save_run_stats / log_timeseries_datapoint
    MimuleTimeoutLogger: record

All methods either no-op or record events to in-memory lists so the
orchestrator loop can run without side effects.
"""

from pathlib import Path
from typing import TYPE_CHECKING, Any

from mimule.utils import save_run_stats

if TYPE_CHECKING:
    from mimule.analysis import MimuleCrashFingerprinter
    from mimule.corpus_manager import MimuleCorpusManager
    from mimule.coverage import MimuleCoverageManager
    from mimule.health import MimuleHealthMonitor
    from mimule.learning import MimuleMutatorScoreTracker
    from mimule.types import RunStats


class MimuleTimeoutLogger:
    """Structured timeout event recorder — stub.

    Full implementation writes one JSON Lines entry per timeout to
    ``logs/timeout_events.jsonl`` so offline tools can correlate
    timeouts with mutation strategies and parent IDs.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self.events: list[dict[str, Any]] = []

    def record(self, metadata: dict[str, Any]) -> None:
        """Record a timeout event. STUB appends to an in-memory list."""
        self.events.append(metadata)


class MimuleArtifactManager:
    """Handles crash/timeout/divergence/regression recording.

    STUB — the real aggregator will write reproducers to
    ``crashes/``, timeouts to ``timeouts/``, divergences to
    ``divergences/``, and regressions to ``regressions/``, use
    ``MimuleCrashFingerprinter`` for dedup, and track per-session
    telemetry via the health monitor.
    """

    def __init__(
        self,
        crashes_dir: Path | None = None,
        timeouts_dir: Path | None = None,
        divergences_dir: Path | None = None,
        regressions_dir: Path | None = None,
        fingerprinter: "MimuleCrashFingerprinter | None" = None,
        max_timeout_log_bytes: int = 0,
        max_crash_log_bytes: int = 0,
        session_fuzz: bool = False,
        health_monitor: "MimuleHealthMonitor | None" = None,
        save_timeouts: bool = True,
    ) -> None:
        self.crashes_dir = crashes_dir
        self.timeouts_dir = timeouts_dir
        self.divergences_dir = divergences_dir
        self.regressions_dir = regressions_dir
        self.fingerprinter = fingerprinter
        self.max_timeout_log_bytes = max_timeout_log_bytes
        self.max_crash_log_bytes = max_crash_log_bytes
        self.session_fuzz = session_fuzz
        self.health_monitor = health_monitor
        self.save_timeouts = save_timeouts

        self.last_crash_fingerprint: str | None = None
        self.divergences: list[dict[str, Any]] = []
        self.crashes: list[dict[str, Any]] = []
        self.regressions: list[dict[str, Any]] = []

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
        """Classify a run as a crash and record it. STUB returns False."""
        return False

    def save_divergence(
        self,
        source_path: Path,
        jit_output: str,
        nojit_output: str,
        reason: str,
    ) -> None:
        """Record a divergence between two execution modes. STUB."""
        self.divergences.append({
            "source_path": source_path,
            "jit_output": jit_output,
            "nojit_output": nojit_output,
            "reason": reason,
        })

    def save_regression(
        self, source_path: Path, jit_time: float, nojit_time: float
    ) -> None:
        """Record a JIT performance regression. STUB appends to in-memory list."""
        self.regressions.append({
            "source_path": source_path,
            "jit_time": jit_time,
            "nojit_time": nojit_time,
        })


class MimuleTelemetryManager:
    """Run-stats roll-up and time-series logger — stub.

    Full implementation:
      * update_and_save_run_stats: recomputes derived metrics (uptime,
        rates, running averages) and persists ``run_stats.json``.
      * log_timeseries_datapoint: appends one JSONL row to the
        per-run timeseries file for offline analysis (plot campaigns,
        diff runs, etc.).

    The stub version just persists run_stats unchanged and ignores
    the timeseries datapoint.
    """

    def __init__(
        self,
        run_stats: "RunStats",
        coverage_manager: "MimuleCoverageManager",
        corpus_manager: "MimuleCorpusManager",
        score_tracker: "MimuleMutatorScoreTracker",
        timeseries_log_path: Path,
    ) -> None:
        self.run_stats = run_stats
        self.coverage_manager = coverage_manager
        self.corpus_manager = corpus_manager
        self.score_tracker = score_tracker
        self.timeseries_log_path = timeseries_log_path

    def update_and_save_run_stats(self, global_seed_counter: int) -> None:
        """Persist run_stats to disk. STUB just forwards to save_run_stats."""
        self.run_stats["global_seed_counter"] = global_seed_counter
        save_run_stats(self.run_stats)

    def log_timeseries_datapoint(self) -> None:
        """Append one time-series datapoint. STUB is a no-op."""
