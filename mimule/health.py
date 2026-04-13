"""Health monitoring and telemetry for mimule — minimal stub.

Full telemetry (session counts, file-size warnings, mutator effectiveness
rollups, running averages, heartbeat output) lands later in the port. This
module currently exposes the surface area that corpus_manager, scoring,
and orchestrator need: a threshold constant plus recorder methods for
each class of health event.

When the full port lands, every record_* method will emit a structured
JSON Lines entry to ``logs/health_events.jsonl`` and contribute to the
roll-up TelemetryManager uses. Currently they all just append to
in-memory lists so smoke tests can observe the call.
"""

from pathlib import Path
from typing import Any

FILE_SIZE_WARNING_THRESHOLD = 100_000  # 100 KB — matches lafleur's threshold


class MimuleHealthMonitor:
    """Tracks fuzzer health indicators.

    Stubbed: currently records events in in-memory lists. Full
    implementation persists to logs/health_events.jsonl and emits
    warnings on the orchestrator's log stream.
    """

    def __init__(self, log_path: Path | None = None) -> None:
        self.log_path = log_path

        self.file_size_warnings: list[tuple[str, int]] = []
        self.core_code_syntax_errors: list[tuple[str | None, str, str | None]] = []
        self.duplicates_rejected: list[tuple[str, str]] = []
        self.events: list[dict[str, Any]] = []
        self.timeout_streak: int = 0

    def _record_event(self, category: str, event: str, **kwargs: Any) -> None:
        """Append a structured event to the in-memory log. STUB."""
        self.events.append({"category": category, "event": event, **kwargs})

    def record_file_size_warning(self, file_id: str, size_bytes: int) -> None:
        """Record that a corpus file exceeds the size warning threshold."""
        self.file_size_warnings.append((file_id, size_bytes))

    def record_core_code_syntax_error(
        self,
        parent_id: str | None,
        error_str: str,
        strategy: str | None = None,
    ) -> None:
        """Record that a mutation produced syntactically invalid Monkey source."""
        self.core_code_syntax_errors.append((parent_id, error_str, strategy))

    def record_duplicate_rejected(self, content_hash: str, coverage_hash: str) -> None:
        """Record that a mutation was rejected as a duplicate."""
        self.duplicates_rejected.append((content_hash, coverage_hash))

    def record_parent_parse_failure(self, parent_id: str, error: str) -> None:
        """Record that a corpus parent couldn't be parsed for mutation.

        Fires when _prepare_parent_context finds the parent has no
        harness node or is otherwise unreadable. The orchestrator
        also marks the parent sterile so the scheduler deprioritizes
        it.
        """
        self._record_event("parse", "parent_parse_failure", parent_id=parent_id, error=error)

    def record_child_script_none(
        self,
        parent_id: str,
        mutation_seed: int,
        strategy: str | None = None,
    ) -> None:
        """Record that prepare_child_script returned None.

        Usually indicates a mutation produced an un-unparseable tree
        or hit a hygiene short-circuit. Orchestrator just skips the run.
        """
        self._record_event(
            "mutation",
            "child_script_none",
            parent_id=parent_id,
            mutation_seed=mutation_seed,
            strategy=strategy,
        )

    def record_timeout(self, parent_id: str) -> None:
        """Record a run timeout and update the running streak counter."""
        self.timeout_streak += 1
        self._record_event("timeout", "run_timeout", parent_id=parent_id, streak=self.timeout_streak)

    def reset_timeout_streak(self) -> None:
        """Reset the consecutive-timeout counter after a successful run."""
        self.timeout_streak = 0

    def record_corpus_sterility(
        self, parent_id: str, mutations_since_last_find: int
    ) -> None:
        """Record the False→True transition of a corpus file becoming sterile."""
        self._record_event(
            "sterility",
            "corpus_file_sterile",
            parent_id=parent_id,
            mutations_since_last_find=mutations_since_last_find,
        )

    def record_deepening_sterility(
        self, parent_id: str, depth: int, mutations_attempted: int
    ) -> None:
        """Record a deepening session abandoned due to sterility."""
        self._record_event(
            "sterility",
            "deepening_sterile",
            parent_id=parent_id,
            depth=depth,
            mutations_attempted=mutations_attempted,
        )
