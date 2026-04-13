"""Health monitoring and telemetry for mimule — minimal stub.

Full telemetry (session counts, file-size warnings, mutator effectiveness
rollups, running averages, heartbeat output) lands later in the port. This
module currently exposes just the surface area that corpus_manager needs:
a threshold constant and a single warning-recorder method.

When the full port lands, this will include the aggregators lafleur uses
for its campaign and report tools: TelemetryManager's time-series logging,
HealthMonitor's warnings, and the session stat roll-ups that orchestrator
relies on.
"""

FILE_SIZE_WARNING_THRESHOLD = 100_000  # 100 KB — matches lafleur's threshold


class MimuleHealthMonitor:
    """Tracks fuzzer health indicators.

    Stubbed: currently just records events in in-memory lists. Full
    implementation will persist to logs/health.jsonl and emit warnings
    on the orchestrator's log stream.
    """

    def __init__(self) -> None:
        self.file_size_warnings: list[tuple[str, int]] = []
        self.core_code_syntax_errors: list[tuple[str | None, str, str | None]] = []
        self.duplicates_rejected: list[tuple[str, str]] = []

    def record_file_size_warning(self, file_id: str, size_bytes: int) -> None:
        """Record that a corpus file exceeds the size warning threshold.

        Called by corpus_manager when a newly-added file is larger than
        FILE_SIZE_WARNING_THRESHOLD. When the full port lands, this will
        also emit a log line and contribute to the health telemetry roll-up.
        """
        self.file_size_warnings.append((file_id, size_bytes))

    def record_core_code_syntax_error(
        self,
        parent_id: str | None,
        error_str: str,
        strategy: str | None = None,
    ) -> None:
        """Record that a mutation produced syntactically invalid Monkey source.

        Called by scoring.py when the extracted core code fails to parse.
        """
        self.core_code_syntax_errors.append((parent_id, error_str, strategy))

    def record_duplicate_rejected(self, content_hash: str, coverage_hash: str) -> None:
        """Record that a mutation was rejected as a duplicate.

        Called by scoring.py's dedup pass when a new coverage-candidate
        has the same (content_hash, coverage_hash) pair as an existing
        corpus entry.
        """
        self.duplicates_rejected.append((content_hash, coverage_hash))
