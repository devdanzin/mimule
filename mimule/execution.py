"""Child-process execution manager for mimule — minimal stub.

lafleur's ExecutionManager runs CPython as a subprocess with specific
environment variables (PYTHON_JIT, PYTHON_LLTRACE, ASAN_OPTIONS...) to
gather coverage, supports differential testing (JIT on vs. JIT off),
timing fuzz, and session fuzz, and contains Python-specific capability
verification (checking that the target interpreter supports the flags
lafleur needs).

For mimule the target runtime is Henry's Monkey interpreter (which
currently spawns through ``node`` plus the Monkey REPL executable), so
every subprocess detail has to change. Until Henry ships the JIT event
instrumentation and we decide on the invocation protocol, this module
exposes just enough API for orchestrator.py to import and wire:

  * ``MimuleExecutionManager`` with ``execute_child`` returning
    ``(None, None)`` so every mutation path short-circuits cleanly.
  * ``verify_target_capabilities`` as a no-op print.

The real port will replicate lafleur's _build_env / _run_timed_trial /
differential-stage plumbing in terms of Monkey commands.
"""

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from mimule.artifacts import MimuleArtifactManager
    from mimule.corpus_manager import MimuleCorpusManager


class MimuleExecutionManager:
    """Run a mutated child through the target runtime and collect results.

    STUB: construction succeeds so orchestrator wiring works, but
    ``execute_child`` returns ``(None, None)`` — the orchestrator's
    per-mutation loop treats that as "nothing executed, skip" and moves
    on. ``verify_target_capabilities`` prints a warning and returns,
    so startup doesn't abort.
    """

    def __init__(
        self,
        target_runtime: str = "node",
        timeout: int = 10,
        artifact_manager: "MimuleArtifactManager | None" = None,
        corpus_manager: "MimuleCorpusManager | None" = None,
        differential_testing: bool = False,
        timing_fuzz: bool = False,
        session_fuzz: bool = False,
        no_ekg: bool = False,
    ):
        self.target_runtime = target_runtime
        self.timeout = timeout
        self.artifact_manager = artifact_manager
        self.corpus_manager = corpus_manager
        self.differential_testing = differential_testing
        self.timing_fuzz = timing_fuzz
        self.session_fuzz = session_fuzz
        self.no_ekg = no_ekg

    def verify_target_capabilities(self) -> None:
        """Confirm the target runtime supports everything the fuzzer needs.

        STUB: prints a notice and returns. Full implementation will probe
        Henry's interpreter for the JIT event-stream flag, --version, etc.
        """
        print(
            f"[stub] MimuleExecutionManager: target_runtime={self.target_runtime} "
            "(capability verification not yet implemented)"
        )

    def execute_child(
        self,
        child_source: str,
        child_source_path: Path,
        child_log_path: Path,
        parent_path: Path,
    ) -> tuple[Any, str | None]:
        """Run a single mutated child and return (result, stat_key).

        STUB: returns ``(None, None)`` so the orchestrator's loop treats
        every mutation as "no result, skip". This keeps smoke tests from
        crashing; the real implementation will spawn the Monkey runtime,
        capture stdout/stderr, optionally run differential trials, and
        return a ``MimuleExecutionResult`` with coverage data.
        """
        return None, None
