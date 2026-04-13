"""Coverage state management for mimule — minimal stub.

Full implementation lands once Henry's JIT event instrumentation is in place
and we can parse real events from his 5-backend Monkey interpreter. Until
then, this module provides just enough surface area for corpus_manager and
(eventually) scoring to run against a fake-but-well-shaped coverage state.

State shape (what the real implementation will populate):

    state["per_file_coverage"]:  dict[str, CorpusFileMetadata]
        Per-file metadata: parent_id, lineage_depth, baseline_coverage,
        lineage_coverage_profile, execution_time_ms, etc.

    state["global_coverage"]:    dict[str, Counter[int]]
        Sub-dicts "uops", "edges", "rare_events", each a Counter mapping
        integer IDs → global hit count.

    state["uop_map"]:            dict[str, int]
    state["edge_map"]:           dict[str, int]
    state["rare_event_map"]:     dict[str, int]
        String-to-integer-ID mappings, assigned as new coverage items are
        observed. Stable across runs (persisted in coverage_state.pkl).

Compared to lafleur's coverage.py this is much simpler because:

1. We don't yet have the log parser (lafleur's parse_log_for_edge_coverage
   reads CPython verbose JIT output; mimule will read Henry's JSON Lines).

2. We don't yet have the state-machine logic for tracking TRACING/OPTIMIZED/
   EXECUTING state transitions — Monkey's linear IR doesn't need them.

3. We don't yet have the integer-ID allocator — it'll be ported alongside
   scoring.py where it matters for the interestingness check.
"""

import pickle
import sys
from pathlib import Path
from typing import Any

COVERAGE_STATE_FILE = Path("coverage") / "coverage_state.pkl"


class MimuleCoverageManager:
    """Holds the global coverage state dict.

    Stubbed: exposes only the `state` attribute that CorpusScheduler reads.
    Full implementation will add integer-ID allocation, log parsing, and
    state serialization helpers when we wire mimule to Henry's event stream.
    """

    def __init__(self, state: dict[str, Any] | None = None):
        self.state: dict[str, Any] = state if state is not None else {
            "per_file_coverage": {},
            "global_coverage": {
                "uops": {},
                "edges": {},
                "rare_events": {},
            },
            "uop_map": {},
            "edge_map": {},
            "rare_event_map": {},
        }


def save_coverage_state(state: dict[str, Any]) -> None:
    """Persist the coverage state dict to disk.

    Uses pickle to match lafleur's format so future mimule versions can
    migrate (or drop and regenerate) with known shape.
    """
    COVERAGE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(COVERAGE_STATE_FILE, "wb") as f:
        pickle.dump(state, f)


def load_coverage_state() -> MimuleCoverageManager:
    """Load coverage state from disk, or create a fresh one if not present."""
    if not COVERAGE_STATE_FILE.is_file():
        return MimuleCoverageManager()
    try:
        with open(COVERAGE_STATE_FILE, "rb") as f:
            state = pickle.load(f)
        return MimuleCoverageManager(state=state)
    except (pickle.PickleError, OSError, EOFError) as e:
        print(
            f"[!] Warning: Could not load coverage state ({e}), starting fresh",
            file=sys.stderr,
        )
        return MimuleCoverageManager()
