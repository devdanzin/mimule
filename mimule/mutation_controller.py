"""Mutation strategy controller for mimule — minimal stub.

lafleur's MutationController ("The Alchemist") is ~550 LOC that selects
and applies mutation strategies (deterministic / havoc / spam / sniper /
helper_sniper) to Python ASTs, extracts boilerplate from source files,
and stitches child scripts back together. Every piece of it touches
Python ast nodes, so the real port has to wait until we decide on
mimule's tree abstraction (tree-sitter-monkey vs. subprocess bridge
through Henry's parser).

This stub exists so ``mimule.orchestrator`` can import and construct
without a working mutation pipeline. Every method raises
``NotImplementedError`` on first use — the goal is for orchestrator
setup to succeed (so we can smoke-test the loop wiring) and for the
actual mutation-running hot path to fail loudly until we port the real
implementation.

HYGIENE_MUTATORS is kept as a class attribute with placeholder types
because orchestrator.py filters on it to avoid double-counting hygiene
passes in adaptive scoring.
"""

from pathlib import Path
from typing import TYPE_CHECKING, Any

from mimule.mutators import (
    ImportChaosMutator,
    ImportPrunerMutator,
    MimuleASTMutator,
    RedundantStatementSanitizer,
    StatementDuplicator,
)
from mimule.types import MutationInfo

if TYPE_CHECKING:
    from mimule.corpus_manager import MimuleCorpusManager
    from mimule.health import MimuleHealthMonitor
    from mimule.learning import MimuleMutatorScoreTracker


class MimuleMutationController:
    """Controls mutation strategy selection and application.

    STUB — orchestrator constructs one and wires it to the corpus/health
    managers, but every actual mutation operation raises NotImplementedError
    until we port the real strategies and pick a tree abstraction for Monkey.
    """

    HYGIENE_MUTATORS: list[tuple[type, float]] = [
        (ImportChaosMutator, 0.15),
        (ImportPrunerMutator, 0.20),
        (StatementDuplicator, 0.08),
        (RedundantStatementSanitizer, 0.05),
    ]

    def __init__(
        self,
        ast_mutator: "MimuleASTMutator",
        score_tracker: "MimuleMutatorScoreTracker",
        corpus_manager: "MimuleCorpusManager | None" = None,
        differential_testing: bool = False,
        forced_strategy: str | None = None,
    ):
        self.ast_mutator = ast_mutator
        self.score_tracker = score_tracker
        self.corpus_manager: MimuleCorpusManager | None = corpus_manager
        self.differential_testing = differential_testing
        self.forced_strategy = forced_strategy
        self.boilerplate_code: str | None = None
        self.health_monitor: MimuleHealthMonitor | None = None

    def get_boilerplate(self) -> str:
        """Return the cached boilerplate prelude. STUB returns empty string."""
        return self.boilerplate_code or ""

    def _get_core_code(self, source_code: str) -> str:
        """Strip boilerplate and return the core test body.

        STUB: returns the full source unchanged. Monkey's equivalent of
        fusil's BOILERPLATE_START / BOILERPLATE_END markers will be
        decided when we wire the seed_source pipeline to
        monkey-lang-tests-corpus.
        """
        return source_code

    def _calculate_mutations(self, parent_score: float) -> int:
        """Map a parent score to a target mutation count.

        STUB: returns a fixed placeholder. The real implementation
        mirrors lafleur's log-based scaling: more mutations for
        higher-scoring parents, capped.
        """
        return 10

    def _get_nodes_from_parent(
        self, parent_path: Path
    ) -> tuple[Any, Any, list[Any] | None]:
        """Parse a corpus file and return (harness_node, core_tree, setup_nodes).

        STUB: returns (None, None, None) so orchestrator marks the parent
        sterile and skips it. The real implementation parses the file
        into whatever tree type mimule ends up using for Monkey.
        """
        return None, None, None

    def get_mutated_harness(
        self,
        base_harness_node: Any,
        mutation_seed: int,
        watched_keys: list[str] | None = None,
    ) -> tuple[Any, MutationInfo | None]:
        """Apply a mutation strategy and return (mutated_node, mutation_info).

        STUB: returns (None, None) so ``_execute_single_mutation`` short-circuits.
        """
        return None, None

    def prepare_child_script(
        self,
        parent_core_tree: Any,
        mutated_harness_node: Any,
        runtime_seed: int,
    ) -> str | None:
        """Stitch a mutated harness back into its parent tree and unparse.

        STUB: returns None so the child-script path is skipped.
        """
        return None
