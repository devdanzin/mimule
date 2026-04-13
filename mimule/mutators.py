"""Mutation transformers for mimule — minimal stub.

lafleur's mutators/ package is a 2K+ LOC tree of ``ast.NodeTransformer``
subclasses that mutate Python AST. For mimule, the equivalent will target
Monkey syntax trees — most likely via tree-sitter-monkey once we finish
reviving the grammar, or via a custom walker over Henry's parser output
if we go with the subprocess bridge approach.

This file exposes just enough surface area for the orchestrator and
mutation_controller stubs to import cleanly:

  * ``MimuleASTMutator``: a placeholder with an empty ``transformers``
    list so orchestrator's diagnostic filter / --list-mutators path
    has something to iterate over.

  * ``EmptyBodySanitizer``, ``FuzzerSetupNormalizer``, ``HarnessInstrumentor``,
    ``RedundantStatementSanitizer``, ``SlicingMutator``, ``ImportChaosMutator``,
    ``ImportPrunerMutator``, ``StatementDuplicator``, ``HelperFunctionInjector``,
    ``SniperMutator``: placeholder classes referenced by mutation_controller's
    HYGIENE_MUTATORS and strategy pipeline. They exist purely as import
    targets until we port real Monkey-aware mutators.

No mutator here does anything — they're all type-hierarchy placeholders.
"""

from typing import Any


class _PlaceholderTransformer:
    """Base placeholder for a Monkey-tree transformer.

    When the real mutators land, these will subclass whatever node
    walker abstraction we choose (tree-sitter query handler, a
    hand-written visitor, etc.). For now they're just named hooks
    so mutation_controller.HYGIENE_MUTATORS can reference them by type.
    """

    def visit(self, node: Any) -> Any:
        return node


class EmptyBodySanitizer(_PlaceholderTransformer):
    """Removes or pads empty block bodies. STUB."""


class FuzzerSetupNormalizer(_PlaceholderTransformer):
    """Normalizes fuzzer setup/teardown scaffolding. STUB."""


class HarnessInstrumentor(_PlaceholderTransformer):
    """Injects harness call-points into a test body. STUB."""


class RedundantStatementSanitizer(_PlaceholderTransformer):
    """Removes obviously-redundant statements. STUB."""


class SlicingMutator(_PlaceholderTransformer):
    """Extracts or substitutes code slices between lineage members. STUB."""


class ImportChaosMutator(_PlaceholderTransformer):
    """Randomly perturbs imports (analog of lafleur's ImportChaosMutator). STUB."""


class ImportPrunerMutator(_PlaceholderTransformer):
    """Removes unused imports. STUB."""


class StatementDuplicator(_PlaceholderTransformer):
    """Duplicates statements to stress the JIT. STUB."""


class HelperFunctionInjector(_PlaceholderTransformer):
    """Injects helper functions into the test body. STUB."""


class SniperMutator(_PlaceholderTransformer):
    """Targeted mutator driven by watched-dependency hints. STUB."""


def _dump_unparse_diagnostics(*args: Any, **kwargs: Any) -> None:
    """Diagnostic dump for failed unparse. STUB."""


class MimuleASTMutator:
    """Top-level mutator registry.

    lafleur's ASTMutator holds the full pool of transformers and applies
    them per the current strategy. mimule's equivalent will wrap either
    a tree-sitter-monkey query registry or a custom walker. For now it
    exposes just an empty ``transformers`` list so orchestrator's
    --list-mutators / --mutators filter paths can run without crashing.
    """

    def __init__(self) -> None:
        self.transformers: list[type] = []

    def apply(self, tree: Any, transformer_cls: type) -> Any:
        """Apply a single transformer — STUB returns the tree unchanged."""
        return tree
