# mimule

A feedback-driven, evolutionary fuzzer for the [Monkey](https://monkeylang.org/) language tracing JIT in [`henry-the-frog/monkey-lang`](https://github.com/henry-the-frog/monkey-lang).

**Status: early development. Not yet usable.** This is a port-and-adapt of [`lafleur`](https://github.com/devdanzin/lafleur) (CPython JIT fuzzer) targeted at Henry's Monkey implementation. The language-agnostic core from lafleur is being ported largely unchanged; the mutation engine, coverage collector, JIT introspection, and execution harness are Monkey-specific.

The project name continues the botanical naming lineage — *la fleur au fusil* ("flower in the rifle barrel") → *mimule* (French for the monkey-face flower *Mimulus*), targeting the **Monkey** language.

## Design

mimule's core evolutionary loop is inherited from lafleur and operates in five stages:

1. **Selection** — pick a parent test case from the corpus via multi-heuristic weighted scoring (rarity, fertility, depth, trace quality, execution time, size)
2. **Mutation** — apply a pipeline of AST-based mutations, with strategy selection adapted via epsilon-greedy learning on mutator success scores
3. **Execution** — run the mutated program through the Monkey JIT in a monitored subprocess with opt-in event instrumentation
4. **Analysis** — parse the JIT event stream to extract edge coverage, rare events, structural metrics; decide if the mutation produced new behavior
5. **Introspection** — optional: read JIT executor vitals (trace counts, guard exit rates, side trace presence) to drive the adaptive feedback

The seed corpus is bootstrapped from [`monkey-lang-tests-corpus`](https://github.com/devdanzin/monkey-lang-tests-corpus), which provides 13,131 Monkey programs harvested from 336 permissively-licensed third-party implementations.

## What mimule needs from `monkey-lang`

To reach its full feedback-driven form, mimule needs two surgical additions to `henry-the-frog/monkey-lang`:

1. **JIT event instrumentation** — a `JIT_EVENTS=1` env-var-gated event stream on stderr, emitting JSON Lines for trace lifecycle, optimization passes, execution, guard failures, and bailouts.
2. **AST → source serializer** — an upgrade to the existing `toString()` methods in `ast.js` so parsed programs round-trip cleanly through `parse → modify → toString → parse`.

A proposal for both has been sent to Henry. If either or both don't land, mimule has fallbacks:

- Instrumentation → subprocess stdout/exit-code coverage (weaker but functional)
- Serializer → byte-range text mutation via `tree-sitter-monkey` (more mutator work, less flexible)

## Project layout

```
mimule/
├── mimule/              ← main package
│   ├── __init__.py
│   └── (modules ported from lafleur + Monkey-specific additions)
├── tests/               ← test suite
└── pyproject.toml       ← project metadata, deps
```

## License

GPL-2.0-only, matching lafleur for lineage consistency. See [`LICENSE`](LICENSE).
