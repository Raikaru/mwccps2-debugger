# Contributing

Contributions are welcome when they preserve the project's central contract:
compiler claims must be deterministic, evidence-backed, and bounded to the exact
executable and stage that were observed.

## Legal and repository hygiene

Do not commit or attach:

- Metrowerks compiler or linker binaries;
- game executables, disc images, extracted retail bytes, or proprietary SDKs;
- object files or debugger dumps containing third-party material;
- license files, credentials, local configuration, or private workstation paths
  from third-party installations.

Use compiler hashes, virtual addresses, decoded text, minimal original reducers,
and sanitized logs. Contributors must provide their own legally obtained tools
and game data.

By contributing original work to this repository, you agree that it is
available under the repository's [MIT License](LICENSE).

## Development setup

Required for the host-independent suite:

```text
Python 3.10+
```

Run:

```powershell
python -m compileall -q .
python -m unittest discover -s tests -p "test_*.py"
```

The suite does not require the proprietary compiler or GDB. Live collector
changes require additional local verification with a legally obtained exact
compiler build.

Read before changing behavior:

- [Getting started](docs/getting-started.md)
- [Experiments and artifacts](docs/experiments.md)
- [Architecture and extension points](docs/architecture.md)
- [Troubleshooting](docs/troubleshooting.md)

P3-specific contributors should also read [P3 matching
workflow](docs/p3-workflow.md).

## Good contribution types

- a minimal source reducer that isolates one compiler behavior;
- a bounded decoder for a previously opaque field with independent evidence;
- tests for malformed, boundary, unreadable, and cyclic structures;
- a validated profile for another exact compiler executable;
- a scheduler/allocation/selector replay rule proven against a live capture;
- a host transport with clearly stated validation level;
- corrected documentation or reproducible troubleshooting evidence;
- a game adapter kept outside the compiler-model layers.

A large decompiler dump, an unsupported semantic rename, or a collection of
uncontrolled source mutations is not sufficient evidence.

## Experiment contributions

Every checked-in experiment must:

1. ask one concrete question;
2. use a schema-v1 `experiment.json`;
3. include one baseline and focused source variants;
4. keep compatible global function signatures;
5. change one source property per variant;
6. record exact compiler flags and variant intent;
7. compile directly and under GDB;
8. prove equal direct and snapshot object SHA-256 values;
9. identify the earliest semantic PCode divergence;
10. avoid committing generated `build/` output.

Prefer self-contained C using original stand-in structs/globals. Do not copy a
whole game translation unit or copyrighted retail bytes into a reducer.

## Solver transform contributions

Add a source transform only when its edit is lossless, bounded, and anchored by
the conservative C structure. Its catalog entry must state the exact
preconditions, assumptions, default-search status, and evidence boundary. A
not-reachable or hypothesis-only lever stays disabled by default; do not enable
it merely because it produces an attractive candidate.

For each transform, add deterministic tests covering enumeration order,
application, rejection outside scope or preconditions, assumption gating, type
parameter handling where applicable, and duplicate/cycle-safe bounded search.
If it changes capture or P3 ranking behavior, also test required versus partial
stages, stage-objective digests, checkpoint incompatibility, and the rule that
only an authoritative P3 verifier `MATCH` can produce `solution.c`.

Do not add a collector, breakpoint, stage anchor, or semantic explanation from
a solver failure alone. Capture-gap requests require a proven comparison blind
spot and direct/instrumented equality; otherwise retain the result as unknown
or record the rejection.

## Decoder and profile contributions

For every new field, flag, breakpoint, or semantic name, include:

- exact compiler fingerprint;
- virtual address and structure offset where applicable;
- static writer/reader or call-boundary evidence;
- live fixture evidence when available;
- confidence and explicit unknown boundary;
- maximum counts, width checks, and cycle termination;
- deterministic tests.

Never copy b210 addresses into another build's profile because the binaries
produce similar object code. Rediscover the anchors and layouts independently.

Opaque fields should remain opaque until evidence proves a stronger name.

## Ghidra and reverse-engineering evidence

Useful evidence includes:

- exact function/global addresses;
- direct call relationships;
- disassembly/decompiler control conditions;
- embedded source/diagnostic string references;
- independent readers and writers agreeing on layout;
- a live capture consistent with the static interpretation.

Separate these statements in reports:

```text
Observed: directly read or established from the local compiler binary/run.
Inference: likely explanation for another artifact, including retail code.
Unknown: semantics not established by available evidence.
```

The final retail executable cannot reveal its original transient compiler AST,
PCode, scheduler queue, or interference graph.

## Runtime and serialization boundaries

Actual local executable paths may exist in process memory while running a
corpus, but public artifacts must not expose contributor usernames or checkout
paths. Use the existing `<workspace>` and `<home>` normalization and keep
runtime-only values under underscore-prefixed fields removed by
`_public_artifact()`.

Generated files belong under the ignored `build/` directory. Before opening a
pull request, scan the tracked diff for local absolute paths and proprietary
artifacts.

## Tests

Every behavioral change needs a test that fails for a plausible regression.
Cover boundaries and invalid data, not source-text implementation details.

Examples:

- decoder: valid layout, maximum count, unreadable pointer, cycle;
- scheduler: ready predicate, comparison precedence, stable tie;
- allocation: invalid endpoint, parent cycle, paired color, spill result;
- transport: exact command construction, timeout/failure translation;
- serialization: path redaction and runtime-field exclusion;
- CLI/schema: duplicate keys, unknown fields, unsafe paths, nonzero errors.

Run the complete suite before submitting:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Live compiler changes must additionally report:

- compiler SHA-256;
- exact command/fixture;
- direct object SHA-256;
- instrumented object SHA-256;
- capture completeness;
- predicted versus observed result when a semantic model is involved.

## Pull requests

Keep each pull request focused. Include:

- problem and evidence;
- exact files/addresses/stages affected;
- behavior before and after;
- tests and live commands run;
- observed facts versus inference;
- limitations or unvalidated hosts/builds;
- confirmation that no proprietary binaries or private paths are included.

Do not describe a model, profile, or transport as supported beyond the evidence
level exercised in the pull request.
