# Architecture and extension points

The project separates host process control, executable-specific memory layouts,
GDB-side collection, deterministic normalization, and semantic replay. Keep
those boundaries when extending it.

## Data flow

```text
source C + selected transform catalog
        │
        ▼
lossless bounded C discovery → assumption-gated applications
        │
        ▼
deterministic BFS / checkpoint / ranked candidates
        │
        ├──────────────▶ optional exact-b210 direct + instrumented capture
        │                         │
        │                         ▼
        │                 object-equality gate → complete stage digests
        │
        └──────────────▶ optional authoritative P3 verify.py adapter
                                  │
                                  ▼
                        exact report row + normalized_diff rank
                                  │
                                  ▼
canonical summary, evidence, checkpoint, and source artifact under build/
```

Capture evidence and P3 verification are independent inputs. Snapshot/object
equality and normalized stage data rank or reject candidates; only the P3
adapter's exact `verify.py` row `MATCH` can certify `solution.c`.


The direct object and instrumented object converge only at the acceptance gate.
A capture is rejected if their hashes differ.

## Layer responsibilities

### CLI and experiment layer

Files:

```text
mwccps2_probe.py
mwccps2_experiment.py
mwccps2_scheduler_experiment.py
mwccps2_portability.py
mwccps2_p3_reduce.py
```

Responsibilities:

- strict argument and JSON validation;
- compiler fingerprint validation;
- source/output path containment;
- process orchestration;
- direct/instrumented object hashing;
- snapshot-manifest validation;
- cross-variant comparison;
- atomic summary/artifact writes;
- user-facing errors and nonzero exits.

This layer should not contain hard-coded inferior-memory decoding. That belongs
to the b210 model/profile layer.

### Solver layer

Files:

```text
mwccps2_solve.py
decomp/c_ast.py
decomp/source_transforms.py
decomp/mwccps2_transforms.py
solver/search.py
solver/b210_evaluator.py
solver/p3_verify.py
solver/evidence.py
```

Responsibilities:

- tokenize enough lossless C structure to locate unambiguous transform anchors;
- enumerate catalog applications deterministically and gate assumptions;
- apply one bounded source edit per BFS edge and deduplicate source digests;
- evaluate optional b210 capture and optional P3 verification independently;
- rank complete stage digest objectives and P3 normalized differences;
- checkpoint only identity-compatible state and write portable evidence;
- certify source only from the P3 verifier's exact `MATCH` row.

The solver is not a compiler, full AST recovery layer, or universal matching
engine. It must not turn missing/partial capture into equality, or create a
collector, anchor, or semantic claim from a candidate failure.


### Transport layer

Files:

```text
transports/process.py
transports/gdb.py
transports/capabilities.py
transports/capture_compare.py
```

Responsibilities:

- build process commands;
- quote paths/arguments safely;
- execute with timeout and captured diagnostics;
- remove temporary command files;
- report optional host executable capabilities;
- normalize host paths and line endings for cross-host comparison.

The transport package deliberately does not import b210 memory layouts. A
transport receives an opaque profile path and collector script.

`GdbSnapshotRequest` is the boundary object. `WindowsGdbTransport` runs native
GDB. `Retrowin32GdbTransport` wraps a Windows GDB invocation in retrowin32's
command form. Capability discovery for Wine/Wibo is evidence only, not a live
snapshot implementation.

### GDB command layer

Files:

```text
gdb/mwccps2_b210_snapshot.py
gdb/mwccps2_b210_scheduler.py
```

Commands installed inside GDB:

```text
b210-snapshot start --profile <profile> --output <directory>
b210-snapshot stop

b210-scheduler start --profile <profile> --output <directory>
b210-scheduler stop
```

Responsibilities:

- verify the selected inferior compiler executable loaded in GDB matches the exact profile;
- install/remove breakpoints;
- read registers and inferior memory;
- invoke pure model functions;
- write ordered manifests and companions;
- auto-continue without modifying inferior memory.

Breakpoint callbacks return control immediately after capture. They must not
patch code, registers, or compiler heap state. Instrumentation neutrality is
also checked at the object-hash gate.

### Pure model layer

Files:

```text
gdb/b210_snapshot_model.py
gdb/b210_regalloc_model.py
gdb/b210_scheduler_model.py
gdb/b210_frontend_model.py
```

Responsibilities:

- parse and validate the b210 profile;
- bound all memory reads and record walks;
- detect cycles and unreadable memory;
- decode PCode, operands, blocks, labels, frontend records, scheduler nodes, and
  allocation graphs;
- replace structural pointers with stable identities;
- preserve explicitly opaque values without assigning unsupported semantics;
- format deterministic text and JSON-compatible data.

These modules import outside GDB and are tested with synthesized memory. Keep
GDB APIs out of them.

### Semantic decompilation layer

Files:

```text
decomp/instruction_selection.py
decomp/scheduler.py
decomp/register_allocation.py
decomp/frontend_optimizations.py
```

Responsibilities:

- encode recovered decision rules as executable, evidence-bounded models;
- replay captured decisions;
- reject requests outside recovered invariants;
- emit deterministic evidence manifests;
- state exact addresses and unknown boundaries.

A semantic model is not a replacement implementation of the whole compiler.
Only behavior corroborated by static disassembly, live capture, or both belongs
here.

### Profiles and evidence

Files:

```text
profiles/mwcps2-3.0.1-b210.json
profiles/mwccps2-version-portability-policy-v1.json
profiles/*.portability.json
analysis/*.json
reports/*.json
```

The b210 profile binds:

- executable identity;
- named functions and globals;
- frontend anchors/layouts;
- PCode opcode-table layout;
- stage breakpoints;
- scheduler layout and globals;
- register-allocation layout and globals;
- evidence strings/addresses.

Portable profiles bind PE fingerprints and direct-corpus behavior for nearby
compiler builds. They do not silently inherit b210 live addresses.

`analysis/` contains reusable behavioral conclusions. `reports/` contains a
specific mismatch explanation. Both must separate observed evidence from
inference.

## Profile trust model

A live profile is trusted only after all identity fields match:

```text
filename-independent SHA-256
file size
PE timestamp
image base
required static/string anchors
```

The filename and directory are convenience metadata. They are not identity.

Portability discovery keeps the actual selected compiler path only in an
in-memory `_runtime` field needed by the direct corpus. Serialization removes
runtime-only fields. Paths beneath the checkout workspace or user home are
written as `<workspace>/...` or `<home>/...`, so checked profiles retain useful
provenance without publishing a contributor's username or absolute checkout
path.

Every address in `mwcps2-3.0.1-b210.json` is a virtual address for the exact
profile executable. Even a nearby Metrowerks build may move functions, globals,
heap layouts, or callback conventions.

## Snapshot normalization

The collector preserves two different views:

### Runtime evidence

Raw addresses may be retained in the full JSON where useful for debugging one
run. They are process-specific and cannot be compared semantically across
runs/hosts.

### Structural identity

Graph relationships use stable IDs:

```text
block-0001
pcode-0004
class-0-virtual-00034
candidate-0002
```

Edges normalize by endpoint identities. Linked-list pointers and hash-bucket
links are omitted from semantic topology. Host path fields and line endings are
removed by the cross-host comparator.

Do not add a pointer value to deterministic text unless the pointer itself is
the subject of the investigation and is clearly labeled runtime-only.

## Safety invariants

Every new collector/model must enforce:

- exact profile before breakpoint installation;
- unsigned/signed width checks;
- maximum node, block, operand, string, and edge counts;
- address-range overflow checks;
- cycle detection for every linked structure;
- readable-memory failure as explicit termination/error;
- no inferior-memory writes;
- atomic output writes where partial artifacts could be mistaken for complete;
- a manifest status describing completeness or the exact termination reason.

Never replace a failed read with zero or an empty list. That fabricates compiler
state.

## Adding a new PCode interpretation

1. Locate independent static readers/writers in Ghidra.
2. Record exact offsets, widths, and conditions.
3. Add the layout/evidence to the profile when executable-specific.
4. Extend the pure decoder without changing existing opaque fallback output.
5. Add synthesized-memory tests for valid, boundary, unreadable, and cyclic
   cases.
6. Capture a minimal live fixture.
7. Confirm deterministic text and direct/instrumented object equality.
8. Update experiment/artifact documentation only after the live evidence.

Do not rename an opaque tag or flag from one suggestive example.

## Adding a capture stage

1. Identify the pipeline call boundary in `CodeGen_Generator` or the relevant
   driver.
2. Prove the target structure is live and stable at that exact instruction.
3. Determine whether the breakpoint is before or after the instruction at the
   address; x86 call/return boundaries matter.
4. Add an evidence-backed profile entry.
5. Add a bounded collector that reads only the necessary state.
6. Add a stable stage name without reusing an existing semantic meaning.
7. Version the manifest schema if consumers must change.
8. Extend summary comparison ordering and missing-stage handling.
9. Add unit tests and one live compiler smoke.
10. Reconfirm the instrumented object hash.

## Adding an evidence-backed solver transform

1. Identify a source rewrite whose target syntax is unambiguous in the bounded,
   lossless C model.
2. State its preconditions, required integer spelling (if any), and every
   semantic assumption in the catalog manifest.
3. Keep an unproven or not-reachable lever disabled by default.
4. Implement deterministic enumeration and application without broad textual
   replacement.
5. Add tests for accepted, rejected, assumption-required, integer-typed,
   ordering, and duplicate-source cases.
6. Add b210/P3 evidence only for behavior actually observed; an attractive
   candidate or P3 non-match is not transform evidence.
7. Preserve the authority boundary: stage digests and object equality rank;
   only `verify.py` `MATCH` writes `solution.c`.

## Extending solver evidence or evaluation

Keep evaluator output separate from pure search. A new durable field needs a
versioned schema, canonical ordering, path redaction, malformed-artifact tests,
and resume-identity coverage. Capture-gap requests may reference only a proven
blind spot at an existing profile stage with proven capture neutrality; no new
collector or profile anchor may be inferred from the request.

## Adding a compiler build

For a nearby MWCCPS2 build:

1. add its exact SHA-256, size, timestamp, and image base to the portability
   policy;
2. use `mwccps2_portability.py` to fingerprint and run the direct corpus;
3. localize at least one behavioral relationship relative to b210;
4. rediscover anchors using strings, xrefs, signatures, and control flow;
5. independently recover globals and structure layouts;
6. create a new live profile only after validating each required anchor;
7. run the capture corpus and compare normalized schemas;
8. never copy b210 addresses merely because a direct-object result is similar.

A portable direct profile and a live-debug profile are separate support levels.

## Adding a scheduler rule

1. capture a ready set where the rule actually distinguishes candidates;
2. locate the exact branch/comparison in `0x004c0a00` or its helper;
3. add the field only if it is present in the live node/callback state;
4. update the semantic comparison ladder in execution order;
5. test tie preservation and boundary cycles;
6. prove predicted winner equals observed winner;
7. retain `no_selection` cycles separately from complete winner predictions.

## Adding a register-allocation rule

1. choose a capture boundary before transient graph destruction;
2. preserve physical nodes `[0,P)` and virtual nodes `[P,N)`;
3. normalize edges by endpoints and validate double incidence;
4. preserve raw color and canonical/coalesced color separately;
5. validate parent-map bounds and cycles;
6. replay work-list/color behavior against the observed assignment;
7. treat spill/fallback behavior literally; do not invent a color for raw `-1`;
8. use source reducers to test lifetime/interference hypotheses.

## Adding a game integration

Do not put game-specific report parsing into the compiler models.

Create a boundary adapter like `mwccps2_p3_reduce.py` that:

- validates the game's report schema;
- normalizes function identity, source path, address, and mismatch fields;
- fingerprints imported experiment/analysis evidence;
- emits a deterministic local bundle;
- never imports into or alters the game's required build;
- leaves final retail verification to the game project.

Keep the core experiment format game-independent.

## Adding a transport

A new transport should implement process-command construction around the same
opaque `GdbSnapshotRequest` contract. It must not duplicate PCode or profile
logic.

Required evidence levels:

1. command construction unit tests;
2. executable discovery and version smoke;
3. one real compiler/GDB capture;
4. normalized comparison with the Windows reference;
5. direct/instrumented object equality.

Do not advertise level 3–5 support after completing only level 1 or 2.

## Schema changes

Artifacts use explicit schema names and versions. For a backward-compatible
optional field, update validators and tests deliberately. For changed meaning,
required fields, stage ordering, or normalization, increment the schema
version and retain a clear migration boundary.

Never silently reinterpret a checked-in version-1 field.

## Verification expectations

Production changes require:

```powershell
python -m unittest discover -s tests -p "test_*.py"
python -m compileall -q .
```

Behavioral collector changes additionally require a focused live compiler run.
The acceptance report must name:

- exact compiler fingerprint;
- command/experiment;
- direct and instrumented object hashes;
- capture completeness;
- predicted versus observed result where a model is involved.
