# Getting started

For a first human-readable 2.4 capture, the shortest path is:

```powershell
python mwccps2_prepare_24.py D:/mwcps2-2.4-001213/mwccps2.exe --output D:/mwcps2-2.4-001213/debug/mwccps2.exe
python mwccps2_debugger.py -e D:/mwcps2-2.4-001213/debug/mwccps2.exe fixtures/codegen_smoke.c load_indexed -- -O4,p
```

The second command automatically starts GDB and produces readable frontend,
PCode, scheduler, and register-allocation files. No manual GDB session or
breakpoint entry is required. Read the project [README](../README.md) for the
artifact walkthrough, exact support boundary, and evidence rules.

The rest of this guide covers the longer b210 differential-experiment workflow
from an empty local `build/` directory.

## Prerequisites

Required:

- Windows, or a compatible environment capable of running the 32-bit Windows
  MWCCPS2 executable;
- Python 3.10 or newer;
- GNU GDB with Python scripting support; GDB 16.3 is the validated version;
- a legally obtained supported compiler: the exact b210 executable for the
  differential workflow, or the exact 2.4 archive for the human live workflow;
- enough permission for GDB to start and debug the compiler process.

The runtime uses the Python standard library. No project-specific package
installation is required.

For Persona 3 work, keep the repositories as siblings:

```text
source/
  Persona3-FES-Decompilation/
  mwccps2-debugger/
```

That is the layout assumed by the optional P3 configuration and the examples in
these docs. The compiler and retail ELF remain outside both repositories.

## Verify the Python suite

From `source/mwccps2-debugger`:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

The suite is host-independent: it does not require the compiler or GDB. It
covers schema validation, normalization, selector/scheduler/allocation models,
transports, P3 report handling, and portability logic.

## Verify GDB

```powershell
gdb --version
```

The GDB executable must include Python support because the collectors are GDB
Python commands. If `--gdb` is omitted, experiment runners invoke `gdb` from
`PATH`.

The validated native command shape is:

```text
gdb --batch --nx --quiet --command <generated-command-file>
```

The command file loads the compiler, sets its arguments, stops at `starti`,
loads the collector, arms breakpoints, continues compilation, validates the
compiler exit code, and removes the temporary command file.

## Fingerprint the compiler

Never trust the toolchain directory name alone:

```powershell
python mwccps2_probe.py D:/mwcps2-3.0.1b210-060308/mwccps2.exe
```

Expected exact identity:

```text
sha256:      286548490e2e902cfef21dcf39cd5af23766731585d90dea747f8781eadcafd7
size:        2180096
pe_timestamp: 0x440f429b
image_base:  0x00400000
```

Write a persistent local probe report if needed:

```powershell
python mwccps2_probe.py D:/mwcps2-3.0.1b210-060308/mwccps2.exe --json build/compiler-probe.json
```

The b210 profile contains absolute virtual addresses and internal structure
offsets. A hash mismatch is a hard stop for live b210 capture. Use the
portability tool to inventory another build; do not bypass profile validation.

## Run a first PCode experiment

```powershell
python mwccps2_experiment.py experiments/commutative_mul_s --output build/quickstart-mul
```

Requirements enforced by the runner:

- the experiment directory contains a strict schema-v1 `experiment.json`;
- the output is a fresh directory beneath this repository's `build/`;
- every source variant defines the declared global function with a compatible
  signature;
- compiler flags do not replace runner-owned source/output arguments;
- the exact b210 executable matches the profile;
- the direct and instrumented object hashes match.

Successful output ends with a summary path such as:

```text
summary: .../build/quickstart-mul/experiment-summary-v1.json
```

Inspect:

```text
build/quickstart-mul/
  experiment-summary-v1.json
  variants/
    fresh_times_invariant/
      direct.o
      snapshot.o
      snapshots/
        snapshot-manifest.json
        000001-codegen_entry.json
        000001-codegen_entry.pcode.txt
        ...
```

Start with the human-readable `*.pcode.txt`, then use the JSON when exact
operands, hashes, flags, graph fields, or automated comparison are required.

## Override local paths

Every main runner accepts explicit compiler, GDB, and profile paths:

```powershell
python mwccps2_experiment.py experiments/commutative_mul_s --compiler C:/toolchains/mwcps2-3.0.1b210-060308/mwccps2.exe --gdb C:/tools/gdb/bin/gdb.exe --profile profiles/mwcps2-3.0.1-b210.json --output build/quickstart-mul
```

Use forward slashes in documentation and configuration. The transport converts
paths into a GDB-safe form.

## Manual suspended launch

`mwccps2_debug_launch.py` is useful when manually attaching a debugger before a
short-lived compiler exits:

```powershell
python mwccps2_debug_launch.py --compiler D:/mwcps2-3.0.1b210-060308/mwccps2.exe --cwd C:/work/reducer -- -O2 -c reducer.c -o reducer.o
```

The launcher creates the process suspended, prints process/thread information,
waits for explicit operator input, and then resumes the main thread. Use the
automated experiment runners for reproducible evidence; the manual launcher is
for discovery and debugging.

## Run a scheduler capture

The normal P3 `-O2` configuration often does not enter the scheduler. Use a
manifest that deliberately enables scheduling, such as the checked-in `-O3`
reducer:

```powershell
python mwccps2_scheduler_experiment.py experiments/scheduler_ready_tie --output build/quickstart-scheduler
```

The summary reports:

- whether observed PCode issue order diverged across variants;
- direct and instrumented object hashes;
- selection count;
- how many complete predictions matched the observed winner.

See [Experiments and artifacts](experiments.md) for interpretation.

## Inventory compiler versions

```powershell
python mwccps2_portability.py --json build/compiler-portability.json
```

Add local search roots without changing the checked-in policy:

```powershell
python mwccps2_portability.py --search-root C:/toolchains --json build/compiler-portability.json
```

To run all checked-in reducers directly under every available requested build:

```powershell
python mwccps2_portability.py --run-corpus --work-dir build/version-corpus --json build/version-corpus.json
```

For the exact MWCCPS2 2.4 engineering build 0017 archive:

```powershell
python mwccps2_prepare_24.py D:/mwcps2-2.4-001213/mwccps2.exe --output D:/mwcps2-2.4-001213/debug/mwccps2.exe
```

The preparer validates both the original and resulting SHA-256 fingerprints.
Use a nested output directory so the portability scanner finds the prepared
binary under the required `mwccps2.exe` basename. The prepared image also
matches the independently recovered live profile. Capture one function with:

```powershell
python mwccps2_debugger.py -e D:/mwcps2-2.4-001213/debug/mwccps2.exe fixtures/codegen_smoke.c load_indexed -- -O4,p
```

This creates readable frontend, eight-pass backend PCode, scheduler, and
register-allocation files plus equivalent JSON and a manifest. The profile is
selected by the prepared executable's exact SHA-256. b151, b198, and b205 still
receive fingerprints and direct-object comparisons only.

## Bounded solver

`mwccps2_solve.py` searches a deterministic breadth-first frontier of lossless
source edits. It is an optional aid after a credible reducer or P3 mismatch, not
a full C parser, original-source recovery tool, or guarantee of a match.

### Select transforms deliberately

By default the solver uses only catalog entries enabled for search. Use repeated
`--transform <id>` to narrow that catalog. `--include-disabled` exposes
not-reachable levers for explicit investigation; it does not make them
evidence-backed defaults. Applications whose preconditions cannot be proven are
withheld unless `--allow-assumptions` is set. That flag records the assumptions;
it does not prove C semantic equivalence.

`--integer-type <type>` supplies the integer spelling required by transforms
that need one. `--max-depth` limits transform-chain length and
`--max-candidates` limits the generated candidates. Keep both small and
increase one only for a justified hypothesis.

### Choose evidence stages

Choose at least one evaluator:

- **b210 capture** is selected only by providing `--compiler`, `--gdb`, and
  `--profile` together, plus `--source-root` (or `--p3-root`) containing the
  source;
- **P3 verification** is selected only by providing both `--p3-root` and the
  eight-hex-digit `--address`.

`--required-stage <stage>` makes a complete capture mandatory before a candidate
can rank as usable. A missing or partial required stage remains unknown, never
a digest match. `--stage-objective <stage>=<sha256>` compares the canonical
ordered occurrence digest of a complete stage, using normalized stage, graph,
and PCode digests. Objectives guide ranking and prune proven complete
mismatches; they do not certify retail equality.

### Read solver output

Every solver run writes below `build/<run>/`:

```text
solve-summary-v1.json             mwccps2-solver-summary v1; termination and best rank
solver-evidence-v1.json           mwccps2-solver-evidence v1; failures and capture-gap records
search-checkpoint-v1.json         mwccps2-guided-search-state v1; deterministic BFS state
run-identity-v1.json              mwccps2-solver-run-identity v1; configuration identity
best-candidate.c                  best ranked source when not certified
solution.c                        source only when P3 verify.py reports exact MATCH
```

The source artifact is one or the other, never both. `best-candidate.c` is
search progress: snapshot/object equality and P3 `normalized_diff` can rank it,
but cannot make it a solution. Only the authoritative P3 `tools/verify.py`
report row `MATCH` sets `matched: true` and writes `solution.c`.

Artifacts use canonical JSON, sorted deterministic ordering, SHA-256
identities, and no durable raw host paths. Resume accepts only an existing
checkpoint whose baseline, catalog, objective, and search configuration
digests, plus the run identity, are unchanged.

Failures are recorded in solver-evidence v1. Missing or partial capture remains
unknown. A capture-gap request is emitted only when direct/instrumented equality
is proven and the comparison establishes a blind spot at an already profiled
stage; otherwise its rejection is recorded. The solver never invents a
collector, breakpoint, or anchor.

## Host transport status

- **Windows GDB:** implemented and live-validated.
- **retrowin32 GDB:** concrete command transport implemented and covered by
  tests; no live local compiler session has been validated in this project.
- **Wine/Wibo:** capability evidence records executable discovery and a real
  `--version` smoke when installed. Availability alone does not claim b210 GDB
  snapshot support.

Use `transports.capabilities.probe_capabilities()` when recording host evidence.
Do not describe an untested host as supported.

## Next steps

- To create a reducer, continue with [Experiments and artifact
  interpretation](experiments.md).
- To investigate a P3 mismatch, use the stricter [P3 matching
  workflow](p3-workflow.md).
- To add a collector, compiler build, or transport, read [Architecture and
  extension points](architecture.md).
- For common failures, see [Troubleshooting](troubleshooting.md).
