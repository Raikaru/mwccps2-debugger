# Getting started

This guide takes a new contributor from an empty local `build/` directory to a
verified b210 PCode experiment. Read the project [README](../README.md) first for
the support boundary and evidence rules.

## Prerequisites

Required:

- Windows, or a compatible environment capable of running the 32-bit Windows
  MWCCPS2 executable;
- Python 3.10 or newer;
- GNU GDB with Python scripting support; GDB 16.3 is the validated version;
- a legally obtained `mwcps2-3.0.1b210-060308/mwccps2.exe`;
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

Only b210 receives full live-profile validation. Other builds receive exact PE
fingerprints and direct-object behavior comparisons unless a separately
validated live profile is added.

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
