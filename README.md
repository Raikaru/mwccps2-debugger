# MWCCPS2 Debugger

A dynamic-analysis and behavioral-reduction toolkit for the Metrowerks
CodeWarrior PlayStation 2 C/C++ compiler. It exposes selected internal compiler
stages so matching-decompilation projects can determine *why* equivalent C
source produces different MIPS object code.

The toolkit was developed against Persona 3 FES, but its core is not
P3-specific. Any project using the exact supported MWCCPS2 build can use the
fingerprinting, PCode snapshots, experiment runner, scheduler capture,
register-allocation capture, semantic replayers, and cross-version corpus.
Persona 3 integration is an optional adapter at the repository boundary.

## Status and support boundary

The fully validated live-debug profile is:

```text
Compiler:   mwcps2-3.0.1b210-060308
SHA-256:    286548490e2e902cfef21dcf39cd5af23766731585d90dea747f8781eadcafd7
PE time:    0x440f429b
Image base: 0x00400000
```

Portable fingerprints and direct-object corpus support also exist for b151,
b198, and b205. Their live internal layouts are not assumed to equal b210.

Validated host configuration:

```text
Windows 11 x64
Python 3.10.11
GNU GDB 16.3 with Python support
```

The compiler and game data are not distributed with this repository. Supply a
compiler copy and retail executable that you are legally entitled to use.

## What it answers

For a reduced function or expression, the debugger can answer questions such
as:

- Did two source variants already differ when backend PCode was created?
- Did instruction scheduling reorder otherwise identical operations?
- Did register allocation assign different physical registers to the same
  virtual roles?
- Did an apparent source change alter only opaque graph metadata while leaving
  semantic PCode and final object bytes unchanged?
- Is a behavior specific to b210 or different in b151/b198/b205?
- Which source-shaping experiments are plausible for a real P3 mismatch?

The captured stage order is:

```text
C / frontend IR
    ↓
codegen_entry
    ↓
before_scheduling
    ↓
after_scheduling
    ↓
before_register_allocation
    ↓
after_colorgraph_assignment
    ↓
after_register_allocation
    ↓
object code
```

Not every optimization level executes every stage. In particular, an `-O2`
compile may not hit the scheduler breakpoints; this is reported as a missing
stage rather than fabricated data.

## Repository map

```text
mwccps2_probe.py                  PE fingerprint and static anchor report
mwccps2_debug_launch.py           suspended Windows launch for manual attach
mwccps2_experiment.py             normal PCode/regalloc differential runner
mwccps2_scheduler_experiment.py   live scheduler differential runner
mwccps2_portability.py            compiler discovery and cross-version corpus
mwccps2_p3_reduce.py              optional P3 verifier-report bundle adapter

gdb/
  mwccps2_b210_snapshot.py        GDB command for PCode/regalloc snapshots
  mwccps2_b210_scheduler.py       GDB command for scheduler decisions
  b210_*_model.py                 pure validation and normalization models

decomp/
  instruction_selection.py       recovered selector decision model
  scheduler.py                   ready-queue and dependency semantic model
  register_allocation.py         colorgraph replay
  frontend_optimizations.py      bounded frontend rewrite model

transports/
  gdb.py                         Windows and retrowin32 command transports
  capabilities.py                Wine/Wibo capability evidence
  capture_compare.py             host-independent snapshot comparison

experiments/                     checked-in source-variant reducer corpus
profiles/                        exact fingerprints, anchors, and layouts
analysis/                        machine-readable behavioral conclusions
reports/                         concrete mismatch explanations
tests/                           deterministic regression suite
build/                           ignored local snapshots and summaries
```

## Quick start

### 1. Verify prerequisites

Use Python 3.10 or newer. The project uses only the standard library at runtime.
Install a GDB build with Python scripting support and ensure `gdb` is on
`PATH`.

Run the tests:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Expected repository baseline:

```text
Ran 364 tests
OK
```

### 2. Fingerprint the compiler

```powershell
python mwccps2_probe.py D:/mwcps2-3.0.1b210-060308/mwccps2.exe
```

For a reusable report:

```powershell
python mwccps2_probe.py D:/mwcps2-3.0.1b210-060308/mwccps2.exe --json build/compiler-probe.json
```

Do not continue with the b210 live profile if the SHA-256 differs. Absolute
addresses and internal layouts are executable-specific.

### 3. Run a first experiment

Every output directory must be a fresh child of this repository's ignored
`build/` directory:

```powershell
python mwccps2_experiment.py experiments/commutative_mul_s --output build/quickstart-mul
```

If the compiler or GDB is not at its default location:

```powershell
python mwccps2_experiment.py experiments/commutative_mul_s --compiler C:/toolchains/mwcps2-3.0.1b210-060308/mwccps2.exe --gdb C:/tools/gdb/bin/gdb.exe --output build/quickstart-mul
```

The runner compiles each variant twice:

1. directly with MWCCPS2;
2. under GDB with internal snapshots enabled.

A variant is admissible only when both object SHA-256 values are identical. The
summary is:

```text
build/quickstart-mul/experiment-summary-v1.json
```

Each variant also contains human-readable `*.pcode.txt` files alongside the
machine-readable JSON snapshots.

### 4. Interpret the first divergence

Use the earliest *semantic PCode* divergence, not the earliest raw graph hash
change:

| Result | Interpretation |
| --- | --- |
| `earliest_pcode_divergence: codegen_entry` | Source/frontend/selection shape already differs. |
| First difference after scheduling | Investigate dependencies, latency, resources, and ready-queue ties. |
| PCode equal before allocation but different after allocation | Investigate interference, coalescing, simplify order, and colors. |
| Raw graph differs while PCode and objects remain equal | Opaque/transient metadata changed; not a useful object-code lever in that experiment. |
| PCode equal but objects differ | Investigate later lowering, frame/relocation/encoding behavior; do not invent a captured cause. |

See [Experiments and artifact interpretation](docs/experiments.md) for the
complete workflow.

## Common commands

Run a normal b210 differential experiment:

```powershell
python mwccps2_experiment.py experiments/commutative_addu --output build/addu-analysis
```

Run the scheduler experiment (`-O3` is declared in its manifest):

```powershell
python mwccps2_scheduler_experiment.py experiments/scheduler_ready_tie --output build/scheduler-analysis
```

Replay an observed colorgraph assignment:

```powershell
python decomp/register_allocation.py build/regalloc-o3-smoke-out/variants/load_indexed/snapshots/000005-after_colorgraph_assignment.json
```

Discover local compiler builds and validate b210:

```powershell
python mwccps2_portability.py --json build/compiler-portability.json
```

Run the reducer corpus across every available requested build:

```powershell
python mwccps2_portability.py --run-corpus --work-dir build/version-corpus --json build/version-corpus.json
```

Create a deterministic P3 analysis bundle:

```powershell
python mwccps2_p3_reduce.py --config ../Persona3-FES-Decompilation/config/mwccps2-debugger.json --report ../Persona3-FES-Decompilation/build/h_sfdply_verify.json --function H_SfdPlay_UpdateTask --output build/H_SfdPlay_UpdateTask-analysis
```

See [P3 matching workflow](docs/p3-workflow.md) before using a debugger result
to edit game source.

## Evidence rules

These rules apply to both humans and coding agents:

1. **Retail verification remains authoritative.** A snapshot never proves a P3
   function matches. Only the P3 verifier may report `MATCH`.
2. **Require direct/instrumented object equality.** If GDB changes the object,
   discard the capture as behavioral evidence.
3. **Separate observation from inference.** Retail compiler transient state is
   unavailable. Do not describe a retail interference graph, AST, or scheduler
   queue as observed.
4. **Use semantic PCode for stage classification.** Raw heap addresses and
   opaque graph metadata are diagnostic only.
5. **Change one reducer property at a time.** Otherwise the first divergence
   cannot identify a useful source lever.
6. **Keep generated output under `build/`.** It is local, ignored, and may
   contain host-specific paths.
7. **Do not commit compiler binaries, game binaries, or extracted retail
   bytes.**

## Documentation

- [Getting started](docs/getting-started.md) — setup, compiler fingerprint,
  first captures, and host notes.
- [Experiments and artifacts](docs/experiments.md) — manifest format, output
  schemas, decision tree, scheduler and allocator workflows.
- [P3 matching workflow](docs/p3-workflow.md) — exact agent/human procedure for
  using the debugger from the main decomp.
- [Architecture and extension points](docs/architecture.md) — process boundary,
  profiles, GDB collectors, pure models, and adding a build or capture.
- [Troubleshooting](docs/troubleshooting.md) — fingerprint, GDB, scheduling,
  output-directory, compiler, and interpretation failures.

## Current limitations

- Live internal capture is fully validated only for the exact b210 executable.
- The frontend model is intentionally bounded; it is not a complete AST/IR
  decompiler.
- A retail game's original transient compiler state cannot be recovered from
  its final executable.
- The scheduler capture applies only when the compiler actually invokes the
  scheduler.
- Retrowin32 command construction is implemented and tested, but no live local
  retrowin32 compiler session has been validated here.
- Wine and Wibo are capability-probed; neither was installed on the validated
  workstation and neither is currently advertised as a proven snapshot
  transport.
- This is a diagnostic and experiment tool, not an automatic matching engine.

## Contributing

Start with a small reducer or a bounded compiler behavior. Preserve exact
compiler fingerprints, deterministic JSON ordering, strict bounds/cycle
checks, and direct/instrumented object verification. Add tests for every new
observable contract.

When adding a compiler build, capture point, operand interpretation, or semantic
name, include the evidence address and confidence boundary. Unknown fields
should remain opaque rather than receiving a plausible but unsupported name.

## License

The original tooling and documentation in this repository are available under
the [MIT License](LICENSE). The license does not grant or imply rights to
Metrowerks compiler binaries, Persona 3 assets, retail executables, or other
third-party material. Users must supply any required third-party software or
game data separately and in accordance with the rights applicable to it.
