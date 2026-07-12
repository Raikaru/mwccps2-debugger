# MWCCPS2 Debugger

[![Tests](https://github.com/Raikaru/mwccps2-debugger/actions/workflows/tests.yml/badge.svg)](https://github.com/Raikaru/mwccps2-debugger/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A dynamic-analysis and behavioral-reduction toolkit for the Metrowerks
CodeWarrior PlayStation 2 C/C++ compiler. It exposes selected internal compiler
stages so matching-decompilation projects can determine *why* equivalent C
source produces different MIPS object code.

The toolkit was developed against Persona 3 FES, but its core is not
P3-specific. Any project using the exact supported MWCCPS2 build can use the
fingerprinting, PCode snapshots, experiment runner, scheduler capture,
register-allocation capture, semantic replayers, and cross-version corpus.
Persona 3 integration is an optional adapter at the repository boundary.

## Human quick start

The primary interactive workflow is one command: give the debugger an exact
compiler, a source file, the function to inspect, and the normal compiler
flags. It starts GDB, selects the matching live profile by SHA-256, compiles the
source, and writes pass-by-pass text files without requiring any manual
breakpoint commands:

```powershell
python mwccps2_debugger.py -e D:/mwcps2-2.4-001213/debug/mwccps2.exe fixtures/codegen_smoke.c load_indexed -- -O4,p
```

The output is designed to be read directly:

```text
frontend-*.txt    function and frontend-IR boundaries
backend-*.txt     numbered PCode before and after each backend pass
regalloc-*.txt    virtual-register priority and physical assignments
scheduler.txt     every ready-list choice, rejection, and idle cycle
manifest.json     capture status and complete artifact index
```

Every text artifact has equivalent JSON for scripts and comparisons. Use
`-o build/<name>` to choose the new output directory, `-g <gdb.exe>` when GDB
is not on `PATH`, or `-a="-O4,p -sym on"` when copying flags as one quoted
command line. Omit the function name to capture every generated function.

For the archived 2.4 compiler, run the exact-fingerprint preparer once before
the command above:

```powershell
python mwccps2_prepare_24.py D:/mwcps2-2.4-001213/mwccps2.exe --output D:/mwcps2-2.4-001213/debug/mwccps2.exe
```

## Status and support boundary

The fully validated live-debug profiles are:

```text
MWCCPS2 3.0.1 b210 (2006-03-08)
  SHA-256:    286548490e2e902cfef21dcf39cd5af23766731585d90dea747f8781eadcafd7
  PE time:    0x440f429b
  Image base: 0x00400000

MWCCPS2 2.4 Engineering Build 0017 (2000-12-13), prepared image
  SHA-256:    1233acf014b53ae39669da4cc050062f316d73dd63257150024ad25ad33dbb30
  PE time:    0x3a375fef
  Image base: 0x00400000
```

The 2.4 profile independently validates frontend boundaries, eight backend
PCode boundaries, scheduler choices, and colorgraph allocation state. Portable
fingerprints and direct-object corpus support also exist for b151, b198, and
b205; their live internal layouts are not assumed to equal either validated
profile.

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
mwccps2_debugger.py                one-command human-readable live debugger
mwccps2_prepare_24.py              exact-fingerprint 2.4 preparation
mwccps2_experiment.py             normal PCode/regalloc differential runner
mwccps2_scheduler_experiment.py   live scheduler differential runner
mwccps2_portability.py            compiler discovery and cross-version corpus
mwccps2_p3_reduce.py              optional P3 verifier-report bundle adapter
mwccps2_solve.py                  bounded evidence-guided mismatch search
mwccps2_explain.py                retail-aware function dossier CLI
mwccps2_family_sweep.py           whole-decomp residual-family clustering


gdb/
  mwccps2_capture.py               profile-driven human capture command
  mwccps2_profile_model.py         bounded 2.4 layout decoder and formatter
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
solver/                           deterministic search, capture, P3, and evidence adapters
explain/                          game-agnostic MIPS CFG, alignment, findings, and reports
adapters/                         optional retail-project evidence adapters

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
Ran 398 tests
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

### 3. Dump one function with the human debugger

The one-command workflow mirrors the interface of `cadmic/mwcc-debugger`: give
it the compiler, source, function name, and normal compiler flags. The compiler
profile is selected by SHA-256; no address is guessed.

```powershell
python mwccps2_debugger.py -e D:/mwcps2-2.4-001213/debug/mwccps2.exe fixtures/codegen_smoke.c load_indexed -- -O4,p
```

Use `-a` when copying flags as one quoted command-line fragment:

```powershell
python mwccps2_debugger.py -e D:/mwcps2-2.4-001213/debug/mwccps2.exe fixtures/codegen_smoke.c load_indexed -a="-O4,p -sym on" -o build/load-indexed-24
```

The new output directory contains numbered readable `frontend-*.txt`,
`backend-*.txt`, `regalloc-*.txt`, and `scheduler.txt` files. Matching JSON and
`manifest.json` preserve the same evidence for automation. Omit the function
name to capture every generated function. Existing output is never overwritten.

### 4. Run a first experiment

The experiment runner below remains the b210 differential workflow.

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

### 5. Interpret the first divergence

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

## Solver quick start

`mwccps2_solve.py` performs a deterministic breadth-first search over a small,
lossless C-source transform catalog. It is bounded by `--max-depth` and
`--max-candidates`; it does not promise to solve every mismatch or recover
historical source/AST state.

Capture-only reducer search requires all three exact b210 inputs and a source
root containing the reducer:

```powershell
python mwccps2_solve.py experiments/<question>/baseline.c FunctionName --source-root experiments/<question> --compiler <b210-compiler> --gdb <gdb> --profile profiles/mwcps2-3.0.1-b210.json --compiler-flag=-O2 --max-depth 2 --max-candidates 32 --output build/<capture-search>
```

P3-authoritative search invokes the P3 verifier for every candidate. Its
normalized difference ranks non-matches, but only its exact report row can
certify a result:

```powershell
python mwccps2_solve.py ../Persona3-FES-Decompilation/src/path/file.c FunctionName --p3-root ../Persona3-FES-Decompilation --address 00123450 --max-depth 2 --max-candidates 32 --output build/<p3-search>
```

For combined capture and P3 verification, resume the same identity-bound run:

```powershell
python mwccps2_solve.py ../Persona3-FES-Decompilation/src/path/file.c FunctionName --p3-root ../Persona3-FES-Decompilation --address 00123450 --compiler <b210-compiler> --gdb <gdb> --profile profiles/mwcps2-3.0.1-b210.json --compiler-flag=-O2 --max-depth 2 --max-candidates 32 --output build/<combined-search> --resume
```

The initial combined invocation is identical without `--resume`; `--resume`
requires its existing `search-checkpoint-v1.json`. See [Getting
started](docs/getting-started.md#bounded-solver) for selection, objectives, and
artifacts.

## Function explainer

`mwccps2_explain.py` combines authoritative P3 verification with observed
candidate bytes, retail bytes, relocations, direct calls, control-flow graphs,
and CFG-aware instruction alignment. It emits deterministic JSON plus a text
report; findings remain bounded hypotheses and never claim unavailable retail
compiler state.

Run it from this repository with a fresh output directory under `build/`:

```powershell
python mwccps2_explain.py src/Battle/btlMain.c FUN_0029ec50 --p3-root ../Persona3-FES-Decompilation --output build/explain-0029ec50
```

The output contains:

```text
build/explain-0029ec50/function-dossier-v1.json
build/explain-0029ec50/function-dossier.txt
```

The dossier classifies observed residuals into bounded families such as integer
signedness, integer-versus-float storage/ABI, control-flow shape, instruction
selection, operand/allocation differences, and unmatched operations. Only the
embedded P3 verifier row may certify `MATCH`.

When available, the dossier also records:

- GP-relative and LUI/low-half resolved retail addresses;
- unresolved base-plus-offset structure-field accesses with width and signedness;
- printable strings reached by reconstructed addresses;
- direct retail callers and callees resolved through project symbols;
- unique and ambiguous P3/P4 counterparts from `build/shared_p3.json`;
- observed final-object frame, stack-slot, delay-slot, and relocation evidence;
- optional exact-b210 stage captures with an instrumentation-neutrality gate.

Attach the current P4 mapping report:

```powershell
python mwccps2_explain.py src/Kosaka/k_clump.c K_Clump_MatUsrDataGetInt --p3-root ../Persona3-FES-Decompilation --p4-root ../Persona4-Decompilation --output build/explain-k-clump
```

Attach live compiler stages from the exact supported b210 executable:

```powershell
python mwccps2_explain.py src/h_cursor.c H_Cursor_GetShouldDraw --p3-root ../Persona3-FES-Decompilation --compiler D:/mwcps2-3.0.1b210-060308/mwccps2.exe --gdb C:/msys64/mingw64/bin/gdb.exe --profile profiles/mwcps2-3.0.1-b210.json --output build/explain-cursor-capture
```

The compiler attachment records portable stage digests and direct/instrumented
object equality. The final-lowering section describes facts observable in the
emitted candidate object; it deliberately does not claim an unprofiled internal
compiler pass.

## Whole-decomp residual families

`mwccps2_family_sweep.py` starts from a fresh authoritative P3 verifier report,
selects aligned bounded residuals, compiles every selected source file once, and
clusters functions by bounded finding and candidate/retail mnemonic pair:

```powershell
python mwccps2_family_sweep.py --p3-root ../Persona3-FES-Decompilation --output build/p3-residual-families --max-window 512 --max-diff 40
```

Use `--baseline <report.json>` only to reproduce a pinned prior baseline.
`--limit` provides a deterministic smoke subset. Outputs are
`residual-families-v1.json` and `residual-families.txt`; the JSON binds the
selection to the verifier report SHA-256 and lists extraction failures rather
than silently dropping them.


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

MWCCPS2 2.4 engineering build 0017 requires one deterministic preparation
step before unattended compilation. The preparer accepts only the exact
2000-12-13 executable fingerprint, writes no binary into this repository, and
copies the required `LMGR326B.DLL` beside the result:

```powershell
python mwccps2_prepare_24.py D:/mwcps2-2.4-001213/mwccps2.exe --output D:/mwcps2-2.4-001213/debug/mwccps2.exe
python mwccps2_portability.py --run-corpus --work-dir build/version-corpus --json build/version-corpus.json
```

The generated `mwcps2-2.4-0017-001213.portability.json` profile remains the
direct-compilation/cross-version report. Live GDB capture uses the independently
recovered `profiles/mwcps2-2.4-0017-001213.json`; it contains no inherited b210
addresses.
Run a readable 2.4 capture with:

```powershell
python mwccps2_debugger.py -e D:/mwcps2-2.4-001213/debug/mwccps2.exe fixtures/codegen_smoke.c load_indexed -- -O4,p
```

Create a deterministic P3 analysis bundle:

```powershell
python mwccps2_p3_reduce.py --config ../Persona3-FES-Decompilation/config/mwccps2-debugger.json --report ../Persona3-FES-Decompilation/build/h_sfdply_verify.json --function H_SfdPlay_UpdateTask --output build/H_SfdPlay_UpdateTask-analysis
```

See [P3 matching workflow](docs/p3-workflow.md) before using a debugger result
to edit game source.

Run a bounded source mismatch search:

```powershell
python mwccps2_solve.py experiments/<question>/baseline.c FunctionName --source-root experiments/<question> --compiler <b210-compiler> --gdb <gdb> --profile profiles/mwcps2-3.0.1-b210.json --output build/<solver-run>
```


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
- [Bounded solver](docs/getting-started.md#bounded-solver) — transform gates,
  stage objectives, resume, artifacts, and authority.

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
- This includes a bounded automatic mismatch solver, not a guarantee that every
  function is solvable. It does not recover a full historical AST or original
  source.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) for reducer, evidence, testing, privacy,
and pull-request requirements.

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
