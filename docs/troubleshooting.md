# Troubleshooting

Use the exact error and evidence boundary. Do not suppress validation to make a
capture complete.

## Compiler fingerprint mismatch

Symptom:

```text
profile/executable SHA-256, size, timestamp, image base, or anchor mismatch
```

Action:

1. run `mwccps2_probe.py <compiler>`;
2. compare the SHA-256 with the supported profile;
3. check that `--compiler` does not point to `mwldps2.exe` or another release;
4. inventory the executable with `mwccps2_portability.py`;
5. use b210 live capture only for the exact b210 hash.

Do not edit the profile hash to accept another binary. That leaves every
absolute breakpoint and layout unvalidated.

## `gdb` not found

Pass an explicit executable:

```powershell
python mwccps2_experiment.py experiments/commutative_mul_s --gdb C:/tools/gdb/bin/gdb.exe --output build/run
```

Confirm:

```powershell
C:/tools/gdb/bin/gdb.exe --version
```

The GDB build must support Python. A GDB without Python cannot load the
collectors.

## GDB cannot start or attach to the compiler

Check:

- the compiler is a Windows PE executable accessible to the selected GDB;
- antivirus or process-protection policy is not blocking debugging;
- the working/output paths exist and are writable;
- no path component contains malformed quoting or newline characters;
- the GDB architecture can debug the 32-bit compiler;
- the compiler runs directly with the same arguments.

Use `mwccps2_debug_launch.py` for a manual suspended launch when discovering an
attach problem. Return to the automated runner for accepted evidence.

## `MWCIncludes` warning

The compiler may print:

```text
Environment variable 'MWCIncludes' not found
```

A self-contained reducer can still compile successfully. If it needs headers,
provide explicit include flags in `compiler_flags` or configure the compiler's
include environment. Do not treat the warning as a successful compile if the
process later exits nonzero.

## Output directory already exists

Experiment output must be fresh:

```text
--output build/question-run-2
```

Do not delete/reuse a directory while another run is active. Fresh directories
prevent stale captures from satisfying a new manifest.

## Output path rejected

Normal experiment output is restricted to this repository's ignored `build/`
directory. Use a child path such as:

```text
build/my-experiment
```

Do not use `..`, an absolute path outside `build/`, or a path resolving through
a symlink outside the allowed root.

## Direct and instrumented object hashes differ

This is a hard evidence failure. Possible causes include:

- a breakpoint or callback modified inferior state;
- timing exposed nondeterministic compiler behavior;
- the direct and instrumented commands differ;
- stale outputs were compared;
- environment or working directory differs;
- the compiler process did not complete normally.

Do not use the snapshots to explain compiler behavior. Reduce the collector to
read-only state, compare exact commands/environments, use a fresh output, and
rerun until hashes match.

## Solver rejects a host path

Solver output, checkpoints, and evidence are portable durable artifacts. They
reject raw local absolute paths, including a source string that embeds one. Use
repo-relative source, profile, `--source-root`, and `--output build/<run>`
arguments; keep machine-specific paths only in runtime command inputs. Do not
weaken this rejection or replace it with a path redaction that changes source.

## Solver resume reports drift or incompatibility

`--resume` requires an existing `build/<run>/search-checkpoint-v1.json` and the
same baseline source, selected catalog, objective, depth/candidate configuration,
assumption/disabled settings, integer type, and evaluator identity. Re-run the
original command exactly, or start a fresh `build/<new-run>` when any of those
inputs changed. Do not edit the checkpoint digests.

## Solver checkpoint or evidence is malformed

Treat an unreadable, corrupt, duplicate-key, unknown-field, or incompatible
schema artifact as invalid state. Start a fresh output; do not hand-repair it
to continue a search. Checkpoints are atomically written canonical JSON and
must not contain host paths.

## Solver required stage is partial or missing

Only a complete stage has an ordered occurrence digest. A partial/missing stage
is unknown and cannot meet `--required-stage` or a `--stage-objective`. Remove
the requirement only if the stage is not needed for the hypothesis; otherwise
reduce the input or improve an already evidenced capture boundary. Do not
interpret absence as an equal digest.

## Solver capture fails while P3 verification runs

Capture and P3 verification are independent. A P3 `tools/verify.py` report row
`MATCH` remains the sole match authority, while a failed capture cannot support
a capture claim. If capture stages are required/objectives are set, repair the
capture or use a fresh P3-only run; do not treat a P3 non-match or
`normalized_diff` as capture evidence.

## No applicable guarded solver transforms

The bounded parser found no catalog edit with proven preconditions in the named
function. Confirm the exact function name and conservative syntax, inspect the
selected transform IDs, and use `--include-disabled` only to investigate an
explicit not-reachable lever. `--allow-assumptions` permits recorded
assumption-required applications; it never makes an unsupported transformation
safe. Create a focused reducer or manually reconstruct missing semantics rather
than forcing a textual rewrite.

## No scheduling captures at `-O2`

This is usually expected for the P3 configuration. The compiler may not invoke
the scheduler at that optimization level.

Options:

- classify the normal experiment using the available stages;
- use the checked-in `-O3` scheduler reducer to study scheduler behavior;
- do not change a P3 reducer to `-O3` and then claim its schedule is the P3
  `-O2` schedule.

A missing scheduler stage is not an empty scheduler graph.

## Scheduler prediction reports `no_selection`

The scheduler can advance a cycle without issuing an instruction. In that case
the observed result is `no_selection`. Check resource eligibility, predecessor
counts, and earliest issue cycles.

Only complete observed winner events count toward prediction-match totals.

## Scheduler variants do not diverge

Equivalent source statement order may collapse to the same PCode before the
scheduler. Inspect `codegen_entry` or the scheduler's observed PCode signatures.
Create a reducer whose independent expression-tree order actually survives to
the scheduled PCode. Do not force divergence by changing unrelated semantics.

## Raw graph differs but PCode text does not

This means decoded semantic operations/operands are equal while normalized
structured or opaque state differs. If final objects are also equal, the tested
change is not a demonstrated object-code lever.

Do not report `codegen_entry` semantic divergence from the raw graph field. Use
`earliest_pcode_divergence` for that claim.

## Label or memory operand appears unresolved

The decoder preserves explicit fallback forms when the stronger interpretation
cannot be proven. Check:

- whether the label record is bound at that stage;
- whether its block exists in the captured bounded block walk;
- operand tag and format metadata;
- unreadable-memory or limit termination in the JSON;
- whether the capture occurred before the compiler finalized the descriptor.

Do not replace an unresolved value with a guessed block or pointer meaning.

## Register-allocation capture is absent

The fixture may not create virtual registers for a class, or the active pipeline
may skip allocation. Inspect `before_register_allocation.pcode.txt` and the
snapshot manifest. Create a reducer with a real virtual-register lifetime
without adding unrelated pressure.

## Register-allocation graph validation fails

Common causes:

- capture boundary is after graph storage was freed;
- node/edge count exceeded the configured bound;
- an incidence link is unreadable or cyclic;
- endpoint IDs fall outside `[0,N)`;
- parent map is cyclic or out of range;
- a partially written artifact was used.

Keep the failure explicit. Reconfirm the breakpoint and structure lifetime in
Ghidra before changing a decoder offset.

## Colorgraph replay does not match observed assignment

Check:

- capture phase is post-color and colorgraph returned success;
- work-list links were captured before destruction;
- ordinary/fallback masks and cursors correspond to the active class;
- raw colors were not replaced with canonical colors prematurely;
- paired-register flags and neighbor colors are preserved;
- the semantic model is being run on the matching schema version.

A mismatch is useful evidence that the model is incomplete. Do not coerce the
observed fields to make the replay pass.

## Frontend name or IRO walk terminates early

Inspect the termination reason. The pure model stops on:

- null;
- known sentinel;
- configured limit;
- unreadable memory;
- cycle.

Only null/sentinel completion supports a complete-list claim. Heap addresses
must remain process-specific.

## Portability corpus reports an invalid output path

Use an absolute-resolvable work parent, or a normal relative child under
`build/`:

```powershell
python mwccps2_portability.py --run-corpus --work-dir build/version-corpus --json build/version-corpus.json
```

The portability runner resolves the work directory before passing object paths
to the Windows compiler. If a custom environment still fails, inspect the exact
compiler diagnostic and path length.

## Compiler build is reported unavailable

The checked-in policy searches known locations, but local paths vary. Supply
additional roots:

```powershell
python mwccps2_portability.py --search-root C:/toolchains --search-root D:/archive/mwcc --json build/portability.json
```

An unavailable record is valid evidence. Do not create a profile by copying a
known hash or path for a binary that was not found.

## Wine or Wibo is found but not validated for snapshots

Capability discovery runs an executable/version smoke only. It does not prove
that GDB can debug b210 through that host. Complete the transport evidence
levels in [Architecture and extension points](architecture.md) before claiming
support.

## P3 function not found in a report

`mwccps2_p3_reduce.py` selects an exact function name from the supplied verifier
reports. Confirm:

- the report was produced for the file containing the function;
- the function appears in the report's `results` list;
- spelling/case matches exactly;
- `--report` points to the intended fresh report, not an older sweep.

Generate a focused report from the P3 repository:

```powershell
python tools/verify.py src/path/file.c --json build/target-verify.json
```

Then pass that report to the bundle CLI.

## P3 bundle rejects experiment evidence

The adapter requires a validated `mwccps2-experiment-summary` whose direct and
instrumented object hashes agree. Do not pass an arbitrary JSON or a summary
from an incomplete/failed run.

## A P3 source change looks closer but does not match

Run both:

```powershell
python tools/fndiff.py src/path/file.c FunctionName
python tools/verify.py src/path/file.c
```

A reduced difference is search progress, not completion. Record the remaining
exact instructions. Keep or revert the source change based on whether it moves
the intended compiler role without semantic regression.

## Generated files appear in version control

Local artifacts belong under `build/`, which is ignored. Python caches are also
ignored. Do not commit:

```text
build/
__pycache__/
*.pyc
compiler executables
retail ELF or extracted game bytes
```

Checked-in evidence should be a minimal source reducer, profile, deterministic
analysis/report JSON, test, or documentation—not a local capture directory.
