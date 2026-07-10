# P3 matching workflow

This is the operating procedure for humans and coding agents using the compiler
debugger while working in `Persona3-FES-Decompilation`.

The debugger is diagnostic. The P3 verifier remains the only authority for a
function match.

## Required repository layout

```text
source/
  Persona3-FES-Decompilation/
  mwccps2-debugger/
```

P3 local configuration:

```text
Persona3-FES-Decompilation/tools/verify_config.local.json
```

Optional debugger integration configuration:

```text
Persona3-FES-Decompilation/config/mwccps2-debugger.json
```

Expected compiler:

```text
mwcps2-3.0.1b210-060308
SHA-256 286548490e2e902cfef21dcf39cd5af23766731585d90dea747f8781eadcafd7
P3 verifier flags: -O2 -Iinclude
```

Read the P3 repository's `AGENTS.md` before editing game source. All existing
matching, naming, source-ownership, and verification rules still apply.

## When to use the debugger

Use it when the P3 function compiles and the remaining mismatch plausibly comes
from compiler decisions:

- same operations but different physical registers;
- same operations in a different order;
- commutative operand-order differences;
- extension or mask placement;
- block-layout differences between equivalent source forms;
- loop-invariant versus loop-local expression placement;
- uncertainty about whether a source permutation reaches backend PCode;
- uncertainty about whether a difference starts before scheduling or during
  allocation.

Do not start with the debugger when:

- the C does not compile;
- calls, constants, branches, or side effects are visibly wrong;
- the function is still a stub or broad decompiler translation;
- the mismatch is explained by an unresolved symbol or relocation;
- types and structure layouts are not yet credible;
- the source variants change several properties simultaneously.

Fix semantic reconstruction first. Internal compiler traces cannot compensate
for incorrect C behavior.

## Non-negotiable evidence rules

1. Never claim `MATCH` unless `tools/verify.py` reports `MATCH` for that
   function.
2. Never treat a debugger experiment's object equality as retail equality.
3. Reject any snapshot variant whose direct and GDB-instrumented object hashes
   differ.
4. Do not claim to observe the retail compiler's AST, PCode, scheduler queue, or
   interference graph. Only the locally run compiler is observable.
5. Classify by semantic PCode text before using raw graph differences.
6. Keep debugger output under `mwccps2-debugger/build/`; do not commit it.
7. Check in a reducer only when it captures a reusable compiler question, not a
   dump of copyrighted retail bytes or a whole P3 translation unit.

## End-to-end procedure

### Step 1: establish the real P3 mismatch

From `source/Persona3-FES-Decompilation`:

```powershell
python tools/fndiff.py src/path/file.c FunctionName
python tools/verify.py src/path/file.c
```

If the source marker or retail address is ambiguous, pass the known address to
`fndiff.py`:

```powershell
python tools/fndiff.py src/path/file.c FunctionName --addr 00123450
```

Record:

- source file and function;
- retail address;
- verifier status;
- object size and retail window;
- number and exact offsets of non-relocation differences;
- the first differing instruction pairs;
- relocation fields that were normalized or remain unresolved.

A raw `fndiff` count may include tail padding. Inspect the actual instruction
pairs before choosing a compiler phase.

### Step 2: classify the visible difference

Use the final MIPS difference only as an initial hypothesis:

| Visible residual | First hypothesis |
| --- | --- |
| Different operations/constants/branches | Source semantics or frontend/selection. |
| Same operations, different order | Scheduling, evaluation order, or earlier block construction. |
| Same operations/order, different registers | Live ranges, coalescing, or coloring. |
| Different sign/zero extensions | Types, casts, formal parameters, or selector extension rule. |
| Different block order | Source control-flow shape or frontend simplification. |
| Only relocation fields | Symbol/address recovery, not necessarily codegen. |
| Large unrelated sequence | Reduction is premature; reconstruct better C first. |

Do not lock the conclusion yet. The experiment determines the earliest locally
observable divergence.

### Step 3: reduce one hypothesis

Create a new directory under:

```text
mwccps2-debugger/experiments/<question>/
```

The reducer should preserve the properties relevant to the mismatch:

- exact scalar widths and signedness;
- pointer versus array form;
- `volatile` only when intentionally tested;
- global versus local storage role;
- loop nesting and invariant placement;
- function parameters versus explicit casts;
- P3 optimization level (`-O2`) unless testing scheduler behavior explicitly.

Remove P3-specific dependencies that do not affect the question. Use small
stand-in structs and globals rather than copying a whole translation unit.

Create one baseline and one variant per source lever. See
[Experiments and artifacts](experiments.md) for the manifest contract.

### Step 4: run the local compiler experiment

From `source/mwccps2-debugger`:

```powershell
python mwccps2_experiment.py experiments/<question> --output build/<question>-run
```

Use a new output path on every run.

Before reading stage differences, confirm every relevant variant records equal
direct and instrumented object SHA-256 values. If not, the debugger run is not
admissible evidence.

### Step 5: locate the first semantic divergence

Read:

```text
build/<question>-run/experiment-summary-v1.json
```

Then inspect the paired `*.pcode.txt` files at the first differing stage.

Decision:

#### Diverges at `codegen_entry`

The source change altered frontend/selection output. Investigate:

- types and casts;
- expression tree and operand slots;
- address/immediate form;
- control-flow source shape;
- frontend optimization behavior.

Scheduler and physical-register changes cannot recreate operations or blocks
that are already absent here.

#### Equal at entry, diverges after scheduling

Run or extend a scheduler experiment. Compare ready candidates, dependencies,
latency, resources, deadlines, critical path, and stable-list ties.

#### Equal before allocation, diverges after allocation

Inspect `after_colorgraph_assignment.json` and its `*.regalloc.txt`. Compare
virtual roles, edges, coalescing parents, work-list order, masks, and colors.
Replay with:

```powershell
python decomp/register_allocation.py <capture.json>
```

#### Semantic PCode and objects are equal

The tested source variant is not a useful lever for this mismatch under exact
b210. Stop repeating equivalent spellings and test a different, independently
motivated property.

### Step 6: compare with established behavior

Before inventing another reducer, consult:

```text
analysis/p3-retail-reachability-v1.json
analysis/frontend-pass-reducers-v1.json
reports/p3-allocation-explanation-v1.json
```

Current reusable findings include:

- `mul.s` operand/source form can change codegen-entry PCode and object bytes;
- explicit sign-extension placement can change codegen-entry PCode;
- invariant mask placement can change object output;
- boolean and switch source forms can change block layout at codegen entry;
- tested commutative array/index spellings and redundant `u16` remasking may
  leave semantic PCode and objects unchanged;
- source lifetime changes can exchange physical GPR roles without changing the
  operation shape.

These are scoped experiment results. Reproduce the relevant conditions before
applying them to a P3 function.

### Step 7: apply one source change to P3

Return to `Persona3-FES-Decompilation`. Apply only the source shape supported by
the experiment. Preserve established types, names, and local conventions.

Immediately rerun:

```powershell
python tools/fndiff.py src/path/file.c FunctionName
python tools/verify.py src/path/file.c
```

Record whether:

- normalized difference decreased;
- the expected instruction/role changed;
- an unrelated region regressed;
- the function reached `MATCH`.

A smaller diff is useful search evidence but is not completion. Continue until
`tools/verify.py` reports `MATCH`, or revert the unsuccessful source shape.

### Step 8: preserve reusable evidence

If the compiler behavior is reusable:

- keep the minimal experiment and manifest;
- add deterministic tests for any new decoder/model contract;
- update an `analysis/` artifact with exact hashes and stage evidence;
- document observed facts separately from inference;
- do not check in local `build/` output.

If the result is function-specific, preserve the explanation in the main
decomp's work notes or commit rationale rather than creating a misleading
general compiler rule.

## Optional P3 analysis bundle

Generate a verifier report for the target file:

```powershell
python tools/verify.py src/path/file.c --json build/target-verify.json
```

From the debugger repository, create a deterministic bundle:

```powershell
python mwccps2_p3_reduce.py --config ../Persona3-FES-Decompilation/config/mwccps2-debugger.json --report ../Persona3-FES-Decompilation/build/target-verify.json --function FunctionName --output build/FunctionName-analysis
```

Alternatively, generate a new bundle with verified experiment evidence. Use a
different fresh output directory; bundle creation never mutates an existing
output:

```powershell
python mwccps2_p3_reduce.py --config ../Persona3-FES-Decompilation/config/mwccps2-debugger.json --report ../Persona3-FES-Decompilation/build/target-verify.json --function FunctionName --output build/FunctionName-analysis-with-evidence --experiment-report build/<experiment-run>/experiment-summary-v1.json --analysis-report analysis/p3-retail-reachability-v1.json
```

The CLI validates report schemas, object evidence, paths, function selection,
and analysis fingerprints. It does not edit P3 source and does not run the P3
verifier for you.

## Real example: `K_FldFrame_CreateCtlTask`

Subject:

```text
Function: K_FldFrame_CreateCtlTask
Address:  0x001ad660
Source:   src/Kosaka/Field/k_fldFrame.c
```

Observed final residual:

```text
object: global base in $a3, scaled index in $a2
retail: global base in $a2, scaled index in $a3
```

Eight genuine instruction-byte differences repeat the role exchange in the PC
and EC loops. A ninth `fndiff` count was retail zero tail beyond the object, not
another instruction.

The local reducer showed distinct virtual global-base and scaled-index roles
before allocation and their physical assignments at post-color. The operation
shape was preserved. The report therefore classifies physical coloring as a
high-confidence inference while explicitly stating that the retail graph is
unavailable.

Full evidence:

```text
reports/p3-allocation-explanation-v1.json
experiments/p3_global_base_scaled_index/
```

This is the standard for a useful explanation: exact retail/object pairs,
verified local compiler state, and a bounded inference rather than a fabricated
retail trace.

## Agent handoff format

When handing a debugger-assisted result to another agent or human, report:

```text
P3 subject: <file>, <function>, <address>
Verifier before: <status>, <normalized diff>
Visible residual: <exact instruction/offset summary>
Experiment: <manifest path>, <compiler hash>, <flags>
Object invariant: direct SHA == instrumented SHA
First semantic divergence: <stage or none>
Observed compiler fact: <what the local capture proves>
Inference: <what likely explains retail, explicitly labeled>
P3 source change: <single applied lever>
Verifier after: <status>, <normalized diff>
Remaining risk: <unobserved stage/retail state/other uncertainty>
```

Do not hand off “looks closer” without the verifier result and exact experiment
evidence.
