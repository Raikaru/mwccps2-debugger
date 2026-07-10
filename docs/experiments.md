# Experiments and artifact interpretation

An experiment compares small C source variants under an exact compiler profile.
Its purpose is not merely to show that object files differ. It identifies the
earliest observed compiler stage where a controlled source change becomes a
semantic difference.

## Experiment design rules

A useful experiment obeys these constraints:

1. Ask one concrete question.
2. Change one source property at a time.
3. Preserve function signature and externally visible behavior as far as the
   question permits.
4. Preserve relevant types, qualifiers, signedness, and optimization flags.
5. Keep the reducer self-contained when possible.
6. Include a baseline variant.
7. Require direct and instrumented object SHA-256 equality.
8. Treat retail applicability as a later inference, not as an experiment fact.

Bad experiment:

```text
Variant B changes operand order, adds volatile, changes the loop, and changes
signedness.
```

A resulting object difference cannot identify which change mattered.

Better experiment:

```text
baseline: return fresh * invariant;
variant:  return invariant * fresh;
```

Add a separate third variant if a volatile local is another hypothesis.

## Directory format

Each checked-in experiment has one directory:

```text
experiments/example/
  experiment.json
  baseline.c
  variant.c
```

Schema-v1 manifest:

```json
{
  "schema_version": 1,
  "name": "example",
  "question": "Does reversing these operands change selected PCode?",
  "compiler_flags": ["-O2"],
  "variants": [
    {
      "name": "baseline",
      "source": "baseline.c",
      "function": "example",
      "intent": "Original operand order."
    },
    {
      "name": "reversed",
      "source": "variant.c",
      "function": "example",
      "intent": "Reverses only the two commutative operands."
    }
  ]
}
```

Manifest fields:

| Field | Contract |
| --- | --- |
| `schema_version` | Must be integer `1`. |
| `name` | Stable experiment identifier. |
| `question` | Exact behavior the variants measure. |
| `compiler_flags` | Compiler options only; the runner owns `-c`, source, and `-o`. |
| `variants` | Ordered non-empty variant list; the first variant is the baseline. |
| `variant.name` | Safe identifier used for output directories. |
| `variant.source` | Source path contained inside the experiment directory. |
| `variant.function` | Global function definition to compare. |
| `variant.intent` | The single controlled source property represented by the variant. |

The runner validates duplicate JSON keys, unknown fields, unsafe paths, flags,
and source/function consistency. Do not weaken validation to accept a malformed
experiment; fix the manifest.

## Running an experiment

From the debugger repository:

```powershell
python mwccps2_experiment.py experiments/example --output build/example-run
```

`--output` must name a fresh directory beneath `build/`. A fresh path prevents
old snapshots from being mistaken for the current compiler run.

For each variant the runner:

1. compiles directly;
2. compiles under GDB with snapshots;
3. hashes both objects;
4. rejects instrumentation drift;
5. validates the snapshot manifest and every declared companion file;
6. compares the variant with the baseline by stage occurrence;
7. writes `experiment-summary-v1.json` atomically.

## Output structure

Typical output:

```text
build/example-run/
  experiment-summary-v1.json
  variants/
    baseline/
      direct.o
      snapshot.o
      snapshots/
        snapshot-manifest.json
        000001-codegen_entry.json
        000001-codegen_entry.pcode.txt
        000002-before_scheduling.json
        000002-before_scheduling.pcode.txt
        000003-after_scheduling.json
        000003-after_scheduling.pcode.txt
        000004-before_register_allocation.json
        000004-before_register_allocation.pcode.txt
        000005-after_colorgraph_assignment.json
        000005-after_colorgraph_assignment.pcode.txt
        000005-after_colorgraph_assignment.regalloc.txt
        000006-after_register_allocation.json
        000006-after_register_allocation.pcode.txt
    variant/
      ...
```

The exact files depend on which compiler stages executed. Missing scheduling
captures at `-O2` are expected for many reducers.

## Evidence hierarchy

Use evidence in this order:

1. **Direct object bytes** — what the uninstrumented compiler produced.
2. **Instrumented object equality** — whether the snapshot run preserved that
   behavior.
3. **Semantic PCode text** — stable decoded operations, operands, blocks, and
   labels.
4. **Normalized structured JSON** — detailed graph and allocator state.
5. **Raw/opaque graph differences** — diagnostic clues only.

Do not use raw heap addresses as semantic evidence. They vary with allocation
history and host execution.

## Summary fields

The comparison records include:

### `earliest_pcode_divergence`

The first stage occurrence whose deterministic `*.pcode.txt` differs. This is
the primary phase-localization field.

### `earliest_raw_graph_difference`

The first normalized structured snapshot difference. It may reveal opaque or
not-yet-decoded state even when semantic PCode is identical. It must not be
reported as an instruction difference when `semantic_pcode_text_equal` is
true.

### `final_object_equal`

Whether the variant's direct object SHA-256 equals the baseline's direct object
SHA-256. This answers reachability for the tested source variant, not retail
matching.

### `capture_count_differences` and `missing_stages`

A stage may execute a different number of times or not at all. Do not align
unrelated occurrences silently. A missing stage is explicit evidence about the
active pipeline, not an empty capture.

## PCode text notation

Example before allocation:

```text
block-0001:
  pcode-0001: .start
  pcode-0002: sll gpr:r34, gpr:r5, raw-scalar-or-pointer(0x00000002)
  pcode-0003: addu gpr:r35, gpr:r4, gpr:r34
  pcode-0004: lw gpr:r2, mem[gpr:r35+0x00000000]
  pcode-0005: .end gpr:r2
```

Important forms:

| Form | Meaning |
| --- | --- |
| `gpr:r34` | Register-class 0, register/virtual identifier 34. |
| `fpr:rN` | Floating-point register-class identifier. |
| `imm(0x...)` | Decoded inline immediate. |
| `raw-scalar-or-pointer(0x...)` | Tag-2 scalar/pointer category whose stronger semantic type is intentionally not claimed. |
| `mem[gpr:rX+offset]` | Decoded compound memory operand. |
| `block-000N` | Stable normalized basic-block identity replacing a runtime pointer. |

Virtual identifiers generally start at the class physical-slot count. For GPR
and FPR classes, identifiers 32 and above are normally virtual before
allocation.

## Phase-localization decision tree

### Difference at `codegen_entry`

Investigate:

- expression/statement shape;
- type and signedness;
- frontend optimization;
- instruction selection;
- address/immediate descriptor normalization;
- control-flow construction.

Do not start with scheduler or physical-register tricks: the operations already
differ before those passes.

### Same at entry, different after scheduling

Investigate:

- true/anti/output dependencies;
- memory alias dependencies;
- instruction latency;
- resource availability;
- critical deadlines and critical-path length;
- successor-unlock count;
- pressure-mode score;
- stable list-order ties.

Use the scheduler runner for candidate-level evidence.

### Same before allocation, different after allocation

Investigate:

- liveness and interference edges;
- move coalescing;
- register availability masks;
- simplify-stack order;
- spill score and retry behavior;
- fallback colors;
- virtual-role lifetime changes caused by source temporaries.

Use the post-color JSON and colorgraph replayer.

### Semantic PCode equal, object equal

The tested source change is not a useful object-code lever under that profile.
A raw graph difference alone does not make it useful.

### Semantic PCode equal, object different

The current capture has not localized the difference. Candidate causes include
later lowering, frame construction, relocation, encoding, delay-slot/NOP
passes, or unmodeled metadata. Report the boundary honestly and add a capture
only after locating evidence for the missing pass.

## Scheduler experiments

Scheduler experiments use the same manifest format but run through:

```powershell
python mwccps2_scheduler_experiment.py experiments/scheduler_ready_tie --output build/scheduler-run
```

Output adds:

```text
scheduler-experiment-summary-v1.json
scheduler-experiment-summary-v1.txt
variants/<name>/scheduler-captures/
```

Each ready-selection capture records:

- scheduler driver and selection ordinal;
- current cycle;
- normalized ready-list candidates;
- pending predecessors;
- earliest issue cycle;
- critical deadline and path length;
- immediately unlocked successor count;
- heuristic and resource/pressure fields where observed;
- predicted winner;
- observed winner.

`prediction_matches_observed: true` is meaningful only for a complete observed
selection. A cycle with no issued instruction is retained as `no_selection`,
not counted as a false selected winner.

## Register-allocation captures

At `after_colorgraph_assignment`, the compiler's transient interference graph
is still live. The capture includes:

- active register class;
- physical-slot count `P` and total-node count `N`;
- normalized nodes and edges;
- ordinary and fallback masks;
- coalescing parent map;
- work-list links and observed colors;
- spill/coalesce flags;
- PCode virtual-register correlations.

Human companion output is `*.regalloc.txt`.

Replay a capture:

```powershell
python decomp/register_allocation.py <after-colorgraph-assignment.json>
```

A successful proof contains:

```json
{
  "match_observed": true,
  "mismatches": []
}
```

The replayer models the recovered color-selection behavior. It does not recreate
a retail game's unavailable graph.

## Source-lever examples in the corpus

| Experiment | Question |
| --- | --- |
| `commutative_addu` | Do address/index spellings alter semantic PCode or object bytes? |
| `commutative_mul_s` | Does source operand order alter `mul.s` slots or virtual layout? |
| `u16_remask` | Does redundant masking survive frontend optimization? |
| `repeated_sign_extension` | Where are explicit and parameter-driven extensions emitted? |
| `compare_destination` | Does relation/source direction alter PCode or only later output? |
| `boolean_block_order` | How do equivalent boolean source forms change block layout? |
| `switch_case_order` | How does case/source order affect comparisons and blocks? |
| `invariant_mask` | Does mask placement inside/outside a loop alter lowering? |
| `p3_global_base_scaled_index` | How are global-base and scaled-index roles colored? |
| `scheduler_ready_tie` | Can opposite independent expression order produce divergent issue order? |

Use these as templates. Do not copy a conclusion to an unrelated function
without reproducing the relevant type, operation, and compiler flags.

## Promoting a result into project guidance

Before adding a behavior to `analysis/` or using it in a main decomp:

- preserve the experiment manifest and all source variants;
- record the exact compiler fingerprint and flags;
- verify every direct/instrumented object pair;
- name the first semantic divergence stage;
- state whether final object bytes changed;
- label retail applicability as inference;
- keep unknown fields and pass attribution explicitly bounded;
- verify the real game function with its authoritative verifier after applying
  the source change.
