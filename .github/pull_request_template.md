## Problem and scope

<!-- What bounded compiler/tooling problem does this change address? -->

## Evidence

<!-- Separate direct observations from inference. Include exact compiler fingerprints, addresses, stages, hashes, and reducer paths when relevant. -->

**Observed:**

**Inferred:**

**Explicitly not established:**

## Verification

<!-- List exact commands and results. Live collector changes must include direct and instrumented object SHA-256 values. -->

```text
python -m compileall -q .
python -m unittest discover -s tests -p "test_*.py"
```

## Checklist

- [ ] The change is focused and follows the existing architecture/schema conventions.
- [ ] New behavior has deterministic regression coverage.
- [ ] Compiler-specific claims name the exact executable SHA-256 and evidence address/stage.
- [ ] Direct and GDB-instrumented object hashes match for every submitted live capture.
- [ ] Unknown fields remain opaque; observed facts and inference are separated.
- [ ] Generated output remains under ignored `build/` paths.
- [ ] No compiler/game binaries, extracted retail bytes, credentials, or private workstation paths are included.
- [ ] Documentation reflects any changed command, schema, support level, or limitation.
