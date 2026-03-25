# AI Workflow: Extend Trident Case Study to New Primitives

Status: Runnable

## Goal

Use AI to create a new Solana primitive and its Trident fuzz harness while preserving reproducibility and vulnerability-focused path exploration.

## Inputs Required

- Primitive name (example: `escrow_mini`)
- Trust boundaries (which accounts are attacker-controlled)
- Critical operations (fund movement, authority updates, CPI, sysvar reads)
- One expected exploit class to test first

## Output Contract

AI-generated contribution is acceptable only if it includes all of:

1. Primitive program logic scaffold.
2. Trident harness with `#[init]` and at least one `#[flow]`.
3. Finding predicate and clear finding message.
4. Path trace fields for the flow.
5. Reproducible command list.

## Implementation Steps

1. Copy scaffold from `primitives/escrow_mini/`.
2. Fill the program instruction(s) and account structs.
3. Implement fuzz `#[init]` account seeding.
4. Implement flow dimensions that map to vulnerability hypotheses.
5. Add `trace_path(...)` and `record_finding(...)` calls.
6. Run targeted checks and fill `EVALUATION.md`.

## Minimal Prompt Template (for AI)

```text
Create a Solana primitive named <PRIMITIVE_NAME> using Anchor-style Rust and a Trident fuzz harness.

Constraints:
- Keep logic small and demo-friendly.
- Include one intentionally vulnerable instruction tied to <VULN_CLASS>.
- In fuzz flow, mutate exactly these dimensions: <DIMENSIONS>.
- Emit path trace fields for each iteration.
- Emit a finding marker and JSON artifact on exploit predicate hit.
- Provide commands to run and verify.

Return:
1) changed files
2) run commands
3) expected finding marker
```

## Review Checklist

- Does flow mutation match the threat model?
- Is the finding predicate specific (not broad success-only)?
- Are trace fields enough to explain path evolution?
- Are artifacts written and replayable?
- Do baseline demos still pass?

## Anti-Patterns to Reject

- Adding many instructions before one path is stable.
- Predicates that trigger on generic transaction success only.
- Missing trace output for control dimensions.
- Unbounded scope changes unrelated to demonstration goals.
