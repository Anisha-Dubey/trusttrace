# Runbook: integration order

1. Pin schemas + fixture IDs first.
2. W02 exposes fixture report/evidence objects; W04 builds UI against fixtures.
3. W03 supplies policy outputs and rationale; add contract checks.
4. W01 plugs in safety validator with egress mocked; prove rejection paths.
5. Add actual passive metadata collectors only after Gate B; preserve partial errors.
6. Add community reports after duplicate/source-family semantics are tested.
7. Run both tester tracks, resolve P0/P1, demo freeze.

Keep a working vertical slice. Do not hold UI integration until all collectors or future research layers are complete.
