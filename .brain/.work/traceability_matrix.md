# Requirement traceability matrix

| ID | Requirement | Owner | Acceptance / verification |
|---|---|---|---|
| R1 | Normalize URL and enforce safe target policy | W01 | URL/IP/redirect test cases; Tester 02 |
| R2 | Gather bounded technical observations with timestamp/source | W01 | Mocked and controlled checks; partial failures visible |
| R3 | Keep evidence, findings and provider assertions distinct | W02 | Contract/schema tests; source trace drill-down |
| R4 | Prevent duplicate community signals inflating corroboration | W02 | Duplicate/source-family tests; status transitions |
| R5 | Explainable conservative triage and abstention | W03 | Golden case set; decision rationale review |
| R6 | Preserve data/source/license/label metadata for ML experiments | W03 | Dataset manifest gate; no metrics absent gate |
| R7 | Show scan state, dimensions, evidence, limitations and next step | W04 | End-to-end UI acceptance |
| R8 | Rehearsed controlled demo and fallback | W04 | Timed rehearsal checklist |
| R9 | No real secrets/credentials and no unsafe browsing | All | Security gate; code review and test evidence |
| R10 | Claims match measured evidence | W03 + W04 | Pitch/report review against source/results |
