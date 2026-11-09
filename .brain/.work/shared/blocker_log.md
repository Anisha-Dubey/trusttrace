# Blocker and risk log

| ID | Blocker/risk | Severity | Owner | Exit condition |
|---|---|---|---|---|
| B1 | Exact event duration, rules, judging rubric and deployment requirements unknown. | High | W04/team lead | Confirm from organizer; revise phases/pitch. |
| B2 | Current repository, stack and existing code not supplied. | High | W04 | Inspect project repo before implementation. |
| B3 | Live scanning safety depends on egress/IP/redirect controls. | Critical | W01 + Tester 02 | Tests and isolation proof; else fixture-only. |
| B4 | Threat feed/API access and license unknown. | Medium | W03 | Verify access/terms before integration; otherwise exclude. |
| B5 | Dataset version, terms, timestamps and label semantics unverified. | High | W03 | Record data card/manifests; otherwise no ML claims. |
| B6 | Broad novelty claim contradicted by prior work. | High | W03 | Pitch narrowed to integration/evidence-quality hypothesis. |
| B7 | Community intelligence can be poisoned or double-counted. | RESOLVED | W02 | Dedup, source-family lineage, moderation state machine & audit log implemented and verified (tests/test_community_intelligence.py). |
