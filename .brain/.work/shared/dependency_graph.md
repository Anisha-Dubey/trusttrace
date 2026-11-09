# Dependency graph

```text
Decision vocabulary + safety policy
             ↓
W02 observation/finding/report contracts ───────────────┐
        ↓                         ↓                     ↓
W01 URL/collector safety     W03 decision rules      W04 UI contract
        └──────────── observations/findings ────────────┘
                                ↓
                    Integrated fixture vertical slice
                                ↓
           live bounded checks (only after security gate)
                                ↓
             W02 community intelligence integration
                                ↓
       Tester 01 functional + Tester 02 security/release
                                ↓
                   demo freeze / handoff
```

Hard dependency: W04 must use fixture data until safe API/collector path is ready. Live scanning depends on W01 safety controls plus Tester 02 sign-off. Community report states depend on W02 provenance/dedup. Final demo depends on all MVP gates and a fallback.
