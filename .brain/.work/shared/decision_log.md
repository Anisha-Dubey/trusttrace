# Decision log

| ID | Decision | Reason / revisit trigger |
|---|---|---|
| D-01 | Preserve TRUSTTRACE as the chosen umbrella project. | Team direction. Research audit’s PhishShift alternative remains documented, not substituted. |
| D-02 | Hackathon MVP is explainable URL triage, not the complete long-term system. | Full blueprint includes identity delegation, runtime data flow, adaptive collection and graph research; too broad for short event. |
| D-03 | TLS/certificate state is separate from identity trust. | Valid TLS does not establish brand authorization. |
| D-04 | Unknown/missing is a first-class state. | Absence of evidence is not evidence of benignness. |
| D-05 | No arbitrary-site browser execution without isolated environment + tested egress boundary. | Prevent scanner SSRF and hostile-page compromise. |
| D-06 | Start with transparent deterministic rules; ML optional. | Avoid unsupported claims and invalid labels. |
| D-07 | Community signals remain attributed and unverified until independent review/corroboration. | Avoid poisoning, duplicates and false certainty. |
| D-08 | Do not claim generic CT/DNS/ML fusion is novel. | Archive audit identifies close prior art and data-access risks. |
| D-09 | Reports in this workspace are planning templates, not execution results. | No implementation or tests performed in this task. |

| D-10 | Use versioned JSON Schema contracts plus representative fixtures before parallel implementation. | Reduces integration drift; see `.work/contracts/v1/`. |
| D-11 | Use fixture-only mode until privacy/retention and live-scan security gates are approved. | Avoids premature collection and unsafe egress. |
| D-12 | Keep the original audit source content unchanged, restore its UTF-8 filename, and document dead machine-local references in a separate map. | Preserve provenance while making the archive internally consistent. |
