# Claims register — pitch and UI control

| ID | Claim | Status | Evidence required / permitted wording |
|---|---|---|---|
| CL-01 | HTTPS/TLS validity alone does not prove organizational authorization. | APPROVED general product principle | Show certificate result separately from identity support. |
| CL-02 | TRUSTTRACE detects phishing more accurately than existing systems. | PROHIBITED until measured | Requires frozen dataset, valid labels, strong baseline, domain/source split and reproducible metrics. |
| CL-03 | TRUSTTRACE combines observations into evidence-linked triage. | CONDITIONAL on implementation | Demonstrate finding-to-evidence references and source/time in actual build. |
| CL-04 | Community reports corroborate threats. | CONDITIONAL and narrow | Only independent, reviewed sources can increase corroboration; show status and source lineage. |
| CL-05 | We use AI. | Only if actually implemented | Identify exact model/task and whether output is advisory; do not imply model validates certificates. |
| CL-06 | We are first/novel in CT + DNS + ML phishing detection. | PROHIBITED | Archive audit flags substantial prior art and close overlap. |
| CL-07 | A site is safe because no feed match was found. | PROHIBITED | Feed absence is not a benign label. |
| CL-08 | Scan results reflect all user-visible behavior. | PROHIBITED | State observation scope, context and collection limitations. |
| CL-09 | Prototype scored X on evaluation. | CONDITIONAL | Name dataset version/hash, labels, sample count/prevalence, split, metrics and limitations; no synthetic/live mixing. |

Before demo freeze, review each slide/screen/pitch sentence against this table. Keep a copy of the final wording in the release report.
