# TRUSTTRACE

## Four-Person Research Engineering Workflow

### A research-lab operating model for building an AI-powered web threat detection and digital trust platform

**Document type:** Team execution plan, workstream charter, engineering
workflow and research operating protocol\
**Version:** 1.0\
**Prepared:** 9 November 2026\
**Team size:** Four contributors\
**Planning horizon:** 24 weeks (adjustable)\
**Project basis:** TRUSTTRACE Research Master Document and Complete
Technical Build Specification

------------------------------------------------------------------------

# 1. Executive plan

TRUSTTRACE should be run as a small research engineering lab, not as
four people independently building four disconnected features. The team
has two simultaneous responsibilities:

1.  **Build a reliable system:** an authenticated application that can
    safely investigate a submitted website, collect evidence, analyse
    it, and produce an explainable report.
2.  **Test a research thesis:** whether organisational
    identity/delegation evidence, runtime data-flow observations, and
    adaptive evidence acquisition improve web-trust assessment beyond
    conventional URL, reputation, and visual phishing detection.

The four-person structure is deliberately asymmetric. Each person owns a
coherent subsystem, but every subsystem must expose documented contracts
so that the other three can integrate with it. One person is not "the
frontend person" and another "the AI person"; each is an accountable
technical owner and research contributor.

**Recommended execution model:** a modular monolith for the application,
independently isolated browser workers, a shared PostgreSQL evidence
store, asynchronous job orchestration, and a versioned ML research
pipeline. Avoid premature microservices and Kubernetes.

## 1.1 The four workstreams

  -----------------------------------------------------------------------------
  Person            Role              Primary ownership   Research
                                                          responsibility
  ----------------- ----------------- ------------------- ---------------------
  Person 1          Systems Architect API, auth,          End-to-end system
                    & Backend Lead    database,           design,
                                      orchestration,      reproducibility and
                                      integration,        systems evaluation
                                      deployment          

  Person 2          Data & Machine    Data acquisition,   Dataset validity,
                    Learning Lead     cleaning, labels,   generalisation,
                                      features,           ablations and model
                                      baselines,          evaluation
                                      multimodal ML,      
                                      calibration         

  Person 3          Browser Security  Safe fetch          Runtime data-flow
                    & Runtime         boundary,           contribution and
                    Analysis Lead     Playwright worker,  scanner threat model
                                      SSRF controls,      
                                      DOM/network/flow    
                                      observation         

  Person 4          Digital Identity, Organisation        Identity/delegation
                    Graph & Research  claims, signed      contribution, graph
                    Lead              manifest,           reasoning, literature
                                      delegation,         and paper
                                      evidence graph,     
                                      policy/reasoning,   
                                      research protocol   
  -----------------------------------------------------------------------------

These are ownership boundaries, not silos. Person 1 owns the system
contract; Person 2 owns the model contract; Person 3 owns browser
observation safety and correctness; Person 4 owns identity semantics,
evidence semantics and research claims. All four review
security-critical changes.

## 1.2 What success looks like at week 24

A successful project is not defined by a flashy dashboard or a claimed
"99% accuracy". It is defined by a reproducible end-to-end system and
defensible experimental evidence:

-   A user can submit a URL through an authenticated API.
-   The system creates a scan job and returns a scan ID without holding
    the HTTP request open.
-   The target is validated against a strict safety policy.
-   Passive collectors obtain timestamped DNS, RDAP, TLS and other
    permitted observations.
-   An isolated browser worker can render controlled targets and capture
    bounded evidence.
-   Data processing creates versioned, leakage-audited datasets.
-   Classical baselines are measured before deep learning is introduced.
-   Identity claims, delegation and runtime observations are represented
    with provenance.
-   A decision layer distinguishes identity assurance, behavioural
    security and evidence quality.
-   The report cites concrete evidence IDs, records uncertainty and can
    abstain.
-   A controlled evaluation compares baselines, ablations, resource cost
    and failure cases.
-   The paper/demo makes no claim unsupported by the results.

------------------------------------------------------------------------

# 2. Design principles: how a strong research engineering team operates

1.  **One accountable owner per subsystem.** A task can have
    collaborators, but one person is responsible for its interface,
    tests and completion.
2.  **Contracts before parallel implementation.** Agree request/response
    schemas, database entities, event names and error semantics before
    building modules in parallel.
3.  **Build a vertical slice early.** A tiny end-to-end scan is more
    valuable than four large unintegrated subsystems.
4.  **Baseline before sophistication.** Start with deterministic rules,
    Logistic Regression, TF-IDF and LightGBM before ANN, Transformers or
    GNNs.
5.  **Security is an architectural property.** The browser worker must
    be isolated before arbitrary untrusted pages are rendered.
6.  **Evidence is immutable; interpretations are versioned.** Store what
    was observed separately from what a model inferred.
7.  **Unknown is not benign.** Missing data, failed collectors and
    absent identity declarations must not silently become "safe".
8.  **Research hypotheses can fail.** A negative result is a valid
    result; do not tune until the desired story appears.
9.  **Reproducibility is part of implementation.** Every dataset, model,
    configuration and experiment has a version or hash.
10. **No invisible integration.** All changes enter through reviewed
    pull requests and pass automated tests.
11. **No one-person critical knowledge.** Each owner has a named backup
    reviewer and documents how to run their subsystem.
12. **Use the simplest technology that proves the claim.** Add
    infrastructure only when a measured bottleneck or research need
    justifies it.

------------------------------------------------------------------------

# 3. Person-by-person role charters

## Person 1 --- Systems Architect & Backend Lead

**Mission:** Make TRUSTTRACE a coherent, secure, testable application
rather than a set of scripts.

### Owns

-   FastAPI application and public REST API.
-   Pydantic request/response schemas and OpenAPI contract.
-   Authentication integration (OIDC/OAuth 2.0), JWT validation and
    tenant context.
-   Authorisation checks: RBAC plus object/tenant-level checks.
-   PostgreSQL schema, SQLAlchemy models, Alembic migrations and
    transaction boundaries.
-   Scan lifecycle state machine.
-   Redis/Celery job orchestration, retries, idempotency, cancellation
    and timeouts.
-   Evidence persistence interfaces and report assembly integration.
-   Docker Compose development environment, CI pipeline and deployment
    packaging.
-   System-level logs, metrics, traces and integration tests.

### Primary technologies

Python 3.x, FastAPI, Pydantic, SQLAlchemy 2.x, Alembic, PostgreSQL,
Redis, Celery, pytest, Docker, GitHub Actions, OpenAPI, OpenTelemetry.

### Concrete deliverables

1.  `POST /api/v1/scans` creates a scan and returns `202 Accepted`.
2.  `GET /api/v1/scans/{scan_id}` returns state and progress.
3.  `GET /api/v1/scans/{scan_id}/report` returns a report with evidence
    references.
4.  Authenticated tenant isolation and object-level access tests.
5.  Durable scan state and worker task records.
6.  Shared observation/evidence persistence API.
7.  Docker Compose stack that a new contributor can start with one
    documented command.
8.  CI checks for lint, type checks, unit tests, migrations and API
    contract tests.

### Person 1 should become deeply competent in

HTTP semantics, REST resource design, CRUD, status codes, OAuth/OIDC,
JWT validation, PKCE, RBAC/ABAC, BOLA, CSRF, SQL transactions, indexes,
migrations, async task queues, idempotency, caching, retries, circuit
breakers, structured logging and distributed tracing.

### Not this person's job

-   Do not own every data collector implementation.
-   Do not write the research model just because the model needs an API.
-   Do not make the API directly run long browser scans.
-   Do not bypass the agreed evidence schema to "make the demo work".

------------------------------------------------------------------------

## Person 2 --- Data Engineering & Machine Learning Lead

**Mission:** Establish whether the system's predictions are valid,
generalise beyond memorised domains and remain calibrated under
realistic class imbalance.

### Owns

-   Data-source inventory, collection manifests and licence/terms
    review.
-   Dataset ingestion, raw/normalised/curated layers.
-   URL/domain normalisation, HTML/text feature extraction interfaces.
-   Deduplication, near-duplicate detection and domain/campaign
    grouping.
-   Label ontology, label provenance, adjudication workflow and data
    cards.
-   Train/validation/test split manifests and leakage audits.
-   Classical ML baselines and model selection.
-   Deep-learning experiments only when justified by data and baselines.
-   Multimodal fusion and missing-modality robustness.
-   Calibration, threshold selection, error analysis and model cards.
-   MLflow experiment tracking and DVC/data versioning.

### Primary technologies

Python, Pandas or Polars, PyArrow, Parquet, scikit-learn, LightGBM,
XGBoost, PyTorch, Hugging Face Transformers, OpenCV/OCR where needed,
MLflow, DVC, Jupyter for exploration, pytest for production feature
code.

### Concrete deliverables

1.  Dataset source register with licence, collection date, terms,
    provenance and limitations.
2.  Reproducible ingestion and cleaning pipeline.
3.  Label ontology: phishing, legitimate, compromised, impersonation,
    suspicious and unknown/uncertain as applicable.
4.  Strong baseline suite: majority/rule baseline, Logistic Regression,
    TF-IDF character n-grams + linear model, Random Forest,
    LightGBM/XGBoost.
5.  Feature schema with version.
6.  Domain-disjoint and chronological evaluation splits.
7.  Evaluation report with PR-AUC, recall at fixed FPR, precision,
    calibration and confidence intervals.
8.  Error analysis with false positives and false negatives.
9.  Model registry entry and model card for every candidate release.

### Model sequence

**Do not start with a giant neural network.**

1.  Rules/majority baseline.
2.  Logistic Regression on engineered URL features.
3.  Character TF-IDF + Linear SVM/Logistic Regression.
4.  Random Forest and LightGBM/XGBoost on tabular URL/DNS/TLS/HTML
    features.
5.  Separate text and visual encoders if there is sufficient labelled
    data.
6.  Late fusion of modality outputs.
7.  ANN/MLP as a neural tabular baseline where justified.
8.  GNN only after the graph schema and graph baselines are stable.
9.  Semi-supervised, positive-unlabelled and self-supervised approaches
    as research experiments, not assumptions.

### Not this person's job

-   Do not label every unlisted URL as benign.
-   Do not use random row split as the only headline result.
-   Do not treat an anomaly score as a maliciousness probability.
-   Do not deploy a model without a model version, feature schema and
    calibration record.
-   Do not train on test data or analyst feedback without review and
    provenance.

------------------------------------------------------------------------

## Person 3 --- Browser Security & Runtime Analysis Lead

**Mission:** Safely observe what a website presents and where browser
requests go, while preventing the scanner from becoming an SSRF or
browser-exploitation service.

### Owns

-   Safe URL parsing/validation boundary in collaboration with Person 1.
-   Network egress policy and isolated browser-worker design.
-   Playwright + Chromium lifecycle.
-   Browser profiles, timeouts, resource limits and cleanup.
-   Redirect chain and response metadata capture.
-   DOM, form, iframe, script and resource-origin inventory.
-   Fetch/XHR/WebSocket destination observation.
-   Screenshot and bounded HTML capture.
-   Synthetic canary experiments in an authorised lab only.
-   Secret redaction and evidence minimisation.
-   Scanner security test suite and red-team scenarios.

### Primary technologies

Playwright, Chromium, Python, Docker, Linux namespaces/container
security, egress proxy/firewall, mitmproxy only where legally and
technically appropriate, BeautifulSoup/lxml/Selectolax, OpenCV/OCR,
pytest, Hypothesis, network policy tooling.

### Concrete deliverables

1.  A dedicated browser worker that is not running inside the public API
    process.
2.  A safe target policy that rejects unsupported schemes and prohibited
    address ranges.
3.  Redirect-by-redirect revalidation and DNS-rebinding mitigations.
4.  Egress restrictions enforced outside application code.
5.  Browser resource/time/download limits and disposable profiles.
6.  Structured observations for form actions, request destinations,
    redirects and resource origins.
7.  Controlled test pages that exercise form, fetch/XHR and WebSocket
    cases.
8.  Synthetic canary flow tests with immediate redaction.
9.  Security test report proving that browser jobs cannot reach
    loopback, private networks, cloud metadata or internal application
    services.

### Critical research wording

The initial system may claim: - observed destination; - observed form
action; - observed network request; - synthetic canary observed in a
controlled outgoing request; - inferred source-to-sink relationship with
explicit limitations.

It must **not** claim complete browser-wide taint tracking unless the
implementation genuinely tracks propagation across the relevant
JavaScript execution model, service workers, WebSockets and
transformations.

### Not this person's job

-   Do not submit real credentials to public websites.
-   Do not click destructive actions or complete transactions on
    arbitrary targets.
-   Do not rely only on Python URL validation for SSRF defence.
-   Do not store browser cookies, passwords, OTPs or session tokens.
-   Do not let the LLM or page content control browser actions.

------------------------------------------------------------------------

## Person 4 --- Digital Identity, Graph Intelligence & Research Lead

**Mission:** Define what "legitimate representation" means, encode the
evidence and delegation semantics, and make the research claims
defensible.

### Owns

-   Literature review, prior-art and novelty matrix.
-   Threat taxonomy, hypotheses and experimental protocol.
-   Organisation identity claims and verified anchor-set methodology.
-   Web Identity Manifest (WIM) schema.
-   Signature verification, key binding, delegation scope, expiry,
    rotation and revocation semantics.
-   Claim--Evidence graph ontology and temporal edge model.
-   Provenance, evidence dependencies and freshness representation.
-   Deterministic identity/delegation policy rules.
-   Graph feature extraction and graph-learning experiments with Person
    2.
-   Decision-engine specification and evidence-linked explanations.
-   Research paper structure, limitations and responsible-use statement.

### Primary technologies

Python, `cryptography`, JOSE/COSE libraries selected after review, JSON
Schema, PostgreSQL graph tables, NetworkX, PyTorch Geometric for later
experiments, SHAP/evidence-linked explanations, Mermaid, Zotero or a
reference manager, Markdown/LaTeX.

### Concrete deliverables

1.  Research question and hypothesis register.
2.  Related-work and novelty matrix.
3.  Threat model and terminology/label ontology.
4.  WIM schema and signed example manifests.
5.  Valid, invalid, expired, revoked and wrong-scope manifest test
    cases.
6.  Verified test-organisation anchor set with documented verification
    procedure.
7.  Claim--Evidence graph schema with typed, timestamped and
    provenance-linked edges.
8.  Identity/behaviour/evidence-quality decision axes.
9.  Rule-based graph and policy baseline.
10. Graph ablation and graph-vs-tabular experiment plan.
11. Research paper draft with claims linked to actual experiment
    outputs.

### Not this person's job

-   Do not invent a new cryptographic algorithm.
-   Do not claim a signature proves legal identity without a trust
    bootstrap.
-   Do not infer maliciousness from shared CDN, IP, ASN or certificate
    issuer.
-   Do not let graph visualisation substitute for graph precision
    evaluation.
-   Do not make novelty claims before comparing the closest prior work.

------------------------------------------------------------------------

# 4. Shared architecture and ownership map

``` mermaid
flowchart TD
    U[User / Analyst] --> WEB[Web UI]
    WEB --> API[FastAPI API]
    API --> AUTH[AuthN / AuthZ / Tenant Policy]
    API --> ORCH[Scan Orchestrator]
    ORCH --> Q[Redis + Celery Queue]

    Q --> PASS[Passive Collectors]
    Q --> BROWSER[Isolated Browser Worker]

    PASS --> OBS[Observation Contracts]
    BROWSER --> OBS
    OBS --> DB[(PostgreSQL Evidence Store)]

    DB --> FE[Feature Pipeline]
    FE --> ML[ML Models + Calibration]
    DB --> ID[Identity Manifest Verifier]
    DB --> GRAPH[Claim-Evidence Graph]
    ML --> DEC[Decision / Abstention]
    ID --> DEC
    GRAPH --> DEC
    DEC --> REPORT[Evidence-backed Trust Report]
    REPORT --> WEB
```

**Ownership overlay:**

-   Person 1: UI/API integration, Auth, Orchestrator, Queue, DB
    contracts, report API, CI/CD.
-   Person 2: Feature pipeline, dataset, ML models, calibration and
    model registry.
-   Person 3: Passive/browser collection safety, browser worker, runtime
    observation.
-   Person 4: Identity verifier, graph ontology, evidence semantics,
    policy rules and research protocol.

## 4.1 Integration contracts: the most important shared agreement

Every module must communicate through versioned schemas, not private
assumptions.

### A. Scan request contract

``` json
{
  "url": "https://example.org/login",
  "analysis_profile": "standard",
  "requested_modules": ["url", "dns", "rdap", "tls", "html", "browser"],
  "purpose": "user_submitted_url_check",
  "consent": {
    "allow_third_party_reputation_lookup": false,
    "allow_browser_rendering": true
  }
}
```

Owner: Person 1. Person 3 reviews safety fields. Person 4 reviews
purpose/identity semantics.

### B. Observation contract

Every collector returns a common envelope:

``` json
{
  "observation_id": "obs_...",
  "scan_id": "scn_...",
  "kind": "dns_a_record",
  "subject": "example.org",
  "value": ["203.0.113.10"],
  "source": {
    "name": "dns_collector",
    "version": "0.1.0"
  },
  "observed_at": "2026-11-09T10:00:00Z",
  "collected_at": "2026-11-09T10:00:01Z",
  "status": "success",
  "limitations": ["single_resolver"],
  "content_hash": "sha256:..."
}
```

Owner: Person 1 defines schema and persistence. Person 3, Person 4 and
Person 2 implement adapters/producers for their respective data.

### C. Feature vector contract

``` json
{
  "scan_id": "scn_...",
  "feature_schema_version": "url-page-v1",
  "features": {
    "url_length": 47,
    "subdomain_depth": 2,
    "has_ip_literal": false,
    "password_field_count": 1
  },
  "missing_features": ["rdap_domain_age"],
  "source_observation_ids": ["obs_1", "obs_2"]
}
```

Owner: Person 2. Other owners must not silently change feature names or
types.

### D. Prediction contract

``` json
{
  "scan_id": "scn_...",
  "task": "phishing_likelihood",
  "model_name": "lightgbm_url_page",
  "model_version": "0.1.0",
  "raw_score": 0.83,
  "calibrated_probability": null,
  "predicted_class": "review",
  "feature_schema_version": "url-page-v1",
  "evidence_observation_ids": ["obs_1", "obs_2"],
  "limitations": ["calibration_not_released"]
}
```

Owner: Person 2. Person 1 persists and exposes it; Person 4 defines how
it is consumed by the policy layer.

### E. Identity/delegation result contract

``` json
{
  "claim_id": "claim_...",
  "organisation_id": "org_...",
  "claimed_service": "login",
  "candidate_domain": "login.example.org",
  "identity_status": "unverified",
  "delegation_status": "not_found",
  "manifest_version": null,
  "evidence_ids": ["ev_..."],
  "limitations": ["no_verified_manifest_available"]
}
```

Owner: Person 4. Person 1 defines persistence/API compatibility.

### F. Browser flow observation contract

``` json
{
  "flow_id": "flow_...",
  "scan_id": "scn_...",
  "source_type": "form",
  "source_element": "form#login",
  "destination_origin": "https://auth.example.net",
  "method": "POST",
  "canary_observed": false,
  "interaction_mode": "passive",
  "observed_at": "2026-11-09T10:00:00Z",
  "limitations": ["no_form_submission_performed"]
}
```

Owner: Person 3. Person 4 defines delegation comparison; Person 1 stores
the observation.

### G. Final decision contract

``` json
{
  "scan_id": "scn_...",
  "identity_assurance": "unverified",
  "behavioural_security": "suspicious",
  "evidence_quality": "partial",
  "decision": "inconclusive_review",
  "reason_codes": [
    "IDENTITY_CLAIM_UNVERIFIED",
    "FORM_DESTINATION_NOT_IN_DELEGATION"
  ],
  "supporting_evidence_ids": ["ev_1", "ev_2"],
  "contradicting_evidence_ids": ["ev_3"],
  "model_versions": ["lightgbm_url_page:0.1.0"],
  "policy_version": "decision-policy-v1"
}
```

Owner: Person 4 defines semantics; Person 1 implements API/report
integration; Person 2 and Person 3 validate whether evidence references
are accurate.

**Contract rule:** a schema change requires a pull request, a
version/change note, updated fixtures and approval from the consuming
owner.

------------------------------------------------------------------------

# 5. The actual 24-week execution workflow

The schedule is designed so the four people can work in parallel without
building incompatible components. Each phase ends with an integration
gate.

## Phase 0 --- Research freeze and team setup (Weeks 1--2)

### Person 1

-   Create GitHub repository, branch protection, issue templates and
    pull-request template.
-   Create Python package skeleton, FastAPI health endpoint and Docker
    Compose.
-   Draft API resource list and scan state machine.
-   Define coding standards, formatting, lint and test commands.

### Person 2

-   Build dataset source inventory.
-   Inspect dataset cards, papers, licences and terms.
-   Define label ontology and data provenance fields.
-   Draft data split strategy before model training.

### Person 3

-   Write scanner threat model.
-   Build a local authorised test lab with benign pages and controlled
    test endpoints.
-   Draft target-validation and egress policy.
-   List browser events that can be observed reliably.

### Person 4

-   Create literature review matrix and closest-prior-work table.
-   Freeze research questions and candidate hypotheses.
-   Draft WIM semantics and graph ontology.
-   Define what counts as verified organisation identity and delegated
    service.

### Joint gate at end of Week 2

-   One approved system architecture.
-   One shared glossary.
-   API and observation schema v0.1.
-   Threat model and data governance plan.
-   Research protocol draft.
-   No person begins an incompatible implementation based on
    undocumented assumptions.

------------------------------------------------------------------------

## Phase 1 --- Vertical slice and backend foundation (Weeks 3--4)

**Goal:** one authenticated user submits a URL, a scan is queued, a
worker completes a dummy task, and the user retrieves a report.

### Person 1

-   Implement OIDC integration or development auth stub with explicit
    production replacement plan.
-   Implement `POST /scans`, `GET /scans/{id}`,
    `GET /scans/{id}/report`.
-   Create PostgreSQL tables and Alembic migrations.
-   Implement Redis/Celery worker lifecycle.
-   Add tenant and object-level access checks.
-   Add idempotency key and scan state machine.

### Person 2

-   Build a reproducible data ingestion skeleton.
-   Create raw/normalised/curated dataset directory convention.
-   Write data validation and dataset manifest scripts.
-   Create first simple URL feature extractor.

### Person 3

-   Implement URL validation library and negative test cases.
-   Build browser worker interface, initially against local controlled
    pages only.
-   Define worker resource limits and structured output.
-   Test blocked schemes and forbidden address classes.

### Person 4

-   Implement organisation, claim and evidence domain models.
-   Define JSON schema for WIM prototype.
-   Write signature verification test vectors using test keys.
-   Draft identity and evidence status vocabulary.

### Integration gate

A URL scan moves through
`queued → validating → collecting → analysing → completed` using a dummy
collector. The API returns a report object, and cross-tenant access
tests pass.

------------------------------------------------------------------------

## Phase 2 --- Passive evidence collection (Weeks 5--6)

**Goal:** create a safe, reproducible observation package before
advanced browser analysis.

### Person 1

-   Add collector job types, retry policy, timeouts and circuit
    breakers.
-   Add observation persistence and source metadata.
-   Implement scan progress events and partial status.
-   Add cache TTL and provider quota controls.

### Person 2

-   Ingest approved public/research datasets.
-   Deduplicate exact URLs and canonicalised URLs.
-   Group by registrable domain and, where possible, campaign/time.
-   Build initial URL lexical feature table and baseline splits.

### Person 3

-   Implement safe DNS resolution and target validation interface with
    Person 1.
-   Capture HTTP status, redirect chain and response metadata through
    the controlled fetch boundary.
-   Add negative tests for redirect-to-private and DNS-rebinding
    scenarios.
-   Keep browser rendering disabled for arbitrary targets until egress
    controls pass.

### Person 4

-   Build temporal evidence objects and graph edge schema.
-   Implement domain/organisation claim representation.
-   Create a small manually verified organisation anchor set.
-   Define evidence provenance and dependency groups.

### Integration gate

A scan produces timestamped URL, DNS, RDAP/TLS (where available) and
fetch observations. Each observation has source, method, status and
limitation metadata. Failure of one provider produces a partial result,
not a total scan crash.

------------------------------------------------------------------------

## Phase 3 --- Browser and page analysis (Weeks 7--9)

**Goal:** safely inspect a controlled page and return structured
content/behaviour evidence.

### Person 1

-   Integrate browser job scheduling, job state and result persistence.
-   Enforce per-tenant quotas and per-scan budgets.
-   Add object storage interface for screenshots and bounded artefacts.
-   Ensure browser worker has no access to database credentials or
    internal service network.

### Person 2

-   Build HTML/text feature extraction.
-   Add language detection and text normalisation.
-   Create page-level dataset records linked to source observations.
-   Establish modality availability and missingness flags.

### Person 3

-   Complete disposable Playwright/Chromium worker.
-   Add form, iframe, script-origin, redirect, fetch/XHR and WebSocket
    metadata capture.
-   Capture screenshot and bounded DOM snapshot.
-   Add synthetic canary flow tests only on authorised lab sites.
-   Redact canary and secret-like values before persistence.
-   Perform SSRF and worker-isolation test suite.

### Person 4

-   Map browser observations into typed graph edges such as
    `LOADS_RESOURCE`, `REDIRECTS_TO` and `SUBMITS_TO`.
-   Define how endpoint origin is compared with a delegation claim.
-   Create legitimate third-party SSO/payment examples to prevent
    simplistic false positives.
-   Review evidence wording and uncertainty.

### Integration gate

The system renders a controlled test site in an isolated worker,
captures a screenshot and structured network/form observations, persists
them, and produces an evidence-linked report. The worker passes negative
network-access tests.

------------------------------------------------------------------------

## Phase 4 --- Classical ML and dataset validity (Weeks 10--12)

**Goal:** establish credible baselines and prove that the data split is
not leaking domain/campaign identity.

### Person 1

-   Add versioned model inference adapter.
-   Persist model name/version, feature schema and raw prediction.
-   Add API/report display for score plus limitations.
-   Add reproducible worker invocation for offline evaluation.

### Person 2

-   Finalise baseline dataset version.
-   Train majority/rule, Logistic Regression, character TF-IDF + linear
    model, Random Forest and LightGBM/XGBoost.
-   Compare URL-only, URL+DNS/TLS and URL+HTML features.
-   Use domain-disjoint and chronological test splits.
-   Evaluate PR-AUC, precision/recall, FPR, calibration and confidence
    intervals.
-   Perform error analysis and document dataset bias.

### Person 3

-   Audit whether browser-derived features are reproducible across runs.
-   Measure browser overhead, timeout and failure rates.
-   Generate controlled benign and malicious-like lab scenarios with
    known expected observations.
-   Review feature extraction for sensitive-data leakage.

### Person 4

-   Create graph/rule-based identity and delegation baseline.
-   Review whether the label ontology separates phishing, impersonation,
    compromised legitimate site and unknown.
-   Build the evidence-linked reason-code catalogue.
-   Co-author evaluation protocol and baseline interpretation.

### Integration gate

A versioned model can be called through the application. The team has a
reproducible baseline report and a leakage audit. No deep model is
accepted unless it beats an appropriate baseline on the intended test
split or provides another clearly measured capability.

------------------------------------------------------------------------

## Phase 5 --- Identity delegation and evidence graph (Weeks 13--16)

**Goal:** implement the project's first distinctive research pillar and
connect it to actual evidence.

### Person 1

-   Add organisation/manifest APIs and persistence.
-   Add audit events for manifest changes and verification.
-   Implement transactional publication/revision semantics.
-   Integrate graph/evidence query endpoints.

### Person 2

-   Build graph-derived tabular features for comparison with non-graph
    models.
-   Establish graph train/test partition rules that prevent entity
    leakage.
-   Prepare graph baseline evaluation and ablation scripts.
-   Do not jump to GNN before the graph baseline works.

### Person 3

-   Supply realistic browser endpoint and redirect evidence.
-   Add tests for multi-origin login, payment and embedded services.
-   Validate that the browser's observed destination is not mislabelled
    as proven data exfiltration.
-   Add controlled cases where a canary appears in a request.

### Person 4

-   Implement manifest signature verification, key discovery prototype,
    expiry, revocation and purpose-scoped delegation.
-   Implement graph construction and temporal edges.
-   Build rule-based support/contradiction reasoning.
-   Evaluate valid, expired, revoked, wrong-scope, missing and
    invalid-signature manifests.
-   Compare identity-aware results against a baseline without identity
    evidence.

### Integration gate

A controlled organisation can publish a signed manifest; a test service
can be validly delegated; an expired/revoked/wrong-scope service is
rejected or marked invalid; a report explains the exact evidence
supporting the result.

------------------------------------------------------------------------

## Phase 6 --- Runtime data-flow assurance and adaptive investigation (Weeks 17--20)

**Goal:** test whether deeper observation and adaptive action selection
add measurable value.

### Person 1

-   Add investigation action registry and per-scan action budget.
-   Persist action decision, cost, result and stop reason.
-   Add cancellation and timeout propagation.
-   Expose progress and action history in report API.

### Person 2

-   Train/compare models with and without runtime features.
-   Evaluate missing-modality behaviour.
-   Calibrate scores and set review/abstention thresholds on validation
    data.
-   Measure false positives at realistic low prevalence.
-   Compare fixed and adaptive evidence policies using logged controlled
    outcomes.

### Person 3

-   Complete controlled canary-flow suite.
-   Test form, fetch/XHR and WebSocket cases in the lab.
-   Measure flow detection precision/recall against known ground truth.
-   Test browser context divergence, timeouts, resource use and safe
    stopping.
-   Conduct scanner red-team review.

### Person 4

-   Define action catalogue, expected information gain and decision-loss
    model.
-   Implement greedy value-of-information baseline with cost, privacy
    and risk constraints.
-   Define stop/abstain criteria.
-   Integrate graph and identity evidence into the decision policy.
-   Draft primary contribution evaluation.

### Integration gate

The team can compare fixed-lightweight, fixed-exhaustive and adaptive
investigation under the same safety and resource budget. Runtime flow
claims are bounded to what the instrumentation actually observes.

------------------------------------------------------------------------

## Phase 7 --- Robustness, release and research communication (Weeks 21--24)

**Goal:** produce a stable research release and honest account of what
worked.

### Person 1

-   Stabilise API and deployment.
-   Run load, failure-recovery and tenant-isolation tests.
-   Finalise CI/CD, backups, environment configuration and
    observability.
-   Prepare demo deployment and operational runbook.

### Person 2

-   Run final benchmark, ablations and confidence intervals.
-   Freeze final model/data versions.
-   Produce model cards, dataset cards and reproducibility scripts.
-   Document negative results and known generalisation limits.

### Person 3

-   Run scanner security assessment.
-   Test SSRF, DNS rebinding, redirects, resource exhaustion, downloads
    and browser isolation.
-   Finalise runtime-flow limitations and overhead measurements.
-   Produce a security test report.

### Person 4

-   Finalise related work and novelty matrix.
-   Analyse identity/delegation and graph results.
-   Lead paper drafting and evidence-to-claim audit.
-   Prepare limitations, ethics, responsible-use and future-work
    sections.

### Final gate

No headline claim enters the abstract or presentation unless there is a
reproducible experiment, a baseline, an appropriate split, a metric and
an error analysis supporting it.

------------------------------------------------------------------------

# 6. Parallel work: what people can build at the same time

Parallelism should be based on stable contracts, not on arbitrary task
splitting.

  ------------------------------------------------------------------------------------------------
  Period         Person 1             Person 2             Person 3          Person 4
  -------------- -------------------- -------------------- ----------------- ---------------------
  Weeks 1--2     Repo, API and DB     Data/label plan      Threat model/lab  Literature, WIM and
                 design                                                      graph schema

  Weeks 3--4     Auth/API/queue       Ingestion skeleton   Safe target       Identity/evidence
                                                           validation        models

  Weeks 5--6     Observation store    Dataset cleaning +   Passive           Temporal evidence
                                      URL baseline         collectors        graph

  Weeks 7--9     Worker integration   HTML/text features   Browser worker    Endpoint/delegation
                                                                             semantics

  Weeks 10--12   Model adapter        Classical ML         Browser           Identity rules and
                                      evaluation           reproducibility   evaluation

  Weeks 13--16   Manifest/graph APIs  Graph                Runtime evidence  WIM verifier + graph
                                      features/baselines                     reasoning

  Weeks 17--20   Adaptive             Fusion/calibration   Canary-flow       VOI policy and
                 orchestration                             validation        decision layer

  Weeks 21--24   Release/operations   Final experiments    Security          Paper and research
                                                           assessment        claims
  ------------------------------------------------------------------------------------------------

**Rule:** a person may prototype independently, but production
integration begins only when the interface is written down and tested
with fixtures.

------------------------------------------------------------------------

# 7. Toolchain: how a professional small team should work

## 7.1 Source control and project management

  -----------------------------------------------------------------------
  Need                    Recommended tool        How to use it
  ----------------------- ----------------------- -----------------------
  Source control          Git + GitHub            Single source of truth
                                                  for code and reviews

  Work tracking           GitHub Projects or      Issues, milestones,
                          Linear                  owners, blockers

  Design discussions      GitHub Discussions /    Record decisions and
                          short ADRs              alternatives

  Documentation           Markdown in repository  Architecture, runbooks,
                                                  schemas and research
                                                  logs

  Diagrams                Mermaid + diagrams.net  Architecture, state
                                                  machines, data flows

  API exploration         FastAPI Swagger/OpenAPI Contract-first
                                                  integration

  API testing             Bruno or Postman        Shared collections and
                                                  reproducible requests

  Local environment       Docker Compose          Same service topology
                                                  for all four

  Code quality            Ruff, mypy/pyright,     Consistent formatting
                          pre-commit              and static checks

  Testing                 pytest, Hypothesis,     Unit, property,
                          Playwright              integration and browser
                                                  tests

  CI                      GitHub Actions          Run checks on every
                                                  pull request

  Secrets                 Local `.env` excluded   Never commit API keys
                          from Git; hosted secret or credentials
                          store                   

  Research references     Zotero                  Shared bibliography and
                                                  annotations

  Experiments             MLflow                  Parameters, metrics,
                                                  artifacts and model
                                                  lineage

  Dataset versioning      DVC or immutable        Trace exact data used
                          manifests               by each run

  Monitoring              OpenTelemetry +         Logs, metrics and
                          Prometheus/Grafana      traces
  -----------------------------------------------------------------------

Choose one issue tracker and one API client; do not scatter tasks across
WhatsApp, spreadsheets, Trello and GitHub simultaneously. Chat is for
coordination, not the permanent record of decisions.

## 7.2 Repository structure

``` text
trusttrace/
├── apps/
│   ├── api/
│   ├── worker/
│   └── web/
├── backend/
│   ├── core/
│   ├── auth/
│   ├── scans/
│   ├── organisations/
│   ├── collectors/
│   ├── browser/
│   ├── content/
│   ├── identity/
│   ├── graph/
│   ├── flow/
│   ├── ml/
│   ├── reasoning/
│   ├── reports/
│   └── audit/
├── ml/
│   ├── data/
│   ├── features/
│   ├── baselines/
│   ├── multimodal/
│   ├── graph/
│   ├── calibration/
│   └── evaluation/
├── schemas/
│   ├── api/
│   ├── observation/
│   ├── manifest/
│   └── report/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   ├── contract/
│   └── fixtures/
├── research/
│   ├── literature/
│   ├── hypotheses/
│   ├── protocols/
│   ├── experiment-logs/
│   └── paper/
├── docs/
│   ├── architecture/
│   ├── decisions/
│   ├── runbooks/
│   └── threat-model/
├── infra/
│   ├── docker/
│   └── monitoring/
├── docker-compose.yml
├── pyproject.toml
├── uv.lock
└── README.md
```

Do not commit raw sensitive captures, secrets, live malicious payloads
or huge datasets. Store approved data in controlled storage and version
manifests/checksums.

## 7.3 Git workflow

Use a lightweight trunk-based workflow:

-   `main` is always protected and should remain deployable.
-   Short-lived branches: `feat/scan-api`, `feat/browser-flow-observer`,
    `ml/url-baseline`, `research/wim-verifier`.
-   Every change enters through a pull request.
-   Require at least one reviewer; security-sensitive changes require
    review from Person 3 plus the affected owner.
-   Require CI to pass before merge.
-   Squash merge or use a consistent merge policy.
-   Delete merged branches.
-   Tag releases and model/data milestones.

### Pull request template

``` markdown
## What changed?
## Why is this needed?
## Related issue / hypothesis
## Interface or schema changes
## Security and privacy impact
## Tests added / commands run
## Dataset/model version impact
## Screenshots or sample output (if relevant)
## Known limitations
## Reviewer checklist
```

### Commit examples

``` text
feat(api): add asynchronous scan creation
feat(browser): capture form destination metadata
feat(identity): verify manifest signature and expiry
feat(graph): persist temporal evidence edges
ml(data): add domain-disjoint split manifest
ml(baseline): train lightgbm url-page model
test(security): block redirect to private address
docs(research): add hypothesis H2 protocol
```

------------------------------------------------------------------------

# 8. Daily, weekly and milestone operating rhythm

## Daily async update (each person, 3--5 minutes)

Post in the project tracker, not only in chat:

``` text
Yesterday:
- Completed ...

Today:
- Building ...

Blocked by:
- ...

Interface/change risk:
- ...

Evidence of progress:
- PR / commit / test / experiment link
```

## Weekly 60-minute research engineering meeting

1.  **10 min --- System demo:** one working thing, not a slide of
    intentions.
2.  **10 min --- Integration:** API contracts, schema changes and
    cross-module blockers.
3.  **10 min --- Security:** new attack surface, unsafe assumptions and
    privacy issues.
4.  **15 min --- Research:** hypotheses, baseline results, error cases
    and literature.
5.  **10 min --- Decisions:** record decisions and rejected
    alternatives.
6.  **5 min --- Next milestone:** owners and acceptance criteria.

## Weekly written artefacts

-   One merged code increment per workstream where possible.
-   One reproducible experiment or test result where applicable.
-   Updated architecture decision record if a design choice changed.
-   Updated risk/blocker list.
-   Short demo or traceable output.

## Fortnightly integration day

All four stop feature expansion for a short period and integrate `main`
into a working vertical slice. Fix schema mismatches, migrations, worker
failures, test flakiness and broken docs before starting another major
feature.

------------------------------------------------------------------------

# 9. Definition of Done (DoD)

A task is not complete because "the code runs on my laptop".

A subsystem is complete only when:

-   Its input/output contract is documented.
-   It has unit tests for normal, boundary and failure cases.
-   It has an integration fixture or contract test.
-   It logs useful structured events without secrets.
-   It handles timeouts and partial failure.
-   It has explicit security/privacy considerations.
-   It records version/provenance where relevant.
-   It is documented well enough for another teammate to run.
-   It is reviewed and merged.
-   Its acceptance criteria are demonstrated.

## 9.1 Additional ML DoD

-   Dataset version and source provenance recorded.
-   Split manifest fixed before final evaluation.
-   Domain/campaign/time leakage audited.
-   Feature pipeline version pinned.
-   Baseline comparison reported.
-   PR-AUC and low-FPR metrics included.
-   Calibration measured if probabilities are exposed.
-   Error analysis and limitations written.
-   Model artifact and model card registered.

## 9.2 Additional browser-security DoD

-   Target and every redirect validated.
-   Network egress restrictions enforced outside the app.
-   Private, loopback, link-local and metadata destinations blocked.
-   Browser is disposable and unprivileged.
-   No ambient credentials or production secrets.
-   CPU, memory, time, response and download budgets enforced.
-   Synthetic canary only in authorised test environment.
-   Captured evidence redacted and access-controlled.
-   Negative security tests pass.

## 9.3 Additional research DoD

-   Hypothesis and comparison are written before looking at final test
    results.
-   Closest prior work is acknowledged.
-   Baseline is appropriate and reproducible.
-   Dataset and split methodology are disclosed.
-   Confidence intervals or uncertainty are reported where appropriate.
-   Negative results and failure cases are retained.
-   Claim in paper maps to a result table, figure or verified system
    capability.

------------------------------------------------------------------------

# 10. Decision-making and conflict resolution

Research teams often lose time because every design discussion becomes
an open-ended debate. Use a simple decision protocol.

### Architecture Decision Record (ADR)

For decisions that affect interfaces, infrastructure, security or
research validity, create:

``` markdown
# ADR-00X: Decision title
Status: Proposed / Accepted / Superseded
Date:
Owners:

## Context
What problem are we solving?

## Options considered
A. ...
B. ...
C. ...

## Decision
What did we choose?

## Rationale
Why is this the best current choice?

## Consequences
What becomes easier/harder?

## Revisit trigger
What evidence would make us change this?
```

### Who decides?

-   Backend/API/DB: Person 1 proposes; affected consumers review.
-   ML/data/metrics: Person 2 proposes; Person 4 reviews experimental
    validity.
-   Browser isolation/runtime: Person 3 proposes; Person 1 reviews
    deployment integration; all review security-sensitive changes.
-   Identity/graph/research claims: Person 4 proposes; Person 1 reviews
    persistence/API; Person 2 reviews statistical implications.
-   Cross-cutting architecture: all four discuss; one named owner
    records the decision.
-   If no agreement: run a small time-boxed prototype or benchmark
    rather than arguing from preference.

------------------------------------------------------------------------

# 11. Research governance: keep the paper honest

Maintain these shared artefacts from week one:

1.  Problem statement and threat taxonomy.
2.  Literature and prior-art matrix.
3.  Novelty/contribution matrix.
4.  Architecture and data-flow diagrams.
5.  Scanner threat model.
6.  API and observation schemas.
7.  WIM specification and trust-bootstrap policy.
8.  Claim--Evidence graph schema.
9.  Dataset card and label handbook.
10. Experiment protocol and split manifests.
11. Model cards and calibration reports.
12. Security test report.
13. Limitations and failure-case register.
14. Reproducibility instructions.
15. Paper claim-to-evidence table.

### Claim-to-evidence table

  -----------------------------------------------------------------------
  Proposed paper claim                Required evidence
  ----------------------------------- -----------------------------------
  Identity delegation improves        Identity-aware vs no-identity
  identity assessment                 baseline, with legitimate
                                      delegated-service hard cases

  Runtime observation catches         Controlled ground-truth lab suite,
  additional credential-destination   flow attribution metrics and
  risks                               static-only comparison

  Adaptive investigation reduces cost Fixed vs adaptive policies at
                                      matched budgets and quality

  Graph provenance improves reasoning Graph vs tabular/rule baseline,
                                      graph precision, ablation and
                                      leakage-safe split

  Multimodal fusion improves          Single-modality vs fusion,
  detection                           missing-modality and
                                      domain-disjoint tests

  System is safe to operate           SSRF, DNS rebinding, egress,
                                      isolation, resource-exhaustion and
                                      privacy tests
  -----------------------------------------------------------------------

Never translate a successful demo into a general security claim. A demo
proves that one scenario worked; an experiment estimates performance
over a defined population.

------------------------------------------------------------------------

# 12. Risk register

  --------------------------------------------------------------------------------
  Risk              Early warning         Owner             Mitigation
  ----------------- --------------------- ----------------- ----------------------
  Scope explosion   Too many              Person 1 + all    Freeze MVP; extensions
                    models/features                         require evidence and a
                    before vertical slice                   hypothesis

  Data leakage      High random-split     Person 2          Domain/time/campaign
                    score, poor                             split audits
                    domain-disjoint score                   

  Weak labels       Conflicting feed      Person 2 + Person Label provenance,
                    labels and uncertain  4                 PU/weak supervision,
                    benign samples                          adjudicated set

  SSRF / internal   Browser reaches       Person 3          Egress proxy/firewall,
  network access    private or metadata                     redirect revalidation,
                    IP                                      negative tests

  False identity    Valid TLS treated as  Person 4          Separate domain
  assurance         brand authorisation                     control, organisation
                                                            identity and service
                                                            delegation

  False graph       Many unrelated sites  Person 4 + Person Degree caps, evidence
  association       linked by CDN/IP      2                 dependency, negative
                                                            controls

  Model             High scores on        Person 2          Calibration, OOD
  overconfidence    out-of-distribution                     tests, abstention
                    pages                                   

  Integration       Multiple incompatible Person 1          Contract-first
  failure           payload shapes                          schemas, fixtures,
                                                            integration day

  Secret leakage    URLs/tokens appear in Person 1 + Person Redaction, secret
                    logs or artefacts     3                 scanning, retention
                                                            controls

  Unreproducible    Teammate cannot rerun Person 2          Lockfiles,
  results           experiment                              DVC/manifests, MLflow,
                                                            seeds

  Novelty overclaim Contribution overlaps Person 4          Literature matrix and
                    close prior work                        claim audit

  Single-person     Only owner can run    All               Runbooks, pair review,
  dependency        subsystem                               backup maintainer
  --------------------------------------------------------------------------------

------------------------------------------------------------------------

# 13. First 14 days: exact starter checklist

## Day 1 --- Team and repository

-   All: agree working hours, communication channel and ownership.
-   Person 1: create GitHub repo, protected `main`, issue labels and PR
    template.
-   Deliverable: repository and project board.

## Day 2 --- Problem and scope

-   Person 4: one-page research question and contribution hypotheses.
-   Person 3: initial threat boundaries and scanner non-goals.
-   Person 2: candidate data source list.
-   Person 1: initial component diagram.
-   Deliverable: scope freeze v0.1.

## Day 3 --- Prior art

-   Person 4 leads paper reading; each member reads one closest system
    and writes a one-page critique.
-   Deliverable: prior-art comparison matrix.

## Day 4 --- API and data contracts

-   Person 1 drafts scan, observation, prediction and report schemas.
-   Other owners review their fields.
-   Deliverable: JSON examples and OpenAPI draft.

## Day 5 --- Local development environment

-   Person 1 creates Docker Compose with API, PostgreSQL, Redis and
    worker.
-   Everyone verifies the environment from a clean clone.
-   Deliverable: reproducible local setup.

## Day 6 --- Test lab

-   Person 3 creates controlled benign pages and endpoints for
    form/fetch/WebSocket cases.
-   No public target scanning.
-   Deliverable: local browser test environment.

## Day 7 --- Data and labels

-   Person 2 writes label handbook, data manifest and split policy.
-   Person 4 reviews identity vs behaviour label distinctions.
-   Deliverable: dataset protocol v0.1.

## Day 8 --- Identity and evidence

-   Person 4 writes initial WIM schema and graph node/edge glossary.
-   Person 1 reviews storage implications.
-   Deliverable: identity/evidence schema v0.1.

## Day 9 --- First backend vertical slice

-   Person 1 completes scan create/status/report flow with a dummy task.
-   Deliverable: working API demo.

## Day 10 --- Safe collection prototype

-   Person 3 implements URL policy and negative tests.
-   Person 1 integrates policy into scan validation.
-   Deliverable: blocked-target test report.

## Day 11 --- Data baseline

-   Person 2 builds URL parsing, feature extraction and a trivial
    baseline.
-   Deliverable: first reproducible metric table (not a headline
    result).

## Day 12 --- Identity verifier prototype

-   Person 4 creates test key pair, signs a sample manifest and verifies
    valid/invalid signatures.
-   Deliverable: cryptographic test vectors and limitations.

## Day 13 --- Integration

-   All four connect their outputs through the shared observation
    contract.
-   Deliverable: one end-to-end local scan.

## Day 14 --- Research review

-   Demo the system.
-   Review security failures, schema friction and data quality.
-   Decide what to cut, what to fix and what to test next.
-   Deliverable: Phase 1 backlog and revised plan.

------------------------------------------------------------------------

# 14. The minimum viable release: what to build first and what to defer

## Build in the first release

-   Authenticated scan submission and retrieval.
-   Tenant isolation.
-   Scan orchestration and asynchronous workers.
-   Safe URL validation and passive DNS/RDAP/TLS observations.
-   Isolated browser rendering for controlled/approved scope.
-   HTML/DOM/form and destination metadata.
-   Immutable evidence/provenance store.
-   URL + page classical ML baseline.
-   Organisation claim and manifest verifier prototype.
-   Rule-based delegation/evidence reasoning.
-   Evidence-backed report with unknown/inconclusive states.
-   Reproducible evaluation and security tests.

## Defer until the core works

-   Full-scale heterogeneous temporal GNN.
-   Federated learning.
-   Autonomous LLM agent with broad browsing tools.
-   Public global identity registry.
-   Blockchain/token reputation.
-   Kubernetes.
-   Browser extension.
-   Multi-cloud distributed scanner.
-   Real-time global monitoring.
-   Large cross-modal foundation-model fine-tuning.

These are not bad ideas. They are simply expensive distractions before
the core hypotheses have been tested.

------------------------------------------------------------------------

# 15. Suggested team scorecard

Review progress every two weeks. Do not use "number of lines of code" as
a success metric.

  -----------------------------------------------------------------------
  Dimension                           Evidence of progress
  ----------------------------------- -----------------------------------
  System integration                  Working vertical slice and passing
                                      contract tests

  Backend quality                     API correctness, tenant isolation,
                                      queue reliability, migration safety

  Data quality                        Provenance coverage, deduplication,
                                      label agreement, leakage audit

  ML quality                          Baseline comparisons, PR-AUC,
                                      low-FPR recall, calibration and
                                      error analysis

  Browser safety                      Negative SSRF tests, egress
                                      enforcement, worker isolation and
                                      resource limits

  Identity research                   Manifest verification, delegation
                                      test coverage and trust-bootstrap
                                      clarity

  Graph quality                       Evidence provenance, graph
                                      precision and ablation results

  Research quality                    Hypotheses, prior art, reproducible
                                      experiments and claim-to-evidence
                                      mapping

  Reproducibility                     Another teammate can reproduce the
                                      build and reported metrics

  Communication                       Decisions, blockers and interface
                                      changes documented
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 16. Final operating advice

Think of the team as four specialists building one instrument:

-   **Person 1 makes the instrument operable.**
-   **Person 2 proves whether its predictions are statistically
    meaningful.**
-   **Person 3 proves that its observations are safe and faithful to
    browser behaviour.**
-   **Person 4 proves that its identity and evidence reasoning mean what
    the project says they mean.**

The most impressive project will not be the one with the largest list of
technologies. It will be the one where every module has a defensible
purpose, every interface is explicit, every security boundary is tested,
every model is compared to a baseline, and every research claim can be
traced to reproducible evidence.

**The team's first milestone is not "build AI". It is: four people, one
repository, one contract, one controlled test site, and one end-to-end
scan that all four can explain.**
