---
author: Research & Engineering Blueprint
date: 9 November 2026
subtitle: Research Master Document --- Adaptive Web Identity, Runtime
  Data-Flow Assurance, and Adversarial Digital Trust Intelligence
title: TRUSTTRACE
---

# TRUSTTRACE

## Adaptive Web Identity, Runtime Data-Flow Assurance & Adversarial Digital Trust Intelligence

**Research master document \| Version 1.0 \| 9 November 2026**

> **Research thesis:** Can a system establish whether a website is
> legitimately authorised to represent an organisation, determine where
> sensitive information travels during real browser interactions, and
> adaptively gather evidence to distinguish impersonation, compromise
> and uncertainty---more reliably and efficiently than conventional URL,
> reputation and multimodal phishing detectors?

------------------------------------------------------------------------

# Document control

  -----------------------------------------------------------------------
  Field                               Value
  ----------------------------------- -----------------------------------
  Working name                        TRUSTTRACE

  Research area                       Web security, digital identity,
                                      phishing and impersonation, runtime
                                      information-flow analysis, applied
                                      ML, threat intelligence

  Primary research mode               Experimental system + benchmark +
                                      evaluation

  Intended audience                   Security researchers, academic
                                      reviewers, technical competition
                                      panels, product/security
                                      engineering teams

  Status                              Proposed research programme; no
                                      performance claims have yet been
                                      established

  Scope                               Website identity, malicious
                                      behaviour, sensitive-data
                                      destinations, temporal evidence and
                                      safe investigation

  Explicit non-goal                   Claiming universal detection of
                                      every cyberattack or declaring all
                                      unverified websites malicious
  -----------------------------------------------------------------------

**Naming note.** Earlier notes used TRUSTGRAPH and TRUSTTRACE. This
document adopts **TRUSTTRACE** as the umbrella research system.
"Claim--Evidence Graph" is a core internal representation, not a
competing project name.

**Evidence discipline.** This document synthesises the four research
notes supplied with the project and the technical direction developed in
the conversation. It distinguishes (a) established engineering practice
and standards, (b) existing research capabilities that must be treated
as baselines, and (c) proposed contributions that remain hypotheses
until tested. The existence of an idea in this document does not
establish novelty.

------------------------------------------------------------------------

# Executive research brief

## 1. The problem is larger than phishing classification

The conventional framing of phishing detection is:

> Given a URL or webpage, predict whether it is phishing or benign.

That framing is useful but incomplete. It collapses several different
questions into one binary label:

1.  **Identity:** Who does the website claim to represent?
2.  **Authorisation:** Has that organisation authorised this domain,
    service or delegated endpoint?
3.  **Behaviour:** What does the website actually do when loaded and
    interacted with?
4.  **Data flow:** Where does sensitive information travel?
5.  **Infrastructure:** What can be established about its DNS, hosting,
    certificates and service relationships?
6.  **History:** How has the website and its infrastructure changed over
    time?
7.  **Evidence quality:** How reliable, current, independent and
    complete are the observations?
8.  **Decision:** Is the evidence sufficient to classify, warn,
    investigate further or abstain?

A website can have a valid HTTPS certificate and still be fraudulent. A
legitimate organisation's website can be compromised. A new domain can
be benign but unverified. A legitimate website can use third-party
authentication and payment services hosted on unrelated domains. A
screenshot can be visually indistinguishable from a genuine page while
its credential destination is attacker-controlled.

The project should therefore avoid a single undifferentiated "trust
score." It should produce separate, evidence-backed assessments of
**identity assurance**, **behavioural security**, **data-flow policy
compliance**, and **evidence quality**.

## 2. Proposed system

TRUSTTRACE is a research platform that investigates websites as claims
about organisational identity and as executable systems that exchange
data.

It combines:

-   **Organisational identity and service delegation:** signed
    declarations of canonical domains, delegated services and permitted
    purposes.
-   **Runtime data-flow observation:** inspection of forms, scripts,
    browser events and network destinations using synthetic canary
    values in an isolated browser.
-   **Claim--Evidence Graph:** typed, time-indexed relationships among
    organisations, domains, pages, certificates, endpoints, scripts,
    evidence sources and observations.
-   **Adaptive investigation:** selection of the next safe
    evidence-gathering action based on expected decision improvement,
    cost and privacy risk.
-   **Multi-context observation:** comparison of controlled browser
    profiles, locale, viewport, session state and observation time to
    identify security-relevant selective delivery.
-   **Cross-script identity resolution:** Unicode, IDN, transliteration,
    language and visual identity analysis.
-   **Evidence-calibrated reasoning:** support, contradiction, source
    dependency, uncertainty and an explicit "insufficient evidence"
    outcome.
-   **Threat intelligence interoperability:** structured indicators and
    provenance, with STIX/TAXII considered for exchange.
-   **Optional AI-agent safety analysis:** detection and containment of
    webpage-originated instructions that attempt to manipulate browsing
    agents.

## 3. Proposed core contributions

The recommended research scope is deliberately narrow enough to evaluate
but substantial enough to matter.

  -----------------------------------------------------------------------
  Contribution            Research claim to test  Why it matters
  ----------------------- ----------------------- -----------------------
  C1. Identity delegation A scoped, signed        Domain control is not
  model                   representation of       the same as brand or
                          organisational domains  service authorisation
                          and service delegation  
                          can reduce ambiguity    
                          when verifying claimed  
                          identity                

  C2. Runtime destination Observing synthetic     The destination of
  assurance               sensitive-value flows   information is often
                          can detect credential   more security-relevant
                          destinations that       than page appearance
                          static URL and          
                          screenshot analysis     
                          miss                    

  C3. Adaptive evidence   A policy that selects   Exhaustive scanning is
  acquisition             the next investigation  expensive and may
                          action can reduce cost  increase exposure
                          while preserving        
                          decision quality        

  C4. Provenance-aware    Modelling source, time, Evidence is stale,
  temporal reasoning      dependency and          correlated, incomplete
                          contradiction can       and sometimes poisoned
                          improve calibration and 
                          auditability            

  C5. Multi-context       Controlled              A scanner may see a
  integrity analysis      cross-context           benign page while a
                          observations can reveal target user sees a
                          security-relevant       malicious one
                          behavioural divergence  
  -----------------------------------------------------------------------

Cross-script resolution, AI-agent safety, collaborative intelligence and
advanced temporal GNNs are valuable extensions. They should not all be
treated as mandatory first-release contributions.

## 4. The central research question

**RQ0:** Can verifiable organisational service delegation and runtime
sensitive-data-flow observation, combined with provenance-aware adaptive
investigation, detect web impersonation and compromised digital services
more reliably and efficiently than conventional URL, reputation and
multimodal phishing detection systems?

The research must be allowed to falsify this claim. If a simpler
baseline performs equally well, the more complex component should be
removed or its scope narrowed.

------------------------------------------------------------------------

# Part I --- Research framing and novelty discipline

# 1. Research objectives and boundaries

## 1.1 Primary objectives

1.  Establish a defensible representation of an organisation's claimed
    and authorised digital services.
2.  Distinguish domain control, TLS validity, brand resemblance and
    organisational endorsement.
3.  Observe sensitive-value destinations during controlled browser
    interactions.
4.  Correlate identity, infrastructure, content and behavioural evidence
    over time.
5.  Select evidence-gathering actions adaptively under a bounded cost
    and safety budget.
6.  Provide explanations that are traceable to recorded observations.
7.  Evaluate generalisation to unseen domains, organisations, time
    periods and scripts.
8.  Make the scanner safe enough that analysing hostile websites does
    not compromise the platform.

## 1.2 Non-goals and scope exclusions

The first research release will not claim to:

-   Detect every zero-day, malware family, account takeover or
    social-engineering attack.
-   Prove legal ownership of an organisation from DNS or TLS alone.
-   Determine the intent of every website with certainty.
-   Reliably inspect authenticated pages without credentials or an
    authorised test account.
-   Perform intrusive vulnerability exploitation against arbitrary
    external websites.
-   Replace browser vendors, certificate authorities, national CERTs or
    enterprise security operations centres.
-   Treat an absent threat-feed match as evidence of safety.
-   Treat a new domain, unusual IP, certificate change or shared hosting
    relationship as proof of maliciousness.
-   Capture real passwords, OTPs, payment credentials or personal data
    for model training.

## 1.3 Threat taxonomy

The system's supported threat categories should be explicit.

  ----------------------------------------------------------------------------
  Category                Example                 Evidence needed
  ----------------------- ----------------------- ----------------------------
  Phishing                Fake login portal       Identity mismatch, form
                                                  destination, content and
                                                  interaction

  Spear phishing          Targeted link           Message context plus
                                                  destination analysis

  Whaling                 Executive impersonation Identity and communication
                                                  context

  Smishing                SMS-delivered malicious Message plus URL
                          link                    

  QR phishing             QR code redirects to    QR decoding and destination
                          fake portal             chain

  Typosquatting           Misspelled brand domain Lexical and identity
                                                  evidence

  Homograph / IDN abuse   Unicode lookalike       IDNA, script and confusable
                          domain                  analysis

  Brand impersonation     Fake bank, university   Claimed identity, visual and
                          or government site      delegation evidence

  Credential harvesting   Fake page submits       Runtime data-flow
                          credentials externally  observation

  Fake payment portal     Fraudulent payment      Payment workflow and
                          destination             destination authorisation

  Malvertising            Advertisement redirects Redirect chain and source
                          to malicious page       context

  Drive-by download       Visit triggers download Browser download events and
                                                  file metadata

  Malware distribution    Page hosts malicious    Safe metadata and reputation
                          payload                 analysis

  DNS hijacking           Resolution manipulated  DNS history and
                                                  authoritative context

  Domain takeover         Abandoned service       DNS/service lifecycle
                          claimed by attacker     evidence

  Web skimming            Script captures payment Script provenance and
                          data                    runtime flow

  Malicious redirect      Benign-looking URL      Redirect chain and context
                          redirects to attacker   

  AiTM phishing           Reverse proxy captures  Usually requires
                          session                 authentication/session
                                                  telemetry; outside simple
                                                  URL-only scope

  OAuth consent phishing  User grants malicious   OAuth application and
                          app permissions         consent context; separate
                                                  integration

  Session hijacking       Stolen session token    Endpoint/identity-provider
                          replay                  telemetry; not reliably
                                                  visible to public URL
                                                  scanner

  Agent-targeted prompt   Page content attempts   Agent-facing content and
  injection               to manipulate an AI     controlled agent execution
                          agent                   
  ----------------------------------------------------------------------------

**Scope warning:** Some threats require email/SMS context, endpoint
telemetry, identity-provider logs or authenticated testing. A URL-only
scanner cannot reliably detect all of them. The product must state which
observations were actually made.

## 1.4 Threat actor assumptions

Assume an adversary can:

-   Register lookalike domains and obtain ordinary publicly trusted TLS
    certificates.
-   Copy logos, CSS, text, DOM structures and screenshots.
-   Change IP addresses, DNS records, certificates, scripts and redirect
    destinations.
-   Serve different content by user-agent, locale, cookies, referrer, IP
    range or time.
-   Block or fingerprint automated scanners.
-   Submit false reports and poison collaborative intelligence.
-   Insert malicious content into otherwise legitimate websites.
-   Include prompt-injection text in content consumed by an AI analysis
    agent.
-   Attempt SSRF, DNS rebinding, resource exhaustion and browser
    exploitation through submitted URLs.

Assume the adversary cannot automatically break standard cryptographic
primitives, compromise every independent trust anchor, or control all
external observation sources. These assumptions must be documented and
stress-tested.

# 2. Existing work and the novelty boundary

A strong research presentation must acknowledge prior work accurately.

## 2.1 Existing capability families

  -----------------------------------------------------------------------
  Family                  Existing capability     What TRUSTTRACE must
                                                  not claim as new
  ----------------------- ----------------------- -----------------------
  URL reputation          Lists and feeds of      Checking a URL against
                          known unsafe URLs       reputation sources

  URL ML                  Lexical and host-based  Training a URL
                          classification          classifier

  Visual phishing         Logo, screenshot and    Screenshot similarity
  detection               brand similarity        by itself

  Phishing intention      Detecting brand         Merely identifying a
  analysis                impersonation and       logo plus a login form
                          credential-taking       
                          intent                  

  Multimodal detection    Combining URL, HTML,    Combining modalities
                          text, visual and        without a new result
                          behaviour features      

  Infrastructure          Pivoting among domains, A domain/IP/certificate
  correlation             IPs, certificates and   graph alone
                          campaigns               

  Graph ML                GCN, GAT, GraphSAGE,    Using a GNN because
                          R-GCN, HGT and temporal entities form a graph
                          graph learning          

  Certificate monitoring  X.509 validation and    Looking up a
                          Certificate             certificate or
                          Transparency monitoring detecting a new SAN

  Evidence provenance     Recording sources and   Adding a source field
                          timestamps              to an IOC

  LLM-assisted            Tool orchestration and  Putting an LLM around
  investigation           report generation       existing APIs

  Domain verification     DNS or file challenges  Equating control of a
                          to establish control    domain with
                                                  organisational
                                                  endorsement

  Verifiable credentials  Signed                  Inventing a new JSON
                          machine-verifiable      credential format
                          claims                  without a protocol
                                                  contribution
  -----------------------------------------------------------------------

## 2.2 Research works to treat as baselines

The project notes identify the following works and themes for direct
review:

-   **Phishpedia** --- visual brand identification for phishing
    detection.
-   **PhishIntention** --- brand identity and phishing-intention
    analysis, including credential-collection behaviour.
-   **PhishLumos** --- campaign-level investigation, infrastructure
    pivots, graph representation, provenance and LLM-assisted
    investigation.
-   **CrossPhire and other multimodal work** --- combinations of URL,
    visual, semantic and structural features.
-   **Neuro-symbolic and adaptive phishing research** --- multimodal and
    symbolic reasoning, with overlap in adaptive detection.
-   **PHILTER** --- a 2026 review of AI-based phishing detection
    limitations, including real-world functionality, privacy,
    adaptability and evaluation.
-   **Page Transparency** --- work on cryptographic transparency and
    visual verification of login pages.

The precise bibliographic details, versions, publication venues and
claims must be checked against the original papers before being quoted
in a formal submission. The list is a reading queue, not a substitute
for a reproducible literature review.

## 2.3 Novelty matrix

  -------------------------------------------------------------------------
  Proposed idea           Prior-art overlap       Potential differentiator
                                                  to investigate
  ----------------------- ----------------------- -------------------------
  Claim--Evidence Graph   Knowledge graphs and    Typed organisational
                          threat graphs are       claims, scoped
                          established             delegation, evidence
                                                  dependency and temporal
                                                  validity in one formal
                                                  model

  Signed Web Identity     Verifiable credentials  A practical, revocable,
  Manifest                and domain control      purpose-scoped manifest
                          mechanisms exist        of domains and service
                                                  endpoints, plus bootstrap
                                                  trust evaluation

  Runtime sensitive-value Dynamic analysis and    Policy comparison between
  destination analysis    phishing-intention      observed synthetic-value
                          research exist          flows and
                                                  organisation-authorised
                                                  recipients

  Adaptive evidence       Active learning and     Cost-, privacy- and
  acquisition             automated investigation safety-aware action
                          exist                   selection for web trust
                                                  decisions

  Multi-context           Cloaking and            Security-relevant
  divergence              differential content    divergence tied to
                          analysis exist          identity claims and
                                                  data-flow policy

  Cross-script identity   Unicode confusable      Joint organisation-name,
  resolution              detection exists        script, transliteration,
                                                  visual and
                                                  delegated-domain
                                                  reasoning

  Agent-safe web trust    Prompt-injection        Binding agent action
                          research exists         permissions to verified
                                                  identity and observed
                                                  destinations

  Provenance-aware        STIX, MISP, federated   Verifiable source
  collaborative           threat intelligence     accountability and robust
  intelligence            exist                   handling of malicious or
                                                  correlated reports
  -------------------------------------------------------------------------

**Novelty rule:** A contribution is not established by naming a
technique. It is established by a precise problem definition, comparison
with the closest prior work, a reproducible method, and an experiment
that shows a measurable improvement or a new capability.

------------------------------------------------------------------------

# Part II --- Formal system model

# 3. System entities, claims and observations

## 3.1 Core concepts

TRUSTTRACE distinguishes the following:

-   **Organisation (o):** the real-world entity being represented.
-   **Identity claim (c):** a claim made by a website or service about
    the organisation it represents.
-   **Digital entity (v):** a domain, URL, IP, certificate, page,
    script, endpoint or service provider.
-   **Delegation (d):** an organisation-authorised relationship allowing
    another domain or provider to perform a scoped function.
-   **Observation (e):** a collected fact with source, time, method and
    integrity metadata.
-   **Policy (p):** a rule describing which entities may receive which
    data for which purpose.
-   **Investigation action (a):** a safe operation that can gather
    additional evidence.
-   **Decision (y):** a structured conclusion, including the possibility
    of abstention.

## 3.2 Separate the four decision dimensions

The output must not be one scalar.

Let the system produce:

\[ `\mathbf{z}`{=tex}(x,t)= `\left[
I(x,t),\;
B(x,t),\;
F(x,t),\;
Q(x,t)
\right]`{=tex}\]

where:

-   (I): identity assurance;
-   (B): behavioural security risk;
-   (F): data-flow policy violation assessment;
-   (Q): evidence quality and completeness.

A fifth optional dimension can describe infrastructure/security posture
(S(x,t)), but it must not be confused with phishing probability.

### Identity assurance

Possible states:

-   `verified`: sufficient independent evidence supports the claim and
    relevant delegation.
-   `unverified`: insufficient evidence to establish endorsement.
-   `contradicted`: reliable evidence conflicts with the identity claim.
-   `not_applicable`: no organisational identity claim was made.
-   `unknown`: evidence collection failed or is incomplete.

### Behavioural security

Possible states:

-   `no_threat_observed`: no malicious behaviour was observed within the
    tested scope.
-   `suspicious`: one or more meaningful indicators require review.
-   `malicious_evidence`: high-confidence evidence of malicious
    behaviour.
-   `unknown`: behaviour could not be adequately observed.

The label `no_threat_observed` must never be rendered as "safe."

### Data-flow assessment

Possible states:

-   `policy_consistent`
-   `policy_violation`
-   `destination_unverified`
-   `not_observed`
-   `not_applicable`

### Evidence quality

Represent completeness, freshness, provenance strength, independence and
collection reliability separately. An observation can be high-confidence
as a fact (e.g., a DNS response was observed) but weak evidence of
malicious intent.

# 4. Formal problem formulation

## 4.1 Identity verification

Let:

-   \(C\) be the set of claims;
-   (E_t) be observations available by time (t);
-   (G_t) be the time-indexed claim--evidence graph;
-   \(A\) be the set of trust anchors and verification authorities;
-   \(D\) be delegation declarations.

The identity inference problem is:

\[ P(I_o = 1 `\mid `{=tex}C,E_t,G_t,A,D) \]

This is not merely a classifier over URL features. It is an inference
over claims and the evidence that supports or contradicts them.

## 4.2 Runtime data-flow assurance

Let:

-   \(S\) be synthetic sensitive-value sources in a controlled test;
-   \(F\) be observed flows;
-   (R(f)) be the recipient of flow (f);
-   (P_o(a)) be the set of permitted recipients for organisation (o) and
    action/purpose (a).

A basic policy violation predicate is:

\[ V(f,a,o)= `\mathbb{1}`{=tex}`\left[R(f)\notin P_o(a)\right]`{=tex}\]

Real policy evaluation must account for delegated providers, token
exchange, redirects, subresource requests, script execution and purpose
limitation. An endpoint can be authorised for analytics but not for
credentials. Therefore, delegation should be scoped by purpose and data
category, not merely by hostname.

## 4.3 Active investigation

Let (a`\in`{=tex}`\mathcal{A}`{=tex}) be a candidate safe action, (E)
current evidence, (c(a)) its cost and (r(a)) its privacy/safety risk.

A myopic information-gain policy is:

\[ a\^\* = `\arg`{=tex}`\max`{=tex}\_{a`\in`{=tex}`\mathcal{A}`{=tex}}
`\frac{
\mathbb{E}\left[
H(Y\mid E)-H(Y\mid E,E_a)
\right]
}{
c(a)+\lambda r(a)
}`{=tex} \]

A more complete decision-theoretic objective is:

\[ a\^\* = `\arg`{=tex}`\min`{=tex}\_{a`\in`{=tex}`\mathcal{A}`{=tex}}
`\left[
\mathbb{E}\left[L(Y,\hat{Y}\mid E,E_a)\right]`{=tex}+`\lambda`{=tex}\_c
c(a) +`\lambda`{=tex}\_p r_p(a) +`\lambda`{=tex}\_s r_s(a)
`\right`{=tex}\] \]

where (L) is decision loss, (r_p) privacy risk and (r_s) scanner safety
risk.

This formalises the idea that the best next action is not necessarily
the most informative action if it is too expensive, privacy-invasive or
unsafe.

## 4.4 Decision with abstention

The system must be able to say "insufficient evidence."

For a calibrated class posterior (P(Y=k`\mid `{=tex}E)), define a reject
option:

\[ `\hat{Y}`{=tex} =
```{=tex}
\begin{cases}
\arg\max_k P(Y=k\mid E), & \max_k P(Y=k\mid E)\geq \tau_k\\
\text{ABSTAIN}, & \text{otherwise}
\end{cases}
```
\]

Thresholds (`\tau`{=tex}\_k) should be selected on validation data based
on application costs, not chosen to make a demo look impressive.

## 4.5 Evidence independence and source dependence

If multiple features originate from the same underlying webpage, they
are not independent observations. For example, page title, visible text,
logo and screenshot embedding may all derive from one HTML document.

A naive product of likelihoods can overstate confidence:

\[ P(E_1,`\ldots`{=tex},E_n`\mid `{=tex}Y) `\neq`{=tex} `\prod`{=tex}\_i
P(E_i`\mid `{=tex}Y) \]

unless the conditional independence assumptions are justified.

Model evidence dependencies explicitly through source lineage, shared
parent observations, correlation groups or a probabilistic graphical
model. At minimum, prevent the fusion model from counting correlated
features as independent votes.

------------------------------------------------------------------------

# Part III --- Core research contributions

# 5. Contribution C1: Organisational identity and service delegation

## 5.1 Problem

Domain registration, DNS control and TLS certificates provide useful
facts, but none alone proves that a domain is authorised to represent a
named organisation or collect a particular class of information.

A legitimate workflow may span multiple domains:

``` text
organisation.example
  |
  +-- admissions.organisation.example
  |
  +-- login.organisation.example
  |
  +-- identity-provider.example
  |
  +-- payments-provider.example
```

The third-party domains may be legitimate, but their authority must be
scoped and independently established.

## 5.2 Proposed Web Identity Manifest (WIM)

The manifest is an experimental protocol profile, not a claim to have
created a global standard.

Illustrative payload:

``` json
{
  "manifest_version": "0.1",
  "organisation": {
    "identifier": "urn:example:organisation:123",
    "display_name": "Example University"
  },
  "canonical_domains": [
    "example.edu"
  ],
  "delegations": [
    {
      "domain": "admissions.example.edu",
      "service": "admissions",
      "purposes": ["application_submission"],
      "data_categories": ["application_data"],
      "valid_from": "2026-11-01T00:00:00Z",
      "valid_until": "2027-11-01T00:00:00Z"
    },
    {
      "domain": "idp.example.net",
      "service": "authentication",
      "purposes": ["authentication"],
      "data_categories": ["authentication_assertion"],
      "valid_from": "2026-11-01T00:00:00Z",
      "valid_until": "2027-02-01T00:00:00Z"
    }
  ],
  "issuer_key_id": "key-2026-01",
  "issued_at": "2026-11-01T00:00:00Z",
  "expires_at": "2027-11-01T00:00:00Z",
  "status_endpoint": "https://example.edu/.well-known/wim-status"
}
```

The payload should be encoded using a mature signed-credential or
signed-document mechanism. Investigate W3C Verifiable Credentials Data
Model 2.0, JOSE/JWS and COSE rather than designing cryptographic
primitives.

## 5.3 Trust bootstrap

The hardest part is not signature verification. It is establishing that
the signing key belongs to the claimed organisation.

Possible evidence layers:

1.  A pre-verified organisational identity anchor.
2.  Domain-control challenge.
3.  DNSSEC/DNS publication where available.
4.  A key-discovery mechanism.
5.  Independent corroboration from authoritative organisational sources.
6.  A transparent record of issuance, rotation and revocation.
7.  Human review for high-impact organisations.

Do not equate a DNS TXT record with legal identity. It proves a form of
domain control at a point in time, not that the organisation has legal
authority over every claimed service.

## 5.4 Delegation semantics

A delegation should include:

-   Delegator and delegate identifiers.
-   Domain or endpoint scope.
-   Service type.
-   Permitted purposes.
-   Data categories.
-   Validity interval.
-   Issuance and expiry.
-   Revocation/status mechanism.
-   Signature and issuer key identifier.
-   Evidence supporting the delegator's authority.

A broad wildcard such as `*.example.net` is dangerous unless explicitly
justified. Prefer narrow, purpose-specific delegations.

## 5.5 Research questions

-   RQ1.1: Does scoped service delegation reduce false positives for
    legitimate third-party identity and payment providers?
-   RQ1.2: Can a verifier distinguish domain control from organisational
    endorsement?
-   RQ1.3: How quickly can a revoked or expired delegation be detected?
-   RQ1.4: What trust-bootstrap model is practical without a universal
    organisational PKI?

## 5.6 Failure cases to test

-   Stolen organisation signing key.
-   Compromised canonical domain.
-   Manifest replay.
-   Expired manifest.
-   Revoked delegate.
-   Malicious delegate.
-   DNS takeover.
-   Legitimate provider migration.
-   Multiple organisations sharing a service provider.
-   Incorrectly scoped purpose.
-   Key rotation with delayed propagation.

## 5.7 Expected contribution boundary

The likely contribution is not "a new digital certificate." It is a
carefully evaluated model for representing organisational service
delegation and using it to reason about observed website identity and
data flows.

------------------------------------------------------------------------

# 6. Contribution C2: Runtime sensitive-data-flow assurance

## 6.1 Problem

A static page may look legitimate while sending information to an
unrelated endpoint. Screenshot similarity and URL classification do not
necessarily reveal where data travels after interaction.

The project should therefore observe browser behaviour in a controlled
environment.

## 6.2 Safe experimental method

Use a disposable browser worker and synthetic canary values only.

Example canary:

``` text
TRUSTTRACE_CANARY_<random-test-id>
```

The value must not be a real password, OTP, payment number or personal
record. Use it only in controlled pages or explicitly authorised test
environments.

Observe:

-   HTML form actions.
-   Form submission events.
-   JavaScript `fetch`.
-   XMLHttpRequest.
-   WebSocket connection metadata.
-   Navigation and redirects.
-   Requests initiated after a synthetic value is entered.
-   Storage writes where observable.
-   Third-party scripts and their origins.

Avoid collecting full request bodies by default. Record the minimum
metadata needed to establish whether a canary or its derived
representation was transmitted. Redact values and secrets from logs.

## 6.3 Data-flow model

Represent the browser interaction as a directed, time-stamped graph:

\[ G_F=(V_F,E_F) \]

Node types:

-   `InputSource`
-   `DOMField`
-   `Script`
-   `StorageLocation`
-   `Request`
-   `Endpoint`
-   `Redirect`
-   `ThirdPartyService`

Edge types:

-   `entered_into`
-   `read_by`
-   `transformed_by`
-   `stored_in`
-   `sent_via`
-   `redirected_to`
-   `received_by`

Each edge should include timestamp, execution context, frame origin and
observation method.

## 6.4 Destination policy

Define a policy tuple:

\[ p=(o,s,d,u,t) \]

where (o) is organisation, (s) service, (d) data category, (u) purpose
and (t) validity time.

A recipient is authorised only if an active delegation matches the
relevant scope. Matching only a hostname is insufficient.

For each observed flow (f), derive:

-   recipient origin;
-   initiator origin;
-   data category (in the controlled test);
-   purpose inferred from the interaction;
-   delegation match;
-   redirect lineage;
-   policy result;
-   evidence quality.

## 6.5 Important technical limitations

Browser instrumentation cannot automatically prove every possible
information flow:

-   JavaScript can transform, encode, hash or split values.
-   Data may be sent through encrypted channels.
-   Service workers can mediate requests.
-   WebSockets and beacon APIs require coverage.
-   Cross-origin frames complicate attribution.
-   Browser extensions or native helpers may be outside the observation
    boundary.
-   A malicious page may detect instrumentation.
-   A canary may be copied or transformed before transmission.

Therefore, report the observation boundary. Do not claim complete taint
tracking unless you actually implement and validate it.

## 6.6 Evaluation

Create controlled pages with known flows:

1.  Legitimate form to authorised endpoint.
2.  Fake login page to unrelated endpoint.
3.  Form with JavaScript `fetch`.
4.  XMLHttpRequest submission.
5.  WebSocket-based exfiltration simulation.
6.  Third-party authentication flow with a valid delegation.
7.  Redirect to a delegated service.
8.  Redirect to an undeclared destination.
9.  Service worker-mediated request.
10. Page with no sensitive input.
11. Page with a canary copied into an unrelated request.
12. Legitimate analytics request that must not be confused with
    credential submission.

Metrics:

-   Flow detection precision/recall.
-   Recipient attribution accuracy.
-   Policy violation precision/recall.
-   Missed flow categories.
-   Browser overhead.
-   Time to detection.
-   False alarms on legitimate third-party services.

------------------------------------------------------------------------

# 7. Contribution C3: Adaptive evidence acquisition

## 7.1 Why fixed scanning is inefficient

A fixed scanner may always collect every signal:

-   URL parsing.
-   RDAP.
-   DNS.
-   TLS.
-   CT.
-   Screenshot.
-   OCR.
-   HTML.
-   Browser behaviour.
-   Threat-feed queries.
-   Graph expansion.

This increases latency, resource use, external data exposure and attack
surface.

TRUSTTRACE should choose what to investigate next.

## 7.2 Action space

Example safe actions:

  -------------------------------------------------------------------------------
  Action                            Cost Potential value  Safety considerations
  ---------------- --------------------- ---------------- -----------------------
  Parse URL                     Very low Lexical and      Low
  locally                                structural       
                                         features         

  RDAP lookup                        Low Registration     Rate limits and privacy
                                         context          

  DNS resolution                     Low Current DNS      Rebinding and resolver
                                         relationships    trust

  TLS handshake                      Low Certificate and  Safe connection
                                         protocol facts   handling

  CT query                   Low--medium Public           Query limits
                                         certificate      
                                         history          

  Static HTML                     Medium DOM and form     SSRF and content size
  fetch                                  analysis         

  Screenshot                        High Visual and       Browser isolation
  render                                 dynamic content  

  Runtime canary                    High Data-flow        Only
  test                                   evidence         controlled/authorised
                                                          environment

  Threat-feed                   Variable Known indicators Licensing, privacy and
  lookup                                                  API limits

  Multi-context                     High Selective        Resource and network
  render                                 delivery         exposure
  -------------------------------------------------------------------------------

## 7.3 Decision policy

At state (s_t), choose action (a_t) based on:

-   current uncertainty;
-   expected reduction in decision loss;
-   action cost;
-   privacy risk;
-   scanner safety risk;
-   expected time;
-   action availability.

The investigation terminates when:

-   evidence supports a sufficiently confident decision;
-   the remaining uncertainty cannot be reduced within budget;
-   the safety budget is exhausted;
-   required sources are unavailable;
-   or the system should abstain.

## 7.4 Baselines

Compare:

1.  URL-only.
2.  Fixed low-cost scan.
3.  Fixed exhaustive scan.
4.  Random action selection.
5.  Greedy information gain.
6.  Cost-aware decision policy.
7.  Cost-, privacy- and safety-aware policy.

## 7.5 Metrics

-   Decision quality at fixed cost.
-   Cost to reach target confidence.
-   Average number of actions.
-   Browser renders per case.
-   Median and p95 latency.
-   External queries per case.
-   Privacy-risk proxy.
-   Abstention rate.
-   Performance under unavailable tools.

The contribution is meaningful only if adaptive selection reduces cost
or improves quality compared with credible fixed baselines.

------------------------------------------------------------------------

# 8. Contribution C4: Provenance-aware temporal Claim--Evidence Graph

## 8.1 Why a graph

A website is connected to domains, IP addresses, ASNs, certificates,
organisations, scripts, endpoints, reports and other websites. A graph
represents these relationships more naturally than a flat row of
features.

But a graph alone is not novel. The research value lies in how claims,
evidence, provenance, delegation, time and dependency are represented
and evaluated.

## 8.2 Node types

  -----------------------------------------------------------------------
  Node                                Important attributes
  ----------------------------------- -----------------------------------
  Organisation                        Identifier, name, authoritative
                                      references

  IdentityClaim                       Claimed organisation, service,
                                      purpose, timestamp

  Domain                              Registrable domain, IDN form,
                                      creation/expiry where available

  URL                                 Scheme, host, path fingerprint,
                                      redacted query

  IP                                  Address, address family,
                                      observation time

  ASN                                 Number, organisation, prefix
                                      context

  Certificate                         Fingerprint, SAN, issuer, validity,
                                      key metadata

  CA                                  Root/intermediate identity and
                                      trust status

  Webpage                             URL, capture ID, DOM hash,
                                      screenshot hash

  Script                              URL, hash, origin, execution
                                      observations

  Endpoint                            Origin, path class, protocol,
                                      purpose

  Evidence                            Source, method, timestamp,
                                      confidence, integrity hash

  Delegation                          Issuer, delegate, scope, purpose,
                                      validity

  ThreatReport                        Source, label, confidence, sharing
                                      policy

  BrowserObservation                  Profile, locale, viewport, time,
                                      outcome
  -----------------------------------------------------------------------

## 8.3 Edge types

``` text
Organisation --claims_identity--> IdentityClaim
IdentityClaim --refers_to--> Domain
Organisation --authorises--> Delegation
Delegation --permits--> Endpoint
Domain --resolves_to--> IP
IP --announced_by--> ASN
Domain --presents--> Certificate
Certificate --issued_by--> CA
Webpage --loads--> Script
Webpage --contains--> Form
Form --submits_to--> Endpoint
BrowserObservation --observed--> Webpage
Evidence --supports--> IdentityClaim
Evidence --contradicts--> IdentityClaim
ThreatReport --reports--> Domain
Domain --redirects_to--> Domain
Domain --resembles--> Organisation
```

Do not model `resembles` as `belongs_to`. Similarity is not ownership.

## 8.4 Evidence object

``` json
{
  "evidence_id": "ev-000123",
  "subject_id": "domain:example.test",
  "predicate": "resolves_to",
  "object_id": "ip:203.0.113.10",
  "observed_value": "203.0.113.10",
  "source": "resolver-observer-01",
  "source_type": "measurement",
  "collected_at": "2026-11-09T10:00:00Z",
  "valid_until": "2026-11-09T10:05:00Z",
  "collection_method": "DNS_A_lookup",
  "integrity_hash": "sha256:...",
  "confidence": 0.99,
  "confidence_semantics": "confidence_in_observation",
  "parent_observation_ids": [],
  "limitations": ["single_resolver", "single_time_point"]
}
```

The `confidence` field above is illustrative. It must not be interpreted
as probability of maliciousness. Keep observation confidence separate
from inference confidence.

## 8.5 Temporal semantics

Represent an observation as:

\[ e=(s,p,o,t\_{obs},t\_{valid},src,meth,prov) \]

where (s,p,o) are subject, predicate and object; (t\_{obs}) is
observation time; (t\_{valid}) is the validity interval; `src` is
source; `meth` is method; and `prov` is provenance.

A relation that was true yesterday may not be true now. Never overwrite
old observations when a new one arrives. Append a new event and preserve
history.

## 8.6 Source reliability and evidence freshness

Potential model:

\[
w(e,t)=r(src_e)`\cdot `{=tex}q(meth_e)`\cdot `{=tex}f(t-t\_{obs})`\cdot `{=tex}i(e)
\]

where:

-   \(r\) is source reliability;
-   \(q\) is method quality;
-   \(f\) is freshness decay;
-   \(i\) is independence/dependency adjustment.

A simple exponential freshness function is:

\[ f(`\Delta `{=tex}t)=e\^{-`\lambda `{=tex}`\Delta `{=tex}t} \]

But different evidence types require different decay assumptions. DNS
observations may become stale quickly; a signed organisational
declaration may remain valid until expiry or revocation; a historical
phishing report remains historically true but may not indicate current
activity.

## 8.7 Graph learning research plan

Start with interpretable baselines:

1.  Hand-engineered graph features + LightGBM.
2.  NetworkX centrality/community and path features.
3.  GraphSAGE.
4.  R-GCN.
5.  Heterogeneous Graph Transformer.
6.  Temporal Graph Network or TGAT.

Evaluate inductive generalisation to unseen domains and unseen
organisations. Avoid graph leakage through shared infrastructure and
near-duplicate campaigns.

A shared CDN, cloud provider, certificate authority or analytics script
is not proof of malicious association. Edge semantics and context
matter.

------------------------------------------------------------------------

# 9. Contribution C5: Multi-context website integrity analysis

## 9.1 Problem

A site can present different content to different visitors. Automated
scanners may see a harmless page while a human user receives a malicious
page.

Potential context variables:

-   User-agent.
-   Viewport and device emulation.
-   Locale and language.
-   Referrer.
-   Cookie/session state.
-   Time.
-   Authentication state.
-   Network vantage point, where legally and ethically available.

## 9.2 Observation protocol

For each URL, define a bounded context matrix. Do not randomly vary
every possible parameter; use a controlled experimental design.

Example:

  -------------------------------------------------------------------------
  Profile     User-agent   Viewport    Locale      Referrer     Session
  ----------- ------------ ----------- ----------- ------------ -----------
  P1          Desktop      Desktop     en-US       Direct       Fresh
              Chromium                                          

  P2          Mobile       Mobile      en-US       Direct       Fresh
              emulation                                         

  P3          Desktop      Desktop     hi-IN       Direct       Fresh
              Chromium                                          

  P4          Desktop      Desktop     en-US       Controlled   Fresh
              Chromium                             referrer     

  P5          Desktop      Desktop     en-US       Direct       Repeat
              Chromium                                          session
  -------------------------------------------------------------------------

Compare:

-   DOM tree structure.
-   Page text.
-   Screenshot embedding.
-   Form action and method.
-   Script origins and hashes.
-   Redirect chain.
-   Network destinations.
-   Download events.
-   Sensitive-value destination observations.

## 9.3 Divergence score

A possible composite divergence statistic:

\[ D(x_i,x_j)= `\alpha `{=tex}D\_{DOM}+ `\beta `{=tex}D\_{text}+
`\gamma `{=tex}D\_{visual}+ `\delta `{=tex}D\_{flow}+
`\epsilon `{=tex}D\_{redirect} \]

The weights must be learned or validated. High divergence is not
equivalent to maliciousness. A legitimate website can localise or
personalise content. The most security-relevant divergence may be a
change in credential destination or service delegation, not a cosmetic
change.

## 9.4 Evaluation

Use controlled cloaking simulations and benign personalisation/A-B
testing cases. Measure:

-   Attack divergence detection.
-   Benign divergence false positives.
-   Detection latency.
-   Additional scan cost.
-   Stability across repeated runs.

------------------------------------------------------------------------

# 10. Cross-script and multilingual identity resolution

## 10.1 Problem

International impersonation can exploit Unicode confusables, IDNs, mixed
scripts, transliteration, language variation and visual similarity.

## 10.2 Pipeline

1.  Parse hostname according to IDNA rules.
2.  Preserve original Unicode and ASCII/Punycode representations.
3.  Apply Unicode normalisation for analysis, without destroying the
    original input.
4.  Compute confusable skeletons using Unicode Technical Standard #39.
5.  Detect mixed-script patterns.
6.  Compare organisation names using transliteration and phonetic
    variants.
7.  Extract brand mentions with multilingual NLP.
8.  Compare visual logos and page screenshots.
9.  Check whether the domain is authorised by the identity manifest.
10. Return an explanation showing which transformation or relationship
    triggered concern.

## 10.3 Important distinction

A mixed-script domain is not automatically malicious. A domain
containing non-Latin characters may be entirely legitimate. The model
must consider the organisation's language, registered domain, declared
international presence and user-facing context.

## 10.4 Evaluation

Stratify by script and language:

-   Latin.
-   Cyrillic.
-   Arabic.
-   Devanagari.
-   CJK.
-   Mixed-script.
-   Transliteration variants.

Report per-group precision, recall, calibration and false-positive rate.
Do not report only a pooled score that hides failure on minority
scripts.

------------------------------------------------------------------------

# 11. Optional extension: AI-agent-safe web trust

## 11.1 Why it matters

AI browser agents can read webpage content and take actions. A webpage
may include instructions that attempt to manipulate the agent, override
its task or cause unauthorised disclosure.

## 11.2 Proposed controls

-   Treat all webpage content as untrusted data, never as system
    instructions.
-   Separate page interpretation from privileged action execution.
-   Use allowlisted tool permissions.
-   Require explicit confirmation for sensitive actions.
-   Bind actions to verified identity and destination policies.
-   Prevent the page from selecting arbitrary network destinations.
-   Record the origin of instructions and data.
-   Detect suspicious hidden content and instruction patterns.
-   Test actual agent outcomes in a sandbox; string matching alone is
    not proof of successful prompt injection.

## 11.3 Research question

Can binding agent actions to verified organisational identity, scoped
service delegation and runtime destination policies reduce successful
webpage-originated policy violations in controlled agent tasks?

This should be a separate experimental track. It is not required to
validate the core website-trust thesis.

------------------------------------------------------------------------

# Part IV --- Detection and inference methods

# 12. Multimodal detection baselines

## 12.1 Modalities

  --------------------------------------------------------------------------
  Modality          Inputs            Baseline          Advanced candidate
  ----------------- ----------------- ----------------- --------------------
  URL               Characters,       Logistic          Character
                    tokens, host,     regression,       Transformer
                    path              LightGBM          

  Domain            RDAP, DNS, age,   Gradient boosting Temporal embeddings
                    ASN                                 

  HTML/DOM          Forms, scripts,   TF-IDF + tree     DOM-aware
                    text, links       model             Transformer

  Text              Page title,       TF-IDF, n-grams   DistilBERT/DeBERTa
                    labels, content                     

  Visual            Screenshot, logo, OCR + image       CLIP/ViT
                    layout            embeddings        

  Behaviour         Redirects,        Rules + sequence  Sequence model
                    requests, events  features          

  Graph             Relations and     Graph features +  R-GCN/HGT/TGN
                    histories         LightGBM          
  --------------------------------------------------------------------------

## 12.2 Fusion strategy

Do not begin with one enormous model.

Stage A: each modality produces:

``` json
{
  "modality": "visual",
  "model_version": "visual-baseline-0.1",
  "prediction": "possible_impersonation",
  "score": 0.82,
  "calibration_version": "visual-cal-0.1",
  "evidence_ids": ["ev-101", "ev-102"],
  "missing": false,
  "limitations": ["screenshot_only", "brand_reference_versioned"]
}
```

Stage B: combine outputs with a calibrated meta-classifier. Include
modality availability, source dependencies and missingness indicators.

Compare:

-   Early fusion.
-   Late fusion.
-   Hybrid fusion.
-   Gated fusion.
-   Cross-attention.

Use cross-attention only if the dataset and compute budget justify it
and it demonstrably improves generalisation.

## 12.3 Required ablations

-   URL only.
-   URL + domain.
-   URL + HTML.
-   URL + HTML + visual.
-   URL + HTML + visual + behaviour.
-   Multimodal without identity manifest.
-   Multimodal with identity manifest.
-   Fusion without source-dependency modelling.
-   Fusion with source-dependency modelling.

The ablation must isolate the incremental contribution of each
component.

# 13. Certificate and WebPKI intelligence

## 13.1 Core concepts

Study:

-   TLS 1.2 and TLS 1.3.
-   X.509 certificates.
-   Certification paths.
-   Root and intermediate CAs.
-   SAN and hostname matching.
-   Key usage and extended key usage.
-   Signature algorithms and public-key strength.
-   CRLs and OCSP.
-   OCSP stapling.
-   Certificate Transparency.
-   Signed Certificate Timestamps.
-   Inclusion and consistency proofs.
-   Root-store policy and distrust.
-   CA incidents and key generation.

## 13.2 Certificate observations

Record:

-   Subject and issuer.
-   SANs.
-   Serial number.
-   Fingerprint.
-   Not-before and not-after.
-   Public-key algorithm and size.
-   Signature algorithm.
-   Key usage and EKU.
-   Basic constraints.
-   Chain-building result.
-   Trust store and validation time.
-   Revocation evidence and retrieval time.
-   CT observations and log provenance.

A valid certificate means the TLS certificate passed the relevant
validation checks in the specified environment. It does not establish
that the organisation endorses the site.

## 13.3 Certificate Transparency

CT can support:

-   New certificate monitoring.
-   Unexpected subdomain discovery.
-   Issuer changes.
-   Certificate history.
-   Precertificate and SCT analysis.
-   Public auditing of certificate issuance.

CT does not by itself prevent misissuance, establish brand ownership or
guarantee immediate revocation propagation.

## 13.4 eMudhra case study

The supplied research notes identify the eMudhra TLS hierarchy incident
as a case study involving weak key generation and affected intermediate
CA keys, and mention subsequent browser-root-program changes. Before
presenting incident specifics, verify every date, number of affected
keys, affected certificates, browser policy and technical cause against
primary sources such as eMudhra, CERT-In and browser root-program
statements. Do not rely on a secondary summary for exact incident
claims.

Research questions:

1.  How can weak randomness undermine private-key security?
2.  What does an HSM protect, and what does it not protect if key
    generation is flawed?
3.  What is the distinction between intermediate revocation and root
    distrust?
4.  How do browser root programs distribute trust changes?
5.  How does CT support detection of unexpected issuance?
6.  How do clients differ in trust-store and distrust behaviour?

# 14. Domain, DNS and infrastructure intelligence

## 14.1 URL parsing

For each URL, preserve:

-   Original input.
-   Normalised representation.
-   Scheme.
-   Hostname.
-   Port.
-   Path.
-   Query keys (redacted values).
-   Fragment.
-   Embedded credentials detection.
-   Redirect chain.

Never discard the original URL. Normalisation can hide evidence such as
Unicode characters, encoding and unusual delimiters.

## 14.2 Domain intelligence

Investigate:

-   RDAP.
-   DNS A/AAAA.
-   NS.
-   MX. 
-   CNAME.
-   TXT.
-   SOA.
-   DNSSEC where available.
-   ASN and announced prefix.
-   IP reputation.
-   Registration and expiry metadata where available.
-   Passive DNS history where licensed.

IP geolocation is approximate and must not be used to infer an
attacker's physical location.

## 14.3 Similarity methods

Study:

-   Levenshtein distance.
-   Damerau--Levenshtein.
-   Jaro--Winkler.
-   Character n-grams.
-   Token similarity.
-   Unicode confusables.
-   Punycode and IDNA.
-   Script mixing.
-   Transliteration and phonetic similarity.
-   Brand-aware domain classification.

A similarity score is evidence, not proof of impersonation.

# 15. Web application security posture

The problem statement includes insecure configurations and exposed
services. Keep this distinct from phishing and identity.

Passive checks can include:

-   HSTS.
-   Content Security Policy.
-   X-Content-Type-Options.
-   Referrer-Policy.
-   Permissions-Policy.
-   Cookie flags where visible.
-   TLS protocol support.
-   Redirect behaviour.
-   Public DNS configuration.
-   Public server headers.

Use OWASP Top 10 and the OWASP Web Security Testing Guide as reference
frameworks.

Do not conduct intrusive active testing, exploitation or payload
injection against arbitrary public websites. Active assessment requires
explicit authorisation and a documented scope.

------------------------------------------------------------------------

# Part V --- Data, datasets and evidence governance

# 16. Dataset strategy

## 16.1 Dataset families from the research notes

  -----------------------------------------------------------------------
  Dataset/source          Main use                Caveat
  ----------------------- ----------------------- -----------------------
  PhishTank               Phishing URLs and       Reporting and
                          reports                 verification delay

  OpenPhish               Phishing intelligence   Access, licence and
                                                  redistribution limits

  URLhaus                 Malware distribution    Not a general phishing
                          URLs                    dataset

  PhreshPhish             Large URL--HTML         Large scale; inspect
                          phishing/benign dataset label and collection
                                                  methodology

  CompPhish               Multiple phishing and   Understand category
                          compromise categories   definitions and splits

  UCI Phishing Websites   Classic feature-based   Older feature
                          baseline                distribution

  Tranco                  Popular-domain sampling Popular does not mean
                                                  safe

  Common Crawl            Historical web content  Crawl bias,
                                                  availability and
                                                  timestamp issues

  Certificate             Certificate             Certificate presence is
  Transparency logs       observations            not maliciousness

  CISA KEV                Known exploited         Vulnerability context,
                          vulnerabilities         not phishing labels
  -----------------------------------------------------------------------

Before using any dataset, inspect its original paper/card, licence,
collection period, label definition, duplicate handling, class balance,
known leakage and allowed uses.

## 16.2 Dataset design

Create four linked but distinct datasets:

1.  **URL/domain dataset:** URL, registrable domain, RDAP/DNS
    observations and labels.
2.  **Page dataset:** HTML/DOM, text, screenshot, forms and visual
    references.
3.  **Runtime dataset:** browser event sequences and synthetic canary
    flows in controlled environments.
4.  **Identity/delegation dataset:** organisation claims, verified
    domains, service delegations, validity intervals and provenance.

Do not force every dataset into one binary phishing label. Some records
should be `unknown`, `compromised`, `identity_unverified`,
`policy_violation`, or `insufficient_evidence`.

## 16.3 Benchmark proposal: WITNESS

**WITNESS --- Web Identity, Trust, Interaction and Evidence Security
Benchmark**

Proposed benchmark scenarios:

-   Authentic organisation with authorised login service.
-   Impersonation domain with visually accurate page.
-   Valid TLS but unauthorised identity claim.
-   Legitimate website using third-party SSO.
-   Legitimate website using third-party payment service.
-   Compromised legitimate domain.
-   Unexpected sensitive-data destination.
-   Unicode and mixed-script impersonation.
-   Selectively served content.
-   Legitimate personalisation/A-B testing.
-   Expired or revoked delegation.
-   Malicious or compromised identity issuer.
-   Website containing agent-targeted prompt injection.
-   Shared CDN/hosting false association.
-   Stale threat intelligence report.

Each case should have a documented ground-truth basis, observation time,
source provenance, label rationale and adjudication status.

## 16.4 Annotation protocol

Every labelled case should include:

-   Case ID.
-   Claimed organisation.
-   Registrable domain.
-   First-seen time.
-   Observation time.
-   Label(s).
-   Evidence references.
-   Label source.
-   Confidence in label.
-   Reviewer identity or role (pseudonymous).
-   Disagreement record.
-   Last revalidation time.

Use at least two reviewers for difficult identity and compromise labels
where feasible. Resolve disagreements through an explicit adjudication
process.

## 16.5 Leakage prevention

Do not use only random row splits.

Required split designs:

-   Domain-disjoint.
-   Campaign-disjoint where labels allow.
-   Organisation-disjoint.
-   Chronological train/validation/test.
-   Cross-script or cross-language holdout.
-   Infrastructure-disjoint sensitivity analysis.

A temporal experiment should train on observations available before
cutoff (T_0), validate on (\[T_0,T_1)), and test on (\[T_1,T_2)).
Features must not include information published after the prediction
time.

------------------------------------------------------------------------

# Part VI --- Evaluation methodology

# 17. Research questions and hypotheses

  --------------------------------------------------------------------------
  ID                Research question  Null hypothesis   Alternative
                                                         hypothesis
  ----------------- ------------------ ----------------- -------------------
  RQ1               Does identity      Manifest evidence It improves
                    delegation improve does not improve  identity
                    impersonation      performance over  discrimination or
                    decisions?         domain/URL        reduces false
                                       baselines         positives on
                                                         legitimate
                                                         delegated services

  RQ2               Does runtime flow  Runtime           They detect policy
                    analysis detect    observations add  violations missed
                    credential theft   no useful         by
                    missed by static   detection         URL/visual/static
                    methods?           capability        HTML methods

  RQ3               Does adaptive      Adaptive policy   It reduces cost at
                    investigation      offers no         matched decision
                    reduce cost?       cost-quality      quality or improves
                                       advantage         quality at matched
                                                         cost

  RQ4               Does               Provenance and    It improves
                    provenance-aware   dependency        calibration,
                    reasoning improve  modelling do not  auditability or
                    calibration?       improve           robustness
                                       calibration       

  RQ5               Does multi-context Multiple contexts It detects
                    observation expose do not improve    additional
                    selective          detection over    controlled attacks
                    delivery?          one context       with acceptable
                                                         benign divergence
                                                         false positives

  RQ6               Does cross-script  Multilingual      It improves
                    identity           context adds no   per-script identity
                    resolution         benefit over      resolution and
                    generalise?        simple confusable reduces false
                                       detection         positives
  --------------------------------------------------------------------------

## 17.1 Baseline suite

At minimum:

-   Reputation-only.
-   URL-only Logistic Regression.
-   URL-only LightGBM/XGBoost.
-   URL + HTML model.
-   URL + HTML + screenshot model.
-   Behaviour-only baseline.
-   Fixed multimodal pipeline.
-   Graph-feature model.
-   Graph neural model, if justified.
-   Claim--Evidence reasoning without adaptive acquisition.
-   Full TRUSTTRACE.

Use comparable data, time windows and access conditions. Document when
external services use different coverage or labels.

## 17.2 Metrics

### Classification

-   Precision.
-   Recall.
-   F1.
-   PR-AUC.
-   ROC-AUC (secondary where class imbalance is high).
-   False-positive rate.
-   False-negative rate.
-   Detection rate at fixed FPR.
-   False positives per 10,000 benign cases.

### Calibration and uncertainty

-   Brier score.
-   Expected Calibration Error.
-   Reliability diagrams.
-   Selective risk versus coverage.
-   Abstention rate.
-   Calibration under temporal shift.

### Runtime flow

-   Flow detection precision/recall.
-   Recipient attribution accuracy.
-   Policy violation precision/recall.
-   Coverage by API/transport type.
-   Browser instrumentation overhead.

### Active investigation

-   Cost per case.
-   Number of actions.
-   Browser renders per case.
-   External queries.
-   Median and p95 latency.
-   Quality at fixed cost.
-   Cost at fixed quality.

### Operational

-   CPU and memory.
-   Failure rate.
-   Queue delay.
-   API availability.
-   Scan reproducibility.
-   Safe termination rate.

## 17.3 Base-rate analysis

Accuracy and even a strong F1 can be misleading when malicious URLs are
rare.

For prevalence (`\pi`{=tex}), true-positive rate (TPR), and
false-positive rate (FPR):

\[ Precision = `\frac{TPR\cdot\pi}`{=tex}
{TPR`\cdot`{=tex}`\pi`{=tex}+FPR`\cdot`{=tex}(1-`\pi`{=tex})} \]

Illustration: with 0.1% malicious prevalence, 95% recall and 0.1% FPR,
100,000 URLs contain about 100 malicious URLs. The system detects about
95 true positives but produces about 100 false positives. Precision is
therefore roughly 48.7%.

This demonstrates why a small FPR is not automatically small enough for
deployment.

## 17.4 Statistical discipline

-   Report confidence intervals, not only point estimates.
-   Use paired comparisons where appropriate.
-   Use bootstrap confidence intervals for metrics.
-   Report per-category and per-script results.
-   Report sample counts.
-   Predefine primary metrics.
-   Avoid tuning thresholds on the final test set.
-   Preserve a locked test set.
-   Record model/data versions and random seeds.
-   Report negative results and failed hypotheses.

## 17.5 Ablation plan

  -----------------------------------------------------------------------
  Ablation                Remove                  Question
  ----------------------- ----------------------- -----------------------
  A1                      Identity manifest       Does identity
                                                  delegation add value?

  A2                      Runtime flow analysis   Does runtime evidence
                                                  add value?

  A3                      Provenance/dependency   Does evidence quality
                          model                   matter?

  A4                      Temporal features       Does history add value?

  A5                      Adaptive policy         Does action selection
                                                  save cost?

  A6                      Multi-context scans     Does context diversity
                                                  reveal additional
                                                  attacks?

  A7                      Multilingual features   Does cross-script
                                                  context improve
                                                  generalisation?

  A8                      Graph model             Does the graph add
                                                  value beyond tabular
                                                  features?
  -----------------------------------------------------------------------

Do not keep a complex module if removing it does not measurably harm the
system or reduce useful capability.

------------------------------------------------------------------------

# Part VII --- Architecture and engineering specification

# 18. Logical architecture

``` mermaid
flowchart TD
    U[URL / Domain / Organisation Claim] --> API[API and Scan Orchestrator]
    API --> RES[Identity Claim Resolver]
    RES --> ID[Identity Manifest and Delegation Verifier]
    API --> COL[Evidence Collection Scheduler]
    COL --> DNS[DNS / RDAP / ASN]
    COL --> TLS[TLS / X.509 / CT]
    COL --> PAGE[Static HTML / DOM Analysis]
    COL --> BROWSER[Isolated Browser Worker]
    BROWSER --> VIS[Visual / OCR / Screenshot Analysis]
    BROWSER --> FLOW[Runtime Flow Observer]
    COL --> TI[Threat Intelligence Sources]
    ID --> GRAPH[Claim-Evidence Temporal Graph]
    DNS --> GRAPH
    TLS --> GRAPH
    PAGE --> GRAPH
    VIS --> GRAPH
    FLOW --> GRAPH
    TI --> GRAPH
    GRAPH --> POLICY[Identity and Data-Flow Policy Engine]
    GRAPH --> ACTIVE[Adaptive Investigator]
    ACTIVE --> COL
    POLICY --> DEC[Calibrated Decision and Abstention]
    DEC --> REPORT[Evidence-Backed Trust Report]
    REPORT --> MON[Optional Continuous Monitoring]
```

## 18.1 Service boundaries

Start with a modular monolith and a separately isolated browser worker.
Avoid premature microservices.

  -----------------------------------------------------------------------
  Module                              Responsibility
  ----------------------------------- -----------------------------------
  API                                 Authentication, input validation,
                                      scan request

  Orchestrator                        Job state, budgets, retries and
                                      workflow

  Identity resolver                   Extract claims and resolve
                                      organisation candidates

  Manifest verifier                   Verify signatures, scope, expiry
                                      and revocation

  DNS/RDAP collector                  Collect domain and network
                                      observations

  TLS/CT collector                    Validate certificate and retrieve
                                      CT evidence

  Static page analyser                Fetch and parse safe page content

  Browser worker                      Render and observe behaviour in
                                      isolation

  Flow observer                       Track synthetic canary and
                                      destination metadata

  ML service                          Feature extraction, inference and
                                      calibration

  Graph/evidence service              Store claims, observations and
                                      relations

  Policy engine                       Evaluate delegation and recipient
                                      policy

  Active investigator                 Select next action within budgets

  Report generator                    Evidence-linked output

  Monitoring service                  Re-observe authorised domains over
                                      time
  -----------------------------------------------------------------------

## 18.2 Recommended initial stack

  -----------------------------------------------------------------------
  Layer                   Initial choice          Rationale
  ----------------------- ----------------------- -----------------------
  Language                Python                  Research ecosystem and
                                                  rapid experimentation

  API                     FastAPI + Pydantic      Typed APIs and
                                                  validation

  Primary DB              PostgreSQL              Durable observations,
                                                  jobs and evidence

  Graph prototype         NetworkX                Fast research iteration

  Graph persistence       PostgreSQL relations    Avoid operational
                          initially; Neo4j later  complexity too early
                          if justified            

  ML                      scikit-learn, LightGBM, Strong tabular
                          XGBoost                 baselines

  Deep learning           PyTorch                 Flexible model research

  Browser                 Playwright + Chromium   Controlled browser
                                                  automation

  HTML                    BeautifulSoup/lxml      Static parsing

  Visual                  OpenCV + OCR library    Logo, screenshot and
                                                  text extraction

  Crypto                  Python cryptography,    X.509 and signature
                          OpenSSL                 operations

  DNS                     dnspython               DNS observations

  Queue                   Redis + Celery/RQ       Asynchronous scans

  Experiment tracking     MLflow                  Model and run tracking

  Data versioning         DVC or immutable        Reproducibility
                          dataset manifests       

  Containers              Docker                  Isolation and
                                                  deployment

  UI                      React/Next.js           Analyst and user-facing
                                                  views
  -----------------------------------------------------------------------

## 18.3 API contract examples

### Submit scan

``` http
POST /v1/scans
Content-Type: application/json
```

``` json
{
  "url": "https://example.test/login",
  "claimed_organisation": "Example University",
  "scan_profile": "passive_plus_controlled_browser",
  "purpose": "research",
  "consent_to_external_lookups": false
}
```

Response:

``` json
{
  "scan_id": "scan_01H...",
  "status": "queued",
  "created_at": "2026-11-09T10:00:00Z"
}
```

### Retrieve report

``` http
GET /v1/scans/{scan_id}/report
```

Response shape:

``` json
{
  "scan_id": "scan_01H...",
  "identity": {
    "status": "unverified",
    "confidence": null,
    "evidence_ids": ["ev-001", "ev-002"]
  },
  "behaviour": {
    "status": "suspicious",
    "risk_probability": 0.0,
    "evidence_ids": ["ev-010"]
  },
  "data_flow": {
    "status": "destination_unverified",
    "observed_flows": [],
    "evidence_ids": []
  },
  "evidence_quality": {
    "completeness": "partial",
    "freshness": "current",
    "limitations": ["browser_render_not_completed"]
  },
  "decision": {
    "label": "insufficient_evidence",
    "recommended_action": "do_not_enter_sensitive_information_until_verified"
  }
}
```

All numerical values above are placeholders. The API should not return
invented probabilities.

## 18.4 Core database entities

Suggested relational tables:

-   `organisations`
-   `identity_claims`
-   `identity_manifests`
-   `manifest_keys`
-   `delegations`
-   `manifest_status_events`
-   `scans`
-   `scan_actions`
-   `domains`
-   `urls`
-   `dns_observations`
-   `ip_observations`
-   `asn_observations`
-   `certificates`
-   `certificate_observations`
-   `ct_observations`
-   `webpage_captures`
-   `scripts`
-   `browser_observations`
-   `network_events`
-   `data_flows`
-   `evidence`
-   `evidence_dependencies`
-   `threat_reports`
-   `model_predictions`
-   `risk_assessments`
-   `analyst_reviews`
-   `audit_events`

Store raw observations separately from derived predictions. A new model
should be able to recalculate the decision without rewriting the
historical evidence.

## 18.5 Scan state machine

``` mermaid
stateDiagram-v2
    [*] --> Submitted
    Submitted --> Validating
    Validating --> Rejected: Invalid or unsafe target
    Validating --> Queued: Valid input
    Queued --> Collecting
    Collecting --> Investigating
    Investigating --> Collecting: More evidence needed
    Investigating --> Reasoning: Stop condition reached
    Reasoning --> Complete
    Reasoning --> Inconclusive
    Collecting --> Failed: Collection failure
    Failed --> Queued: Retry allowed
    Rejected --> [*]
    Complete --> [*]
    Inconclusive --> [*]
```

------------------------------------------------------------------------

# Part VIII --- Security, privacy and ethics

# 19. Threat model for TRUSTTRACE itself

The scanner is an attack surface. A malicious URL can attempt to
compromise the system that analyses it.

## 19.1 Threats

  -----------------------------------------------------------------------
  Threat                  Attack path             Required control
  ----------------------- ----------------------- -----------------------
  SSRF                    Submitted URL targets   Strict egress policy
                          internal services       and address validation

  DNS rebinding           Domain changes          Resolve and validate at
                          resolution after        connection time;
                          validation              pin/verify destination

  Redirect abuse          Public URL redirects to Revalidate every
                          private address         redirect

  IPv6 bypass             Internal IPv6           Validate IPv4 and IPv6
                          destination bypasses    ranges
                          IPv4 checks             

  Browser exploitation    Malicious page exploits Disposable isolated
                          browser                 worker, patched browser

  Resource exhaustion     Infinite pages, huge    CPU/memory/time/size
                          assets, scripts         quotas

  Download abuse          Page downloads          Disable or quarantine
                          executable payload      downloads

  Credential exposure     Scanner leaks internal  No secrets in browser
                          credentials             environment

  Cross-tenant leakage    One scan accesses       Tenant isolation and
                          another's data          access control

  Prompt injection        Page manipulates        Treat page content as
                          analysis agent          untrusted data

  Data poisoning          False reports influence Provenance,
                          model                   corroboration and
                                                  review

  API abuse               Repeated scans consume  Auth, quotas and rate
                          resources               limiting

  Log leakage             Query tokens or         Redaction and retention
                          canaries stored         controls
  -----------------------------------------------------------------------

## 19.2 Browser sandbox requirements

-   Run browser worker in a separate container/VM or stronger isolation
    boundary.
-   No production credentials or internal API tokens.
-   Deny access to private, loopback, link-local and metadata ranges.
-   Restrict outbound ports and protocols.
-   Revalidate all redirects and resolved IPs.
-   Enforce CPU, memory, wall-clock and page-size limits.
-   Disable downloads by default.
-   Use ephemeral profiles.
-   Destroy browser state after each scan.
-   Restrict filesystem access.
-   Keep browser and OS patched.
-   Record worker image and browser versions.
-   Use a kill switch and queue cancellation.

## 19.3 Privacy-by-design

Potentially sensitive data includes:

-   Full URLs with tokens.
-   Query parameters.
-   Screenshots with personal information.
-   Form values.
-   Cookies.
-   Session identifiers.
-   User-submitted reports.
-   IP addresses and account metadata.

Controls:

1.  Redact query values and URL fragments by default.
2.  Detect token-like values before external lookup.
3.  Never send private URLs to third-party scanners without explicit
    consent.
4.  Use synthetic canaries for runtime flow experiments.
5.  Do not store raw credentials or cookies.
6.  Minimise screenshots and apply redaction where needed.
7.  Define retention periods.
8.  Encrypt stored evidence.
9.  Enforce access controls and audit logs.
10. Support correction and removal of false reports where appropriate.

## 19.4 Legal and ethical review

The project is intended for research and defensive use. Before
real-world deployment, review applicable law and institutional
requirements.

For an India-based project, investigate:

-   Digital Personal Data Protection Act, 2023.
-   Digital Personal Data Protection Rules, 2025 and their commencement
    provisions.
-   CERT-In Directions, 2022 and applicability to the operating entity.
-   Information Technology Act, 2000.
-   Contractual and acceptable-use requirements of data providers.
-   Website terms and scanning permissions.
-   Responsible disclosure obligations.

Do not assume every public webpage can be freely scraped, stored or
redistributed. Consult institutional guidance or qualified counsel for
deployment decisions.

## 19.5 Responsible reporting

The system should provide:

-   Evidence-linked findings.
-   Confidence and limitations.
-   A correction process.
-   A false-positive appeal mechanism.
-   A responsible disclosure channel.
-   No unsupported accusations.
-   No public exposure of unverified personal or organisational
    allegations.

------------------------------------------------------------------------

# Part IX --- Data sources, standards and tooling

# 20. Standards and reference frameworks

These are foundational reading targets. Check the current revision
before implementation.

## WebPKI and certificates

-   RFC 5280 --- Internet X.509 Public Key Infrastructure Certificate
    and CRL Profile: https://www.rfc-editor.org/rfc/rfc5280
-   RFC 8446 --- TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
-   RFC 9162 --- Certificate Transparency Version 2.0:
    https://www.rfc-editor.org/rfc/rfc9162
-   RFC 6960 --- Online Certificate Status Protocol:
    https://www.rfc-editor.org/rfc/rfc6960
-   CA/Browser Forum: https://cabforum.org/
-   Common CA Database: https://www.ccadb.org/
-   Certificate Transparency: https://certificate.transparency.dev/

## Identity and cryptography

-   W3C Verifiable Credentials Data Model 2.0:
    https://www.w3.org/TR/vc-data-model-2.0/
-   JSON Web Signature: https://www.rfc-editor.org/rfc/rfc7515
-   COSE: https://www.rfc-editor.org/rfc/rfc9052
-   DNS-Based Authentication of Named Entities (DANE):
    https://www.rfc-editor.org/rfc/rfc6698
-   DNSSEC overview:
    https://www.icann.org/resources/pages/dnssec-what-is-it-2019-03-05-en

## Web security

-   OWASP Top 10: https://owasp.org/Top10/
-   OWASP Web Security Testing Guide:
    https://owasp.org/www-project-web-security-testing-guide/
-   OWASP SSRF Prevention Cheat Sheet:
    https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
-   MDN SSRF overview:
    https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/SSRF

## Threat intelligence

-   STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/
-   TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/
-   OASIS CTI documentation:
    https://oasis-open.github.io/cti-documentation/
-   MITRE ATT&CK: https://attack.mitre.org/
-   FIRST Traffic Light Protocol: https://www.first.org/tlp/

## Unicode and internationalisation

-   Unicode UTS #39 --- Unicode Security Mechanisms:
    https://www.unicode.org/reports/tr39/
-   IDNA standards: https://www.rfc-editor.org/rfc/rfc5890

## AI risk and security

-   NIST AI Risk Management Framework:
    https://www.nist.gov/itl/ai-risk-management-framework
-   OWASP Top 10 for LLM Applications:
    https://owasp.org/www-project-top-10-for-large-language-model-applications/

## India-specific references

-   CERT-In: https://www.cert-in.org.in/
-   MeitY: https://www.meity.gov.in/
-   India Code: https://www.indiacode.nic.in/

# 21. Threat intelligence sources and API constraints

Potential sources:

  -----------------------------------------------------------------------
  Source                  Use                     Important caveat
  ----------------------- ----------------------- -----------------------
  Google Safe Browsing /  Known unsafe URLs       Product and licence
  Web Risk                                        terms differ; do not
                                                  assume unrestricted
                                                  commercial use

  VirusTotal              Multi-engine URL/file   API quotas and
                          reputation              redistribution terms
                                                  apply

  urlscan.io              Browser-based URL scan  Public/private scan
                          results                 visibility and privacy
                                                  implications

  PhishTank               Phishing reports        Labels and verification
                                                  timing matter

  OpenPhish               Phishing intelligence   Access and commercial
                                                  terms must be checked

  URLhaus                 Malware distribution    Not interchangeable
                          URLs                    with phishing feeds

  ThreatFox               Malware-related         Understand IOC scope
                          indicators              and freshness

  MalwareBazaar           Malware hashes/samples  Avoid unsafe sample
                                                  handling

  AlienVault OTX          Community intelligence  Validate source quality

  Censys                  Internet asset and      Query scope, licence
                          certificate search      and rate limits

  Tranco                  Popular-domain list     Not a benign
                                                  ground-truth list

  Common Crawl            Historical page content Crawl coverage and
                                                  timestamp limitations
  -----------------------------------------------------------------------

Before integration, record:

-   Licence and permitted use.
-   API quota.
-   Rate limit.
-   Data retention restrictions.
-   Redistribution restrictions.
-   Whether submitted URLs are public.
-   Whether data can be used for model training.
-   Availability and failure behaviour.
-   Cost at projected volume.

Use adapters so the system does not depend on a single vendor.

------------------------------------------------------------------------

# Part X --- Product and operational design

# 22. User groups and report modes

## 22.1 Individual users

Use cases:

-   Suspicious scholarship links.
-   Fake internship/recruitment portals.
-   Banking impersonation.
-   QR-code destinations.
-   Payment portals.

Need: concise warning, strongest evidence and safe next action.

## 22.2 Universities

Use cases:

-   Admissions and fee portals.
-   Student authentication.
-   Recruitment and scholarship pages.
-   Third-party identity and payment providers.

Need: verified service inventory, delegation management, impersonation
monitoring and evidence history.

## 22.3 Banks and financial organisations

Use cases:

-   Lookalike banking domains.
-   Credential harvesting.
-   Fake payment pages.
-   Compromised official domains.

Need: low false-positive rate, rapid monitoring, workflow integration
and strong auditability.

## 22.4 Security analysts

Need:

-   Domain and certificate history.
-   DNS and ASN relationships.
-   Redirect chains.
-   Evidence provenance.
-   Graph pivots.
-   Model explanations.
-   Raw observation export.
-   STIX-compatible output.

## 22.5 Two report modes

**Simple mode**

-   Identity status.
-   Behaviour status.
-   Data-flow status.
-   Three strongest findings.
-   What was not checked.
-   Recommended safe action.

**Analyst mode**

-   Full certificate chain.
-   DNS/RDAP/ASN observations.
-   CT evidence.
-   Redirect chain.
-   Browser event timeline.
-   Form and endpoint analysis.
-   Claim--Evidence Graph.
-   Source provenance.
-   Model version and calibration.
-   Confidence, uncertainty and limitations.

------------------------------------------------------------------------

# Part XI --- Implementation roadmap

# 23. Development principles

1.  Build a reproducible research pipeline before a polished UI.
2.  Establish simple baselines before advanced models.
3.  Keep observations immutable and predictions versioned.
4.  Build the scanner security boundary before visiting arbitrary URLs.
5.  Use controlled environments for runtime canary experiments.
6.  Use domain-disjoint and chronological splits from the beginning.
7.  Do not build every extension simultaneously.
8.  Prefer a negative result over a fabricated performance claim.
9.  Track every model, dataset and configuration version.
10. Keep a clear boundary between research prototype and production
    security product.

## 23.1 Phase 0 --- Research freeze (Weeks 1--2)

Deliverables:

-   Literature matrix.
-   Competitor matrix.
-   Threat taxonomy.
-   Scope and non-goals.
-   Formal research questions.
-   Initial novelty statement.
-   Data governance plan.
-   Scanner threat model.
-   Dataset feasibility review.

Exit criteria:

-   Closest prior work identified for every proposed contribution.
-   No unsupported novelty claims.
-   Evaluation protocol drafted before model training.

## 23.2 Phase 1 --- Baseline detection and safe collection (Weeks 3--4)

Build:

-   URL parser and normaliser.
-   Domain extraction.
-   DNS/RDAP collector.
-   TLS certificate inspector.
-   Static HTML parser.
-   Basic reputation adapters.
-   Safe URL-fetching boundary.
-   URL-only ML baseline.

Deliverables:

-   Baseline dataset manifest.
-   Feature schema.
-   API contracts.
-   Unit tests.
-   Initial benchmark results.

## 23.3 Phase 2 --- Claim--Evidence data model (Weeks 5--6)

Build:

-   Organisation and identity-claim schema.
-   Evidence objects.
-   Source provenance.
-   Temporal observations.
-   Basic graph construction.
-   Rule-based support/contradiction engine.
-   Evidence-linked report.

Deliverables:

-   Graph schema.
-   Example cases.
-   Provenance audit.
-   Graph-vs-tabular baseline.

## 23.4 Phase 3 --- Identity manifest prototype (Weeks 7--8)

Build:

-   Manifest schema.
-   Signature verification.
-   Key discovery prototype.
-   Expiry and revocation checks.
-   Scoped delegation.
-   Manually verified test organisations.

Deliverables:

-   Signed example manifests.
-   Invalid/revoked/expired test cases.
-   Trust bootstrap threat model.
-   Delegation evaluation.

## 23.5 Phase 4 --- Runtime data-flow observer (Weeks 9--10)

Build only in a controlled lab:

-   Disposable browser worker.
-   Synthetic canary input.
-   Form submission observer.
-   Fetch/XHR observation.
-   WebSocket metadata observation.
-   Redirect and endpoint capture.
-   Policy comparison.
-   Secret redaction.

Deliverables:

-   Controlled test suite.
-   Flow attribution results.
-   Browser overhead measurements.
-   Security review of worker isolation.

## 23.6 Phase 5 --- Adaptive investigator (Weeks 11--12)

Build:

-   Candidate action catalogue.
-   Cost model.
-   Privacy/safety constraints.
-   Greedy information-gain baseline.
-   Decision-loss policy.
-   Stop/abstain criteria.

Deliverables:

-   Fixed-vs-adaptive evaluation.
-   Cost-quality curves.
-   Failure cases.
-   Action-selection audit trail.

## 23.7 Phase 6 --- Robustness and internationalisation (Weeks 13--16)

Build:

-   Multi-context test profiles.
-   Controlled cloaking cases.
-   Unicode/IDN pipeline.
-   Multilingual organisation-name resolution.
-   Benign divergence dataset.
-   Cross-script evaluation.

Deliverables:

-   Per-context and per-script results.
-   False-positive analysis.
-   Robustness report.

## 23.8 Phase 7 --- Research release (Weeks 17--20)

Build:

-   Analyst UI.
-   Reproducible experiment scripts.
-   Benchmark documentation.
-   Model cards.
-   Data cards.
-   Threat model.
-   System security tests.
-   Final paper and presentation.

Deliverables:

-   Versioned research prototype.
-   WITNESS benchmark release, if licences and ethics permit.
-   Reproducible results.
-   Demo scenarios.
-   Research paper draft.
-   Limitations and responsible-use statement.

**Timeline note:** This is a research plan, not a promise. A smaller
team or limited compute should narrow the scope to C1 and C2, with C3 as
a research extension. A larger team can parallelise the benchmark,
identity manifest and browser instrumentation.

# 24. Suggested team structure

For a five-person team:

  -----------------------------------------------------------------------
  Role                    Responsibility          Primary deliverables
  ----------------------- ----------------------- -----------------------
  Research lead           Literature, hypotheses, Research protocol,
                          evaluation and paper    novelty matrix, paper

  Identity/crypto lead    Manifest, delegation,   Identity verifier and
                          PKI and CT              cryptographic tests

  Browser/security lead   Sandbox, Playwright,    Safe browser worker and
                          runtime flows           flow observer

  ML/graph lead           Baselines, graph,       Models, graph reasoning
                          calibration and active  and experiments
                          policy                  

  Backend/data lead       API, DB, orchestration, Platform integration
                          evidence store          and reproducibility
  -----------------------------------------------------------------------

For a smaller team, merge roles but do not remove security review or
evaluation ownership.

# 25. Immediate 14-day action plan

  ------------------------------------------------------------------------
                           Day Task                  Output
  ---------------------------- --------------------- ---------------------
                             1 Freeze research       One-page problem
                               question and scope    statement

                             2 Read PhishIntention   Prior-art notes
                               and Phishpedia        

                             3 Read PhishLumos and   Overlap matrix
                               closest graph work    

                             4 Read W3C VC 2.0 and   Identity manifest
                               signing standards     design

                             5 Read RFC 5280, RFC    PKI design notes
                               8446 and RFC 9162     

                             6 Read OWASP SSRF       Scanner threat model
                               guidance              

                             7 Define WITNESS labels Annotation
                               and scenarios         specification

                             8 Define URL/domain     Feature schema
                               baseline              

                             9 Implement safe URL    Collector prototype
                               parsing and DNS/TLS   
                               collection            

                            10 Implement evidence    Evidence store
                               schema and immutable  
                               observations          

                            11 Implement identity    Manifest prototype
                               claim and delegation  
                               model                 

                            12 Create controlled     Synthetic test pages
                               browser lab           

                            13 Instrument forms and  Flow observer
                               network destinations  prototype

                            14 Run first ablation    Baseline report and
                               and review            revised plan
  ------------------------------------------------------------------------

------------------------------------------------------------------------

# Part XII --- Research management and reproducibility

# 26. Required research artefacts

Maintain these living documents:

1.  Problem analysis.
2.  Literature review.
3.  Competitor and capability matrix.
4.  Research novelty matrix.
5.  Threat model.
6.  System architecture.
7.  Identity manifest specification.
8.  Claim--Evidence Graph schema.
9.  Runtime data-flow specification.
10. Dataset and annotation card.
11. Experiment protocol.
12. Model cards.
13. Privacy and ethics review.
14. API and database specification.
15. Security test report.
16. Limitations and known failures.
17. Reproducibility instructions.
18. Research paper and presentation.

## 26.1 Experiment record template

``` yaml
experiment_id: RQ2-E03
hypothesis: "Runtime flow analysis detects unauthorised recipients missed by static analysis."
dataset_version: "witness-v0.1"
train_split: "not_applicable"
test_split: "controlled-lab-v0.1"
model_version: "flow-observer-0.1"
browser_version: "record-exact-version"
configuration_hash: "sha256:..."
random_seed: 42
primary_metric: "policy_violation_recall"
secondary_metrics:
  - "policy_violation_precision"
  - "recipient_attribution_accuracy"
  - "browser_overhead_ms"
result: "pending"
limitations:
  - "controlled pages only"
  - "synthetic canary values"
```

## 26.2 Reproducibility checklist

-   [ ] Dataset source and licence recorded.
-   [ ] Collection timestamps preserved.
-   [ ] Domain and campaign leakage checked.
-   [ ] Data transformations versioned.
-   [ ] Train/validation/test splits frozen.
-   [ ] Model and dependency versions pinned.
-   [ ] Random seeds recorded.
-   [ ] Experiment configurations saved.
-   [ ] Metrics and confidence intervals exported.
-   [ ] Failed runs retained.
-   [ ] Scanner/browser versions recorded.
-   [ ] External API responses cached only where permitted.
-   [ ] Personal and secret data redacted.

------------------------------------------------------------------------

# Part XIII --- Risks, limitations and open research problems

# 27. Fundamental limitations

  -----------------------------------------------------------------------
  Limitation              Why it matters          Mitigation
  ----------------------- ----------------------- -----------------------
  No universal identity   Organisations may not   Support unverified
  root                    publish manifests       state and independent
                                                  evidence

  Compromised issuer key  Signed manifest can     Rotation, revocation,
                          become malicious        threshold approval and
                                                  transparency

  Legitimate third-party  Recipient may be        Scoped delegation and
  providers               external but authorised purpose-aware policy

  Compromised legitimate  Identity can be genuine Separate identity and
  website                 while behaviour is      behaviour decisions
                          malicious               

  Incomplete browser      Some flows remain       State observation
  observation             invisible               boundary and coverage

  Selective delivery      Scanner may not see     Multi-context testing
                          target experience       and repeat observations

  Anti-bot controls       Automated scans may     Mark inaccessible; do
                          fail                    not infer benignness

  Shared infrastructure   Graph edges can create  Edge semantics, context
                          false association       and counterfactual
                                                  tests

  Stale threat reports    Historical              Preserve event time and
                          maliciousness may not   current status
                          be current              separately

  Dataset bias            Training labels may     Unseen organisation and
                          overrepresent known     script holdouts
                          brands                  

  Concept drift           Attacker behaviour      Temporal monitoring and
                          changes                 controlled retraining

  False positives         Legitimate sites may be Abstention, calibration
                          harmed                  and appeals

  Privacy restrictions    URLs and screenshots    Redaction, consent and
                          can contain secrets     retention limits

  Model explanation       LLMs may invent         Evidence-grounded
  errors                  rationales              templates and
                                                  deterministic
                                                  provenance
  -----------------------------------------------------------------------

# 28. Open research questions worth future papers

1.  Can organisational identity delegation be made usable without a
    universal identity provider?
2.  How should trust be assigned to an issuer when the issuer's own
    domain is compromised?
3.  How can runtime data-flow monitoring attribute transformed or
    encoded canary values?
4.  Can the system detect sensitive flows through service workers and
    complex cross-origin frames?
5.  What is the minimum context set needed to detect selective delivery?
6.  Can adaptive investigation be formulated as a constrained partially
    observable decision process?
7.  How should evidence freshness differ across DNS, certificates,
    signed manifests and threat reports?
8.  Can source-dependency modelling reduce overconfidence without
    sacrificing recall?
9.  Can graph learning generalise to unseen organisations and
    infrastructure without learning hosting-provider shortcuts?
10. How can cross-script identity resolution avoid unfairly penalising
    legitimate internationalised domains?
11. Can AI-agent actions be cryptographically or policy-bound to
    verified destinations?
12. How can collaborative threat intelligence resist Sybil reports and
    model poisoning without exposing private observations?

------------------------------------------------------------------------

# Part XIV --- Final research positioning

# 29. Recommended paper framing

**Title:**

> TRUSTTRACE: Verifiable Web Identity and Runtime Data-Flow Assurance
> Against Adaptive Digital Impersonation

**Abstract draft:**

Web phishing and digital impersonation increasingly exploit the gap
between a website's visible identity and the services that actually
process user information. Conventional detection systems commonly
classify URLs, reputation indicators, page content or screenshots, but
these observations do not necessarily establish whether an organisation
authorised the domain or whether sensitive information is transmitted to
an approved recipient. This work proposes TRUSTTRACE, an
evidence-centric framework for web identity and runtime trust assurance.
TRUSTTRACE represents organisational identity claims, scoped service
delegations, digital infrastructure and browser observations in a
provenance-aware temporal Claim--Evidence Graph. A runtime observer
records controlled browser interactions using synthetic canary values
and evaluates observed destinations against purpose-scoped delegation
policies. A cost-aware investigation policy selects additional
evidence-gathering actions under latency, privacy and scanner-safety
constraints. The system produces separate identity, behavioural,
data-flow and evidence-quality assessments, including an abstention
outcome when evidence is insufficient. We propose WITNESS, a benchmark
of controlled identity, delegation, impersonation, compromise and
data-flow scenarios, and an evaluation protocol using domain-disjoint
and chronological splits. The central hypotheses are that runtime
destination evidence can expose attacks missed by static inspection, and
that adaptive evidence acquisition can reduce investigation cost without
degrading decision quality. These hypotheses will be tested against URL,
reputation, static multimodal and fixed-scan baselines.

**Important:** This is a proposal abstract. Replace future-tense
hypotheses with results only after experiments are complete.

## 29.1 Contribution statement template

A defensible paper should claim contributions in this form:

1.  We formalise \_\_\_\_\_\_ as \_\_\_\_\_\_.
2.  We design \_\_\_\_\_\_ to address \_\_\_\_\_\_.
3.  We implement \_\_\_\_\_\_ with an explicit observation/security
    boundary.
4.  We construct \_\_\_\_\_\_ with documented labels and provenance.
5.  We evaluate against \_\_\_\_\_\_ under \_\_\_\_\_\_ splits and
    report \_\_\_\_\_\_.
6.  We release \_\_\_\_\_\_ where legal, ethical and licensing
    constraints permit.

Do not write "the first system" unless a thorough literature review
supports that exact claim.

## 29.2 Questions a serious reviewer will ask

-   What does your system establish that PhishIntention does not?
-   What does it add beyond PhishLumos' infrastructure and evidence
    investigation?
-   How is the organisation's identity issuer authenticated?
-   What happens when the identity issuer is compromised?
-   How do you distinguish a legitimate third-party authentication
    provider from an attacker?
-   Can your runtime observer identify flows through JavaScript and
    service workers?
-   What is your browser observation boundary?
-   Does adaptive investigation outperform a fixed scanner?
-   How do you prevent graph leakage?
-   How do you evaluate previously unseen organisations?
-   What is your false-positive rate on legitimate sites with complex
    delegation?
-   How do you handle websites that cannot be rendered?
-   How do you protect the scanner from SSRF and malicious browser
    content?
-   How do you avoid storing secrets?
-   Can another research group reproduce your benchmark and results?

The project is ready for a serious research discussion only when these
questions have evidence-backed answers.

# 30. Final recommendation

The strongest version of TRUSTTRACE is not the one with the most models,
APIs or dashboard panels.

It is the one that establishes a new, testable security capability:

**A website should not be trusted merely because it looks authentic, has
HTTPS or appears on no blacklist. Its claimed identity, delegated
services and observed handling of sensitive information should be
evaluated against traceable, time-aware evidence.**

Build the project around three primary pillars:

1.  **Verifiable organisational identity and scoped service
    delegation.**
2.  **Runtime sensitive-data-flow assurance using synthetic values in
    controlled environments.**
3.  **Adaptive, provenance-aware investigation with explicit uncertainty
    and safety constraints.**

Use multimodal ML, temporal graphs, certificate intelligence,
multilingual analysis and AI-agent security as supporting components or
carefully scoped extensions.

The standard for success is not a target accuracy chosen in advance. It
is a reproducible demonstration that the proposed evidence and
investigation methods provide a capability or cost-quality improvement
over strong baselines, while keeping false positives, privacy risk and
scanner risk under control.

------------------------------------------------------------------------

# Appendix A --- Compact glossary

  Term     Meaning
  -------- --------------------------------------------------------
  ASN      Autonomous System Number
  CA       Certificate Authority
  CT       Certificate Transparency
  DOM      Document Object Model
  DNS      Domain Name System
  IDN      Internationalised Domain Name
  IOC      Indicator of Compromise
  JWS      JSON Web Signature
  PKI      Public Key Infrastructure
  RDAP     Registration Data Access Protocol
  SAN      Subject Alternative Name
  SSRF     Server-Side Request Forgery
  STIX     Structured Threat Information Expression
  TAXII    Trusted Automated Exchange of Intelligence Information
  TLS      Transport Layer Security
  WIM      Web Identity Manifest
  X.509    Public-key certificate format
  OOD      Out-of-distribution
  ECE      Expected Calibration Error
  PR-AUC   Area under the Precision--Recall curve

# Appendix B --- Core formulas

## B.1 Precision

\[ Precision=`\frac{TP}{TP+FP}`{=tex} \]

## B.2 Recall

\[ Recall=`\frac{TP}{TP+FN}`{=tex} \]

## B.3 F1

\[
F1=2`\cdot`{=tex}`\frac{Precision\cdot Recall}{Precision+Recall}`{=tex}
\]

## B.4 False-positive rate

\[ FPR=`\frac{FP}{FP+TN}`{=tex} \]

## B.5 Brier score

For binary outcomes and predicted probabilities (p_i):

\[ BS=`\frac{1}{N}`{=tex}`\sum`{=tex}\_{i=1}^{N}(p_i-y_i)^2 \]

## B.6 Expected calibration error

\[ ECE=`\sum`{=tex}\_{b=1}\^{B}`\frac{|S_b|}{N}`{=tex}
`\left`{=tex}\|`\operatorname{acc}`{=tex}(S_b)-`\operatorname{conf}`{=tex}(S_b)`\right`{=tex}\|
\]

## B.7 Evidence freshness

\[ f(`\Delta `{=tex}t)=e\^{-`\lambda`{=tex}`\Delta `{=tex}t} \]

Use only where an exponential decay model is defensible for the evidence
type.

## B.8 Multi-context divergence

\[ D(x_i,x_j)= `\alpha `{=tex}D\_{DOM}+ `\beta `{=tex}D\_{text}+
`\gamma `{=tex}D\_{visual}+ `\delta `{=tex}D\_{flow}+
`\epsilon `{=tex}D\_{redirect} \]

Weights must be empirically validated.

## B.9 Cost-aware action selection

\[ a\^\* = `\arg`{=tex}`\min`{=tex}\_{a`\in`{=tex}`\mathcal{A}`{=tex}}
`\left[
\mathbb{E}[L(Y,\hat Y\mid E,E_a)]`{=tex}+`\lambda`{=tex}\_c c(a)
+`\lambda`{=tex}\_p r_p(a) +`\lambda`{=tex}\_s r_s(a) `\right`{=tex}\]
\]

## B.10 Data-flow policy violation

\[ V(f,a,o)= `\mathbb{1}`{=tex}`\left[R(f)\notin P_o(a)\right]`{=tex}\]

These formulas define candidate methods and metrics; they do not imply
that a particular model or system has already achieved a result.

# Appendix C --- Research source register

The following links are starting points. Verify publication metadata,
versions, access dates and exact claims before citing them in a paper.

## Research papers and datasets

-   Phishpedia (USENIX Security 2021):
    https://www.usenix.org/conference/usenixsecurity21/presentation/lin
-   PhishIntention (USENIX Security 2022):
    https://www.usenix.org/conference/usenixsecurity22/presentation/liu-ruofan
-   PhishLumos (2026 IEEE Access; verify final bibliographic metadata):
    https://doi.org/10.1109/ACCESS.2026.3696597
-   PhreshPhish dataset: https://huggingface.co/datasets/ had a space in
    some copied references; locate the exact dataset card and canonical
    repository before citing.
-   CompPhish: locate and verify the original dataset paper/card before
    use.
-   PHILTER (USENIX Security 2026): verify the official proceedings page
    and exact paper title before citation.
-   CrossPhire: locate the original paper and benchmark version.
-   Page Transparency: locate the original paper and protocol
    specification.

## Official technical references

-   W3C VC Data Model 2.0: https://www.w3.org/TR/vc-data-model-2.0/
-   RFC 5280: https://www.rfc-editor.org/rfc/rfc5280
-   RFC 8446: https://www.rfc-editor.org/rfc/rfc8446
-   RFC 9162: https://www.rfc-editor.org/rfc/rfc9162
-   RFC 6960: https://www.rfc-editor.org/rfc/rfc6960
-   Unicode UTS #39: https://www.unicode.org/reports/tr39/
-   OWASP SSRF Prevention:
    https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
-   OWASP WSTG:
    https://owasp.org/www-project-web-security-testing-guide/
-   MITRE ATT&CK: https://attack.mitre.org/
-   STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/
-   TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/

------------------------------------------------------------------------

**End of research master document.**

*Version 1.0 is a research blueprint. It must be updated as literature
review, implementation, evaluation and expert review produce new
evidence.*
