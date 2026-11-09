# TRUSTTRACE research synthesis

## What the research supports
Phishing detection is not a single homogeneous prediction task. URL lexical classification, brand lookalikes, page content, visual impersonation, infrastructure, TLS/certificate properties, runtime behavior and threat-feed matches have different evidence and labels. Collapsing these into an unexplained binary “safe/malicious” score risks overclaiming.

The TRUSTTRACE master research document proposes a broader system: organisational identity and service delegation; runtime observation of sensitive-data destinations; a time-indexed Claim–Evidence Graph; adaptive evidence acquisition; cross-context checks; and explicit abstention. These are a long-term research programme, not a credible all-at-once hackathon commitment.

The build specification’s useful design principle is to separate cryptographic verification, deterministic policy, learned model outputs and final decision. Evidence should be immutable or traceable; interpretations should be versioned. Missing observations should remain missing rather than becoming “safe.”

## What the archive audit cautions against
The supplied audit identifies substantial existing research in URL classifiers, certificate transparency phishing detection, certificate anomaly detection, CT plus passive DNS, visual detection, and provenance/intelligence tooling. It flags generic CT+passive-DNS scoring as weak novelty, including close patent overlap and access/licensing risks for historical passive DNS. It also notes evidence-trail and bibliographic issues in the earlier synthesis. These warnings mean the team should not repeat unsupported “first system” claims.

The audit’s alternative PhishShift recommendation is an evaluation-focused concept: compare random-row with domain/source-separated phishing-URL evaluation, subject to a data gate. TRUSTTRACE is retained here as the chosen product concept; the PhishShift recommendation is preserved as a material strategic caveat and possible fallback, not silently substituted for the team’s project.

## Hackathon contribution boundary
Build one coherent scan-to-report journey. It can combine safe URL normalization, bounded TLS/DNS/redirect/header observations, transparent rules, evidence provenance, uncertainty, and a small community report loop. This demonstrates system integration and responsible interpretation. It does not establish superior detection.

A narrowly testable extension is evidence-quality triage: compare a flat rule summary with a result that exposes evidence freshness, missing checks, source dependence and contradiction. Measure whether a reviewer can interpret cases more accurately or quickly on a small controlled set. This is a proposed experiment; do not claim improved outcomes until it is run and reported.

## Core product distinctions
- **TLS validity:** hostname/certificate technical result, not organisational endorsement.
- **Identity assurance:** evidence that the site is authorised to represent a named service; generally unavailable for arbitrary organizations unless a trustworthy authority/delegation record exists.
- **Observed behavior:** only what the defined scan actually saw; a page not exhibiting malicious behavior in one visit is not cleared.
- **Feed match:** provider assertion with its own timestamp, semantics and limitations. Feed absence is not a benign label.
- **Community report:** unverified until independently corroborated/reviewed; repeat/copy submissions are not independent confirmation.
- **Model score:** model output, not verified probability unless calibration has been properly evaluated for the target population.
- **Unknown/inconclusive:** valid output when evidence is absent, stale, conflicting or collection fails.

## First-pass feature priorities
1. URL syntax, normalized host, IDNA/confusable signals and registrable-domain grouping.
2. Safe redirect chain and DNS/TLS observations with resolver/source and timestamp.
3. Certificate validity and hostname match, clearly separated from identity.
4. Small transparent rules and explicit evidence references.
5. Optional headers/static form metadata only if safe and feasible.
6. Community report status and source dependence.

Defer model training, visual embeddings, deep learning, broad crawling, active vulnerability probing, passive-DNS dependency, adaptive agents and production identity delegation until data, time and safety conditions are met.

## Evaluation discipline
If a model is evaluated, preserve exact dataset version/hash, source terms, collection time, label policy and grouping. Deduplicate exact/near duplicates and group by registrable domain to reduce leakage. Use source or temporal holdout only when metadata support those claims. Report prevalence, sample counts, precision, recall, F1, false-positive rate and PR-AUC; include uncertainty or limitations. Separate controlled synthetic fixtures from real-world performance claims. A negative result is reportable.

## Vocabulary for UI and pitch
Prefer “known feed match,” “suspicious signal,” “identity unverified,” “no threat observed within these checks,” and “inconclusive.” Avoid “safe,” “guaranteed,” “all phishing,” “99% accurate,” and “first ever” unless evidence directly supports the exact claim.
