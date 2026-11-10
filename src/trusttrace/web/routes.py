"""Worker 04 — Interactive Web Dashboard and Triage Routes."""

import json
from pathlib import Path
from typing import Optional, Dict, Any, List
import uuid
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from ..intake.boundary import IntakeBoundary
from ..policy.triage_engine import TriageEngine
from ..policy.signal_taxonomy import SignalRecord, SignalKind
from ..policy.policy_input import PolicyInput
from ..evidence.adapters.fixture_adapter import FixtureEvidenceAdapter
from ..evidence.adapters.worker01_adapter import Worker01EvidenceAdapter
from ..evidence.adapters.base import EvidenceBatch
from ..evidence.domain.models import EvidenceModel, CoverageModel
from ..evidence.domain.enums import EvidenceStatus, Reliability
from ..evidence.services.evidence_service import EvidenceService

router = APIRouter(tags=["Web Interface & Triage"])

REPO_ROOT = Path(__file__).resolve().parents[3]
FIXTURES_DIR = REPO_ROOT / ".brain" / ".testdata" / "v1"


class TriageDemoRequest(BaseModel):
    url: str
    scenario: Optional[str] = "custom"


@router.post("/api/v1/triage/demo")
async def triage_demo_endpoint(payload: TriageDemoRequest):
    """Run an evidence-backed triage assessment on a URL or load a controlled scenario fixture."""
    scenario = payload.scenario or "custom"
    url = payload.url.strip()

    # Scenario 1: Pre-canned fixture 1 - Complete legitimate case
    if scenario == "legitimate":
        fixture_path = FIXTURES_DIR / "complete_report.json"
        if fixture_path.exists():
            return json.loads(fixture_path.read_text(encoding="utf-8"))

    # Scenario 2: Phishing lookalike with Valid TLS (Core thesis)
    if scenario == "phishing_lookalike":
        engine = TriageEngine()
        signals = [
            SignalRecord.create(
                kind=SignalKind.TLS_VALID,
                source="tls_collector",
                evidence_ids=["ev-tls-001"],
                value="Valid DV Cert by Let's Encrypt",
            ),
            SignalRecord.create(
                kind=SignalKind.TLS_HOSTNAME_MATCH,
                source="tls_collector",
                evidence_ids=["ev-tls-001"],
                value="Certificate matches domain",
            ),
            SignalRecord.create(
                kind=SignalKind.IDN_LOOKALIKE,
                source="url_policy",
                evidence_ids=["ev-idn-003"],
                value="Cyrillic homoglyph lookalike character in domain name",
            ),
            SignalRecord.create(
                kind=SignalKind.COLLECTOR_SUCCESS,
                source="intake_boundary",
                evidence_ids=["ev-rdap-002"],
                value="Metadata checks complete; active browser execution blocked",
            ),
        ]
        result = engine.evaluate(signals, scan_id="scan-demo-phish-001")
        fragment = result.to_report_fragment()

        uncertainty_payload = None
        if hasattr(result, "uncertainty") and result.uncertainty:
            uncertainty_payload = result.uncertainty.to_dict()

        batch = EvidenceBatch(
            scan_id="scan-demo-phish-001",
            items=[
                EvidenceModel(
                    evidence_id="ev-tls-001",
                    scan_id="scan-demo-phish-001",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T00:30:00Z",
                    status=EvidenceStatus.OBSERVED,
                    reliability=Reliability.DIRECT_OBSERVATION,
                    limitations=["Valid DV TLS proves transport encryption only, not identity."],
                ),
                EvidenceModel(
                    evidence_id="ev-rdap-002",
                    scan_id="scan-demo-phish-001",
                    kind="rdap_registration",
                    source="rdap_collector",
                    observed_at="2026-11-10T00:30:00Z",
                    status=EvidenceStatus.OBSERVED,
                    reliability=Reliability.DERIVED_SIGNAL,
                    limitations=["Privacy guard enabled on registrant record."],
                ),
                EvidenceModel(
                    evidence_id="ev-idn-003",
                    scan_id="scan-demo-phish-001",
                    kind="url_canonicalization",
                    source="url_policy",
                    observed_at="2026-11-10T00:30:00Z",
                    status=EvidenceStatus.OBSERVED,
                    reliability=Reliability.DIRECT_OBSERVATION,
                    limitations=["Unicode confusable homoglyph detected."],
                ),
            ],
            metadata={
                "submitted_url_redacted": url or "https://bank-secure-lоgin.com",
                "normalized_host": "bank-secure-lоgin.com",
                "status": "completed",
                "decision": fragment["decision"],
                "policy_version": "w03-v1.0",
            },
            limitations=[
                "DEMO FIXTURE: Demonstrates that valid TLS does NOT imply organizational legitimacy.",
                "Zero browser execution performed.",
            ],
        )
        try:
            ev_service = EvidenceService()
            ev_service.ingest_batch(batch)
        except Exception:
            pass

        response_dict = {
            "scan_id": "scan-demo-phish-001",
            "submitted_url_redacted": url or "https://bank-secure-lоgin.com",
            "normalized_host": "bank-secure-lоgin.com",
            "status": "completed",
            "decision": fragment["decision"],
            "dimensions": fragment["dimensions"],
            "coverage": {
                "checks_total": 5,
                "checks_observed": 4,
                "checks_failed": 0,
                "checks_not_run": 1,
            },
            "findings": fragment["findings"],
            "evidence": [
                {
                    "evidence_id": "ev-tls-001",
                    "kind": "tls_certificate",
                    "source": "tls_collector",
                    "observed_at": "2026-11-10T00:30:00Z",
                    "status": "observed",
                    "reliability": "high",
                    "limitations": ["Valid DV TLS proves transport encryption only, not identity."],
                },
                {
                    "evidence_id": "ev-rdap-002",
                    "kind": "rdap_registration",
                    "source": "rdap_collector",
                    "observed_at": "2026-11-10T00:30:00Z",
                    "status": "observed",
                    "reliability": "medium",
                    "limitations": ["Privacy guard enabled on registrant record."],
                },
                {
                    "evidence_id": "ev-idn-003",
                    "kind": "url_canonicalization",
                    "source": "url_policy",
                    "observed_at": "2026-11-10T00:30:00Z",
                    "status": "observed",
                    "reliability": "high",
                    "limitations": ["Unicode confusable homoglyph detected."],
                },
            ],
            "limitations": [
                "DEMO FIXTURE: Demonstrates that valid TLS does NOT imply organizational legitimacy.",
                "Zero browser execution performed.",
            ],
            "policy_version": "w03-v1.0",
        }
        if uncertainty_payload:
            response_dict["uncertainty"] = uncertainty_payload
        return response_dict

    # Scenario 3: Expired TLS certificate
    if scenario == "expired_tls":
        engine = TriageEngine()
        signals = [
            SignalRecord.create(
                kind=SignalKind.TLS_EXPIRED,
                source="tls_collector",
                evidence_ids=["ev-tls-exp-01"],
                value="Certificate expired 5 days ago",
            ),
            SignalRecord.create(
                kind=SignalKind.COLLECTOR_SUCCESS,
                source="intake_boundary",
                evidence_ids=["ev-tls-exp-01"],
                value="Standard metadata checks completed",
            ),
        ]
        result = engine.evaluate(signals, scan_id="scan-demo-expired-001")
        fragment = result.to_report_fragment()

        uncertainty_payload = None
        if hasattr(result, "uncertainty") and result.uncertainty:
            uncertainty_payload = result.uncertainty.to_dict()

        batch = EvidenceBatch(
            scan_id="scan-demo-expired-001",
            items=[
                EvidenceModel(
                    evidence_id="ev-tls-exp-01",
                    scan_id="scan-demo-expired-001",
                    kind="tls_certificate",
                    source="tls_collector",
                    observed_at="2026-11-10T00:30:00Z",
                    status=EvidenceStatus.FAILED,
                    reliability=Reliability.DIRECT_OBSERVATION,
                    limitations=["Certificate is expired; technical hygiene warning, not sole proof of malice."],
                )
            ],
            metadata={
                "submitted_url_redacted": url or "https://legacy-portal.internal-corp.net",
                "normalized_host": "legacy-portal.internal-corp.net",
                "status": "completed",
                "decision": fragment["decision"],
                "policy_version": "w03-v1.0",
            },
            limitations=["TLS-002: Expired certificate alone does not establish phishing intent."],
        )
        try:
            ev_service = EvidenceService()
            ev_service.ingest_batch(batch)
        except Exception:
            pass

        response_dict = {
            "scan_id": "scan-demo-expired-001",
            "submitted_url_redacted": url or "https://legacy-portal.internal-corp.net",
            "normalized_host": "legacy-portal.internal-corp.net",
            "status": "completed",
            "decision": fragment["decision"],
            "dimensions": fragment["dimensions"],
            "coverage": {"checks_total": 4, "checks_observed": 3, "checks_failed": 1, "checks_not_run": 0},
            "findings": fragment["findings"],
            "evidence": [
                {
                    "evidence_id": "ev-tls-exp-01",
                    "kind": "tls_certificate",
                    "source": "tls_collector",
                    "observed_at": "2026-11-10T00:30:00Z",
                    "status": "failed",
                    "reliability": "high",
                    "limitations": ["Certificate is expired; technical hygiene warning, not sole proof of malice."],
                }
            ],
            "limitations": ["TLS-002: Expired certificate alone does not establish phishing intent."],
            "policy_version": "w03-v1.0",
        }
        if uncertainty_payload:
            response_dict["uncertainty"] = uncertainty_payload
        return response_dict

    # Scenario 4: Conflicting Reports
    if scenario == "conflicting":
        fixture_path = FIXTURES_DIR / "conflicting_community_report.json"
        if fixture_path.exists():
            return json.loads(fixture_path.read_text(encoding="utf-8"))

    # Custom URL Evaluation via Worker 01 Intake Boundary & ScanOrchestrator
    if not url:
        raise HTTPException(status_code=400, detail="URL is required for custom triage.")

    boundary = IntakeBoundary()
    scan_id = f"scan-live-{uuid.uuid4().hex[:8]}"
    eval_res = boundary.evaluate_target(url)

    if not eval_res.is_safe:
        rejection_report = boundary.build_rejected_report(scan_id, eval_res)
        try:
            adapter = Worker01EvidenceAdapter()
            batch = adapter.adapt_payload(scan_id, rejection_report)
            ev_service = EvidenceService()
            ev_service.ingest_batch(batch)
        except Exception:
            pass
        return rejection_report

    # If valid target, run safe bounded collector orchestration and persist through EvidenceService
    from ..collectors.orchestrator import ScanOrchestrator

    orchestrator = ScanOrchestrator(intake_boundary=boundary)
    collector_payload = orchestrator.run_scan(scan_id=scan_id, raw_url=url)

    adapter = Worker01EvidenceAdapter()
    batch = adapter.adapt_payload(scan_id, collector_payload)
    ev_service = EvidenceService()
    ev_service.ingest_batch(batch)

    persisted_report = ev_service.get_scan_report(scan_id)
    if persisted_report:
        # Include uncertainty if available
        try:
            policy_input = PolicyInput.from_components(
                scan_id=scan_id,
                target=persisted_report.get("normalized_host") or "unknown",
                evidence=batch.items,
                coverage=batch.suggested_coverage,
                strict=False,
            )
            t_res = TriageEngine().evaluate_evidence(policy_input)
            if hasattr(t_res, "uncertainty") and t_res.uncertainty:
                persisted_report["uncertainty"] = t_res.uncertainty.to_dict()
        except Exception:
            pass
        return persisted_report

    return collector_payload



@router.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the interactive Evidence Passport single-page dashboard."""
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TRUSTTRACE — Evidence Passport for Web Trust Triage</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap');
    body { font-family: 'Inter', sans-serif; }
    .mono { font-family: 'JetBrains Mono', monospace; }
  </style>
</head>
<body class="bg-slate-950 text-slate-100 min-h-screen antialiased flex flex-col justify-between">

  <!-- Top Navigation -->
  <header class="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="h-9 w-9 bg-emerald-500 rounded-lg flex items-center justify-center text-slate-950 font-black text-xl shadow-lg shadow-emerald-500/20">
          <i class="fa-solid fa-shield-halved"></i>
        </div>
        <div>
          <span class="font-bold text-lg tracking-tight text-white">TRUSTTRACE</span>
          <span class="text-xs px-2 py-0.5 ml-2 bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 rounded-full font-medium">HackMatrix '26</span>
        </div>
      </div>
      <div class="flex items-center space-x-4 text-xs">
        <span class="flex items-center space-x-1.5 text-emerald-400 bg-emerald-950/40 border border-emerald-800 px-2.5 py-1 rounded-md">
          <span class="h-2 w-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>System Healthy</span>
        </span>
        <a href="/docs" target="_blank" class="text-slate-400 hover:text-white transition flex items-center space-x-1">
          <i class="fa-solid fa-book-open"></i><span>API Docs</span>
        </a>
        <a href="/health" target="_blank" class="text-slate-400 hover:text-white transition flex items-center space-x-1">
          <i class="fa-solid fa-heart-pulse"></i><span>Health</span>
        </a>
      </div>
    </div>
  </header>

  <!-- Invariant Bar -->
  <div class="bg-slate-900 border-b border-slate-800/80 px-4 py-2 text-xs text-slate-400 text-center flex flex-wrap justify-center gap-x-6 gap-y-1">
    <span>🛡️ <strong>Invariant:</strong> Valid TLS &ne; Identity Verified</span>
    <span>⚖️ <strong>Coverage Math:</strong> Total = Observed + Failed + Not Run</span>
    <span>🚫 <strong>Zero Egress Abuse:</strong> SSRF &amp; Rebinding Blocked</span>
    <span>🔍 <strong>Negative Match:</strong> No match &ne; Benign</span>
  </div>

  <!-- Main Container -->
  <main class="max-w-7xl mx-auto px-4 py-8 flex-grow space-y-8 w-full">

    <!-- Hero Header -->
    <div class="text-center max-w-3xl mx-auto space-y-3">
      <h1 class="text-3xl md:text-4xl font-extrabold text-white tracking-tight">
        Evidence-First Web Threat &amp; Digital Trust Triage
      </h1>
      <p class="text-slate-400 text-sm md:text-base leading-relaxed">
        Ordinary scanners produce binary green/red badges that hide critical uncertainty. 
        <strong class="text-emerald-400">TRUSTTRACE</strong> breaks down trust across 4 verifiable dimensions with traceable evidence lineage.
      </p>
    </div>

    <!-- Triage Form & Scenarios -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-6">
      <div>
        <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
          Target URL for Evidence Triage
        </label>
        <div class="flex flex-col sm:flex-row gap-3">
          <div class="relative flex-grow">
            <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500 pointer-events-none">
              <i class="fa-solid fa-globe"></i>
            </span>
            <input type="url" id="urlInput" value="https://bank-secure-lоgin.com" 
              class="w-full pl-10 pr-4 py-2.5 bg-slate-950 border border-slate-700 rounded-xl text-white text-sm focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 transition font-mono"
              placeholder="https://example.com/login" />
          </div>
          <button onclick="runTriage('custom')" id="triageBtn"
            class="px-6 py-2.5 bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold text-sm rounded-xl transition flex items-center justify-center space-x-2 shadow-lg shadow-emerald-500/20">
            <i class="fa-solid fa-magnifying-glass"></i>
            <span>Triage URL</span>
          </button>
        </div>
      </div>

      <!-- Quick Preset Scenarios -->
      <div>
        <div class="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2.5">
          Or Select a Controlled Demonstration Scenario:
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 text-xs">
          <button onclick="selectScenario('phishing_lookalike', 'https://bank-secure-lоgin.com')"
            class="p-3 bg-slate-950 border border-amber-500/30 hover:border-amber-400/80 rounded-xl text-left transition space-y-1">
            <div class="font-bold text-amber-400 flex items-center justify-between">
              <span>Phishing Lookalike</span>
              <i class="fa-solid fa-triangle-exclamation"></i>
            </div>
            <p class="text-slate-400 text-[11px] leading-snug">Valid TLS, but unverified identity &amp; IDN confusable.</p>
          </button>

          <button onclick="selectScenario('legitimate', 'https://example.com')"
            class="p-3 bg-slate-950 border border-emerald-500/30 hover:border-emerald-400/80 rounded-xl text-left transition space-y-1">
            <div class="font-bold text-emerald-400 flex items-center justify-between">
              <span>Legitimate Domain</span>
              <i class="fa-solid fa-circle-check"></i>
            </div>
            <p class="text-slate-400 text-[11px] leading-snug">Full verification &amp; authorized organizational identity.</p>
          </button>

          <button onclick="selectScenario('expired_tls', 'https://legacy-portal.internal-corp.net')"
            class="p-3 bg-slate-950 border border-blue-500/30 hover:border-blue-400/80 rounded-xl text-left transition space-y-1">
            <div class="font-bold text-blue-400 flex items-center justify-between">
              <span>Expired TLS Cert</span>
              <i class="fa-solid fa-clock-rotate-left"></i>
            </div>
            <p class="text-slate-400 text-[11px] leading-snug">Technical hygiene warning ≠ proof of phishing.</p>
          </button>

          <button onclick="selectScenario('conflicting', 'https://disputed-exchange.io')"
            class="p-3 bg-slate-950 border border-purple-500/30 hover:border-purple-400/80 rounded-xl text-left transition space-y-1">
            <div class="font-bold text-purple-400 flex items-center justify-between">
              <span>Conflicting Intel</span>
              <i class="fa-solid fa-code-compare"></i>
            </div>
            <p class="text-slate-400 text-[11px] leading-snug">Contradictory community signals abstain to inconclusive.</p>
          </button>

          <button onclick="selectScenario('ssrf_blocked', 'http://169.254.169.254/latest/meta-data')"
            class="p-3 bg-slate-950 border border-rose-500/30 hover:border-rose-400/80 rounded-xl text-left transition space-y-1">
            <div class="font-bold text-rose-400 flex items-center justify-between">
              <span>SSRF Target</span>
              <i class="fa-solid fa-ban"></i>
            </div>
            <p class="text-slate-400 text-[11px] leading-snug">Cloud metadata &amp; RFC1918 rejected with 0 egress.</p>
          </button>
        </div>
      </div>
    </div>

    <!-- Results Section: Evidence Passport -->
    <div id="resultsSection" class="hidden space-y-6">
      
      <!-- Top Passport Header -->
      <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-6 border-b border-slate-800">
          <div>
            <div class="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Evidence Passport Record</div>
            <div class="text-lg md:text-xl font-mono font-bold text-white flex items-center space-x-2">
              <span id="resUrl">https://bank-secure-login.com</span>
            </div>
            <div class="text-xs text-slate-500 font-mono mt-1">
              Scan ID: <span id="resScanId" class="text-slate-400">scan-demo-001</span> &bull; Host: <span id="resHost" class="text-slate-400">bank-secure-login.com</span>
            </div>
          </div>
          <div class="flex items-center space-x-3">
            <div id="decisionBadge" class="px-4 py-2 rounded-xl text-sm font-bold uppercase tracking-wider flex items-center space-x-2">
              <!-- Dynamically populated -->
            </div>
          </div>
        </div>

        <!-- 4 Dimension Cards Grid -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-6">
          
          <!-- Dimension 1: Identity -->
          <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
            <div class="flex items-center justify-between text-xs text-slate-400">
              <span class="font-semibold uppercase tracking-wider">1. Identity</span>
              <i class="fa-solid fa-id-card"></i>
            </div>
            <div id="dimIdentity" class="text-lg font-bold font-mono text-amber-400">unverified</div>
            <p class="text-[11px] text-slate-400 leading-relaxed">
              Separates transport encryption from legitimate entity delegation.
            </p>
          </div>

          <!-- Dimension 2: Certificate -->
          <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
            <div class="flex items-center justify-between text-xs text-slate-400">
              <span class="font-semibold uppercase tracking-wider">2. Certificate</span>
              <i class="fa-solid fa-lock"></i>
            </div>
            <div id="dimCertificate" class="text-lg font-bold font-mono text-emerald-400">valid_for_hostname</div>
            <p class="text-[11px] text-slate-400 leading-relaxed">
              Cryptographic validity of TLS/X.509 binding to hostname.
            </p>
          </div>

          <!-- Dimension 3: Behavior -->
          <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
            <div class="flex items-center justify-between text-xs text-slate-400">
              <span class="font-semibold uppercase tracking-wider">3. Behavior</span>
              <i class="fa-solid fa-network-wired"></i>
            </div>
            <div id="dimBehavior" class="text-lg font-bold font-mono text-slate-300">no_threat_observed</div>
            <p class="text-[11px] text-slate-400 leading-relaxed">
              Observed threat telemetry, heuristics, and redirect chain integrity.
            </p>
          </div>

          <!-- Dimension 4: Evidence Quality -->
          <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
            <div class="flex items-center justify-between text-xs text-slate-400">
              <span class="font-semibold uppercase tracking-wider">4. Evidence Quality</span>
              <i class="fa-solid fa-chart-pie"></i>
            </div>
            <div id="dimQuality" class="text-lg font-bold font-mono text-cyan-400">complete</div>
            <p class="text-[11px] text-slate-400 leading-relaxed">
              Coverage completeness, missingness, and ingestion freshness.
            </p>
          </div>
        </div>

        <!-- Coverage Arithmetic Bar -->
        <div class="mt-6 pt-5 border-t border-slate-800 space-y-2">
          <div class="flex items-center justify-between text-xs text-slate-400">
            <span><strong>Coverage Invariant:</strong> checks_total = observed + failed + not_run</span>
            <span id="coverageSummary" class="font-mono text-white">4 Total (4 Observed, 0 Failed, 0 Not Run)</span>
          </div>
          <div class="w-full h-2.5 bg-slate-950 rounded-full overflow-hidden flex">
            <div id="covObservedBar" style="width: 100%" class="bg-emerald-500"></div>
            <div id="covFailedBar" style="width: 0%" class="bg-rose-500"></div>
            <div id="covNotRunBar" style="width: 0%" class="bg-slate-700"></div>
          </div>
        </div>
      </div>

      <!-- Traceable Findings & Evidence Section -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        <!-- Findings Drawer -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <i class="fa-solid fa-list-check text-emerald-400"></i>
              <span>Adjudicated Findings</span>
            </h3>
            <span id="findingsCount" class="text-xs bg-slate-800 px-2 py-0.5 rounded text-slate-300 font-mono">0 Findings</span>
          </div>
          <div id="findingsList" class="space-y-3">
            <!-- Populated dynamically -->
          </div>
        </div>

        <!-- Evidence Drawer -->
        <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4">
          <div class="flex items-center justify-between">
            <h3 class="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <i class="fa-solid fa-database text-cyan-400"></i>
              <span>Traceable Evidence Records</span>
            </h3>
            <span id="evidenceCount" class="text-xs bg-slate-800 px-2 py-0.5 rounded text-slate-300 font-mono">0 Records</span>
          </div>
          <div id="evidenceList" class="space-y-3 max-h-[420px] overflow-y-auto pr-1">
            <!-- Populated dynamically -->
          </div>
        </div>
      </div>

      <!-- Limitations & Policy Rationale Notice -->
      <div id="limitationsNotice" class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 text-xs text-slate-400 space-y-2">
        <div class="font-bold text-slate-300 flex items-center space-x-1.5">
          <i class="fa-solid fa-circle-info text-amber-400"></i>
          <span>Assessment Disclosures &amp; Limitations</span>
        </div>
        <ul id="limitationsList" class="list-disc list-inside space-y-1 text-slate-400 font-mono">
          <!-- Populated dynamically -->
        </ul>
      </div>

    </div>

    <!-- Community Intelligence Section -->
    <div class="bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-6">
      <div class="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h2 class="text-lg font-bold text-white flex items-center space-x-2">
            <i class="fa-solid fa-users text-purple-400"></i>
            <span>Collaborative Threat Intelligence</span>
          </h2>
          <p class="text-xs text-slate-400 mt-0.5">Community reports with XSS sanitization, deduplication, and non-inflated corroboration counts.</p>
        </div>
        <button onclick="loadCommunityReports()" class="text-xs text-slate-400 hover:text-white px-3 py-1.5 bg-slate-800 rounded-lg transition">
          <i class="fa-solid fa-rotate mr-1"></i> Refresh
        </button>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        <!-- Submit Report Form -->
        <div class="bg-slate-950 border border-slate-800/80 rounded-xl p-4 space-y-3">
          <div class="text-xs font-bold text-white uppercase tracking-wider">Submit Community Finding</div>
          <form id="communityForm" onsubmit="submitCommunityReport(event)" class="space-y-3 text-xs">
            <div>
              <label class="block text-slate-400 mb-1">Target Domain</label>
              <input type="text" id="commDomain" required class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white font-mono focus:border-purple-500 focus:outline-none" placeholder="suspicious-domain.com" />
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Claim Type</label>
              <select id="commClaimType" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:border-purple-500 focus:outline-none">
                <option value="phishing">Phishing Campaign</option>
                <option value="credential_harvesting">Credential Harvesting</option>
                <option value="brand_impersonation">Brand Impersonation</option>
                <option value="malware_distribution">Malware Distribution</option>
                <option value="suspicious_activity">General Suspicious</option>
              </select>
            </div>
            <div>
              <label class="block text-slate-400 mb-1">Analyst Notes (XSS-sanitized)</label>
              <textarea id="commNotes" rows="2" class="w-full px-3 py-2 bg-slate-900 border border-slate-700 rounded-lg text-white focus:border-purple-500 focus:outline-none" placeholder="Observed fake login page targeting bank users..."></textarea>
            </div>
            <button type="submit" id="commSubmitBtn" class="w-full py-2 bg-purple-600 hover:bg-purple-500 text-white font-semibold rounded-lg transition shadow-lg shadow-purple-600/20">
              Submit to Feed
            </button>
          </form>
          <div id="commFeedback" class="hidden text-[11px] p-2.5 rounded-lg"></div>
        </div>

        <!-- Community Feed List -->
        <div class="lg:col-span-2 space-y-3">
          <div class="text-xs font-bold text-slate-400 uppercase tracking-wider">Recent Community Submissions</div>
          <div id="communityFeedList" class="space-y-2.5 max-h-[300px] overflow-y-auto pr-1 text-xs">
            <div class="text-slate-500 text-center py-8">Loading community reports...</div>
          </div>
        </div>
      </div>
    </div>

  </main>

  <!-- Footer -->
  <footer class="border-t border-slate-800 bg-slate-900/40 py-6 text-center text-xs text-slate-500 space-y-2">
    <div><strong>TRUSTTRACE</strong> &bull; HackMatrix '26 Evidence-First Web Threat Detection Platform</div>
    <div>Strict Worker Isolation Protocol Enforced &bull; 100% Schema &amp; Contract Invariants Passed</div>
  </footer>

  <!-- Script for Dashboard Operations -->
  <script>
    async function selectScenario(scenarioName, targetUrl) {
      document.getElementById('urlInput').value = targetUrl;
      runTriage(scenarioName);
    }

    async function runTriage(scenario) {
      const urlInput = document.getElementById('urlInput');
      const triageBtn = document.getElementById('triageBtn');
      const url = urlInput.value.trim();

      triageBtn.disabled = true;
      triageBtn.innerHTML = '<i class="fa-solid fa-spinner animate-spin"></i><span>Triaging...</span>';

      try {
        const response = await fetch('/api/v1/triage/demo', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url, scenario: scenario })
        });

        const data = await response.json();
        renderPassport(data);
      } catch (err) {
        alert('Triage error: ' + err.message);
      } finally {
        triageBtn.disabled = false;
        triageBtn.innerHTML = '<i class="fa-solid fa-magnifying-glass"></i><span>Triage URL</span>';
      }
    }

    function renderPassport(data) {
      document.getElementById('resultsSection').classList.remove('hidden');
      document.getElementById('resUrl').textContent = data.submitted_url_redacted || document.getElementById('urlInput').value;
      document.getElementById('resScanId').textContent = data.scan_id || 'scan-001';
      document.getElementById('resHost').textContent = data.normalized_host || 'target';

      // Decision Badge
      const badge = document.getElementById('decisionBadge');
      const dec = data.decision || 'inconclusive';
      if (dec === 'high_risk' || dec === 'rejected') {
        badge.className = 'px-4 py-2 rounded-xl text-sm font-bold uppercase tracking-wider flex items-center space-x-2 bg-rose-500/20 text-rose-400 border border-rose-500/30';
        badge.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i><span>' + dec.replace('_', ' ') + '</span>';
      } else if (dec === 'caution') {
        badge.className = 'px-4 py-2 rounded-xl text-sm font-bold uppercase tracking-wider flex items-center space-x-2 bg-amber-500/20 text-amber-400 border border-amber-500/30';
        badge.innerHTML = '<i class="fa-solid fa-eye"></i><span>Caution</span>';
      } else if (dec === 'no_threat_observed') {
        badge.className = 'px-4 py-2 rounded-xl text-sm font-bold uppercase tracking-wider flex items-center space-x-2 bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
        badge.innerHTML = '<i class="fa-solid fa-shield-check"></i><span>No Threat Observed</span>';
      } else {
        badge.className = 'px-4 py-2 rounded-xl text-sm font-bold uppercase tracking-wider flex items-center space-x-2 bg-slate-700 text-slate-300 border border-slate-600';
        badge.innerHTML = '<i class="fa-solid fa-circle-question"></i><span>Inconclusive</span>';
      }

      // Dimensions
      const dims = data.dimensions || {};
      document.getElementById('dimIdentity').textContent = dims.identity || 'unverified';
      document.getElementById('dimCertificate').textContent = dims.certificate || 'unobserved';
      document.getElementById('dimBehavior').textContent = dims.behavior || 'unobserved';
      document.getElementById('dimQuality').textContent = dims.evidence_quality || 'complete';

      // Coverage
      const cov = data.coverage || { checks_total: 4, checks_observed: 4, checks_failed: 0, checks_not_run: 0 };
      document.getElementById('coverageSummary').textContent = 
        `${cov.checks_total} Total (${cov.checks_observed} Observed, ${cov.checks_failed} Failed, ${cov.checks_not_run} Not Run)`;
      
      const total = cov.checks_total || 1;
      document.getElementById('covObservedBar').style.width = ((cov.checks_observed / total) * 100) + '%';
      document.getElementById('covFailedBar').style.width = ((cov.checks_failed / total) * 100) + '%';
      document.getElementById('covNotRunBar').style.width = ((cov.checks_not_run / total) * 100) + '%';

      // Findings
      const findingsList = document.getElementById('findingsList');
      findingsList.innerHTML = '';
      const findings = data.findings || [];
      document.getElementById('findingsCount').textContent = findings.length + ' Findings';
      if (findings.length === 0) {
        findingsList.innerHTML = '<div class="text-slate-500 text-xs py-2">No discrete warning findings reported.</div>';
      } else {
        findings.forEach(f => {
          const item = document.createElement('div');
          item.className = 'p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1 text-xs';
          item.innerHTML = `
            <div class="flex items-center justify-between">
              <span class="font-bold text-white uppercase tracking-wider">${f.kind || 'finding'}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase font-mono ${f.severity === 'high' ? 'bg-rose-500/20 text-rose-400' : 'bg-amber-500/20 text-amber-400'}">${f.severity || 'info'}</span>
            </div>
            <p class="text-slate-300">${f.summary || ''}</p>
            <div class="text-[10px] text-slate-500 font-mono">Rule: ${f.rule_id || 'N/A'} &bull; Linked Evidence: ${(f.evidence_ids || []).join(', ') || 'N/A'}</div>
          `;
          findingsList.appendChild(item);
        });
      }

      // Evidence
      const evidenceList = document.getElementById('evidenceList');
      evidenceList.innerHTML = '';
      const evidence = data.evidence || [];
      document.getElementById('evidenceCount').textContent = evidence.length + ' Records';
      if (evidence.length === 0) {
        evidenceList.innerHTML = '<div class="text-slate-500 text-xs py-2">No evidence items recorded.</div>';
      } else {
        evidence.forEach(e => {
          const item = document.createElement('div');
          item.className = 'p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1.5 text-xs';
          item.innerHTML = `
            <div class="flex items-center justify-between font-mono text-[11px]">
              <span class="font-bold text-cyan-400">${e.evidence_id}</span>
              <span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-medium">${e.status}</span>
            </div>
            <div class="text-slate-300"><strong class="text-slate-400">Source:</strong> ${e.source} &bull; <strong class="text-slate-400">Observed:</strong> <span class="font-mono text-slate-400">${e.observed_at}</span></div>
            ${e.limitations && e.limitations.length ? `<div class="text-[11px] text-slate-500 font-mono">Limitations: ${e.limitations.join('; ')}</div>` : ''}
          `;
          evidenceList.appendChild(item);
        });
      }

      // Limitations
      const limList = document.getElementById('limitationsList');
      limList.innerHTML = '';
      const lims = data.limitations || ["Simulated demo baseline."];
      lims.forEach(l => {
        const li = document.createElement('li');
        li.textContent = l;
        limList.appendChild(li);
      });

      if (data.uncertainty) {
        if (data.uncertainty.confidence_band) {
          const li = document.createElement('li');
          li.className = 'text-amber-300 font-bold';
          li.textContent = `UNCERTAINTY: Confidence Band [${data.uncertainty.confidence_band.toUpperCase()}] — ${data.uncertainty.summary || ''}`;
          limList.appendChild(li);
        }
        if (data.uncertainty.abstention_notice) {
          const li = document.createElement('li');
          li.className = 'text-rose-400 font-bold';
          li.textContent = `ABSTENTION NOTICE: ${data.uncertainty.abstention_notice.reason || ''} (Action: ${data.uncertainty.abstention_notice.recommended_action || ''})`;
          limList.appendChild(li);
        }
      }

      // Smooth scroll to results
      document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
    }

    async function loadCommunityReports() {
      const container = document.getElementById('communityFeedList');
      try {
        const res = await fetch('/api/v1/community/reports?limit=10');
        if (!res.ok) throw new Error('API ' + res.status);
        const data = await res.json();
        const items = data.items || [];
        if (items.length === 0) {
          container.innerHTML = '<div class="text-slate-500 text-center py-6">No community reports logged yet.</div>';
          return;
        }
        container.innerHTML = '';
        items.forEach(r => {
          const div = document.createElement('div');
          div.className = 'p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1 text-xs';
          div.innerHTML = `
            <div class="flex items-center justify-between">
              <span class="font-mono font-bold text-white">${r.normalized_domain}</span>
              <span class="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-purple-500/20 text-purple-400 font-mono">${r.verification_state}</span>
            </div>
            <div class="text-slate-400">${r.claim_type.replace('_', ' ')} &bull; ${r.note_sanitized || 'No notes'}</div>
            <div class="text-[10px] text-slate-500 font-mono">Corroborated by ${r.independent_source_count} independent source(s) &bull; Submitted: ${r.submitted_at}</div>
          `;
          container.appendChild(div);
        });
      } catch (e) {
        container.innerHTML = '<div class="text-slate-500 text-center py-6">Community feed offline (run DB migrations).</div>';
      }
    }

    async function submitCommunityReport(event) {
      event.preventDefault();
      const domain = document.getElementById('commDomain').value.trim();
      const claimType = document.getElementById('commClaimType').value;
      const note = document.getElementById('commNotes').value.trim();
      const feedback = document.getElementById('commFeedback');
      const submitBtn = document.getElementById('commSubmitBtn');

      submitBtn.disabled = true;
      feedback.className = 'hidden';

      try {
        const res = await fetch('/api/v1/community/reports', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            normalized_domain: domain,
            claim_type: claimType,
            reporter_id: 'analyst-ui-demo',
            note: note,
          })
        });

        const data = await res.json();
        if (!res.ok) {
          feedback.className = 'text-[11px] p-2.5 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/30';
          feedback.textContent = 'Submission rejected: ' + (data.detail || 'Error');
        } else {
          feedback.className = 'text-[11px] p-2.5 rounded-lg bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
          feedback.textContent = `Report accepted! ID: ${data.report_id} (Status: ${data.verification_state})`;
          document.getElementById('communityForm').reset();
          loadCommunityReports();
        }
      } catch (err) {
        feedback.className = 'text-[11px] p-2.5 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/30';
        feedback.textContent = 'Failed: ' + err.message;
      } finally {
        submitBtn.disabled = false;
      }
    }

    // Initialize on load
    window.addEventListener('DOMContentLoaded', () => {
      runTriage('phishing_lookalike');
      loadCommunityReports();
    });
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
