#!/usr/bin/env python3
"""Validate TRUSTTRACE v1 JSON fixtures and report cross-record invariants.
Install with: python -m pip install -r requirements-validation.txt
Run from repository root: python .brain/.work/contracts/v1/validate_fixtures.py
"""
from pathlib import Path
import json
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / ".work/contracts/v1"
FIXTURES = ROOT / ".testdata/v1"
CHECKER = FormatChecker()

def load(path):
    return json.loads(path.read_text(encoding="utf-8"))

def validator(name):
    schema = load(SCHEMAS / name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=CHECKER)

checks = 0
req = validator("scan_request.schema.json")
req.validate(load(FIXTURES / "scan_request_valid.json")); checks += 1
invalid_req = load(FIXTURES / "scan_request_invalid.json")
assert list(req.iter_errors(invalid_req)), "invalid scan request unexpectedly passed"
checks += 1
report_validator = validator("scan_report.schema.json")
for name in ("complete_report.json", "partial_report.json", "rejected_report.json"):
    report = load(FIXTURES / name)
    report_validator.validate(report)
    checks += 1
    evidence_ids = {ev["evidence_id"] for ev in report["evidence"]}
    for finding in report["findings"]:
        assert set(finding["evidence_ids"]) <= evidence_ids, f"dangling evidence ref in {name}"
    coverage = report["coverage"]
    total = coverage["checks_observed"] + coverage["checks_failed"] + coverage["checks_not_run"]
    assert total == coverage["checks_total"], f"coverage arithmetic mismatch in {name}"
    if report["decision"] == "no_threat_observed":
        assert report["status"] == "completed" and coverage["checks_failed"] == 0 and coverage["checks_not_run"] == 0
community_validator = validator("community_report.schema.json")
community = load(FIXTURES / "conflicting_community_report.json")
community_validator.validate(community); checks += 1
all_evidence_ids = set()
for report_name in ("complete_report.json", "partial_report.json", "rejected_report.json"):
    all_evidence_ids.update(ev["evidence_id"] for ev in load(FIXTURES / report_name)["evidence"])
assert set(community["linked_evidence_ids"]) <= all_evidence_ids, "community report has dangling evidence reference"
checks += 1
assert community["verification_state"] == "disputed", "conflict fixture must remain explicitly disputed"
checks += 1
print(f"PASS: {checks} schema/negative/cross-record fixture checks")
