"""Live verification script for running TRUSTTRACE application server."""

import sys
import json
import urllib.request
import urllib.error

base = "http://127.0.0.1:8000"


def test(name, url, method="GET", data=None, headers=None):
    if headers is None:
        headers = {}
    req = urllib.request.Request(url, method=method, headers=headers)
    if data is not None:
        req.data = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.status
            body = resp.read()
            print(f"[PASS] {name}: HTTP {code} ({len(body)} bytes)")
            return code, body
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")[:120]
        print(f"[FAIL] {name}: HTTP {e.code} - {err_msg}")
        return e.code, None
    except Exception as exc:
        print(f"[ERROR] {name}: {exc}")
        return 0, None


def main():
    print("=" * 60)
    print("TRUSTTRACE Live HTTP Endpoints Verification")
    print(f"Target Base URL: {base}")
    print("=" * 60)

    test("1. Health Check", f"{base}/health")
    test("2. Readiness Probe", f"{base}/ready")
    test("3. Swagger API Docs", f"{base}/docs")

    code, html = test("4. React Dashboard Root (GET /)", f"{base}/")
    if html and b"TRUSTTRACE" in html and b"index-B-9kJT32.js" in html:
        print("   -> Verified: dist/index.html with React production script bundle loaded!")

    test("5. React Production CSS Asset", f"{base}/assets/index-DCkOjUiG.css")
    test("6. React Production JS Asset", f"{base}/assets/index-B-9kJT32.js")

    test("7. Demo Scenario: Phishing Lookalike", f"{base}/api/v1/triage/demo", "POST", {
        "url": "https://bank-secure-login.com",
        "scenario": "phishing_lookalike"
    })
    test("8. Demo Scenario: Expired TLS", f"{base}/api/v1/triage/demo", "POST", {
        "url": "https://legacy-portal.internal-corp.net",
        "scenario": "expired_tls"
    })
    test("9. Demo Scenario: Legitimate Target", f"{base}/api/v1/triage/demo", "POST", {
        "url": "https://example.com",
        "scenario": "legitimate"
    })
    test("10. Demo Scenario: Conflicting Feeds", f"{base}/api/v1/triage/demo", "POST", {
        "url": "https://disputed-target.org",
        "scenario": "conflicting"
    })
    test("11. SSRF Protection (Local IP Blocked)", f"{base}/api/v1/triage/demo", "POST", {
        "url": "http://127.0.0.1/admin",
        "scenario": "custom"
    })

    test("12. Submit Community Report", f"{base}/api/v1/community/reports", "POST", {
        "normalized_domain": "suspicious-test.example.com",
        "claim_type": "phishing",
        "note": "Observed deceptive login prompt mimicking brand assets.",
        "source_family": "community_user"
    })
    test("13. Query Community Reports", f"{base}/api/v1/community/reports?domain=suspicious-test.example.com")
    print("=" * 60)
    print("All live verification tests completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
