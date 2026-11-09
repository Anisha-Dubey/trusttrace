# Acceptance criteria

## User journey
- User can submit a supported URL or select a controlled fixture and see scan status.
- Invalid/blocked destinations are rejected with a safe, useful explanation.
- A completed or partial report displays distinct identity, certificate, behavior, evidence-quality and decision states.
- User can expand a finding and identify its evidence/source/time/limitations.
- A community report can be created and visibly remains unverified until evidence justifies another state.

## Decision semantics
- Valid TLS does not yield `identity=supported` by itself.
- Missing threat-feed match does not yield `no_threat_observed` without stating checks/coverage and must never yield `safe`.
- Failed collectors remain visible and can produce `partial` or `inconclusive`.
- Conflicting or dependent reports do not count as independent corroboration.

## Security gate
- Only HTTP(S); reject credentials in URL and unsupported schemes.
- Reject loopback/private/link-local/reserved/multicast/metadata IPs for IPv4 and IPv6; revalidate DNS and every redirect.
- Bounded redirects, time, bytes, concurrency and per-user rate; no forwarding of cookies/auth headers.
- No form submission, credentials, file execution, exploit probes or arbitrary port scans.
- If browser rendering exists, isolated disposable environment and egress restrictions are tested; otherwise no external rendering.

## Demo/release
- Controlled positive, benign and partial/conflicting cases available.
- All fixture/simulated output labeled; fallback has a recorded-fixture label.
- Build/setup instructions and limitations documented.
- No unsupported metrics or novelty claims.


## Evidence identifiers
Each acceptance case is assigned a stable test ID in `test_matrix.csv`. A case can be marked `PASS` only with build/commit, command/procedure, actual output and retained evidence. The schema/fixture contract is in `.work/contracts/v1/`; cross-record evidence references and coverage arithmetic require application-level validation.
