# Tester 02 — security and release plan

## Cases
Schemes and credentials; IPv4/IPv6 prohibited ranges; DNS resolving prohibited addresses; redirect chain to prohibited address; rebinding/TOCTOU mitigation; timeouts and oversized bodies; loop/redirect ceiling; rate/concurrency limits; no cookie/auth forwarding; HTML/text escaping; token/query redaction; community-report abuse; API secret exposure; browser isolation if applicable.

## Release gate
Document actual protections, test evidence, unresolved risks and disabled features. Do not infer safety from design text. If arbitrary browser execution cannot be proven isolated, block it. If URL/IP/redirect checks are incomplete, block live scans.
