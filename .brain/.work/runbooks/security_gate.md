# Runbook: live scanning security gate

Live network scanning stays disabled until all P0 cases in `.work/shared/test_matrix.csv` pass on the implementation.

1. Document exact resolver/connect library behavior and DNS/IP validation order.
2. Unit test URL parser, IPv4/IPv6 special-use ranges, numeric/encoded host variants, IDNA and userinfo.
3. Demonstrate resolution-time and connect-time destination checks; test DNS changes/rebinding.
4. Revalidate every redirect; enforce redirect cap and scheme policy.
5. Prove timeout, body-byte, concurrency, request-rate and cancellation bounds.
6. Verify no cookie/auth/client certificate forwarding, no forms, no script execution, no download/execution and no arbitrary ports.
7. Inspect logs, traces and screenshots for query secrets or tokens.
8. Tester 02 independently signs off with build ID and artifacts.

If any P0 control is absent, use local fixture mode only. A design description is not proof of implementation.
