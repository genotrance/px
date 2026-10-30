# Continuous integration

The workflow structure and release gates are documented in
[Build and release](build.md). This page records CI-specific operational
details that are easy to lose when diagnosing hosted-runner failures.

## Windows SSPI scenario

The `scenario-windows` job runs Px natively on Windows while its corporate
proxy lab runs in WSL2. NTLM uses the localhost-published proxy port. Negotiate
uses Kerberos because libcurl 8.23 excludes NTLM from SPNEGO: the host file
maps `squid-sso.corp.test` to the published proxy, while the WSL2 address maps
`dc.corp.test` to the lab AD DC. Compose publishes TCP and UDP Kerberos and
LDAP ports, and `klist add_bind` directs `CORP.TEST` discovery to that DC.

The job first runs native `curl.exe --proxy-negotiate` with the explicit
`pxgood@CORP.TEST` test identity. Its verbose output and the following `klist`
are the boundary diagnostic: the probe must show a Negotiate token followed
by a successful HTTP response, and the Squid helper log must confirm Kerberos
accepted `HTTP/squid-sso.corp.test`. Only then does the job run Px with
`NEGOTIATE` and `ANY`, including streamed upload integrity checks.

`SEC_E_NO_CREDENTIALS` before a token is sent means Windows could not acquire
Kerberos credentials. A 407 after a token was sent means the ticket or SPN was
not accepted by Squid. See [Testing](testing.md#ci-testing) for the complete
scenario and manual domain-joined SSPI coverage.
