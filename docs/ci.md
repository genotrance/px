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
LDAP ports. The job declares `CORP.TEST` with Windows `ksetup.exe` rather than `klist add_bind`:
`add_bind` locates the realm's DC through the AD DC locator (DsGetDCName over
RPC, LDAP and netlogon), which a workgroup runner cannot use against the WSL2
Samba DC and fails with `DsGetDCName 0x6ba`. `ksetup /addkdc` names the KDC
explicitly, so Windows treats `CORP.TEST` as a non-AD realm and skips the
locator. The job also sets TCP support for the realm and maps
`squid-sso.corp.test` and the `.corp.test` suffix to it, so the SPN for the proxy
resolves to the lab realm. Microsoft documents that `ksetup /addkdc` takes effect
after a restart; a hosted runner cannot be restarted mid-job, so if the Kerberos
probe reports no credentials despite a successful `ksetup`, that is the first
thing to check.

The job starts a long-lived `wsl.exe` client before Docker and stops it only
after log collection and scenario teardown. WSL2 otherwise considers the distro
idle while Windows-only Px, upload, and SSPI steps run; idle termination sends
SIGTERM to dockerd and every lab container. A direct authenticated NTLM request
through the project's `uv` environment and `mcurl` immediately before the HTTPS
burst verifies that the lab is still alive without depending on the Windows
runner's `curl.exe` feature set. It reports a WSL2 lab failure rather than
attributing its 502 responses to Px.
The job calls Windows `klist.exe` by its absolute `System32` path: the runner's
JDK `bin` directory precedes `System32` on `PATH`, and the JDK's Java `klist`
shadows the bare name, printing its usage instead of showing the ticket cache.
The same applies to `ksetup`, which the job also calls by absolute path.

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
