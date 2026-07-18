# Configuration

---

## Configuration sources

Px requires only one piece of information to function — the server name and port
of the proxy server. If not specified, Px will check Internet Options or
environment variables for any proxy definitions. Without this, Px will try to
connect to sites directly.

Configuration can be supplied from multiple sources, applied in order of
precedence (highest first):

1. **Command-line flags** (e.g. `--proxy`, `--listen`, `--auth`).
2. **Environment variables** prefixed with `PX_` (e.g. `PX_SERVER`, `PX_PORT`).
3. **Variables in a dotenv file** (`.env`) — in the working directory or Px directory.
4. **Configuration file** `px.ini` — searched in the working directory, user config
   directory, or Px directory.

### User config directory

| Platform | Path |
|----------|------|
| Windows | `%APPDATA%\px` |
| Linux | `~/.config/px` |
| macOS | `~/Library/Application Support/px` |

### Saving configuration

The `--save` flag writes the current configuration to `px.ini`:

- Px saves to `--config=path/px.ini` or `PX_CONFIG` if specified.
- Otherwise, it loads `px.ini` from the working, user config or Px directory if
  it exists and updates it.
- If the file is not writable, it tries the next location in order.
- If no `px.ini` is found, it defaults to the user config directory.

---

## Actions

| Flag | Description |
|------|-------------|
| `--save` | Save current configuration to `px.ini` |
| `--install [--force]` | Add Px to the Windows registry to run on startup |
| `--uninstall` | Remove Px from the Windows registry |
| `--quit` | Quit a running instance of Px |
| `--restart` | Quit and start a new instance |
| `--password` | Prompt and save password to keyring |
| `--client-password` | Prompt and save client password to keyring |
| `--test[=URL]` | Test Px connectivity (defaults to httpbin.org) |

---

## Proxy options

| Flag | Env var | INI key | Default | Description |
|------|---------|---------|---------|-------------|
| `--proxy=HOST:PORT` | `PX_SERVER` | `proxy:server` | *(none)* | Upstream proxy server(s), comma-separated |
| `--pac=URL` | `PX_PAC` | `proxy:pac` | *(none)* | PAC file URL or local path |
| `--pac_encoding=ENC` | `PX_PAC_ENCODING` | `proxy:pac_encoding` | auto-detect | PAC file encoding (auto-detects via Content-Type charset/BOM/UTF-8/cp1252/cp1251/Latin-1; set only if needed) |
| `--listen=IP` | `PX_LISTEN` | `proxy:listen` | `127.0.0.1` | Local interface(s) to bind, comma-separated |
| `--port=NUM` | `PX_PORT` | `proxy:port` | `3128` | Listening port |
| `--gateway=0\|1` | `PX_GATEWAY` | `proxy:gateway` | `0` | Allow remote clients; overrides `--listen` |
| `--hostonly=0\|1` | `PX_HOSTONLY` | `proxy:hostonly` | `0` | Restrict to local interfaces only |
| `--allow=IPGLOB` | `PX_ALLOW` | `proxy:allow` | `*.*.*.*` | Allowed client IPs (specific, wildcard, range, CIDR) |
| `--noproxy=LIST` | `PX_NOPROXY` | `proxy:noproxy` | *(none)* | Hosts/IPs that bypass upstream proxy (IP, wildcard, range, CIDR, domain) |
| `--useragent=STR` | `PX_USERAGENT` | `proxy:useragent` | *(none)* | Override or send User-Agent header |

---

## Authentication options

| Flag | Env var | INI key | Default | Description |
|------|---------|---------|---------|-------------|
| `--username=DOMAIN\user` | `PX_USERNAME` | `proxy:username` | *(none)* | Username for upstream proxy auth |
| `--auth=TYPE` | `PX_AUTH` | `proxy:auth` | `ANY` | Upstream proxy auth type |
| `--kerberos=0\|1` | `PX_KERBEROS` | `proxy:kerberos` | `0` | Enable Kerberos ticket management (Linux/macOS only) |

When `--kerberos` is enabled, Px acquires and renews Kerberos tickets
automatically using `--username` as the Kerberos principal and the password from
`PX_PASSWORD` or keyring. Requires `--username` and libcurl with GSS-API support.
See [usage.md](usage.md#kerberos-authentication) for details.

### Auth type values

- `ANY`, `NTLM`, `NEGOTIATE`, `DIGEST`, `BASIC` — standard auth methods.
- Prefix `NO` to exclude a method (e.g. `NONTLM` → ANY minus NTLM).
- Prefix `SAFENO` to exclude from ANYSAFE (e.g. `SAFENONTLM`).
- Prefix `ONLY` to allow only that method (e.g. `ONLYNTLM`).
- `NONE` — defer all authentication to the client. Useful for chaining Px instances.

See [libcurl CURLOPT_HTTPAUTH](https://curl.se/libcurl/c/CURLOPT_HTTPAUTH.html)
for the full list of supported types.

---

## Client authentication options

| Flag | Env var | INI key | Default | Description |
|------|---------|---------|---------|-------------|
| `--client-username=DOMAIN\user` | `PX_CLIENT_USERNAME` | `client:client_username` | *(none)* | Username for client auth |
| `--client-auth=TYPE` | `PX_CLIENT_AUTH` | `client:client_auth` | `NONE` | Client auth mechanisms (ANY, ANYSAFE, NTLM, NEGOTIATE, DIGEST, BASIC, NONE) |
| `--client-nosspi=0\|1` | `PX_CLIENT_NOSSPI` | `client:client_nosspi` | `0` | Disable SSPI for client auth on Windows |

---

## Settings

| Flag | Env var | INI key | Default | Description |
|------|---------|---------|---------|-------------|
| `--workers=N` | `PX_WORKERS` | `settings:workers` | `1` | Number of worker processes |
| `--threads=N` | `PX_THREADS` | `settings:threads` | `32` | Thread pool size for upstream connections |
| `--idle=N` | `PX_IDLE` | `settings:idle` | `30` | Idle timeout for CONNECT sessions (seconds) |
| `--socktimeout=N` | `PX_SOCKTIMEOUT` | `settings:socktimeout` | `20` | Connection timeout (seconds) |
| `--proxyreload=N` | `PX_PROXYRELOAD` | `settings:proxyreload` | `60` | Proxy info refresh interval (seconds) |
| `--foreground=0\|1` | `PX_FOREGROUND` | `settings:foreground` | `0` | Run in foreground when compiled/frozen |
| `--log=LEVEL` | `PX_LOG` | `settings:log` | `0` | Logging: 0=off, 1=script dir, 2=working dir, 3=unique file, 4=stdout |

### Other flags

| Flag | Description |
|------|-------------|
| `--config=PATH` | Specify config file path (also `PX_CONFIG`) |

---

## Credentials

If SSPI is not available, `--username` in `domain\username` format allows Px to
authenticate as that user. The password is retrieved using Python keyring under
the realm `Px`.

```bash
px --username=domain\username --password
```

`PX_PASSWORD` and `PX_CLIENT_PASSWORD` environment variables are available as
alternatives when keyring is not available.

`PX_KEYRING_PLAINTEXT` can be set to `1` to use a plaintext file-based keyring
backend as a fallback when the system keyring is unavailable or problematic.
**This is not recommended** as passwords are stored unencrypted on disk.

See [usage.md](usage.md) for platform-specific keyring setup instructions.
