# Architecture

---

## Overview

Px is a lightweight HTTP/HTTPS proxy server that enables applications to authenticate through NTLM or Kerberos proxy servers without handling the complex handshake themselves. It leverages Windows SSPI (or equivalent mechanisms on other OSes) to perform single-sign-on using the currently logged-in user credentials. Px runs on Windows, Linux and macOS, either as a Python module installed via `pip` or as a compiled binary built with Nuitka.

## Runtime model

Px uses an async, single-process architecture (with optional multi-process
scaling via `--workers`):

1. **Process** (`main.py`) — parses config, runs an `asyncio` event loop with
   `asyncio.start_server` bound to the configured listen address and port.
   Additional worker processes can be spawned with `--workers` on all platforms
   but the default is 1 since the async event loop handles concurrency
   efficiently.
2. **Thread pool** (`--threads`, default 32) — blocking `mcurl.do()` calls are
   dispatched to a `ThreadPoolExecutor` via `asyncio.to_thread()`. Threads are
   held only for the duration of the upstream request, not the full connection
   or tunnel lifetime.
3. **Connection handling** — each TCP connection is handled by a
   `ConnectionHandler` coroutine. HTTP parsing uses `h11` to read requests from
   the client.
4. **CONNECT tunnelling** — established tunnels use zero-thread bidirectional
   relays. The relay strategy is platform-specific (see below).

```
Client ─── HTTP request ──► ConnectionHandler._handle_request()
                              │
                    ┌─────────▼──────────┐
                    │ _get_destination()  │
                    │  STATE.reload_proxy │
                    │  Wproxy.find_proxy  │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────┐
                    │ mcurl.Curl         │
                    │  set_auth()        │
                    │  set_proxy()       │
                    │  asyncio.to_thread │
                    └─────────┬──────────┘
                              │
                         Response ◄── Upstream proxy / direct
                              │
              BridgeWriter ──► transport.write() ──► Client
```

### Multi-process architecture

When `--workers` is greater than 1, the main process creates its own listening
sockets and then spawns `workers - 1` additional child processes.  Each child
creates its own independent listening sockets bound to the same port — no
socket sharing or duplication between processes.

- **Linux:** `SO_REUSEPORT` enables kernel-level load balancing across all
  listening sockets on the same port.
- **macOS:** `SO_REUSEPORT` allows multiple sockets to bind; the kernel
  distributes connections (distribution may not be perfectly even).
- **Windows:** `SO_REUSEADDR` allows multiple sockets to bind to the same
  port.  Each process registers its own socket with its own IOCP, avoiding
  the `WinError 87` that occurred when a shared socket was registered with
  multiple IOCPs (#267).

## Package layout

| File | Responsibility |
|------|----------------|
| `px/main.py` | Entry point, multiprocessing, async server setup, `--test` logic |
| `px/handler.py` | `ConnectionHandler` — h11 HTTP parsing, request handling, client auth, curl integration, CONNECT tunnel relay, spnego monkey-patching |
| `px/config.py` | `State` singleton, CLI/env/INI/dotenv parsing, proxy reload, `quit`/`restart` actions |
| `px/wproxy.py` | `Wproxy` — proxy discovery from config, environment, Windows Internet Options, PAC |
| `px/pac.py` | `Pac` — PAC file loading and evaluation via quickjs-ng |
| `px/pacutils.py` | Mozilla PAC utility functions injected into the QuickJS runtime |
| `px/debug.py` | `Debug` singleton — stdout/file logging redirection |
| `px/help.py` | CLI help text (rendered from `--help`) |
| `px/kerberos.py` | `KerberosManager` — Kerberos ticket lifecycle (kinit, renewal, cleanup) |
| `px/version.py` | Version string |
| `px/windows.py` | Windows-specific: registry install/uninstall, console attach/detach |

## State singleton (`px.config`)

`State` is a module-level singleton (`STATE = State()`) that holds all runtime
configuration and shared objects. Key attributes:

- **Config fields** — `gateway`, `hostonly`, `listen`, `port`, `noproxy`, `pac`,
  `auth`, `username`, `client_auth`, `client_username`, etc.
- **Shared objects** — `config` (a `configparser.ConfigParser`), `mcurl`
  (a `mcurl.MCurl` instance), `wproxy` (a `Wproxy` instance), `debug`
  (a `Debug` instance).
- **Thread safety** — `state_lock` protects `reload_proxy()` so concurrent
  handler coroutines (which may call reload from `asyncio.to_thread`) do not
  refresh proxy info simultaneously.

Configuration is parsed in `parse_config()` which processes the CLI flags,
environment variables (`PX_*`), dotenv files, and `px.ini` in precedence order.
The `DEFAULTS` dict defines fallback values for every config key.

## Request handling (`px.handler`)

`ConnectionHandler._handle_request()` is the central request handler. The
connection handler uses `h11` for parsing incoming HTTP requests and sends
responses as raw bytes (since curl's bridge writes directly to the asyncio
transport, bypassing h11's state machine). A fresh `h11.Connection` is created
for each request to avoid state conflicts.

1. **Client auth** — if `--client-auth` is enabled, `_do_client_auth()` validates
   the client using NEGOTIATE/NTLM/DIGEST/BASIC. NTLM client auth uses
   monkey-patched `spnego._ntlm._get_credential` to look up credentials from
   keyring or `PX_CLIENT_PASSWORD`.
2. **Destination** — `_get_destination()` calls `STATE.reload_proxy()` (if the
   `proxyreload` interval has elapsed) and then `Wproxy.find_proxy_for_url()`
   to get the upstream proxy or DIRECT.
3. **Curl setup** — creates/reuses a `mcurl.Curl` object, sets proxy, auth,
   headers, and request body.
4. **Streaming** — for plain HTTP, a `BridgeWriter` forwards curl response data
   from the thread pool to the asyncio transport via `call_soon_threadsafe`.
   CONNECT tunnelling uses zero-thread bidirectional relays: `TunnelRelay`
   (FD watchers) on Linux, `_async_tunnel_relay` (StreamReader/Writer +
   IOCP) on Windows.
5. **Keep-alive** — the connection loop supports HTTP/1.1 keep-alive, processing
   multiple requests on a single TCP connection until a `Connection: close`
   header or a CONNECT tunnel consumes the socket.

### spnego monkey-patching

`handler.py` replaces `spnego._ntlm._get_credential` and
`spnego._ntlm._get_credential_file` before importing `spnego` itself. This
allows Px to supply NTLM credentials from keyring for client authentication
without requiring a credential file on disk. The import of `spnego` at module
level (line 57) is intentionally after the monkey-patch and is suppressed via
`E402` in ruff.

## Authentication

Px can authenticate to the upstream proxy using:
- **SSPI / GSS-API** when available (Windows default). Detected via
  `mcurl.get_curl_features()`.
- **Username / password** supplied via `--username` and stored in the system
  keyring (`keyring` module) under the realm `Px`. Falls back to `PX_PASSWORD`.
- **Explicit `--auth=NONE`** to defer authentication to the client. In this
  mode, `curl.is_easy = True` to use the easy interface for persistent
  connections needed by NTLM.

Downstream client authentication (gateway mode) is optional and supports
`NEGOTIATE`, `NTLM`, `DIGEST`, and `BASIC`. Credentials are retrieved from the
keyring under the realm `PxClient` or from `PX_CLIENT_PASSWORD` /
`PX_CLIENT_USERNAME`.

## Proxy discovery (`px.wproxy`)

The `Wproxy` class abstracts proxy information from several sources:

| Mode | Source | Trigger |
|------|--------|---------|
| `MODE_CONFIG` | `--proxy` flag | Explicit server list |
| `MODE_CONFIG_PAC` | `--pac` flag | PAC file URL or local path |
| `MODE_ENV` | `http_proxy` / `https_proxy` env vars | No explicit config |
| `MODE_AUTO` | Windows auto-detect (WPAD) | IE proxy config |
| `MODE_PAC` | Windows IE PAC URL | IE proxy config |
| `MODE_MANUAL` | Windows IE manual proxy | IE proxy config |
| `MODE_NONE` | No proxy found | Fallback to DIRECT |

On Windows, the `Wproxy` subclass uses `WinHttpGetIEProxyConfigForCurrentUser()`
and `WinHttpGetProxyForUrl()` via ctypes to discover and resolve proxies from
Internet Options.

### noproxy

The `parse_noproxy()` function parses the noproxy string into two structures:
- `netaddr.IPSet` for IP addresses, ranges (`1.2.3.4-1.2.3.5`), CIDR
  (`10.0.0.0/8`), and wildcards (`192.168.*.*`).
- `set` of hostname strings for domain-based bypasses.

`find_proxy_for_url()` checks both structures before forwarding to the proxy.

## PAC file evaluation (`px.pac`)

The `Pac` class loads a PAC file (from URL or local path) and evaluates it using
[quickjs-ng](https://github.com/nickg/quickjs-ng). The JavaScript runtime is
initialised with Mozilla PAC utility functions from `pacutils.py`
(`dnsDomainIs`, `isInNet`, `shExpMatch`, `myIpAddress`, etc.).

`Pac` uses `quickjs.Function` (rather than `quickjs.Context`) to ensure thread
safety — each call to `find_proxy_for_url()` is dispatched to a thread pool
internally by `quickjs.Function`.

## Proxy reload

`STATE.reload_proxy()` is called on every request. It checks whether
`proxyreload` seconds have elapsed since the last refresh. If so, it acquires
`state_lock` and rebuilds the `Wproxy` instance from the current configuration.
This allows Px to pick up proxy changes (e.g. WPAD updates, PAC file changes)
without restarting.

## CONNECT tunnel relay

CONNECT tunnels are the most complex part of the proxy. After `mcurl.do()`
establishes the upstream connection (and performs proxy authentication if
needed), the proxy must relay raw bytes bidirectionally between the client
socket and the upstream socket until one side closes or an idle timeout fires.

### Design goals

- **Zero additional threads** — tunnels must not consume thread pool slots.
  The thread pool is reserved for `mcurl.do()` calls only.
- **High concurrency** — hundreds of simultaneous tunnels must coexist on a
  single event loop without degrading performance.
- **Bounded resources** — thread count and memory must stay roughly constant
  regardless of active tunnel count.

### Platform-specific relay strategies

#### Linux — `TunnelRelay` (FD watchers)

On Linux, `SelectorEventLoop` supports `add_reader()`/`add_writer()` for raw
file descriptors. `TunnelRelay` uses `os.dup()` to duplicate the client FD
(so asyncio's transport ownership tracking doesn't conflict), then registers
FD watchers for both sides:

- `_on_client_readable` → `os.read()` from client FD → `os.write()` to upstream FD
- `_on_upstream_readable` → `os.read()` from upstream FD → `os.write()` to client FD

Partial writes are buffered and drained via `add_writer()` callbacks. An idle
timeout fires via `call_later()`. All I/O is non-blocking and multiplexed by
epoll — no threads involved.

#### Windows — `_async_tunnel_relay` (StreamReader/Writer + IOCP)

On Windows, `ProactorEventLoop` does not support `add_reader()`/`add_writer()`
for raw FDs. Instead, `_async_tunnel_relay` uses a hybrid approach:

- **Client side:** asyncio `StreamReader.read()` / `StreamWriter.write()` —
  the transport keeps its IOCP ownership of the client socket.
- **Upstream side:** `loop.sock_recv()` / `loop.sock_sendall()` on the raw
  libcurl socket (which has no asyncio transport).

Two async tasks run concurrently:
- `client_to_upstream()` — reads from `reader`, sends via `sock_sendall`
- `upstream_to_client()` — reads via `sock_recv`, writes to `writer`

A watchdog task monitors idle timeout. When any task completes (connection
closed, error, or timeout), the remaining tasks are cancelled.

### Windows IOCP design rationale

The Windows relay uses `StreamReader`/`StreamWriter` for the client side
instead of raw `sock_recv()` because **ProactorEventLoop's IOCP creates
exclusive ownership of a socket's overlapped I/O.** The asyncio transport
holds the client socket's IOCP registration; issuing a second overlapped
read via `sock_recv()` on the same socket causes undefined behavior
(assertion failures in `_loop_reading`, data loss from competing IOCP
completions). Using the `StreamReader`/`StreamWriter` API lets the
transport manage all IOCP operations on the client socket while the relay
reads and writes through the standard asyncio streams interface.

For the upstream (libcurl) socket, `sock_recv()`/`sock_sendall()` work
because that socket has no asyncio transport — it was created by libcurl
and accessed via `socket.fromfd()`.  See `debug.md` for detailed research
notes on Windows IOCP and socket duplication challenges.

### Relay lifecycle

```
_handle_request()
  │
  ├─ asyncio.to_thread(STATE.mcurl.do, curl)   ← thread pool slot
  │     └─ Thread released after do() returns
  │
  └─ _handle_connect_tunnel()
       ├─ Send "200 Connection established" to client
       ├─ writer.drain()  ← flush the 200 response
       │
       ├─ [Linux]   pause_reading() + os.dup(client_fd)
       │             → TunnelRelay(add_reader/add_writer)
       │
       └─ [Windows] reader/writer kept as-is (transport keeps IOCP ownership)
                     → _async_tunnel_relay(reader, writer, curl_sock)
                          │
                          ├─ client_to_upstream()  ← reader.read() → sock_sendall()
                          ├─ upstream_to_client()  ← sock_recv() → writer.write()
                          └─ watchdog(idle_timeout)
```

### Benchmark results

With default `--threads=32` on a single worker process (`--workers=1`).
Benchmarks test up to 1 000–1 024 concurrent connections.

| Metric | Linux | Windows |
|--------|-------|---------|
| HTTP throughput (1 000 concurrent) | ~620 req/s, 200/200 | ~250 req/s, 200/200 |
| CONNECT throughput (1 000 concurrent) | ~520 req/s, 200/200 | ~267 req/s, 200/200 |
| Thread pool saturation (1 024 concurrent) | ~770 req/s, 200/200 | ~256 req/s, 200/200 |
| Active tunnel data exchange (512 tunnels) | ~80–100% succeed | 512/512 succeed |
| Active tunnel data exchange (1 024 tunnels) | ~30–67% succeed | ~72% succeed |
| Thread count under load | 35 (constant) | 40–46 (constant) |
| Memory baseline / under load | ~57 MB / ~65 MB | ~87 MB / ~88 MB |
| Thread pool saturation point | concurrency ≈ 32 | concurrency ≈ 128 |

Thread count stays bounded near the thread pool size regardless of active tunnel
count — the zero-thread relay design keeps tunnels off the pool entirely.
`psutil.num_threads()` reports total OS threads (pool + main + event loop +
runtime helpers); on Windows the ProactorEventLoop's IOCP completion threads add
a few more, hence 40–46 vs 35 on Linux, but neither grows with tunnel count.
Memory growth is modest under load. The active data exchange test uses
barrier-synchronised threads so all tunnels fire simultaneously; at 1 024
tunnels, OS-level limits (FDs, kernel buffers) become the dominant factor rather
than the proxy itself.

## Error handling

- **Unhandled exceptions** — `handle_exceptions()` in `main.py` installs a
  global exception handler that writes tracebacks to `debug.log` in the working
  directory.
- **Connection errors** — `ConnectionHandler.handle()` catches exceptions during
  request processing, logs them, cleans up the curl handle, and closes the
  connection.
- **Debug module** — `pprint()` and `dprint()` silently swallow exceptions to
  ensure logging never crashes the proxy. Bare excepts in `debug.py` are
  intentional. In `--verbose` mode (stdout), `dprint()` skips file I/O and
  `os.fsync()`, and omits the process name when `--workers=1`, keeping
  per-call overhead minimal. In `--debug` mode (file), full flush-after-write
  with `os.fsync()` is retained for crash diagnostics.

## Kerberos ticket management (`px.kerberos`)

On Linux and macOS, upstream Kerberos (NEGOTIATE) authentication requires a
valid TGT in the credential cache. `KerberosManager` handles the full ticket
lifecycle so users do not need external `kinit` scripts.

### MIT vs Heimdal detection

At startup, `KerberosManager` runs `klist --version` and checks whether the
output contains "heimdal". Heimdal's `klist` prints its version string while
MIT's `klist` does not recognise `--version` and exits with an error. The
detection result (`_is_heimdal`) selects the correct flags and date-format
parsers throughout the manager's lifetime. If `klist` is not installed, the
manager defaults to MIT behaviour.

### Inline check pattern

`reload_kerberos()` follows the same pattern as `reload_proxy()`: it is called
on every request from `get_destination()`, uses a timestamp gate for the fast
path, and acquires a blocking lock so concurrent threads wait for renewal
instead of proceeding with an expired ticket.

### Per-process isolation

Each worker process creates its own `KerberosManager` with an isolated
credential cache (`KRB5CCNAME=FILE:/tmp/krb5cc_px_<pid>`). Since workers call
`parse_config()` independently after `spawn`, each gets its own instance with
no shared state.

### GSS-API startup check

`parse_config()` verifies that libcurl was built with GSS-API support before
creating a `KerberosManager`. If the feature is missing, px exits with an
error. SSPI (Windows) is not checked because `--kerberos` only applies to
Linux and macOS.

### GSS-API path override

When `--kerberos` is enabled, `set_curl_auth()` forces `key = ":"` (GSS-API
mode) regardless of whether `--username` is set. The username and password are
used only by `KerberosManager` for `kinit`, not passed to libcurl.

### PTY-based password piping

`kinit` reads passwords from `/dev/tty`, not stdin. `KerberosManager` uses
`pty.openpty()` to create a pseudo-terminal pair, makes the slave side the
child process's controlling terminal via `setsid` + `TIOCSCTTY`, then writes
the password on the master side so that kinit's `read(/dev/tty)` sees it.
No keytab file is created — credentials stay in memory.

### Auth failure recovery

When libcurl reports an SSO failure (`resp == 401`, "single sign-on failed") or
a mechanism error (`resp == 407`, "auth mechanism error"), the reactive check
forces a ticket renewal bypassing both the fast-path timestamp gate and the
in-lock double-check. If the ticket is invalid, a new one is acquired and
`MCURL.failed` is cleared so previously-blocked proxies are retried.

### Credential cache cleanup

`atexit` registers `_cleanup()` to remove the per-process ccache file.
`do_quit()` calls `cleanup_kerberos()` explicitly before `os._exit()` since
`os._exit()` bypasses `atexit` handlers.
