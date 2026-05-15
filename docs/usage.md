# Usage

---

## Quick start

```bash
# Run as a simple proxy on localhost
px --proxy=proxyserver.com:8080

# Use a PAC file
px --pac=file:///path/to/config.pac

# Run with verbose logging
px --proxy=proxyserver.com:80 --verbose

# Save configuration to px.ini
px --proxy=proxyserver.com:8080 --save

# Test connectivity
px --test
```

For all CLI flags, environment variables, and INI keys, see the
[configuration reference](configuration.md).

## Running Px

Once installed, Px can be run as follows:

- `px` or `python -m px` — run in foreground
- `pxw` or `pythonw -m px` — run in the background (Windows)
- `px --quit` — stop a running instance
- `px --restart` — stop and start a new instance
- `CTRL-C` — stop when running in the foreground

### Windows auto-start

Px can be set up to run on startup on Windows:

    pxw --install

Remove with `--uninstall`. Use `--force` to overwrite an existing entry. If
`px.ini` is at a non-default location:

    pxw --install --config=path/px.ini

Command line parameters passed with `--install` are not saved for use on
startup. Use `--save` or edit `px.ini` manually.

## Credentials

If SSPI is not available or not preferred, providing `--username` in
`domain\username` format allows Px to authenticate as that user. The password is
retrieved from the system keyring.

```bash
# Set credentials interactively
px --username=domain\username --password

# If username is already configured
px --password
```

Information on keyring backends: <https://pypi.org/project/keyring>

As an alternative, `PX_PASSWORD` or a dotenv file can supply credentials (only
recommended when keyring is not available).

### Plaintext keyring fallback

If the system keyring is unavailable or problematic, set `PX_KEYRING_PLAINTEXT=1`
to use a plaintext file-based keyring backend. **This is not recommended** as
passwords are stored unencrypted on disk, but it is available as a fallback option
when other backends fail.

### Windows

Credential Manager is the recommended backend. The password is stored as a
'Generic Credential' with 'Px' as the network address name.

    Control Panel > User Accounts > Credential Manager > Windows Credentials

Or: `rundll32.exe keymgr.dll, KRShowKeyMgr`

### Mac

Keychain Access is used:

- Pick 'Passwords' → 'login' and add a keychain item for 'Px' / 'PxClient'.
- Select 'Always Allow' when prompted.

CLI: `security add-generic-password -s Px -a username -w password`

### Linux

Gnome Keyring or KWallet is used. For headless systems:

```bash
dbus-run-session -- sh
# or in a script:
export DBUS_SESSION_BUS_ADDRESS=$(dbus-daemon --fork --config-file=/usr/share/dbus-1/session.conf --print-address)
echo 'somecredstorepass' | gnome-keyring-daemon --unlock
```

gnome-keyring-daemon 48+ requires the keyrings directory
(`~/.local/share/keyrings`) to be owned by the current user with mode `700`.
If the directory has incorrect ownership or permissions, the daemon silently
fails to create the keyring collection with a `Prompt dismissed.` error.

If the default SecretService backend does not work, install a third-party
[backend](https://github.com/jaraco/keyring#third-party-backends).

For Nuitka binaries where keyring is unavailable, use `PX_PASSWORD` instead.

## Kerberos authentication

On Linux and macOS, upstream proxy authentication using Kerberos (NEGOTIATE)
requires a valid Kerberos ticket in the credential cache. Px can manage this
automatically with the `--kerberos` flag.

When `--kerberos` is enabled, Px:

- Acquires a Kerberos TGT at startup using `kinit` with the configured
  `--username` as the Kerberos principal and the password from `PX_PASSWORD`
  or the system keyring.
- Renews the ticket proactively before it expires.
- Retries acquisition if authentication fails (e.g. after laptop sleep).
- Cleans up the per-process credential cache on exit.

No keytab file is created — credentials stay in memory.

### Native usage

Save the password to keyring first (one-time setup), then run with `--kerberos`:

```bash
# Save password to keyring (prompts interactively)
px --username=user@REALM --password

# Run with Kerberos ticket management
px --kerberos --auth=NEGOTIATE --username=user@REALM
```

If keyring is unavailable, `PX_PASSWORD` can be used instead:

```bash
PX_PASSWORD=... px --kerberos --auth=NEGOTIATE --username=user@REALM
```

### Docker usage

The Docker image includes the `krb5` package which provides `kinit` and `klist`.
Mount `/etc/krb5.conf` from the host (or bake it into a custom image) so that
Kerberos can find the KDC for your realm.

The full image requires `--cap-add IPC_LOCK` so that `gnome-keyring-daemon` can
lock memory pages for secure credential storage. The keyrings volume must be
owned by `root` with mode `700` inside the container — do not pre-create the
host directory; let Docker create it so that ownership is correct. If the
directory has wrong ownership, gnome-keyring-daemon silently fails with a
`Prompt dismissed.` error.

The recommended approach is to store the password in keyring rather than passing
it via `PX_PASSWORD`. Mount a host directory for keyring persistence and save
the password once:

```bash
# Save password to keyring (one-time setup)
docker run --rm -it --cap-add IPC_LOCK \
    -v /keyrings:/root/.local/share/keyrings \
    genotrance/px --username=user@REALM --password
```

Then run Px with the keyring mount and Kerberos enabled:

```bash
docker run --rm -d --network host --cap-add IPC_LOCK \
    -v /etc/krb5.conf:/etc/krb5.conf:ro \
    -v /keyrings:/root/.local/share/keyrings \
    -e PX_KERBEROS=1 \
    -e PX_AUTH=NEGOTIATE \
    -e PX_USERNAME=user@REALM \
    genotrance/px
```

This avoids placing the password in an environment variable (which is visible
in `docker inspect` and `/proc/<pid>/environ`). The keyring volume can be reused
across container restarts.

If keyring is not an option (e.g. when using the mini image), fall back to the
environment variable:

```bash
docker run --rm -d --network host \
    -v /etc/krb5.conf:/etc/krb5.conf:ro \
    -e PX_KERBEROS=1 \
    -e PX_AUTH=NEGOTIATE \
    -e PX_USERNAME=user@REALM \
    -e PX_PASSWORD=... \
    genotrance/px:mini
```

### Self-managed tickets

Without `--kerberos`, Px does not manage Kerberos tickets. You must run `kinit`
externally and handle renewal (e.g. via `kinit -R` in a cron job or startup
script). If the ticket expires, Px will fail to authenticate until a new ticket
is obtained and Px is restarted.

### Password expiry

If the password in `PX_PASSWORD` or keyring expires while Px is running, ticket
renewal via `kinit -R` continues working as long as the current TGT is still
valid and within its renewable lifetime. Once renewal fails, Px logs a message
and backs off. Update the password via `PX_PASSWORD` or `--password` and restart
Px.

On Windows, `--kerberos` is silently ignored because Windows uses SSPI for
Kerberos authentication, which handles ticket management transparently.

## Client authentication

Px can authenticate downstream clients connecting to it. This is useful in
`gateway` mode where remote clients should log in before using the proxy.

Supported mechanisms: `NEGOTIATE`, `NTLM`, `DIGEST`, `BASIC`.

Client authentication is off by default. Enable with `--client-auth` (recommended
value: `ANYSAFE`).

```bash
px --client-auth=ANYSAFE --client-username=DOMAIN\user
px --client-username=domain\username --client-password
```

SSPI is enabled by default on Windows; disable with `--client-nosspi`.

Multiple client users are supported when using keyring — add each user under the
`PxClient` network address.

## Examples

Use `proxyserver.com:80` and allow requests from localhost only:

    px --proxy=proxyserver.com:80

Don't use any forward proxy at all, just log what's going on:

    px --noproxy=0.0.0.0/0 --debug

Allow requests from `localhost` and all locally assigned IP addresses (useful for
Docker for Windows and VMs in a NAT configuration):

    px --proxy=proxyserver.com:80 --hostonly

Allow requests from localhost, local IPs and specific external IPs:

    px --proxy=proxyserver:80 --hostonly --gateway --allow=172.*.*.*

Allow requests from everywhere (every client will use your login):

    px --proxy=proxyserver.com:80 --gateway

### Docker for Windows

Set your proxy in containers to `http://host.docker.internal:3128` or
`http://<your_ip>:3128`.

    docker build --build-arg http_proxy=http://<your_ip>:3128 --build-arg https_proxy=http://<your_ip>:3128 -t name .

### WSL2

Set up your proxy in `/etc/profile`:

```bash
export http_proxy="http://$(tail -1 /etc/resolv.conf | cut -d' ' -f2):3128"
export https_proxy="http://$(tail -1 /etc/resolv.conf | cut -d' ' -f2):3128"
```

### MQTT over websockets

Increase the idle timeout to 120 seconds (`--idle=120`) since the default MQTT
keepalive period is 60 seconds.

## Dependencies

Px depends on the following Python packages:

- [h11](https://pypi.org/project/h11/)
- [keyring](https://pypi.org/project/keyring/)
- [keyrings.alt](https://pypi.org/project/keyrings.alt/)
- [netaddr](https://pypi.org/project/netaddr/)
- [pymcurl](https://pypi.org/project/pymcurl/)
- [psutil](https://pypi.org/project/psutil/)
- [pyspnego](https://pypi.org/project/pyspnego/)
- [python-dotenv](https://pypi.org/project/python-dotenv/)
- [quickjs-ng](https://pypi.org/project/quickjs-ng/)

## Limitations

- On Windows, connection distribution across multiple `--workers` processes may
  not be perfectly even. The default `--workers=1` is sufficient for most
  workloads since the async event loop handles concurrency efficiently.
