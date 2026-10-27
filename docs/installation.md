# Installation

---

## Quick install

If direct internet access is available along with Python (≥ 3.10):

    pip install px-proxy

Or using [uv](https://docs.astral.sh/uv/):

    uv tool install px-proxy
    uvx --from px-proxy px

Or using [pipx](https://pipx.pypa.io/):

    pipx install px-proxy

These installs include Px's platform-specific event-loop dependency: `uvloop`
on Linux and macOS, or `winloop` on Windows. There is no separate Px extra to
select; pip chooses the dependency from the platform markers in
`pyproject.toml`. Px falls back to Python's built-in `asyncio` event loop if
the selected loop cannot be imported at runtime. `winloop` does not yet publish
Python 3.15 wheels, so use a supported Python version on Windows until those
wheels are available.

On Windows, [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/)
and [Scoop](https://scoop.sh) can also be used:

    winget install genotrance.px
    scoop install px

## Offline install via wheels

The whole point of Px is to help tools get through a typical corporate proxy.
This means using a package manager to install Px might not always be feasible
which is why Px offers prebuilt wheels:

1. Download the platform-specific `px-v<version>-<platform>-wheels` archive
   from the [releases](https://github.com/genotrance/px/releases) page. Linux
   archives use `.tar.gz`; Windows uses `.zip`.
2. Extract and install:

       python -m pip install --no-index -f /path/to/extracted-wheels px-proxy

The matching archive includes Px and all of its dependencies, including the
platform event-loop package (`uvloop` or `winloop`). Keep all of its wheels in
the extracted directory while installing.

## Standalone binary

If Python is not available, download the latest compiled binary from the
[releases](https://github.com/genotrance/px/releases) page. The Windows binary
is built using Python Embedded and the Mac and Linux binaries are compiled with
[Nuitka](https://nuitka.net) and contain everything needed to run standalone.
Linux and macOS Nuitka binaries bundle `uvloop`; the Windows Embedded binary
installs `winloop` from its matching wheel archive. This includes both glibc and
musl Linux binaries.

## Running Px

Once installed, Px can be run as follows:

- `px` or `python -m px`
- In the background on Windows: `pxw` or `pythonw -m px`
- As a wrapped service using [WinSW](https://github.com/winsw/winsw)

### Running as a Windows service using WinSW

Download the executable `WinSW-x64.exe` from
[WinSW](https://github.com/winsw/winsw) (tested with 2.12.0).

Place a minimal `WinSW-x64.xml` configuration file next to the executable:

```xml
<service>
  <id>Px</id>
  <name>Px Service (powered by WinSW)</name>
  <description>Px HTTP proxy service</description>
  <executable>D:\px\px.exe</executable>

  <!-- Run under a specific user account to access their credentials via SSPI -->
  <serviceaccount>
    <domain>DOMAIN</domain>
    <user>username</user>
    <password>password</password>
    <allowLogonAsService>true</allowLogonAsService>
  </serviceaccount>

  <!-- Alternative: Pass credentials via environment variables running as LocalSystem
  <env name="PX_USERNAME" value="DOMAIN\username"/>
  <env name="PX_PASSWORD" value="password"/>
  -->
</service>
```

Run from an elevated administrator prompt:

    WinSW-x64.exe install WinSW-x64.xml

Start the service:

    WinSW-x64.exe start WinSW-x64.xml

> **Note:** When running Px as a Windows service using WinSW, the service typically runs
> under the LocalSystem account. This account does not have access to SSPI for NTLM or
> Kerberos authentication, which relies on the interactive user's security context.
> You have two options:
>
> 1. Use `<serviceaccount>` to run the WinSW service under a specific user account, which allows SSPI to work with that user's credentials
> 2. Use `<env>` to pass explicit username/password credentials via environment variables when running as LocalSystem
>
> If you need to use your current user's credentials through SSPI or Credential Manager, consider using `pxw` with automatic startup instead
> of having to write your credentials in the service configuration.

## Source install

The latest version can be installed from source via pip:

    python -m pip install https://github.com/genotrance/px/archive/master.zip

Or clone and install:

```bash
git clone https://github.com/genotrance/px
cd px
python -m pip install .
```

> **Note:** Source install methods require internet access since Python will try
> to install Px dependencies from the internet. The wheels mentioned above can
> bootstrap a source install.

### Without installation

Px can be run as a local Python script without installation:

```bash
pip install h11 keyring keyrings.alt netaddr psutil "pymcurl>=8.23.0.2" pyspnego python-dotenv quickjs-ng
pip install uvloop  # Linux/macOS; selected automatically by a package install
pip install winloop  # Windows; no Python 3.15 wheels yet

pythonw px.py  # run in the background
python px.py   # run in a console window
```

## Uninstallation

`px --uninstall` only removes the Windows sign-in auto-start entry created by
`px --install`. It does not delete any files, so run it before removing the
install. Stop Px first with `px --quit`.

Winget (Windows):

    px --quit
    px --uninstall
    winget uninstall genotrance.px

Add `--purge` to `winget uninstall` to delete everything in the package folder.
Delete `%APPDATA%\px\px.ini` if a configuration was saved there.

pip:

    px --quit
    px --uninstall    # Windows only, if auto-start was set up
    python -m pip uninstall px-proxy

For a `uv tool` install, run `uv tool uninstall px-proxy`; for pipx, run
`pipx uninstall px-proxy`. Remove the extracted offline-wheel directory only
after every installed package that uses it has been removed.

Standalone binary: run `px --quit`, `px --uninstall` if auto-start was set up,
then delete the folder containing the binary.

## Docker

Px is available as a prebuilt Docker
[image](https://hub.docker.com/r/genotrance/px).

Two images are posted — the default includes keyring and associated dependencies
whereas the mini version is smaller but requires `PX_PASSWORD` and
`PX_CLIENT_PASSWORD` environment variables for credentials.

### Docker flags

```
--name px       name container so it is easy to stop it
-d              run in the background
--rm            remove container on exit

--cap-add IPC_LOCK
                required for the full image — gnome-keyring-daemon needs
                the IPC_LOCK capability to manage secure memory
```

### Networking

```
--network host  make Px directly accessible from host network
  OR
-p 3128:3128    publish the port — Px needs to run in --gateway mode
```

### Configuration

```
-e PX_LOG=4     set environment variables to configure Px

-v /dir:/px     mount a host directory with a px.ini or .env file
  OR
--mount source=/dir,target=/px

docker run ... genotrance/px --gateway --verbose
                configure directly from the command line
```

### Credentials

Keyring credentials can be stored in a host folder and mounted:

```
-v /keyrings:/root/.local/share/keyrings
  OR
--mount source=/keyrings,target=/root/.local/share/keyrings
```

Save credentials via CLI:

```
docker run ... genotrance/px --username=... --password
```

The mini image requires environment variables:

```
-e PX_PASSWORD=... -e PX_CLIENT_PASSWORD=...
```

### Kerberos in Docker

The full Docker image includes the `krb5` package (providing `kinit` and
`klist`) and runs `gnome-keyring-daemon` via `start.sh`, so both Kerberos ticket
management and keyring credential storage work out of the box. The mini image
does not include keyring support.

See the [Kerberos Docker usage](https://github.com/genotrance/px/blob/master/docs/usage.md#docker-usage)
section for `docker run` examples covering keyring setup, volume mounts, and
`PX_PASSWORD` fallback.
