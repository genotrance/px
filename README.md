[![Chat on Gitter](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/genotrance/px)
[![Chat on Matrix](https://img.shields.io/matrix/genotrance_px:matrix.org)](https://matrix.to/#/#genotrance_px:matrix.org)

# Px

An HTTP(s) proxy server that allows applications to authenticate through an
NTLM or Kerberos proxy server, typically used in corporate deployments, without
having to deal with the actual handshake. Px leverages Windows SSPI or single
sign-on and automatically authenticates using the currently logged in Windows
user account. It is also possible to run Px on Windows, Linux and MacOS without
single sign-on by configuring the domain, username and password to authenticate
with.

Px uses libcurl and supports all the authentication mechanisms supported by
[libcurl](https://curl.se/libcurl/c/CURLOPT_HTTPAUTH.html).

**Requires Python ≥ 3.10**

## Installation

```bash
python -m pip install px-proxy
```

On Windows, the following package managers can be used:
| Package Manager                                                             | Command                        |
|-----------------------------------------------------------------------------|--------------------------------|
| [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/) | `winget install genotrance.px` |
| [Scoop](https://scoop.sh)                                                   | `scoop install px`             |

Prebuilt binaries and offline wheel packages are available on the
[releases](https://github.com/genotrance/px/releases) page. See the
[installation guide](https://github.com/genotrance/px/blob/master/docs/installation.md)
for all options including Docker, WinSW, and source installs.

## Quick start

```bash
# Run with an upstream proxy
px --proxy=proxyserver.com:8080

# Run with a PAC file
px --pac=http://example.com/proxy.pac

# Run with verbose logging
px --proxy=proxyserver.com:80 --verbose

# Save configuration to px.ini
px --proxy=proxyserver.com:8080 --save

# Test connectivity
px --test
```

## Configuration

Px can be configured via command-line flags, environment variables (`PX_*`),
dotenv files, or `px.ini`. See `px --help` for all options.

Common options:

| Flag | Description |
|------|-------------|
| `--proxy=HOST:PORT` | Upstream proxy server(s), comma-separated |
| `--pac=URL` | PAC file URL or local path |
| `--port=NUM` | Listening port (default 3128) |
| `--gateway` | Allow remote clients |
| `--hostonly` | Restrict to local interfaces |
| `--noproxy=LIST` | Hosts/IPs that bypass the upstream proxy |
| `--auth=TYPE` | Force upstream auth type (ANY, NTLM, NEGOTIATE, BASIC, NONE) |
| `--username=DOMAIN\user` | Username for upstream proxy auth |
| `--log=4` | Log to stdout (verbose mode) |

Full reference:
[Configuration](https://github.com/genotrance/px/blob/master/docs/configuration.md)

### Credentials

If SSPI is not available, provide `--username` in `domain\username` format. The
password is stored in the system keyring:

```bash
px --username=domain\username --password
```

`PX_PASSWORD` can be used as an alternative when keyring is not available.

See the
[usage guide](https://github.com/genotrance/px/blob/master/docs/usage.md)
for platform-specific keyring setup and client authentication.

## Documentation

| | |
|---|---|
| **User guides** | |
| [Installation](https://github.com/genotrance/px/blob/master/docs/installation.md) | pip, wheels, binary, Docker, scoop, WinSW, uninstallation |
| [Usage](https://github.com/genotrance/px/blob/master/docs/usage.md) | Credentials, client auth, examples, dependencies, limitations |
| [Configuration](https://github.com/genotrance/px/blob/master/docs/configuration.md) | All CLI flags, environment variables, INI keys, auth types |
| **Developer guides** | |
| [Architecture](https://github.com/genotrance/px/blob/master/docs/architecture.md) | Runtime model, package layout, data flow, state management |
| [Build](https://github.com/genotrance/px/blob/master/docs/build.md) | Build system, `pyproject.toml`, GitHub Actions, wheels, Nuitka, Docker |
| [Testing](https://github.com/genotrance/px/blob/master/docs/testing.md) | Test suite layout, running tests, fixtures, coverage |
| **Reference** | |
| [Changelog](https://github.com/genotrance/px/blob/master/docs/changelog.md) | Release history |

## Development

Requires [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/genotrance/px.git
cd px
make install
make test
```

| Target | Description |
|---|---|
| `make install` | Create venv, install dependencies, install pre-commit hooks |
| `make check` | Run linters (ruff) and type checking (mypy) |
| `make test` | Run tests with coverage |
| `make build` | Build sdist and wheel |
| `make clean` | Remove build artifacts |

## Contributing

Bug reports and pull requests are welcome at
<https://github.com/genotrance/px/issues>.

1. Fork and clone the repository.
2. `make install` to set up the venv and pre-commit hooks.
3. Create a feature branch, make changes, add tests in `tests/`.
4. `make check && make test` — all checks must pass.
5. Open a pull request.

## Feedback

Px is definitely a work in progress and any feedback or suggestions are welcome.
It is hosted on [GitHub](https://github.com/genotrance/px) with an MIT license
so issues, forks and PRs are most appreciated. Join us on the
[discussion](https://github.com/genotrance/px/discussions) board,
[Gitter](https://gitter.im/genotrance/px) or
[Matrix](https://matrix.to/#/#genotrance_px:matrix.org) to chat about Px.

## Credits

Thank you to all
[contributors](https://github.com/genotrance/px/graphs/contributors) for their
PRs and all issue submitters.

Px is based on code from all over the internet and acknowledges innumerable
sources.
