[![Chat on Gitter](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/genotrance/px)
[![Chat on Matrix](https://img.shields.io/matrix/genotrance_px:matrix.org)](https://matrix.to/#/#genotrance_px:matrix.org)

# Px

## What is Px?
Px is a HTTP(s) proxy server that allows applications to authenticate through
an NTLM or Kerberos proxy server, typically used in corporate deployments,
without having to deal with the actual handshake. Px leverages Windows SSPI or
single sign-on and automatically authenticates using the currently logged in
Windows user account. It is also possible to run Px on Windows, Linux and MacOS
without single sign-on by configuring the domain, username and password to
authenticate with.

Px uses libcurl and as a result supports all the authentication mechanisms
supported by [libcurl](https://curl.se/libcurl/c/CURLOPT_HTTPAUTH.html).

## Installation

The whole point of Px is to help tools get through a typical corporate proxy.
This means using a package manager to install Px might not always be feasible
which is why Px offers two binary options:
- If Python is already available, Px and all its dependencies can be easily
installed by downloading the `wheels` package for the target OS from the
[releases](https://github.com/genotrance/px/releases) page. After extraction,
Px and all dependencies can be installed with `pip`:

	`python -m pip install px-proxy --no-index -f /path/to/wheels`

- If Python is not available, get the latest compiled binary from the
[releases](https://github.com/genotrance/px/releases) page instead. These
binaries are compiled with [Nuitka](https://nuitka.net) and contain everything
needed to run standalone.

If direct internet access is available along with Python, Px can be easily
installed using the Python package manager `pip`. This will download and install
Px as a Python module along with all dependencies:

	python -m pip install px-proxy

On Windows, `scoop` can also be used to install Px:

	scoop install px

Once installed, Px can be run as follows:
- Running `px` directly
- In the background: `pythonw -m px`
- In the foreground in a console window: `python -m px`

Px requires [libcurl](https://curl.se/libcurl/) and the Windows builds ship with
a copy. On Linux, it is required to install libcurl using the package manager:

- RHEL: `yum install libcurl`
- Ubuntu: `apt install libcurl4`
- Alpine: `apk add libcurl`

### Source install

The latest Px version can be downloaded and installed from source via pip:

	python -m pip install git+https://github.com/genotrance/px

Source can also be downloaded separately and installed:

- Via git:

	`git clone https://github.com/genotrance/px`

- Download [ZIP](https://github.com/genotrance/px/archive/master.zip):

	`https://github.com/genotrance/px/archive/master.zip`

Once downloaded, Px can be installed as a standard Python module along with all
dependencies :

	python -m pip install .

NOOTE: Source install methods will require internet access since Python will try
to install Px dependencies from the internet. The binaries mentioned in the
previous section could be used to bootstrap a source install.

NOTE: libcurl will need to be installed on Linux, as described earlier, using
the package manager. For Windows, [download](https://curl.se/windows/) and
extract `libcurl.dll` and `libcurl-x64.dll` to `$PATH`.

### Without installation

Px can be run as a local Python script without installation. Download the source
as described above, install all dependencies and then run Px:

```
pip install keyring netaddr psutil quickjs futures

# Download/install libcurl

pythonw px.py # run in the background
python px.py # run in a console window
```

### Uninstallation

If Px has been installed to the Windows registry to start on boot, it should be
removed before uninstallation:

	python -m px --uninstall

Px can then be uninstalled using `pip` as follows:

	python -m pip uninstall px-proxy

## Configuration

Px requires only one piece of information in order to function - the server
name and port of the proxy server. This needs to be configured in `px.ini`. If not
specified, Px will check Internet Options or environment variables for any proxy
definitions and use them. Without this, Px will try to connect to sites directly.

The noproxy capability allows Px to connect to hosts in the configured subnets
directly, bypassing the proxy altogether. This allows clients to connect to
hosts within the intranet without requiring additional configuration for each
client or at the proxy.

### Credentials

If SSPI is not available or not preferred, providing a `username` in `domain\username`
format allows Px to authenticate as that user. The corresponding password is
retrieved using Python keyring and needs to be setup in the appropriate OS specific
backend.

Credentials can be setup with the command line:

	px --username=domain\username --password

If username is already defined in `px.ini`:

	px --password

Information on keyring backends can be found [here](https://pypi.org/project/keyring).

#### Windows

Credential Manager is the recommended backend for Windows and the password is stored
as a 'Generic Credential' type with 'Px' as the network address name. Credential Manager
can be accessed as follows:

	Control Panel > User Accounts > Credential Manager > Windows Credentials

	Or on the command line: `rundll32.exe keymgr.dll, KRShowKeyMgr`

### Linux

Gnome Keyring or KWallet is used to store passwords on Linux. For systems without
a GUI (headless, docker), refer to these [instructions](https://github.com/jaraco/keyring#using-keyring-on-headless-linux-systems-in-a-docker-container)
to start the SecretService backend.

If the default SecretService keyring backend does not work, the [keyring_jeepney](https://pypi.org/project/keyring_jeepney)
package might provide an alternative.

	python -m pip install keyring_jeepney

Worst case, the [keyrings.alt](https://pypi.org/project/keyrings.alt/) package can
be used.

	python -m pip install keyrings.alt

### Misc

There are a few other settings to tweak in `px.ini` file but most are obvious.
All settings can be specified on the command line for convenience. The INI file
can also be created or updated from the command line using `--save`.

The binary distribution of Px runs in the background once started and can be
quit by running `px --quit`. When running in the foreground, use `CTRL-C`.

Px can also be setup to automatically run on startup with the `--install` flag.
This is done by adding an entry into the Window registry which can be removed
with `--uninstall`.

NOTE: Command line parameters passed with `--install` are not saved for use on
startup. The `--save` flag or manual editing of `px.ini` is required to provide
configuration to Px on startup.

## Usage

```
px [FLAGS]
python px.py [FLAGS]

Actions:
  --save
  Save configuration to px.ini or file specified with --config
    Allows setting up Px config directly from command line
    Values specified on CLI override any values in existing config file
    Values not specified on CLI or config file are set to defaults

  --install
  Add Px to the Windows registry to run on startup

  --uninstall
  Remove Px from the Windows registry

  --quit
  Quit a running instance of Px.exe

  --password
  Collect and save password to default keyring. Username needs to be provided
  via --username or already specified in the config file

Configuration:
  --config=
  Specify config file. Valid file path, default: px.ini in working directory

  --proxy=  --server=  proxy:server= in INI file
  NTLM server(s) to connect through. IP:port, hostname:port
    Multiple proxies can be specified comma separated. Px will iterate through
    and use the one that works

  --pac=  proxy:pac=
  PAC file to use to connect
    Use in place of --server if PAC file should be loaded from a URL or local
    file. Relative paths will be relative to the Px script or binary

  --listen=  proxy:listen=
  IP interface to listen on. Valid IP address, default: 127.0.0.1

  --port=  proxy:port=
  Port to run this proxy. Valid port number, default: 3128

  --gateway  proxy:gateway=
  Allow remote machines to use proxy. 0 or 1, default: 0
    Overrides 'listen' and binds to all interfaces

  --hostonly  proxy:hostonly=
  Allow only local interfaces to use proxy. 0 or 1, default: 0
    Px allows all IP addresses assigned to local interfaces to use the service.
    This allows local apps as well as VM or container apps to use Px when in a
    NAT config. Px does this by listening on all interfaces and overriding the
    allow list.

  --allow=  proxy:allow=
  Allow connection from specific subnets. Comma separated, default: *.*.*.*
    Whitelist which IPs can use the proxy. --hostonly overrides any definitions
    unless --gateway mode is also specified
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR

  --noproxy=  proxy:noproxy=
  Direct connect to specific subnets like a regular proxy. Comma separated
    Skip the NTLM proxy for connections to these subnets
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR

  --useragent=  proxy:useragent=
  Override or send User-Agent header on client's behalf

  --username=  proxy:username=
  Authentication to use when SSPI is unavailable. Format is domain\\username
  Service name "Px" and this username are used to retrieve the password using
  Python keyring. Px only retrieves credentials and storage should be done
  directly in the keyring backend.
    On Windows, Credential Manager is the recommended backed and can be accessed
    from Control Panel > User Accounts > Credential Manager > Windows Credentials.
    Create a generic credential with Px as the network address, this username
    and corresponding password.
    On Linux, Gnome Keyring or KWallet can be used to store passwords. For headless
    systems, the keyring_jeepney or keyrings.alt package might be needed.

  --auth=  proxy:auth=
  Force instead of discovering upstream proxy type
    By default, Px will attempt to discover the upstream proxy type. This
    option can be used to force either NTLM, KERBEROS, DIGEST, BASIC or the
    other libcurl supported upstream proxy types. See:
      https://curl.se/libcurl/c/CURLOPT_HTTPAUTH.html
    To control which methods are available during proxy detection:
      Prefix NO to avoid method - e.g. NONTLM => ANY - NTLM
      Prefix SAFENO to avoid method - e.g. SAFENONTLM => ANYSAFE - NTLM
      Prefix ONLY to support only that method - e.g ONLYNTLM => ONLY + NTLM

  --workers=  settings:workers=
  Number of parallel workers (processes). Valid integer, default: 2

  --threads=  settings:threads=
  Number of parallel threads per worker (process). Valid integer, default: 5

  --idle=  settings:idle=
  Idle timeout in seconds for HTTP connect sessions. Valid integer, default: 30

  --socktimeout=  settings:socktimeout=
  Timeout in seconds for connections before giving up. Valid float, default: 20

  --proxyreload=  settings:proxyreload=
  Time interval in seconds before refreshing proxy info. Valid int, default: 60
    Proxy info reloaded from manual proxy info defined in Internet Options

  --foreground  settings:foreground=
  Run in foreground when frozen or with pythonw.exe. 0 or 1, default: 0
    Px will attach to the console and write to it even though the prompt is
    available for further commands. CTRL-C in the console will exit Px

  --verbose  settings:verbose=
  Enable debug output. default: 0

  --debug  settings:log=
  Enable debug logging. default: 0
    Logs are written to working directory and over-written on startup
    A log is automatically created if Px crashes for some reason

  --uniqlog
  Generate unique log file names in current working directory
    Prevents logs from being overwritten on subsequent runs. Also useful if
    running multiple instances of Px
```

## Examples

Use `proxyserver.com:80` and allow requests from localhost only:

	px --proxy=proxyserver.com:80

Don't use any forward proxy at all, just log what's going on:

	px --noproxy=0.0.0.0/0 --debug

Allow requests from `localhost` and all locally assigned IP addresses. This
is very useful for Docker for Windows and VMs in a NAT configuration because
all requests originate from the host's IP:

	px --proxy=proxyserver.com:80 --hostonly

Allow requests from `localhost`, locally assigned IP addresses and the IPs
specified in the allow list outside the host:

	px --proxy=proxyserver:80 --hostonly --gateway --allow=172.*.*.*

Allow requests from everywhere. Be careful, every client will use your login:

	px --proxy=proxyserver.com:80 --gateway

NOTE: In Docker for Windows you need to set your proxy to `http://host.docker.internal:3128` or `http://<your_ip>:3128`
(or actual port Px is listening to) in your containers and be aware of https://github.com/docker/for-win/issues/1380.

Workaround:

	docker build --build-arg http_proxy=http://<your ip>:3128 --build-arg https_proxy=http://<your ip>:3128 -t containername ../dir/with/Dockerfile

NOTE: In WSL2 you can setup your proxy in `/etc/profile` as follows:

```
export http_proxy="http://$(tail -1 /etc/resolv.conf | cut -d' ' -f2):3128"
export https_proxy="http://$(tail -1 /etc/resolv.conf | cut -d' ' -f2):3128"
```

NOTE: When running MQTT over websockets, it will help to increase the idle
timeout to 120 seconds: `--idle=120`. The default value of 30 will cause the
websocket connection to disconnect since the default MQTT keepalive period
is 60 seconds.

## Dependencies

Px doesn't have any GUI and runs completely in the background. It depends on
the following Python packages:

- [keyring](https://pypi.org/project/keyring/)
- [netaddr](https://pypi.org/project/netaddr/)
- [psutil](https://pypi.org/project/psutil/)
- [quickjs](https://pypi.org/project/quickjs/)
- Linux
  - [jeepney](https://pypi.org/project/jeepney/)
  - [keyring_jeepney](https://pypi.org/project/keyring_jeepney/)
  - [keyrings.alt](https://pypi.org/project/keyrings.alt/)
- [futures](https://pypi.org/project/futures/) on Python 2.x

Px also depends on [libcurl](https://curl.se/libcurl) for all outbound HTTP
connections and proxy authentication.

## Limitations

Windows multiprocessing only works on Python 3.3+ since that's when support was
added to share sockets across processes. On older versions of Python, Px will run
multi-threaded but in a single process.

MacOSX socket sharing is not implemented at this time and is limited to running
in a single process.

While it should mostly work, Px is not tested on MacOSX since there's no test
environment available at this time to verify functionality. PRs are welcome to
help fix any issues.

## Building

To build a self-sufficient executable that does not depend on the presence of
Python and dependency modules, both Nuitka and PyInstaller scripts are provided.
Run `python tools.py` for more details.

## Feedback

Px is definitely a work in progress and any feedback or suggestions are welcome.
It is hosted on [GitHub](https://github.com/genotrance/px) with an MIT license
so issues, forks and PRs are most appreciated. Join us on the [discussion](https://github.com/genotrance/px/discussions)
board, [Gitter](https://gitter.im/genotrance/px) or [Matrix](https://matrix.to/#/#genotrance_px:matrix.org)
to chat about Px.

## Credits

Thank you to all [contributors](https://github.com/genotrance/px/graphs/contributors) for their PRs and all issue submitters.

Px is based on code from all over the internet and acknowledges innumerable sources.
