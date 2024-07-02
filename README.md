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
[releases](https://github.com/genotrance/px/releases) page instead. The Windows
binary is built using Python Embedded and the Linux and OSX binaries are compiled
with [Nuitka](https://nuitka.net) and contain everything needed to run standalone.

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
- As a wrapped service using [WinSW](https://github.com/winsw/winsw)

Px requires [libcurl](https://curl.se/libcurl/) and the Windows builds ship with
a copy. On Linux, it is required to install libcurl using the package manager:

- RHEL: `yum install libcurl`
- Ubuntu: `apt install libcurl4`
- Alpine: `apk add libcurl`

### Running as a windows service using WinSW

Manually prepare and configure px to be able to run it and verify the connectivity.
Download the executable WinSW-x64.exe from [WinSW](https://github.com/winsw/winsw). We are using 2.12.0.

Place a minimal WinSW-x64.xml configuration file next to the executable. 
```
<service>
  
  <!-- ID of the service. It should be unique across the Windows system-->
  <id>Px</id>
  <!-- Display name of the service -->
  <name>Px Service (powered by WinSW)</name>
  <!-- Service description -->
  <description>This service is a service created from a minimal configuration</description>
  
  <!-- Path to the executable, which should be started -->
  <executable>D:\px\px.exe</executable>

</service>
```

Run 
```WinSW-x64.exe install WinSW-x64.xml``` from elevated administrator cmd. You should now have a new service on your computer named `Px Service (powered by WinSW)`.
You can run it from Services window or run ```WinSW-x64.exe start WinSW-x64.xml```.


### Source install

The latest Px version can be downloaded and installed from source via pip:

	python -m pip install https://github.com/genotrance/px/archive/master.zip

Source can also be downloaded and installed:

- Via git:

	`git clone https://github.com/genotrance/px`

- Download [ZIP](https://github.com/genotrance/px/archive/master.zip):

	`https://github.com/genotrance/px/archive/master.zip`

Once downloaded, Px can be installed as a standard Python module along with all
dependencies :

	python -m pip install .

NOTE: Source install methods will require internet access since Python will try
to install Px dependencies from the internet. The binaries mentioned in the
previous section could be used to bootstrap a source install.

NOTE: libcurl will need to be installed on Linux, as described earlier, using
the package manager. For Windows, [download](https://curl.se/windows/) and
extract `libcurl.dll` and `libcurl-x64.dll` to `$PATH`.

### Without installation

Px can be run as a local Python script without installation. Download the source
as described above, install all dependencies and then run Px:

```
pip install keyring netaddr psutil python-dotenv pyspnego quickjs

# Download/install libcurl

pythonw px.py # run in the background
python px.py # run in a console window
```

### Uninstallation

If Px has been installed to the Windows registry to start on boot, it should be
uninstalled before removal:

	python -m px --uninstall

Px can then be uninstalled using `pip` as follows:

	python -m pip uninstall px-proxy

## Docker

Px is available as a prebuilt Docker [image](https://hub.docker.com/r/genotrance/px).

Two images are posted - the default includes keyring and associated dependencies
whereas the mini version is smaller but will have to depend on `PX_PASSWORD` and
`PX_CLIENT_PASSWORD` for credentials.

The following Docker flags will be useful to configure and run Px:
```
--name px       name container so it is easy to stop it
-d              run in the background
--rm            remove container on exit
```

#### Networking
```
--network host  make Px directly accessible from host network
  OR
-p 3128:3128    publish the port - Px needs to run in --gateway mode
```

#### Configuration
```
-e PX_LOG=4     set environment variables to configure Px

-v /dir:/px     mount a host directory with a px.ini or .env file to configure Px
  OR
--mount source=/dir,target=/px
                mount a volume if preferred

docker run ... genotrance/px --gateway --verbose
                configure directly from the command line
```

#### Credentials

Keyring credentials can be stored in a host folder and mounted into the container
as follows:
```
-v /keyrings:/root/.local/share/keyrings
                mount a local dir to store keyring info
  OR
--mount source=/keyrings,target=/root/.local/share/keyrings
                mount a volume if preferred
```

Credentials can be saved using the command line:
```
docker run ... genotrance/px --username=... --password
                configure keyring directly from the command line
```

The mini version does not have keyring so credentials need to be set using environment
variables:
```
-e PX_PASSWORD=... -e PX_CLIENT_PASSWORD=...
                set environment variables to configure credentials
```

## Configuration

Px requires only one piece of information in order to function - the server
name and port of the proxy server. If not specified, Px will check `Internet
Options` or environment variables for any proxy definitions. Without this, Px
will try to connect to sites directly.

The `noproxy` capability allows Px to connect to configured hosts directly,
bypassing the proxy altogether. This allows clients to connect to hosts within
the intranet without requiring additional configuration for each client or at
the proxy.

Configuration can be specified in multiple ways, listed in order of precedence:
- Command line flags
- Environment variables
- Variables in a dotenv file (.env)
  - In the working directory
  - In the Px directory
- Configuration file `px.ini`
  - In the working directory
  - In the Px directory

There are many configuration options to tweak - refer to the [Usage](#usage)
section or `--help` for details and syntax.

### Credentials

If SSPI is not available or not preferred, providing `--username` in `domain\username`
format allows Px to authenticate as that user. The corresponding password is
retrieved using Python keyring and needs to be setup in the appropriate OS
specific backend.

Credentials can be setup with the command line:

	px --username=domain\username --password

If username is already defined with `PX_USERNAME` or in `px.ini`:

	px --password

Information on keyring backends can be found [here](https://pypi.org/project/keyring).

As an alternative, Px can also load credentials from the environment variable
`PX_PASSWORD` or a dotenv file. This is only recommended when keyring is not
available.

#### Windows

Credential Manager is the recommended backend for Windows and the password is
stored as a 'Generic Credential' type with 'Px' as the network address name.
Credential Manager can be accessed as follows:

	Control Panel > User Accounts > Credential Manager > Windows Credentials

	Or on the command line: `rundll32.exe keymgr.dll, KRShowKeyMgr`

#### Linux

Gnome Keyring or KWallet is used to store passwords on Linux.

For systems without a GUI (headless, docker), D-Bus can be started interactively:

	dbus-run-session -- sh

If this needs to be done in a script:

	export DBUS_SESSION_BUS_ADDRESS=`dbus-daemon --fork --config-file=/usr/share/dbus-1/session.conf --print-address`

Gnome Keyring can then be unlocked as follows:

	echo 'somecredstorepass' | gnome-keyring-daemon --unlock

If the default SecretService keyring backend does not work, a third-party
[backend](https://github.com/jaraco/keyring#third-party-backends) might be
required. Simply install and configure one and `keyring` will use it. Remember
to specify the environment variables they require before starting Px.

This will not work for the Nuitka binaries so as a fallback, `PX_PASSWORD` can
be used instead to set credentials.

### Client authentication

Px is useful to authenticate with the upstream proxy server on behalf of clients
but it can also authenticate the client that connects to it if needed. This can
be useful in `gateway` mode where remote clients should log in before accessing
the upstream proxy via Px. `BASIC` and `DIGEST` auth are supported, along with
`NTLM` and `NEGOTIATE`.

The client credentials can be different from the upstream proxy credentials or
the same if preferred. SSPI is also supported on Windows and can be leveraged
for only the client or upstream or both.

Client authentication is turned off by default and can be enabled using
`--client-auth`, `PX_CLIENT_AUTH` or `px.ini`. Setting the value to `ANYSAFE` is
recommended.

Similar to the upstream proxy, the client username can be configured with
`--client-username`, `PX_CLIENT_USERNAME` or `px.ini` The password can be setup
in keyring using `PxClient` as the network address name. `PX_CLIENT_PASSWORD` is
available for cases where keyring is not available.

SSPI is enabled by default on Windows and can be disabled with `--client-nosspi`,
`PX_CLIENT_NOSSPI` or in `px.ini`.

Client credentials can be setup in keyring with the command line:

	px --client-username=domain\username --client-password

Px only supports one credential for the upstream proxy but can be configured to
support multiple client users when keyring is used. Each user should be added to
keyring with the `PxClient` network address.

Using an upstream proxy is not required so Px can also be used simply as an
authenticating proxy for smaller setups.

### Misc

The configuration file `px.ini` can be created or updated from the command line
using `--save`.

The binary distribution of Px runs in the background once started and can be
quit by running `px --quit`. When running in the foreground, use `CTRL-C`.

Px can also be setup to automatically run on startup on Windows with the
`--install` flag. This is done by adding an entry into the Window registry which
can be removed with `--uninstall`.

NOTE: Command line parameters passed with `--install` are not saved for use on
startup. The `--save` flag or manual editing of `px.ini` is required to provide
configuration to Px on startup.

NOTE: When using the Px binary distribution on Windows, run `.\pythonw -m px --install`
instead of using `px.exe`. This will avoid the popup console window on startup.

## Usage

```
px [FLAGS]
python px.py [FLAGS]
python -m px [FLAGS]

Actions:
  --save
  Save configuration to file specified with --config or px.ini in working directory
    Allows setting up Px config directly from command line
    Values specified on CLI override any values in existing config file
    Values not specified on CLI or config file are set to defaults

  --install
  Add Px to the Windows registry to run on startup

  --uninstall
  Remove Px from the Windows registry

  --quit
  Quit a running instance of Px

  --restart
  Quit a running instance of Px and start a new instance

  --password | PX_PASSWORD
  Collect and save password to default keyring. Username needs to be provided
  via --username, PX_USERNAME or in the config file.
  As an alternative, Px can also load credentials from the environment variable
  `PX_PASSWORD` or a dotenv file.

  --client-password | PX_CLIENT_PASSWORD
  Collect and save password to default keyring. Username needs to be provided
  via --client-username, PX_CLIENT_USERNAME or in the config file.
  As an alternative, Px can also load credentials from the environment variable
  `PX_CLIENT_PASSWORD` or a dotenv file.

  --test=URL | --test
  Test Px as configured with the URL specified. This can be used to confirm that
  Px is configured correctly and is able to connect and authenticate with the
  upstream proxy. If URL is skipped, Px runs multiple tests against httpbin.org.

Configuration:
  --config= | PX_CONFIG=
  Specify config file. Valid file path, default: px.ini in working directory
  or script directory

  --proxy=  --server= | PX_SERVER= | proxy:server=
  NTLM server(s) to connect through. IP:port, hostname:port
    Multiple proxies can be specified comma separated. Px will iterate through
    and use the one that works

  --pac= | PX_PAC= | proxy:pac=
  PAC file to use to connect
    Use in place of --server if PAC file should be loaded from a URL or local
    file. Relative paths will be relative to the Px script or binary

  --pac_encoding= | PX_PAC_ENCODING= | proxy:pac_encoding=
  PAC file encoding
    Specify in case default 'utf-8' encoding does not work

  --listen= | PX_LISTEN= | proxy:listen=
  Network interface(s) to listen on. Comma separated, default: 127.0.0.1
    --gateway and --hostonly override this to bind to all interfaces

  --port= | PX_PORT= | proxy:port=
  Port to run this proxy on - default: 3128

  --gateway | PX_GATEWAY= | proxy:gateway=
  Allow remote machines to use proxy. 0 or 1, default: 0
    Overrides --listen and binds to all interfaces

  --hostonly | PX_HOSTONLY= | proxy:hostonly=
  Allow only local interfaces to use proxy. 0 or 1, default: 0
    Px allows all IP addresses assigned to local interfaces to use the service.
    This allows local apps as well as VM or container apps to use Px when in a
    NAT config. Overrides --listen and binds to all interfaces, overrides the
    default --allow rules

  --allow= | PX_ALLOW= | proxy:allow=
  Allow connection from specific subnets. Comma separated, default: *.*.*.*
    Whitelist which IPs can use the proxy. --hostonly overrides any definitions
    unless --gateway mode is also specified
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR

  --noproxy= | PX_NOPROXY= | proxy:noproxy=
  Direct connect to specific subnets or domains like a regular proxy. Comma separated
    Skip the NTLM proxy for connections to these hosts
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR
    example.com - domains

  --useragent= | PX_USERAGENT= | proxy:useragent=
  Override or send User-Agent header on client's behalf

  --username= | PX_USERNAME= | proxy:username=
  Authentication to use when SSPI is unavailable. Format is domain\username
  Service name "Px" and this username are used to retrieve the password using
  Python keyring if available.

  --auth= | PX_AUTH= | proxy:auth=
  Force instead of discovering upstream proxy type
    By default, Px will attempt to discover the upstream proxy type. This
    option can be used to force either NEGOTIATE, NTLM, DIGEST, BASIC or the
    other libcurl supported upstream proxy types. See:
      https://curl.se/libcurl/c/CURLOPT_HTTPAUTH.html
    To control which methods are available during proxy detection:
      Prefix NO to avoid method - e.g. NONTLM => ANY - NTLM
      Prefix SAFENO to avoid method - e.g. SAFENONTLM => ANYSAFE - NTLM
      Prefix ONLY to support only that method - e.g ONLYNTLM => ONLY + NTLM
    Set to NONE to defer all authentication to the client. This allows multiple
    instances of Px to be chained together to access an upstream proxy that is not
    directly connected:
      Client -> Auth Px -> no-Auth Px -> Upstream proxy
        'Auth Px' cannot directly access upstream proxy but 'no-Auth Px' can

  --client-username= | PX_CLIENT_USERNAME= | client:client_username=
  Client authentication to use when SSPI is unavailable. Format is domain\username
  Service name "PxClient" and this username are used to retrieve the password using
  Python keyring if available.

  --client-auth= | PX_CLIENT_AUTH= | client:client_auth=
  Enable authentication for client connections. Comma separated, default: NONE
  Mechanisms supported: NEGOTIATE, NTLM, DIGEST, BASIC
    ANY     = enable all supported mechanisms
    ANYSAFE = enable all supported mechanisms except BASIC
    NTLM    = enable only NTLM, etc.
    NONE    = disable client authentication altogether (default)

  --client-nosspi= | PX_CLIENT_NOSSPI= | client:client_nosspi=
  Disable SSPI for client authentication on Windows. default: 0
    Set to 1 to disable SSPI and use the configured username and password

  --workers= | PX_WORKERS= | settings:workers=
  Number of parallel workers (processes). Valid integer, default: 2

  --threads= | PX_THREADS= | settings:threads=
  Number of parallel threads per worker (process). Valid integer, default: 32

  --idle= | PX_IDLE= | settings:idle=
  Idle timeout in seconds for HTTP connect sessions. Valid integer, default: 30

  --socktimeout= | PX_SOCKTIMEOUT= | settings:socktimeout=
  Timeout in seconds for connections before giving up. Valid float, default: 20

  --proxyreload= | PX_PROXYRELOAD= | settings:proxyreload=
  Time interval in seconds before refreshing proxy info. Valid int, default: 60
    Proxy info reloaded from manual proxy info defined in Internet Options

  --foreground | PX_FOREGROUND= | settings:foreground=
  Run in foreground when compiled or run with pythonw.exe. 0 or 1, default: 0
    Px will attach to the console and write to it even though the prompt is
    available for further commands. CTRL-C in the console will exit Px

  --log= | PX_LOG= | settings:log=
  Enable debug logging. default: 0
    1 = Log to script dir [--debug]
    2 = Log to working dir
    3 = Log to working dir with unique filename [--uniqlog]
    4 = Log to stdout [--verbose]. Implies --foreground
    If Px crashes without logging, traceback is written to the working dir
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

NOTE: In Docker for Windows you need to set your proxy to
`http://host.docker.internal:3128` or `http://<your_ip>:3128` (or actual port
Px is listening to) in your containers and be aware of
https://github.com/docker/for-win/issues/1380.

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
- [pyspnego](https://pypi.org/project/pyspnego/)
- [python-dotenv](https://pypi.org/projects/python-dotenv/)
- [quickjs](https://pypi.org/project/quickjs/)

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
There is also a Python Embedded build that is preferable on Windows. Check out
`python tools.py` for more details.

## Feedback

Px is definitely a work in progress and any feedback or suggestions are welcome.
It is hosted on [GitHub](https://github.com/genotrance/px) with an MIT license
so issues, forks and PRs are most appreciated. Join us on the
[discussion](https://github.com/genotrance/px/discussions) board,
[Gitter](https://gitter.im/genotrance/px) or
[Matrix](https://matrix.to/#/#genotrance_px:matrix.org) to chat about Px.

## Credits

Thank you to all [contributors](https://github.com/genotrance/px/graphs/contributors)
for their PRs and all issue submitters.

Px is based on code from all over the internet and acknowledges innumerable sources.
