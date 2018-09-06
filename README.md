[![Chat on Gitter](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/genotrance/px)

# Px

## What is Px?
Px is a HTTP(s) proxy server that allows applications to authenticate through
an NTLM or Kerberos proxy server, typically used in corporate deployments,
without having to deal with the actual handshake. It is primarily designed to
run on Windows systems and authenticates on behalf of the application using the
currently logged in Windows user account.

Px is similar to "NTLM Authorization Proxy Server" [NTLMAPS](http://ntlmaps.sourceforge.net/)
and [Cntlm](http://cntlm.sourceforge.net/) in that it sits between the corporate
proxy and applications and offloads authentication. The advantage is that Px is
able to use the currently logged in user's credentials automatically without
requiring any user supplied credentials. This is accomplished by using Microsoft
SSPI to generate the tokens and signatures required to authenticate with the proxy.

Px also supports Kerberos and works with user supplied credentials for cases
where SSPI is not available.

Microsoft provides a good starting point to understand how NTLM [authentication](https://msdn.microsoft.com/en-us/library/dd925287.aspx)
works. And similarly for [Kerberos](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772815(v=ws.10)) (warning: long!)

## Installation

Px can be obtained in multiple ways:-

- Download the latest binary ZIP from the [releases](https://github.com/genotrance/px/releases)
  page. Once downloaded, extract to a folder of choice and use the `--save`
  and `--install` commands as documented below.

- If Python is already available, Px can be easily installed using the Python
  package manager `pip`. This will download and install Px along with all
  dependencies.

  - Latest: `pip install git+https://github.com/genotrance/px`

  - Stable: `pip install px-proxy`

- Px can also be run from source if Python is available.

  - Download a source ZIP of the latest release from above releases link

  - Clone the latest source:

    `git clone https://github.com/genotrance/px`

  - Download the latest source ZIP:

    `https://github.com/genotrance/px/archive/master.zip`

Running from source requires a few dependencies installed. Px along with all
dependencies can be installed to the standard Python location using:

  `python setup.py install`

After installation, Px can be run on the command line like an executable and
the `--save` and `--install` commands can be used per usual.

```
px --proxy=proxy.server.com --save
px --install
````

NOTE: Command line parameters passed with `--install` are not saved for use on
startup. The `--save` flag or manual editing of `px.ini` is required to provide
configuration to Px on startup.

If installed, Px can be uninstalled as follows:

```
px --uninstall
pip uninstall px-proxy
```

Lastly, Px can be run as a standard Python script. Download the source as
described above. Install all dependencies manually using pip and then run Px:

```
pip install keyring netaddr ntlm-auth psutil pywin32 winkerberos futures

python px.py --help
```

## Configuration

Px requires only one piece of information in order to function - the server
name and port of the proxy server. This needs to be configured in px.ini. If not
specified, Px will check Internet Options for any proxy definitions and use them.
Without this, Px will not work and exit immediately.

The noproxy capability allows Px to connect to hosts in the configured subnets
directly, bypassing the proxy altogether. This allows clients to connect to
hosts within the intranet without requiring additional configuration for each
client or at the proxy. If noproxy is defined, the proxy is optional - this
allows Px to run as a regular proxy full time if required.

If SSPI is not available or not preferred, providing a `username` in `domain\username`
format allows Px to authenticate as that user. The corresponding password is
retrieved using Python keyring and needs to be setup directly in the backend.

On Windows, Credential Manager is the backend and can be accessed as follows:

    Control Panel > User Accounts > Credential Manager > Windows Credentials

Px looks for a generic credential with Px as the network address. More
information on keyring backends can be found [here](https://pypi.org/project/keyring).

There are a few other settings to tweak in the INI file but most are obvious.
All settings can be specified on the command line for convenience. The INI file
can also be created or updated from the command line using `--save`.

The binary distribution of Px runs in the background once started and can be
quit by running `px --quit`. When run directly using Python, use `CTRL-C` to quit.

Px can also be setup to automatically run on startup with the --install flag.
This is done by adding an entry into the Window registry which can be removed
with `--uninstall`.

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

Configuration:
  --config=
  Specify config file. Valid file path, default: px.ini in working directory

  --proxy=  --server=  proxy:server= in INI file
    Proxy server(s) to connect through. IP:port, hostname:port
    Multiple proxies can be specified comma separated. Px will iterate through
    and use the one that works. Required field unless --noproxy is defined. If
    remote server is not in noproxy list and proxy is undefined, Px will reject
    the request

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
    Skip the proxy for connections to these subnets
    127.0.0.1 - specific ip
    192.168.0.* - wildcards
    192.168.0.1-192.168.0.255 - ranges
    192.168.0.1/24 - CIDR

  --useragent=  proxy:useragent=
  Override or send User-Agent header on client's behalf

  --username=  proxy:username=
  Authentication to use when SSPI is unavailable. Format is domain\username
  Service name "Px" and this username are used to retrieve the password using
  Python keyring. Px only retrieves credentials and storage should be done
  directly in the keyring backend.
    On Windows, Credential Manager is the backed and can be accessed from
    Control Panel > User Accounts > Credential Manager > Windows Credentials.
    Create a generic credential with Px as the network address, this username
    and corresponding password.

  --workers=  settings:workers=
  Number of parallel workers (processes). Valid integer, default: 2

  --threads=  settings:threads=
  Number of parallel threads per worker (process). Valid integer, default: 5

  --idle=  settings:idle=
  Idle timeout in seconds for HTTP connect sessions. Valid integer, default: 30

  --socktimeout=  settings:socktimeout=
  Timeout in seconds for connections before giving up. Valid float, default: 20

  --proxyreload=  settings:proxyreload=
  Time interval in seconds before reloading proxy info. Valid int, default: 60
    Proxy info is reloaded from a PAC file found via WPAD or AutoConfig URL, or
    manual proxy info defined in Internet Options

  --foreground  settings:foreground=
  Run in foreground when frozen or with pythonw.exe. 0 or 1, default: 0
    Px will attach to the console and write to it even though the prompt is
    available for further commands. CTRL-C in the console will exit Px

  --debug  settings:log=
  Enable debug logging. default: 0
    Logs are written to working directory and over-written on startup
    A log is automatically created if Px crashes for some reason

  --uniqlog
  Generate unique log file names
    Prevents logs from being overwritten on subsequent runs. Also useful if
    running multiple instances of Px
```

## Examples

Use `proxyserver.com:80` and allow requests from localhost only:

  `px --proxy=proxyserver.com:80`

Don't use any forward proxy at all, just log what's going on:

  `px --noproxy=0.0.0.0/0 --debug`

Allow requests from `localhost` and all locally assigned IP addresses. This
is very useful for Docker for Windows and VMs in a NAT configuration because
all requests originate from the host's IP:

  `px --proxy=proxyserver.com:80 --hostonly`

Allow requests from `localhost`, locally assigned IP addresses and the IPs
specified in the allow list outside the host:

  `px --proxy=proxyserver:80 --hostonly --gateway --allow=172.*.*.*`

Allow requests from everywhere. Be careful, every client will use your login:

  `px --proxy=proxyserver.com:80 --gateway`

NOTE: In Docker for Windows you need to set your proxy to `http://<your_ip>:3128`
(or actual port Px is listening to) and be aware of https://github.com/docker/for-win/issues/1380.

Workaround:

`docker build --build-arg http_proxy=http://<your ip>:3128 --build-arg https_proxy=http://<your ip>:3128 -t containername ../dir/with/Dockerfile`

## Dependencies

Px doesn't have any GUI and runs completely in the background. It is distributed
using Python 3.x and PyInstaller to have a self-contained executable but can
also be run using a Python distribution with the following additional packages.

  `keyring`, `netaddr`, `ntlm-auth`, `psutil`, `pywin32`, `winkerberos`

  `futures` on Python 2.x

Px is tested with the latest releases of Python 2.7, 3.4, 3.5 and 3.6 using the
Miniconda distribution.

In order to make Px a capable proxy server, it is designed to run in multiple
processes. The number of parallel workers or processes is configurable. However,
this only works on Python 3.3+ since that's when support was added to share
sockets across processes in Windows. On older versions of Python, Px will run
multi-threaded but in a single process. The number of threads per process is
also configurable.

## Feedback

Px is definitely a work in progress and any feedback or suggestions are welcome.
It is hosted on [GitHub](https://github.com/genotrance/px) with an MIT license
so issues, forks and PRs are most appreciated. Also join us on [Gitter](https://gitter.im/genotrance/px)
to chat about Px.

## Credits

Thank you to all [contributors](https://github.com/genotrance/px/graphs/contributors) for their PRs and all issue submitters.

Px is based on code from all over the internet and especially acknowledges these sources:

http://stackoverflow.com/questions/2969481/ntlm-authentication-in-python

http://www.oki-osk.jp/esc/python/proxy/

http://stupidpythonideas.blogspot.com/2014/09/sockets-and-multiprocessing.html

https://curl.haxx.se/mail/lib-2014-09/0070.html

https://github.com/fl4re/curl/blob/master/lib/curl_sasl_sspi.c

https://github.com/mongodb-labs/winkerberos/issues/19

https://www.tillett.info/2013/05/13/how-to-create-a-windows-program-that-works-as-both-as-a-gui-and-console-application/

http://www.boku.ru/2016/02/28/posting-to-console-from-gui-app/

https://stackoverflow.com/questions/42108978/what-is-the-priority-mechanism-in-proxy-settings-of-internet-explorer-browser

https://gist.github.com/mgeeky/8960f4fa3f9462ae7bcd6db4ce42a8d3

https://github.com/pypa/sampleproject/
