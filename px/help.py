"Help string for Px"

from .version import __version__

HELP = f"""Px v{__version__}

An HTTP proxy server to automatically authenticate through an NTLM proxy

Usage:
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

  --test=URL
  Test Px as configured with the URL specified. This can be used to confirm that
  Px is configured correctly and is able to connect and authenticate with the
  upstream proxy.

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
  IP interface to listen on - default: 127.0.0.1

  --port= | PX_PORT= | proxy:port=
  Port to run this proxy on - default: 3128

  --gateway | PX_GATEWAY= | proxy:gateway=
  Allow remote machines to use proxy. 0 or 1, default: 0
    Overrides 'listen' and binds to all interfaces

  --hostonly | PX_HOSTONLY= | proxy:hostonly=
  Allow only local interfaces to use proxy. 0 or 1, default: 0
    Px allows all IP addresses assigned to local interfaces to use the service.
    This allows local apps as well as VM or container apps to use Px when in a
    NAT config. Px does this by listening on all interfaces and overriding the
    allow list.

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
  Authentication to use when SSPI is unavailable. Format is domain\\username
  Service name "Px" and this username are used to retrieve the password using
  Python keyring if available.

  --auth= | PX_AUTH= | proxy:auth=
  Force instead of discovering upstream proxy type
    By default, Px will attempt to discover the upstream proxy type. This
    option can be used to force either NTLM, KERBEROS, DIGEST, BASIC or the
    other libcurl supported upstream proxy types. See:
      https://curl.se/libcurl/c/CURLOPT_HTTPAUTH.html
    To control which methods are available during proxy detection:
      Prefix NO to avoid method - e.g. NONTLM => ANY - NTLM
      Prefix SAFENO to avoid method - e.g. SAFENONTLM => ANYSAFE - NTLM
      Prefix ONLY to support only that method - e.g ONLYNTLM => ONLY + NTLM

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
    If Px crashes without logging, traceback is written to the working dir"""
