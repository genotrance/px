"Px is an HTTP proxy server to automatically authenticate through an NTLM proxy"

import concurrent.futures
import configparser
import getpass
import http.server
import multiprocessing
import os
import signal
import socket
import socketserver
import sys
import threading
import time
import traceback
import urllib.parse
import warnings

from .debug import pprint, Debug
from .version import __version__

from . import mcurl
from . import wproxy

if sys.platform == "win32":
    import ctypes
    import winreg

warnings.filterwarnings("ignore")

# External dependencies

try:
    import keyring

    # Explicit imports for Nuitka
    if sys.platform == "win32":
        import keyring.backends.Windows
    elif sys.platform.startswith("linux"):
        import keyring.backends.SecretService
    elif sys.platform == "darwin":
        import keyring.backends.macOS
except ImportError:
    pprint("Requires module keyring")
    sys.exit()

try:
    import netaddr
except ImportError:
    pprint("Requires module netaddr")
    sys.exit()

try:
    import psutil
except ImportError:
    pprint("Requires module psutil")
    sys.exit()

try:
    import dotenv
except ImportError:
    pprint("Requires module python-dotenv")
    sys.exit()

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
  Quit a running instance of Px.exe

  --password
  Collect and save password to default keyring. Username needs to be provided
  via --username or already specified in the config file

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
  Number of parallel threads per worker (process). Valid integer, default: 5

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

  --verbose
  Enable verbose output. default: 0. Implies --foreground

  --debug | PX_LOG= | settings:log=
  Enable debug logging. default: 0
    Logs are written to working directory and over-written on startup
    A log is automatically created if Px crashes for some reason

  --uniqlog
  Generate unique log file names in current working directory
    Prevents logs from being overwritten on subsequent runs. Also useful if
    running multiple instances of Px"""

class State:
    """Stores runtime state per process - shared across threads"""

    # Config
    hostonly = False
    ini = ""
    idle = 30
    noproxy = ""
    pac = ""
    proxyreload = 60
    socktimeout = 20.0
    useragent = ""

    # Auth
    auth = "ANY"
    username = ""

    # Objects
    allow = netaddr.IPGlob("*.*.*.*")
    config = None
    debug = None
    mcurl = None
    stdout = None
    wproxy = None

    # Tracking
    exit = False
    proxy_last_reload = None

    # Lock for thread synchronization of State object
    # multiprocess sync isn't neccessary because State object is only shared by
    # threads - every process has it's own State object
    state_lock = threading.Lock()

# Script path
def get_script_path():
    "Get full path of running script or compiled executable"
    return os.path.normpath(os.path.join(os.getcwd(), sys.argv[0]))

def get_script_dir():
    "Get directory of running script or compiled executable"
    return os.path.dirname(get_script_path())

# Debug shortcut
dprint = lambda x: None

def dfile():
    "Generate filename for debug output"
    name = multiprocessing.current_process().name
    if "--quit" in sys.argv:
        name = "quit"
    path = get_script_dir()
    if "--uniqlog" in sys.argv:
        for arg in sys.argv:
            # Add port to filename
            if arg.startswith("--port="):
                name = arg[7:] + "-" + name
                break
        name = f"{name}-{time.time()}"
        path = os.getcwd()
    logfile = os.path.join(path, f"debug-{name}.log")
    return logfile

def is_compiled():
    "Return True if compiled with PyInstaller or Nuitka"
    return getattr(sys, "frozen", False) or "__compiled__" in globals()

###
# Proxy handler

class Proxy(http.server.BaseHTTPRequestHandler):
    "Handler for each proxy connection - unique instance for each thread in each process"

    protocol_version = "HTTP/1.1"

    # Contains the proxy servers responsible for the url this Proxy instance
    # (aka thread) serves
    proxy_servers = []
    curl = None

    def handle_one_request(self):
        try:
            http.server.BaseHTTPRequestHandler.handle_one_request(self)
        except socket.error as error:
            self.close_connection = True
            easyhash = ""
            if self.curl is not None:
                easyhash = self.curl.easyhash + ": "
                State.mcurl.stop(self.curl)
                self.curl = None
            if "forcibly closed" in str(error):
                dprint(easyhash + "Connection closed by client")
            else:
                traceback.print_exc(file=sys.stdout)
                dprint(easyhash + "Socket error: %s" % error)

    def address_string(self):
        host, port = self.client_address[:2]
        #return socket.getfqdn(host)
        return host

    def log_message(self, format, *args):
        dprint(format % args)

    def do_curl(self):
        if self.curl is None:
            self.curl = mcurl.Curl(self.path, self.command, self.request_version, State.socktimeout)
        else:
            self.curl.reset(self.path, self.command, self.request_version, State.socktimeout)
        self.curl.set_debug()

        dprint(self.curl.easyhash + ": Path = " + self.path)
        ipport = self.get_destination()
        if ipport is None:
            dprint(self.curl.easyhash + ": Configuring proxy settings")
            server = self.proxy_servers[0][0]
            port = self.proxy_servers[0][1]
            # libcurl handles noproxy domains only. IP addresses are still handled within wproxy
            # since libcurl only supports CIDR addresses since v7.86 and does not support wildcards
            # (192.168.0.*) or ranges (192.168.0.1-192.168.0.255)
            noproxy_hosts = ",".join(State.wproxy.noproxy_hosts) or None
            ret = self.curl.set_proxy(proxy = server, port = port, noproxy = noproxy_hosts)
            if not ret:
                # Proxy server has had auth issues so returning failure to client
                self.send_error(401, "Proxy server authentication failed: %s:%d" % (server, port))
                return

            key = ""
            pwd = None
            if len(State.username) != 0:
                key = State.username
                pwd = keyring.get_password("Px", key)
            if len(key) == 0:
                dprint(self.curl.easyhash + ": Using SSPI to login")
                key = ":"
            self.curl.set_auth(user = key, password = pwd, auth = State.auth)
        else:
            dprint(self.curl.easyhash + ": Skipping auth proxying")

        # Plain HTTP can be bridged directly
        if not self.curl.is_connect():
            self.curl.bridge(self.rfile, self.wfile, self.wfile)

        # Set headers for request
        self.curl.set_headers(self.headers)

        # Turn off transfer decoding
        self.curl.set_transfer_decoding(False)

        # Set user agent if configured
        self.curl.set_useragent(State.useragent)

        if not State.mcurl.do(self.curl):
            dprint(self.curl.easyhash + ": Connection failed: " + self.curl.errstr)
            self.send_error(self.curl.resp, self.curl.errstr)
        elif self.curl.is_connect():
            dprint(self.curl.easyhash + ": SSL connected")
            self.send_response(200, "Connection established")
            self.send_header("Proxy-Agent", self.version_string())
            self.end_headers()
            State.mcurl.select(self.curl, self.connection, State.idle)

        State.mcurl.remove(self.curl)

    def do_GET(self):
        self.do_curl()

    def do_HEAD(self):
        self.do_curl()

    def do_POST(self):
        self.do_curl()

    def do_PUT(self):
        self.do_curl()

    def do_DELETE(self):
        self.do_curl()

    def do_PATCH(self):
        self.do_curl()

    def do_CONNECT(self):
        self.do_curl()

    def get_destination(self):
        # Reload proxy info if timeout exceeded
        reload_proxy()

        # Find proxy
        servers, netloc, path = State.wproxy.find_proxy_for_url(
            ("https://" if "://" not in self.path else "") + self.path)
        if servers[0] == wproxy.DIRECT:
            dprint(self.curl.easyhash + ": Direct connection")
            return netloc
        else:
            dprint(self.curl.easyhash + ": Proxy = " + str(servers))
            self.proxy_servers = servers
            return None

###
# Multi-processing and multi-threading

def get_host_ips():
    localips = [ip[4][0] for ip in socket.getaddrinfo(
        socket.gethostname(), 80, socket.AF_INET)]
    localips.insert(0, "127.0.0.1")

    return localips

class PoolMixIn(socketserver.ThreadingMixIn):
    pool = None

    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

    def verify_request(self, request, client_address):
        dprint("Client address: %s" % client_address[0])
        if client_address[0] in State.allow:
            return True

        if State.hostonly and client_address[0] in get_host_ips():
            dprint("Host-only IP allowed")
            return True

        dprint("Client not allowed: %s" % client_address[0])
        return False

class ThreadedTCPServer(PoolMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass,
            bind_and_activate=True):
        socketserver.TCPServer.__init__(self, server_address,
            RequestHandlerClass, bind_and_activate)

        try:
            # Workaround bad thread naming code in Python 3.6+, fixed in master
            self.pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=State.config.getint("settings", "threads"),
                thread_name_prefix="Thread")
        except:
            self.pool = concurrent.futures.ThreadPoolExecutor(
                max_workers=State.config.getint("settings", "threads"))

def print_banner():
    pprint("Serving at %s:%d proc %s" % (
        State.config.get("proxy", "listen").strip(),
        State.config.getint("proxy", "port"),
        multiprocessing.current_process().name)
    )

    if sys.platform == "win32":
        if is_compiled() or "pythonw.exe" in sys.executable:
            if State.config.getint("settings", "foreground") == 0:
                detach_console()

    for section in State.config.sections():
        for option in State.config.options(section):
            dprint(section + ":" + option + " = " + State.config.get(
                section, option))

def serve_forever(httpd):
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        dprint("Exiting")
        State.exit = True

    httpd.shutdown()

def start_worker(pipeout):
    parse_config()
    httpd = ThreadedTCPServer((
        State.config.get("proxy", "listen").strip(),
        State.config.getint("proxy", "port")), Proxy, bind_and_activate=False)
    mainsock = pipeout.recv()
    if hasattr(socket, "fromshare"):
        mainsock = socket.fromshare(mainsock)
    httpd.socket = mainsock

    print_banner()

    serve_forever(httpd)

def run_pool():
    try:
        httpd = ThreadedTCPServer((State.config.get("proxy", "listen").strip(),
                                   State.config.getint("proxy", "port")), Proxy)
    except OSError as exc:
        if "attempt was made" in str(exc):
            pprint("Px failed to start - port in use")
        else:
            pprint(exc)
        return

    mainsock = httpd.socket

    print_banner()

    if sys.platform != "darwin":
        # Multiprocessing enabled on Windows and Linux, no idea how shared sockets
        # work on MacOSX
        if sys.platform == "linux" or hasattr(socket, "fromshare"):
            # Windows needs Python > 3.3 which added socket.fromshare()- have to
            # explicitly share socket with child processes
            #
            # Linux shares all open FD with children since it uses fork()
            workers = State.config.getint("settings", "workers")
            for i in range(workers-1):
                (pipeout, pipein) = multiprocessing.Pipe()
                p = multiprocessing.Process(target=start_worker, args=(pipeout,))
                p.daemon = True
                p.start()
                while p.pid is None:
                    time.sleep(1)
                if hasattr(socket, "fromshare"):
                    # Send duplicate socket explicitly shared with child for Windows
                    pipein.send(mainsock.share(p.pid))
                else:
                    # Send socket as is for Linux
                    pipein.send(mainsock)

    serve_forever(httpd)

###
# Proxy management

def file_url_to_local_path(file_url):
    parts = urllib.parse.urlparse(file_url)
    path = urllib.parse.unquote(parts.path)
    if path.startswith('/') and not path.startswith('//'):
        if len(parts.netloc) == 2 and parts.netloc[1] == ':':
            return parts.netloc + path
        return 'C:' + path
    if len(path) > 2 and path[1] == ':':
        return path

def reload_proxy():
    # Return if proxies specified in Px config
    if State.wproxy.mode in [wproxy.MODE_CONFIG, wproxy.MODE_CONFIG_PAC]:
        return

    # Do locking to avoid updating globally shared State object by multiple
    # threads simultaneously
    State.state_lock.acquire()
    try:
        # Check if need to refresh
        if (State.proxy_last_reload is not None and
                time.time() - State.proxy_last_reload < State.proxyreload):
            dprint("Skip proxy refresh")
            return

        # Reload proxy information
        State.wproxy = wproxy.Wproxy(noproxy = State.noproxy, debug_print = dprint)

        State.proxy_last_reload = time.time()

    finally:
        State.state_lock.release()

###
# Parse settings and command line

def parse_allow(allow):
    State.allow, _ = wproxy.parse_noproxy(allow, iponly = True)

def parse_noproxy(noproxy):
    State.noproxy = noproxy

def set_useragent(useragent):
    State.useragent = useragent

def set_username(username):
    State.username = username

def set_password():
    try:
        if len(State.username) == 0:
            pprint("domain\\username missing - specify via --username or configure in px.ini")
            sys.exit()
        pprint("Setting password for '" + State.username + "'")

        pwd = ""
        while len(pwd) == 0:
            pwd = getpass.getpass("Enter password: ")

        keyring.set_password("Px", State.username, pwd)

        if keyring.get_password("Px", State.username) == pwd:
            pprint("Saved successfully")
    except KeyboardInterrupt:
        pprint("")

    sys.exit()

def set_pac(pac):
    if pac == "":
        return

    pacproxy = False
    if pac.startswith("http"):
        # URL
        pacproxy = True

    elif pac.startswith("file"):
        # file://
        pac = file_url_to_local_path(pac)
        if os.path.exists(pac):
            pacproxy = True

    else:
        # Local file
        if not os.path.isabs(pac):
            # Relative to Px script / binary
            pac = os.path.normpath(os.path.join(get_script_dir(), pac))
        if os.path.exists(pac):
            pacproxy = True

    if pacproxy:
        State.pac = pac
    else:
        pprint("Unsupported PAC location or file not found: %s" % pac)
        sys.exit()

def set_auth(auth):
    if len(auth) == 0:
        auth = "ANY"

    # Test that it works
    _ = mcurl.getauth(auth)

    State.auth = auth

def set_debug(val = "1"):
    global dprint
    if State.debug is None:
        State.debug = Debug(dfile(), "w")
        dprint = State.debug.get_print()

def set_verbose():
    global dprint
    if State.debug is None:
        State.debug = Debug()
        dprint = State.debug.get_print()
        if "--foreground" not in sys.argv:
            # --verbose implies --foreground
            sys.argv.append("--foreground")

def set_idle(idle):
    State.idle = idle

def set_socktimeout(socktimeout):
    State.socktimeout = socktimeout
    socket.setdefaulttimeout(socktimeout)

def set_proxyreload(proxyreload):
    State.proxyreload = proxyreload

def cfg_int_init(section, name, default, proc=None, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    try:
        val = int(val)
    except ValueError:
        pprint("Invalid integer value for " + section + ":" + name)

    State.config.set(section, name, str(val))

    if proc is not None:
        proc(val)

def cfg_float_init(section, name, default, proc=None, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    try:
        val = float(val)
    except ValueError:
        pprint("Invalid float value for " + section + ":" + name)

    State.config.set(section, name, str(val))

    if proc is not None:
        proc(val)

def cfg_str_init(section, name, default, proc=None, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    State.config.set(section, name, val)

    if proc is not None:
        proc(val)

def save():
    with open(State.ini, "w") as cfgfile:
        State.config.write(cfgfile)
    pprint("Saved config to " + State.ini + "\n")
    with open(State.ini, "r") as cfgfile:
        sys.stdout.write(cfgfile.read())

    sys.exit()

def test(testurl):
    # Get Px configuration
    listen = State.config.get("proxy", "listen")
    port = State.config.getint("proxy", "port")

    def query():
        ec = mcurl.Curl(testurl)
        ec.set_proxy(listen, port)
        ec.buffer()
        ec.set_useragent("mcurl v" + __version__)
        ret = ec.perform()
        if ret != 0:
            pprint(f"Failed with error {ret}\n{ec.errstr}")
        else:
            pprint(f"\n{ec.get_headers()}Response length: {len(ec.get_data())}")

        # Quit Px
        p = psutil.Process(os.getpid())
        p.send_signal(signal.SIGINT)

    # Run testurl query in a thread
    t = threading.Thread(target = query)
    t.daemon = True
    t.start()

    # Tweak Px configuration for test - only 1 process and thread required
    State.config.set("settings", "workers", "1")
    State.config.set("settings", "threads", "1")

    # Run Px to respond to query
    run_pool()

def parse_cli():
    "Parse all command line arguments into a dictionary"
    flags = {}
    for arg in sys.argv:
        if not arg.startswith("--") or len(arg) < 3:
            continue
        arg = arg[2:]

        if "=" in arg:
            # --name=val
            name, val = arg.split("=", 1)
            flags[name] = val
        else:
            # --name
            flags[arg] = "1"

    return flags

def parse_env():
    "Load dotenv files and parse PX_* environment variables into a dictionary"

    # Load .env from CWD
    envfile = dotenv.find_dotenv(usecwd=True)
    if not dotenv.load_dotenv(envfile):
        # Else load .env file from script dir if different from CWD
        cwd = os.getcwd()
        script_dir = get_script_dir()
        if script_dir != cwd:
            envfile = os.path.join(script_dir, ".env")
            if not dotenv.load_dotenv(envfile):
                pass

    env = {}
    for var in os.environ:
        if var.startswith("PX_") and len(var) > 3:
            env[var[3:].lower()] = os.environ[var]

    return env

def parse_config():
    "Parse configuration from CLI flags, environment and config file in order"
    if "--debug" in sys.argv:
        set_debug()
    elif "--verbose" in sys.argv:
        set_verbose()

    if sys.platform == "win32":
        if is_compiled() or "pythonw.exe" in sys.executable:
            attach_console()

    if "-h" in sys.argv or "--help" in sys.argv:
        pprint(HELP)
        sys.exit()

    # Load CLI flags and environment variables
    flags = parse_cli()
    env = parse_env()

    # Check if config file specified in CLI flags or environment
    is_save = "save" in flags or "save" in env
    if "config" in flags:
        # From CLI
        State.ini = flags["config"]
    elif "config" in env:
        # From environment
        State.ini = env["config"]

    if len(State.ini) != 0:
        if not (os.path.exists(State.ini) or is_save):
            # Specified file doesn't exist and not --save
            pprint(f"Could not find config file: {State.ini}")
            sys.exit()
    else:
        # Default "CWD/px.ini"
        cwd = os.getcwd()
        path = os.path.join(cwd, "px.ini")
        if os.path.exists(path) or is_save:
            State.ini = path
        else:
            # Alternate "script_dir/px.ini"
            script_dir = get_script_dir()
            if script_dir != cwd:
                path = os.path.join(script_dir, "px.ini")
                if os.path.exists(path):
                    State.ini = path

    # Load configuration file
    State.config = configparser.ConfigParser()
    if os.path.exists(State.ini):
        State.config.read(State.ini)

    ###
    # Create config sections if not already from config file

    # [proxy] section
    if "proxy" not in State.config.sections():
        State.config.add_section("proxy")

    # [settings] section
    if "settings" not in State.config.sections():
        State.config.add_section("settings")

    # Default initialize logging if --debug specified
    cfg_int_init("settings", "log", "0" if State.debug is None else "1")

    # Default values for all keys
    defaults = {
        "proxy": "",
        "server": "",
        "pac": "",
        "pac_encoding": "utf-8",
        "port": "3128",
        "listen": "127.0.0.1",
        "allow": "*.*.*.*",
        "gateway": "0",
        "hostonly": "0",
        "noproxy": "",
        "useragent": "",
        "username": "",
        "auth": "",
        "workers": "2",
        "threads": "5",
        "idle": "30",
        "socktimeout": "20.0",
        "proxyreload": "60",
        "foreground": "0",
        "log": "0"
    }

    # Callback functions for initialization
    callbacks = {
        "pac": set_pac,
        "allow": parse_allow,
        "noproxy": parse_noproxy,
        "useragent": set_useragent,
        "username": set_username,
        "auth": set_auth,
        "log": set_debug,
        "idle": set_idle,
        "socktimeout": set_socktimeout,
        "proxyreload": set_proxyreload
    }

    def cfg_init(name, val, override=False):
        callback = callbacks.get(name)
        # [proxy]
        if name in ["proxy", "server", "pac", "pac_encoding", "listen", "allow", "noproxy",
                    "useragent", "username", "auth"]:
            cfg_str_init("proxy", name, val, callback, override)
        elif name in ["port", "gateway", "hostonly"]:
            cfg_int_init("proxy", name, val, callback, override)
        # [settings]
        elif name in ["workers", "threads", "idle", "proxyreload", "foreground", "log"]:
            cfg_int_init("settings", name, val, callback, override)
        elif name in ["socktimeout"]:
            cfg_float_init("settings", name, val, callback, override)

    # Default initilize if not already from config file
    for name, val in defaults.items():
        cfg_init(name, val)

    # Override from environment
    for name, val in env.items():
        cfg_init(name, val, override=True)

    # Final override from CLI which takes highest precedence
    for name, val in flags.items():
        cfg_init(name, val, override=True)

    ###
    # Dependency propagation

    # If gateway mode
    if State.config.getint("proxy", "gateway") == 1:
        # Listen on all interfaces
        cfg_str_init("proxy", "listen", "", None, True)

    # If hostonly mode
    if State.config.getint("proxy", "hostonly") == 1:
        State.hostonly = True

        # Listen on all interfaces
        cfg_str_init("proxy", "listen", "", None, True)

        # If not gateway mode or gateway with default allow rules
        if (State.config.getint("proxy", "gateway") == 0 or
                (State.config.getint("proxy", "gateway") == 1 and
                 State.config.get("proxy", "allow") in [
                    "*.*.*.*", "0.0.0.0/0"])):
            # Purge allow rules
            cfg_str_init("proxy", "allow", "", parse_allow, True)

    ###
    # Handle actions

    if sys.platform == "win32":
        if "--install" in sys.argv:
            install()
        elif "--uninstall" in sys.argv:
            uninstall()

    if "--quit" in sys.argv:
        quit()
    elif "--save" in sys.argv:
        save()
    elif "--password" in sys.argv:
        set_password()

    ###
    # Discover proxy info from OS

    servers = wproxy.parse_proxy(State.config.get("proxy", "server"))
    if len(servers) != 0:
        State.wproxy = wproxy.Wproxy(wproxy.MODE_CONFIG, servers, noproxy = State.noproxy, debug_print = dprint)
    elif len(State.pac) != 0:
        pac_encoding = State.config.get("proxy", "pac_encoding")
        State.wproxy = wproxy.Wproxy(wproxy.MODE_CONFIG_PAC, [State.pac], noproxy = State.noproxy, pac_encoding = pac_encoding, debug_print = dprint)
    else:
        State.wproxy = wproxy.Wproxy(noproxy = State.noproxy, debug_print = dprint)
        State.proxy_last_reload = time.time()

    # Curl multi object to manage all easy connections
    State.mcurl = mcurl.MCurl(debug_print = dprint)

    # Test the proxy with user specified URL if --test=URL
    if "test" in flags:
        test(flags["test"])
    elif "test" in env:
        test(env["test"])

###
# Exit related

def quit(checkOnly = False):
    count = 0
    mypids = [os.getpid(), os.getppid()]
    mypath = os.path.realpath(sys.executable).lower()

    # Add .exe for Windows
    ext = ""
    if sys.platform == "win32":
        ext = ".exe"
        _, tail = os.path.splitext(mypath)
        if len(tail) == 0:
            mypath += ext
    mybin = os.path.basename(mypath)

    for pid in sorted(psutil.pids(), reverse=True):
        if pid in mypids:
            continue

        try:
            p = psutil.Process(pid)
            exepath = p.exe().lower()
            if sys.platform == "win32":
                # Set \IP to \\IP for Windows shares
                if len(exepath) > 1 and exepath[0] == "\\" and exepath[1] != "\\":
                    exepath = "\\" + exepath
            if exepath == mypath:
                qt = False
                if "python" in mybin:
                    # Verify px is the script being run by this instance of Python
                    if "-m" in p.cmdline() and "px" in p.cmdline():
                        qt = True
                    else:
                        for param in p.cmdline():
                            if param.endswith("px.py") or param.endswith("px" + ext):
                                qt = True
                                break
                elif is_compiled():
                    # Binary
                    qt = True
                if qt:
                    count += 1
                    for child in p.children(recursive=True):
                        child.kill()
                    p.kill()
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError, SystemError):
            pass
        except:
            traceback.print_exc(file=sys.stdout)

    if count != 0:
        if checkOnly:
            pprint(" Failed")
        else:
            sys.stdout.write("Quitting Px ..")
            sys.stdout.flush()
            time.sleep(4)
            quit(checkOnly = True)
    else:
        if checkOnly:
            pprint(" DONE")
        else:
            pprint("Px is not running")

    sys.exit()

def handle_exceptions(extype, value, tb):
    # Create traceback log
    lst = (traceback.format_tb(tb, None) +
        traceback.format_exception_only(extype, value))
    tracelog = '\nTraceback (most recent call last):\n' + "%-20s%s\n" % (
        "".join(lst[:-1]), lst[-1])

    if State.debug is not None:
        pprint(tracelog)
    else:
        sys.stderr.write(tracelog)

        # Save to debug.log
        dbg = open(dfile(), 'w')
        dbg.write(tracelog)
        dbg.close()

###
# Install Px to startup

if sys.platform == "win32":
    def get_script_cmd():
        spath = get_script_path()
        if spath[-3:] == ".py":
            if "__main__.py" in spath:
                # Case "python -m px"
                return sys.executable + ' -m px'
            else:
                # Case: "python px.py"
                return sys.executable + ' "%s"' % spath

        # Case: "px.exe" from pip
        # Case: "px.exe" from nuitka
        return spath

    def check_installed():
        ret = True
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
        try:
            winreg.QueryValueEx(runkey, "Px")
        except:
            ret = False
        winreg.CloseKey(runkey)

        return ret

    def install():
        if check_installed() is False:
            runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                winreg.KEY_WRITE)
            winreg.SetValueEx(runkey, "Px", 0, winreg.REG_EXPAND_SZ,
                get_script_cmd())
            winreg.CloseKey(runkey)
            pprint("Px installed successfully")
        else:
            pprint("Px already installed")

        sys.exit()

    def uninstall():
        if check_installed() is True:
            runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                winreg.KEY_WRITE)
            winreg.DeleteValue(runkey, "Px")
            winreg.CloseKey(runkey)
            pprint("Px uninstalled successfully")
        else:
            pprint("Px is not installed")

        sys.exit()

    ###
    # Attach/detach console

    def reopen_stdout():
        """Reopen stdout after attaching to the console"""

        clrstr = "\r" + " " * 80 + "\r"
        if State.debug is None:
            State.stdout = sys.stdout
            sys.stdout = open("CONOUT$", "w")
            sys.stdout.write(clrstr)
        else:
            State.stdout = State.debug.stdout
            State.debug.stdout = open("CONOUT$", "w")
            State.debug.stdout.write(clrstr)

    def restore_stdout():
        """Restore stdout before detaching from the console"""

        if State.debug is None:
            sys.stdout.close()
            sys.stdout = State.stdout
        else:
            State.debug.stdout.close()
            State.debug.stdout = State.stdout

    def attach_console():
        if ctypes.windll.kernel32.GetConsoleWindow() != 0:
            dprint("Already attached to a console")
            return

        # Find parent cmd.exe if exists
        pid = os.getpid()
        while True:
            try:
                p = psutil.Process(pid)
            except psutil.NoSuchProcess:
                # No such parent - started without console
                pid = -1
                break

            if os.path.basename(p.name()).lower() in [
                    "cmd", "cmd.exe", "powershell", "powershell.exe"]:
                # Found it
                break

            # Search parent
            pid = p.ppid()

        # Not found, started without console
        if pid == -1:
            dprint("No parent console to attach to")
            return

        dprint("Attaching to console " + str(pid))
        if ctypes.windll.kernel32.AttachConsole(pid) == 0:
            dprint("Attach failed with error " +
                str(ctypes.windll.kernel32.GetLastError()))
            return

        if ctypes.windll.kernel32.GetConsoleWindow() == 0:
            dprint("Not a console window")
            return

        reopen_stdout()

    def detach_console():
        if ctypes.windll.kernel32.GetConsoleWindow() == 0:
            return

        restore_stdout()

        if not ctypes.windll.kernel32.FreeConsole():
            dprint("Free console failed with error " +
                str(ctypes.windll.kernel32.GetLastError()))
        else:
            dprint("Freed console successfully")

###
# Startup

def main():
    multiprocessing.freeze_support()
    sys.excepthook = handle_exceptions

    parse_config()

    run_pool()

if __name__ == "__main__":
    main()
