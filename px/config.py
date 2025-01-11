"Configuration and state management"

import configparser
import getpass
import multiprocessing
import os
import socket
import sys
import threading
import time
import urllib.parse

from .debug import pprint, dprint, Debug
from .help import HELP

from . import wproxy

if sys.platform == "win32":
    from . import windows

# Errors
PxErrors = int
(
    ERROR_SUCCESS,    # 0
    ERROR_IMPORT,     # 1
    ERROR_CONFIG,     # 2
    ERROR_QUIT,       # 3
    ERROR_TEST,       # 4
    ERROR_PORTINUSE,  # 5
    ERROR_UNKNOWN,    # 6
) = range(7)

try:
    import mcurl
except ImportError:
    pprint("Requires module pymcurl")
    sys.exit(ERROR_IMPORT)

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
    sys.exit(ERROR_IMPORT)

try:
    import netaddr
except ImportError:
    pprint("Requires module netaddr")
    sys.exit(ERROR_IMPORT)

try:
    import psutil
except ImportError:
    pprint("Requires module psutil")
    sys.exit(ERROR_IMPORT)

try:
    import dotenv
except ImportError:
    pprint("Requires module python-dotenv")
    sys.exit(ERROR_IMPORT)

# Realms for keyring and authentication
REALM = "Px"
CLIENT_REALM = "PxClient"

# Debug log locations
LogLocation = int
(
    LOG_NONE,
    LOG_SCRIPTDIR,
    LOG_CWD,
    LOG_UNIQLOG,
    LOG_STDOUT
) = range(5)

###
# Get info


def get_script_path():
    "Get full path of running script or compiled executable"
    return os.path.normpath(os.path.join(os.getcwd(), sys.argv[0]))


def get_script_dir():
    "Get directory of running script or compiled executable"
    return os.path.dirname(get_script_path())


def get_script_cmd():
    "Get command for starting Px"
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


def get_logfile(location):
    "Get file path for debug output"
    name = multiprocessing.current_process().name
    if "--quit" in sys.argv:
        name = "quit"
    path = os.getcwd()

    if location == LOG_SCRIPTDIR:
        # --log=1 - log to script directory = --debug
        path = get_script_dir()
    elif location == LOG_CWD:
        # --log=2 - log to working directory
        pass
    elif location == LOG_UNIQLOG:
        # --log=3 - log to working directory with unique filename = --uniqlog
        for arg in sys.argv:
            # Add --port to filename
            if arg.startswith("--port="):
                name = arg[7:] + "-" + name
                break
        name = f"{name}-{time.time()}"
    elif location == LOG_STDOUT:
        # --verbose | --log=4 - log to stdout
        return sys.stdout
    else:
        # --log=0 - no logging
        return None

    # Log to file
    return os.path.join(path, f"debug-{name}.log")


def is_compiled():
    "Return True if compiled with PyInstaller or Nuitka"
    return getattr(sys, "frozen", False) or "__compiled__" in globals()


def get_host_ips():
    "Get IP addresses assigned to this host"
    localips = netaddr.IPSet([])
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    for intf in addrs:
        if stats[intf].isup:
            for addr in addrs[intf]:
                # IPv4 only for now
                if addr.family in [socket.AF_INET]:  # , socket.AF_INET6]:
                    localips.add(addr.address.split("%")[0])

    return localips


def file_url_to_local_path(file_url):
    parts = urllib.parse.urlparse(file_url)
    path = urllib.parse.unquote(parts.path)
    if path.startswith('/') and not path.startswith('//'):
        if len(parts.netloc) == 2 and parts.netloc[1] == ':':
            return parts.netloc + path
        return 'C:' + path
    if len(path) > 2 and path[1] == ':':
        return path


def get_listen():
    "Get local interface that Px will listen on"
    listen = STATE.listen[0]
    if len(listen) == 0:
        # Listening on all interfaces - figure out which one is allowed
        hostips = get_host_ips()
        if STATE.gateway:
            # Check allow list
            for ip in hostips:
                if ip in STATE.allow:
                    listen = str(ip)
                    break
            if len(listen) == 0:
                return ""
        elif STATE.hostonly:
            # Use first host IP
            listen = str(list(hostips)[0])

    return listen

###
# Actions


def quit(exit=True):
    "Quit running instances of Px for loaded configuration"
    listen = get_listen()
    port = STATE.config.getint("proxy", "port")

    if len(listen) == 0:
        pprint("Failed: Px not listening on localhost - cannot quit")
        sys.exit(ERROR_QUIT)

    # Check if Px is running
    count = 0
    while True:
        try:
            socket.create_connection((listen, port), 1)
            break
        except socket.timeout:
            # Too busy?
            time.sleep(0.1)
            count += 1
            if count == 5:
                pprint("Failed: Px not responding")
                if exit:
                    sys.exit(ERROR_QUIT)
        except ConnectionRefusedError:
            # Px not running
            pprint("Px is not running")
            if exit:
                sys.exit(ERROR_QUIT)
            return False

    try:
        sys.stdout.write("Quitting Px ..")
        sys.stdout.flush()
    except:
        pass

    # Connect to Px and send quit request
    url = f"http://{listen}:{port}/PxQuit"
    mc = mcurl.MCurl(debug_print=dprint)
    ec = mcurl.Curl(url)
    ec.buffer()
    success = False
    while True:
        # Loop until all workers quit
        ret = ec.perform()
        if ret in [0, 56]:
            # Success / disconnected

            # Get response code
            ret, resp = ec.get_response()
            if ret != 0:
                pprint(f" Failed: response error {ret}\n{ec.errstr}")
                break
            if resp == 200:
                # Quit successful
                success = True
                continue
            elif resp == 403:
                pprint(" Failed: cannot quit Px on remote host")
                break
            else:
                pprint(f" Failed: response {resp}\n{ec.get_data()}")
                break
        elif ret == 7:
            # Px no longer running
            break
        elif ret == 52:
            # Connection rejected - not in allow list
            break
        else:
            # Quit failed - other error
            pprint(f" Failed: error {ret}\n{ec.errstr}")
            break

        ec.reset(url)
        ec.buffer()
        time.sleep(0.01)

    if success:
        # Check if Px still running
        try:
            socket.create_connection((listen, port), 1)
            pprint(" Failed: Px still running")
            success = False
        except (socket.timeout, ConnectionRefusedError):
            pprint(" DONE")
    else:
        pprint(" Failed")

    ret = 0 if success else ERROR_QUIT
    if exit:
        sys.exit(ret)

    return ret

###
# Parse settings and command line


# Default values for all keys
DEFAULTS = {
    "server": "",
    "pac": "",
    "pac_encoding": "utf-8",
    "port": "3128",
    "listen": "127.0.0.1",
    "gateway": "0",
    "hostonly": "0",
    "allow": "*.*.*.*",
    "noproxy": "",
    "useragent": "",
    "username": "",
    "auth": "",
    "workers": "2",
    "threads": "32",
    "idle": "30",
    "socktimeout": "20.0",
    "proxyreload": "60",
    "foreground": "0",
    "log": "0",

    "test": None
}

# Client authentication related
AUTH_SUPPORTED = ["NEGOTIATE", "NTLM", "DIGEST", "BASIC"]


class State:
    """Stores runtime state per process - shared across threads"""

    instance = None

    # Config
    gateway = False
    hostonly = False
    ini = ""
    idle = 30
    listen = None
    noproxy = ""
    pac = ""
    proxyreload = 60
    socktimeout = 20.0
    useragent = ""

    # Auth
    auth = "ANY"
    username = ""

    client_auth = []
    client_username = ""
    client_nosspi = False

    # Objects
    allow = netaddr.IPGlob("*.*.*.*")
    config = None
    debug = None
    location = LOG_NONE
    mcurl = None
    stdout = None
    wproxy = None

    # Tracking
    proxy_last_reload = None

    # Lock for thread synchronization of State object
    # multiprocess sync isn't neccessary because State object is only shared by
    # threads - every process has it's own State object
    state_lock = threading.Lock()

    test = None

    callbacks = None

    def __new__(cls):
        "Create a singleton instance of State"
        if cls.instance is None:
            cls.instance = super(State, cls).__new__(cls)
        return cls.instance

    def __init__(self):
        # Callback functions for initialization
        self.callbacks = {
            "pac": self.set_pac,
            "listen": self.set_listen,
            "gateway": self.set_gateway,
            "hostonly": self.set_hostonly,
            "allow": self.set_allow,
            "noproxy": self.set_noproxy,
            "useragent": self.set_useragent,
            "username": self.set_username,
            "auth": self.set_auth,
            "client_username": self.set_client_username,
            "client_auth": self.set_client_auth,
            "client_nosspi": self.set_client_nosspi,
            "log": self.set_debug,
            "idle": self.set_idle,
            "socktimeout": self.set_socktimeout,
            "proxyreload": self.set_proxyreload,

            "test": self.set_test
        }

    def set_pac(self, pac):
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
            self.pac = pac
        else:
            pprint("Unsupported PAC location or file not found: %s" % pac)
            sys.exit(ERROR_CONFIG)

    def set_listen(self, listen):
        if len(listen) == 0:
            # Listen on localhost only if blank
            # Explicit --gateway or --hostonly required to listen on all interfaces
            self.listen = ["127.0.0.1"]
        else:
            self.listen = []
            for intf in listen.split(","):
                clean = intf.strip()
                if len(clean) != 0 and clean not in self.listen:
                    self.listen.append(clean)

    def set_gateway(self, gateway):
        self.gateway = True if gateway == 1 else False

    def set_hostonly(self, hostonly):
        self.hostonly = True if hostonly == 1 else False

    def set_allow(self, allow):
        self.allow, _ = wproxy.parse_noproxy(allow, iponly=True)

    def set_noproxy(self, noproxy):
        self.noproxy = noproxy

    def set_useragent(self, useragent):
        self.useragent = useragent

    def set_username(self, username):
        self.username = username

    def set_password(self):
        try:
            if len(self.username) == 0:
                pprint(
                    "domain\\username missing - specify via --username or configure in px.ini")
                sys.exit(ERROR_CONFIG)
            pprint("Setting password for '" + self.username + "'")

            pwd = ""
            while len(pwd) == 0:
                pwd = getpass.getpass("Enter password: ")

            keyring.set_password(REALM, self.username, pwd)

            if keyring.get_password(REALM, self.username) == pwd:
                pprint("Saved successfully")
        except KeyboardInterrupt:
            pprint("")

        sys.exit(ERROR_SUCCESS)

    def set_auth(self, auth):
        if len(auth) == 0:
            auth = "ANY"

        # Test that it works
        _ = mcurl.getauth(auth)

        self.auth = auth

    def set_client_username(self, username):
        "Set client username"
        self.client_username = username

    def set_client_password(self):
        try:
            if len(self.client_username) == 0:
                pprint("domain\\username missing - specify via --client-username")
                sys.exit(ERROR_CONFIG)
            pprint("Setting client password for '" +
                   self.client_username + "'")

            pwd = ""
            while len(pwd) == 0:
                pwd = getpass.getpass("Enter password: ")

            keyring.set_password(CLIENT_REALM, self.client_username, pwd)

            if keyring.get_password(CLIENT_REALM, self.client_username) == pwd:
                pprint("Saved successfully")
        except KeyboardInterrupt:
            pprint("")

        sys.exit(ERROR_SUCCESS)

    def set_client_auth(self, auth):
        "Set client authentication"
        self.client_auth = []
        for val in auth.split(","):
            val = val.strip().upper()
            if val == "ANY":
                self.client_auth = AUTH_SUPPORTED
                return
            elif val == "ANYSAFE":
                self.client_auth = AUTH_SUPPORTED
                self.client_auth.remove("BASIC")
                return
            elif val == "NONE":
                return
            elif val not in AUTH_SUPPORTED:
                dprint("Unsupported client auth type: " + auth)
                raise ValueError("Unsupported client auth type: " + auth)
            else:
                self.client_auth.append(val)

    def set_client_nosspi(self, nosspi):
        "Set client nosspi"
        if nosspi == 1:
            self.client_nosspi = True

    def set_debug(self, location=LOG_SCRIPTDIR):
        if self.debug is None:
            logfile = get_logfile(location)

            if logfile is not None:
                self.location = location
                if logfile is sys.stdout:
                    # Log to stdout
                    self.debug = Debug()
                else:
                    # Log to <path>/debug-<name>.log
                    self.debug = Debug(logfile, "w")

    def set_idle(self, idle):
        self.idle = idle

    def set_socktimeout(self, socktimeout):
        self.socktimeout = socktimeout
        socket.setdefaulttimeout(socktimeout)

    def set_proxyreload(self, proxyreload):
        self.proxyreload = proxyreload

    def set_test(self, test):
        self.test = test

    # Configuration setup

    def cfg_int_init(self, section, name, default, proc=None, override=False):
        val = default
        if not override:
            try:
                val = self.config.get(section, name).strip()
            except configparser.NoOptionError:
                pass

        try:
            val = int(val)
        except ValueError:
            pprint("Invalid integer value for " + section + ":" + name)

        self.config.set(section, name, str(val))

        if proc is not None:
            proc(val)

    def cfg_float_init(self, section, name, default, proc=None, override=False):
        val = default
        if not override:
            try:
                val = self.config.get(section, name).strip()
            except configparser.NoOptionError:
                pass

        try:
            val = float(val)
        except ValueError:
            pprint("Invalid float value for " + section + ":" + name)

        self.config.set(section, name, str(val))

        if proc is not None:
            proc(val)

    def cfg_str_init(self, section, name, default, proc=None, override=False):
        val = default
        if not override:
            try:
                val = self.config.get(section, name).strip()
            except configparser.NoOptionError:
                pass

        self.config.set(section, name, val)

        if proc is not None:
            proc(val)

    def cfg_init(self, name, val, override=False):
        callback = self.callbacks.get(name)
        # [proxy]
        if name in ["server", "pac", "pac_encoding", "listen", "allow", "noproxy",
                    "useragent", "username", "auth"]:
            self.cfg_str_init("proxy", name, val, callback, override)
        elif name in ["port", "gateway", "hostonly"]:
            self.cfg_int_init("proxy", name, val, callback, override)

        # [client]
        elif name in ["client_username", "client_auth"]:
            self.cfg_str_init("client", name, val, callback, override)
        elif name in ["client_nosspi"]:
            self.cfg_int_init("client", name, val, callback, override)

        # [settings]
        elif name in ["workers", "threads", "idle", "proxyreload", "foreground", "log"]:
            self.cfg_int_init("settings", name, val, callback, override)
        elif name in ["socktimeout"]:
            self.cfg_float_init("settings", name, val, callback, override)

        # Non-config
        elif name in ["test"] and callback is not None:
            callback(val)

    def save(self):
        with open(self.ini, "w") as cfgfile:
            self.config.write(cfgfile)
        pprint("Saved config to " + self.ini + "\n")
        with open(self.ini, "r") as cfgfile:
            sys.stdout.write(cfgfile.read())

        sys.exit(ERROR_SUCCESS)

    # Config sources

    def parse_cli(self):
        "Parse all command line arguments into a dictionary"
        flags = {}
        for arg in sys.argv:
            if not arg.startswith("--") or len(arg) < 3:
                continue
            arg = arg[2:]

            if "=" in arg:
                # --name=val
                name, val = arg.split("=", 1)
                flags[name.replace("-", "_")] = val
            else:
                # --name
                flags[arg.replace("-", "_")] = "1"

        if "proxy" in flags:
            # --proxy is synonym for --server
            flags["server"] = flags["proxy"]
            del flags["proxy"]

        return flags

    def parse_env(self):
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

    def parse_config(self):
        "Parse configuration from CLI flags, environment and config file in order"
        if "--debug" in sys.argv:
            self.set_debug(LOG_SCRIPTDIR)
        elif "--uniqlog" in sys.argv:
            self.set_debug(LOG_UNIQLOG)
        elif "--verbose" in sys.argv:
            self.set_debug(LOG_STDOUT)

            if "--foreground" not in sys.argv:
                # --verbose implies --foreground
                sys.argv.append("--foreground")

        if sys.platform == "win32":
            if is_compiled() or "pythonw.exe" in sys.executable:
                windows.attach_console(self)

        if "-h" in sys.argv or "--help" in sys.argv:
            pprint(HELP)
            sys.exit(ERROR_SUCCESS)

        # Load CLI flags and environment variables
        flags = self.parse_cli()
        env = self.parse_env()

        # Check if config file specified in CLI flags or environment
        is_save = "save" in flags or "save" in env
        if "config" in flags:
            # From CLI
            self.ini = flags["config"]
        elif "config" in env:
            # From environment
            self.ini = env["config"]

        if len(self.ini) != 0:
            if not (os.path.exists(self.ini) or is_save):
                # Specified file doesn't exist and not --save
                pprint(f"Could not find config file: {self.ini}")
                sys.exit(ERROR_CONFIG)
        else:
            # Default "CWD/px.ini"
            cwd = os.getcwd()
            path = os.path.join(cwd, "px.ini")
            if os.path.exists(path) or is_save:
                self.ini = path
            else:
                # Alternate "script_dir/px.ini"
                script_dir = get_script_dir()
                if script_dir != cwd:
                    path = os.path.join(script_dir, "px.ini")
                    if os.path.exists(path):
                        self.ini = path

        # Load configuration file
        self.config = configparser.ConfigParser()
        if os.path.exists(self.ini):
            self.config.read(self.ini)

        ###
        # Create config sections if not already from config file

        # [proxy] section
        if "proxy" not in self.config.sections():
            self.config.add_section("proxy")

        # [client] section
        if "client" not in self.config.sections():
            self.config.add_section("client")

        # [settings] section
        if "settings" not in self.config.sections():
            self.config.add_section("settings")

        # Save --log state if --debug | --verbose | --uniqlog specified
        save_location = self.location

        # Default initilize if not already from config file
        for name, val in DEFAULTS.items():
            self.cfg_init(name, val)

        # Override from environment
        for name, val in env.items():
            self.cfg_init(name, val, override=True)

        # Final override from CLI which takes highest precedence
        for name, val in flags.items():
            self.cfg_init(name, val, override=True)

        # Restore --log state if --debug | --verbose | --uniqlog specified
        if save_location != LOG_NONE:
            self.cfg_int_init("settings", "log", str(
                save_location), override=True)

        ###
        # Dependency propagation

        # If gateway mode
        allow = self.config.get("proxy", "allow")
        if self.gateway == 1:
            # Listen on all interfaces
            self.listen = [""]
            self.config.set("proxy", "listen", "")
            dprint("Gateway mode - overriding 'listen' and binding to all interfaces")
            if allow in ["*.*.*.*", "0.0.0.0/0"]:
                dprint("Configure 'allow' to restrict access to trusted subnets")

        # If hostonly mode
        if self.hostonly:
            # Listen on all interfaces
            self.listen = [""]
            self.config.set("proxy", "listen", "")
            dprint("Host-only mode - overriding 'listen' and binding to all interfaces")
            dprint("Px will automatically restrict access to host interfaces")

            # If not gateway mode or gateway with default allow rules
            if (self.gateway == 0 or (self.gateway == 1 and allow in ["*.*.*.*", "0.0.0.0/0"])):
                # Purge allow rules
                self.cfg_init("allow", "", True)
                dprint("Removing default 'allow' everyone rule")

        ###
        # Handle actions

        if sys.platform == "win32":
            if "--install" in sys.argv:
                windows.install(get_script_cmd())
            elif "--uninstall" in sys.argv:
                windows.uninstall()

        if "--quit" in sys.argv:
            quit()
        elif "--restart" in sys.argv:
            ret = quit(exit=False)
            if ret != 0:
                sys.exit(ret)
            sys.argv.remove("--restart")
        elif "--save" in sys.argv:
            self.save()
        elif "--password" in sys.argv:
            self.set_password()
        elif "--client-password" in sys.argv:
            self.set_client_password()

        ###
        # Discover proxy info from OS

        servers = wproxy.parse_proxy(self.config.get("proxy", "server"))
        if len(servers) != 0:
            self.wproxy = wproxy.Wproxy(
                wproxy.MODE_CONFIG, servers, noproxy=self.noproxy, debug_print=dprint)
        elif len(self.pac) != 0:
            pac_encoding = self.config.get("proxy", "pac_encoding")
            self.wproxy = wproxy.Wproxy(wproxy.MODE_CONFIG_PAC, [
                                        self.pac], noproxy=self.noproxy, pac_encoding=pac_encoding, debug_print=dprint)
        else:
            self.wproxy = wproxy.Wproxy(
                noproxy=self.noproxy, debug_print=dprint)
            self.proxy_last_reload = time.time()

        # Curl multi object to manage all easy connections
        self.mcurl = mcurl.MCurl(debug_print=dprint)

    def reload_proxy(self):
        # Return if proxies specified in Px config
        if self.wproxy.mode in [wproxy.MODE_CONFIG, wproxy.MODE_CONFIG_PAC]:
            return

        # Do locking to avoid updating globally shared State object by multiple
        # threads simultaneously
        self.state_lock.acquire()
        try:
            # Check if need to refresh
            if (self.proxy_last_reload is not None and
                    time.time() - self.proxy_last_reload < self.proxyreload):
                dprint("Skip proxy refresh")
                return

            # Reload proxy information
            self.wproxy = wproxy.Wproxy(
                noproxy=self.noproxy, debug_print=dprint)

            self.proxy_last_reload = time.time()

        finally:
            self.state_lock.release()


# Create instance of State object
STATE = State()
