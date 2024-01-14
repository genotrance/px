import configparser
import getpass
import multiprocessing
import os
import socket
import sys
import threading
import time
import urllib.parse

from .debug import pprint, Debug
from .help import HELP

from . import mcurl
from . import wproxy

if sys.platform == "win32":
    from . import windows

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

# Debug shortcut
dprint = lambda x: None

# Debug log locations
LogLocation = int
(
    LOG_NONE,
    LOG_SCRIPTDIR,
    LOG_CWD,
    LOG_UNIQLOG,
    LOG_STDOUT
) = range(5)

class State:
    """Stores runtime state per process - shared across threads"""

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
                if addr.family in [socket.AF_INET]:#, socket.AF_INET6]:
                    localips.add(addr.address.split("%")[0])

    return localips

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
# Actions

def save():
    with open(State.ini, "w") as cfgfile:
        State.config.write(cfgfile)
    pprint("Saved config to " + State.ini + "\n")
    with open(State.ini, "r") as cfgfile:
        sys.stdout.write(cfgfile.read())

    sys.exit()

def quit(checkOnly = False, exit = True):
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
                elif config.is_compiled():
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

    ret = False
    if count != 0:
        if checkOnly:
            pprint(" Failed")
        else:
            sys.stdout.write("Quitting Px ..")
            sys.stdout.flush()
            time.sleep(4)
            ret = quit(checkOnly = True, exit = exit)
    else:
        if checkOnly:
            pprint(" DONE")
            ret = True
        else:
            pprint("Px is not running")

    if exit:
        sys.exit()

    return ret

###
# Parse settings and command line

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

def set_listen(listen):
    if len(listen) == 0:
        # Listen on localhost only if blank
        # Explicit --gateway or --hostonly required to listen on all interfaces
        State.listen = ["127.0.0.1"]
    else:
        State.listen = []
        for intf in listen.split(","):
            clean = intf.strip()
            if len(clean) != 0 and clean not in State.listen:
                State.listen.append(clean)

def set_gateway(gateway):
    State.gateway = True if gateway == 1 else False

def set_hostonly(hostonly):
    State.hostonly = True if hostonly == 1 else False

def set_allow(allow):
    State.allow, _ = wproxy.parse_noproxy(allow, iponly = True)

def set_noproxy(noproxy):
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

def set_auth(auth):
    if len(auth) == 0:
        auth = "ANY"

    # Test that it works
    _ = mcurl.getauth(auth)

    State.auth = auth

def set_debug(location = LOG_SCRIPTDIR):
    global dprint
    if State.debug is None:
        logfile = get_logfile(location)

        if logfile is not None:
            State.location = location
            if logfile is sys.stdout:
                # Log to stdout
                State.debug = Debug()
            else:
                # Log to <path>/debug-<name>.log
                State.debug = Debug(logfile, "w")
            dprint = State.debug.get_print()

def set_idle(idle):
    State.idle = idle

def set_socktimeout(socktimeout):
    State.socktimeout = socktimeout
    socket.setdefaulttimeout(socktimeout)

def set_proxyreload(proxyreload):
    State.proxyreload = proxyreload

def set_test(test):
    State.test = test

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

# Callback functions for initialization
CALLBACKS = {
    "pac": set_pac,
    "listen": set_listen,
    "gateway": set_gateway,
    "hostonly": set_hostonly,
    "allow": set_allow,
    "noproxy": set_noproxy,
    "useragent": set_useragent,
    "username": set_username,
    "auth": set_auth,
    "log": set_debug,
    "idle": set_idle,
    "socktimeout": set_socktimeout,
    "proxyreload": set_proxyreload,

    "test": set_test
}

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

def cfg_init(name, val, override=False):
    callback = CALLBACKS.get(name)
    # [proxy]
    if name in ["server", "pac", "pac_encoding", "listen", "allow", "noproxy",
                "useragent", "username", "auth"]:
        cfg_str_init("proxy", name, val, callback, override)
    elif name in ["port", "gateway", "hostonly"]:
        cfg_int_init("proxy", name, val, callback, override)

    # [settings]
    elif name in ["workers", "threads", "idle", "proxyreload", "foreground", "log"]:
        cfg_int_init("settings", name, val, callback, override)
    elif name in ["socktimeout"]:
        cfg_float_init("settings", name, val, callback, override)

    # Non-config
    elif name in ["test"] and callback is not None:
        callback(val)

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

    if "proxy" in flags:
        # --proxy is synonym for --server
        flags["server"] = flags["proxy"]
        del flags["proxy"]

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
        set_debug(LOG_SCRIPTDIR)
    elif "--uniqlog" in sys.argv:
        set_debug(LOG_UNIQLOG)
    elif "--verbose" in sys.argv:
        set_debug(LOG_STDOUT)

        if "--foreground" not in sys.argv:
            # --verbose implies --foreground
            sys.argv.append("--foreground")

    if sys.platform == "win32":
        if is_compiled() or "pythonw.exe" in sys.executable:
            windows.attach_console(State, dprint)

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

    # Override --log if --debug | --verbose | --uniqlog specified
    cfg_int_init("settings", "log", str(State.location), override = True)

    # Default initilize if not already from config file
    for name, val in DEFAULTS.items():
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
    allow = State.config.get("proxy", "allow")
    if State.gateway == 1:
        # Listen on all interfaces
        State.listen = [""]
        State.config.set("proxy", "listen", "")
        dprint("Gateway mode - overriding 'listen' and binding to all interfaces")
        if allow in ["*.*.*.*", "0.0.0.0/0"]:
            dprint("Configure 'allow' to restrict access to trusted subnets")

    # If hostonly mode
    if State.hostonly:
        # Listen on all interfaces
        State.listen = [""]
        State.config.set("proxy", "listen", "")
        dprint("Host-only mode - overriding 'listen' and binding to all interfaces")
        dprint("Px will automatically restrict access to host interfaces")

        # If not gateway mode or gateway with default allow rules
        if (State.gateway == 0 or (State.gateway == 1 and allow in ["*.*.*.*", "0.0.0.0/0"])):
            # Purge allow rules
            cfg_init("allow", "", True)
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
        if not quit(exit = False):
            sys.exit()
        sys.argv.remove("--restart")
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
