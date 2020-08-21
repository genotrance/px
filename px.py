"Px is an HTTP proxy server to automatically authenticate through an NTLM proxy"

from __future__ import print_function

__version__ = "0.4.0"

import base64
import ctypes
import ctypes.wintypes
import multiprocessing
import os
import select
import signal
import socket
import sys
import threading
import time
import traceback

# Print if possible
def pprint(*objs):
    try:
        print(*objs)
    except:
        pass

# Dependencies
try:
    import concurrent.futures
except ImportError:
    pprint("Requires module futures")
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
    import pywintypes
    import sspi
except ImportError:
    pprint("Requires module pywin32")
    sys.exit()

try:
    import winkerberos
except ImportError:
    pprint("Requires module winkerberos")
    sys.exit()

try:
    import ntlm_auth.ntlm
except ImportError:
    pprint("Requires module ntlm-auth")
    sys.exit()

try:
    import keyring
    import keyring.backends.Windows

    keyring.set_keyring(keyring.backends.Windows.WinVaultKeyring())
except ImportError:
    pprint("Requires module keyring")
    sys.exit()

# Python 2.x vs 3.x support
try:
    import configparser
    import http.server as httpserver
    import socketserver
    import urllib.parse as urlparse
    import winreg
except ImportError:
    import ConfigParser as configparser
    import SimpleHTTPServer as httpserver
    import SocketServer as socketserver
    import urlparse
    import _winreg as winreg

    os.getppid = psutil.Process().ppid
    PermissionError = WindowsError

HELP = """Px v%s

An HTTP proxy server to automatically authenticate through an NTLM proxy

Usage:
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
  NTLM server(s) to connect through. IP:port, hostname:port
    Multiple proxies can be specified comma separated. Px will iterate through
    and use the one that works. Required field unless --noproxy is defined. If
    remote server is not in noproxy list and proxy is undefined, Px will reject
    the request

  --pac=  proxy:pac=
  PAC file to use to connect
    Use in place of server if PAC file should be loaded from a custom URL or
    file location instead of from Internet Options

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
    On Windows, Credential Manager is the backed and can be accessed from
    Control Panel > User Accounts > Credential Manager > Windows Credentials.
    Create a generic credential with Px as the network address, this username
    and corresponding password.

  --auth=  proxy:auth=
  Force instead of discovering upstream proxy type
    By default, Px will attempt to discover the upstream proxy type and either
    use pywin32/ntlm-auth for NTLM auth or winkerberos for Kerberos or Negotiate
    auth. This option will force either NTLM, Kerberos or Basic and not query the
    upstream proxy type.

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
    Proxy info reloaded from a PAC file found via WPAD or AutoConfig URL, or
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
    running multiple instances of Px""" % __version__

# Windows version
#  6.1 = Windows 7
#  6.2 = Windows 8
#  6.3 = Windows 8.1
# 10.0 = Windows 10
WIN_VERSION = float(
    str(sys.getwindowsversion().major) + "." +
    str(sys.getwindowsversion().minor))

# Proxy modes - source of proxy info
MODE_NONE = 0
MODE_CONFIG = 1
MODE_AUTO = 2
MODE_PAC = 3
MODE_MANUAL = 4
MODE_CONFIG_PAC = 5

class State(object):
    allow = netaddr.IPGlob("*.*.*.*")
    config = None
    domain = ""
    exit = False
    hostonly = False
    logger = None
    noproxy = netaddr.IPSet([])
    noproxy_hosts = []
    pac = ""
    proxy_mode = MODE_NONE
    proxy_refresh = None
    proxy_server = []
    proxy_type = {}
    stdout = None
    useragent = ""
    username = ""
    auth = None

    ini = "px.ini"
    max_disconnect = 3
    max_line = 65536 + 1

    # Locks for thread synchronization;
    # multiprocess sync isn't neccessary because State object is only shared by
    # threads but every process has it's own State object
    proxy_type_lock = threading.Lock()
    proxy_mode_lock = threading.Lock()

class Response(object):
    __slots__ = ["code", "length", "headers", "data", "body", "chunked", "close"]

    def __init__(self, code=503):
        self.code = code

        self.length = 0

        self.headers = []
        self.data = None

        self.body = False
        self.chunked = False
        self.close = False

class Log(object):
    def __init__(self, name, mode):
        self.file = open(name, mode)
        self.stdout = sys.stdout
        self.stderr = sys.stderr
        sys.stdout = self
        sys.stderr = self
    def close(self):
        sys.stdout = self.stdout
        sys.stderr = self.stderr
        self.file.close()
    def write(self, data):
        try:
            self.file.write(data)
        except:
            pass
        if self.stdout is not None:
            self.stdout.write(data)
        self.flush()
    def flush(self):
        self.file.flush()
        os.fsync(self.file.fileno())
        if self.stdout is not None:
            self.stdout.flush()

def dprint(msg):
    if State.logger is not None:
        # Do locking to avoid mixing the output of different threads as there are
        # two calls to print which could otherwise interleave
        sys.stdout.write(
            multiprocessing.current_process().name + ": " +
            threading.current_thread().name + ": " + str(int(time.time())) +
            ": " + sys._getframe(1).f_code.co_name + ": " + msg + "\n")

def dfile():
    name = multiprocessing.current_process().name
    if "--quit" in sys.argv:
        name = "quit"
    if "--uniqlog" in sys.argv:
        name = "%s-%f" % (name, time.time())
    logfile = os.path.join(os.path.dirname(get_script_path()),
        "debug-%s.log" % name)
    return logfile

def reopen_stdout():
    clrstr = "\r" + " " * 80 + "\r"
    if State.logger is None:
        State.stdout = sys.stdout
        sys.stdout = open("CONOUT$", "w")
        sys.stdout.write(clrstr)
    else:
        State.stdout = State.logger.stdout
        State.logger.stdout = open("CONOUT$", "w")
        State.logger.stdout.write(clrstr)

def restore_stdout():
    if State.logger is None:
        sys.stdout.close()
        sys.stdout = State.stdout
    else:
        State.logger.stdout.close()
        State.logger.stdout = State.stdout

###
# Auth support

def b64decode(val):
    try:
        return base64.decodebytes(val.encode("utf-8"))
    except AttributeError:
        return base64.decodestring(val)

def b64encode(val):
    try:
        return base64.encodebytes(val.encode("utf-8"))
    except AttributeError:
        return base64.encodestring(val)

class AuthMessageGenerator:
    def __init__(self, proxy_type, proxy_server_address):
        pwd = ""
        if State.username:
            key = State.username
            if State.domain != "":
                key = State.domain + "\\" + State.username
            pwd = keyring.get_password("Px", key)

        if proxy_type == "NTLM":
            if not pwd:
                self.ctx = sspi.ClientAuth("NTLM",
                  os.environ.get("USERNAME"), scflags=0)
                self.get_response = self.get_response_sspi
            else:
                self.ctx = ntlm_auth.ntlm.NtlmContext(
                    State.username, pwd, State.domain, "", ntlm_compatibility=3)
                self.get_response = self.get_response_ntlm
        elif proxy_type == "BASIC":
            if not State.username:
                dprint("No username configured for Basic authentication")
            elif not pwd:
                dprint("No password configured for Basic authentication")
            else:
                # Colons are forbidden in usernames and passwords for basic auth
                # but since this can happen very easily, we make a special check
                # just for colons so people immediately understand that and don't
                # have to look up other resources.
                if ":" in State.username or ":" in pwd:
                    dprint("Credentials contain invalid colon character")
                else:
                    # Additionally check for invalid control characters as per
                    # RFC5234 Appendix B.1 (section CTL)
                    illegal_control_characters = "".join(
                        chr(i) for i in range(0x20)) + "\u007F"

                    if any(char in State.username or char in pwd
                            for char in illegal_control_characters):
                        dprint("Credentials contain invalid characters: %s" % ", ".join("0x" + "%x" % ord(char) for char in illegal_control_characters))
                    else:
                        # Remove newline appended by base64 function
                        self.ctx = b64encode(
                            "%s:%s" % (State.username, pwd))[:-1].decode()
            self.get_response = self.get_response_basic
        else:
            principal = None
            if pwd:
                if State.domain:
                    principal = (urlparse.quote(State.username) + "@" +
                        urlparse.quote(State.domain) + ":" + urlparse.quote(pwd))
                else:
                    principal = (urlparse.quote(State.username) + ":" +
                        urlparse.quote(pwd))

            _, self.ctx = winkerberos.authGSSClientInit("HTTP@" +
                proxy_server_address, principal=principal, gssflags=0,
                mech_oid=winkerberos.GSS_MECH_OID_SPNEGO)
            self.get_response = self.get_response_wkb

    def get_response_sspi(self, challenge=None):
        dprint("pywin32 SSPI")
        if challenge:
            challenge = b64decode(challenge)
        output_buffer = None
        try:
            error_msg, output_buffer = self.ctx.authorize(challenge)
        except pywintypes.error:
            traceback.print_exc(file=sys.stdout)
            return None

        response_msg = b64encode(output_buffer[0].Buffer)
        response_msg = response_msg.decode("utf-8").replace('\012', '')
        return response_msg

    def get_response_wkb(self, challenge=""):
        dprint("winkerberos SSPI")
        try:
            winkerberos.authGSSClientStep(self.ctx, challenge)
            auth_req = winkerberos.authGSSClientResponse(self.ctx)
        except winkerberos.GSSError:
            traceback.print_exc(file=sys.stdout)
            return None

        return auth_req

    def get_response_ntlm(self, challenge=""):
        dprint("ntlm-auth")
        if challenge:
            challenge = b64decode(challenge)
        response_msg = b64encode(self.ctx.step(challenge))
        response_msg = response_msg.decode("utf-8").replace('\012', '')
        return response_msg

    def get_response_basic(self, challenge=""):
        dprint("basic")
        return self.ctx

###
# Proxy handler

class Proxy(httpserver.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # Contains the proxy servers responsible for the url this Proxy instance
    # (aka thread) serves
    proxy_servers = []
    proxy_socket = None

    def handle_one_request(self):
        try:
            httpserver.SimpleHTTPRequestHandler.handle_one_request(self)
        except socket.error as e:
            dprint("Socket error: %s" % e)
            if not hasattr(self, "_host_disconnected"):
                self._host_disconnected = 1
                dprint("Host disconnected")
            elif self._host_disconnected < State.max_disconnect:
                self._host_disconnected += 1
                dprint("Host disconnected: %d" % self._host_disconnected)
            else:
                dprint("Closed connection to avoid infinite loop")
                self.close_connection = True

    def address_string(self):
        host, port = self.client_address[:2]
        #return socket.getfqdn(host)
        return host

    def log_message(self, format, *args):
        dprint(format % args)

    def do_socket_connect(self, destination=None):
        # Already connected?
        if self.proxy_socket is not None:
            return True

        dests = list(self.proxy_servers) if destination is None else [
            destination]
        for dest in dests:
            dprint("New connection: " + str(dest))
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                proxy_socket.connect(dest)
                self.proxy_address = dest
                self.proxy_socket = proxy_socket
                break
            except Exception as e:
                dprint("Connect failed: %s" % e)
                # move a non reachable proxy to the end of the proxy list;
                if len(self.proxy_servers) > 1:
                    # append first and then remove, this should ensure thread
                    # safety with manual configurated proxies (in this case
                    # self.proxy_servers references the shared
                    # State.proxy_server)
                    self.proxy_servers.append(dest)
                    self.proxy_servers.remove(dest)

        if self.proxy_socket is not None:
            return True

        return False

    def do_socket(self, xheaders={}, destination=None):
        dprint("Entering")

        # Connect to proxy or destination
        if not self.do_socket_connect(destination):
            return Response(408)

        # No chit chat on SSL
        if destination is not None and self.command == "CONNECT":
            return Response(200)

        cl = 0
        chk = False
        expect = False
        keepalive = False
        ua = False
        cmdstr = "%s %s %s\r\n" % (self.command, self.path, self.request_version)
        self.proxy_socket.sendall(cmdstr.encode("utf-8"))
        dprint(cmdstr.strip())
        for header in self.headers:
            hlower = header.lower()
            if hlower == "user-agent" and State.useragent != "":
                ua = True
                h = "%s: %s\r\n" % (header, State.useragent)
            else:
                h = "%s: %s\r\n" % (header, self.headers[header])

            self.proxy_socket.sendall(h.encode("utf-8"))
            if hlower != "authorization":
                dprint("Sending %s" % h.strip())
            else:
                dprint("Sending %s: sanitized len(%d)" % (
                    header, len(self.headers[header])))

            if hlower == "content-length":
                cl = int(self.headers[header])
            elif (hlower == "expect" and
                    self.headers[header].lower() == "100-continue"):
                expect = True
            elif hlower == "proxy-connection":
                keepalive = True
            elif (hlower == "transfer-encoding" and
                    self.headers[header].lower() == "chunked"):
                dprint("CHUNKED data")
                chk = True

        if not keepalive and self.request_version.lower() == "http/1.0":
            xheaders["Proxy-Connection"] = "keep-alive"

        if not ua and State.useragent != "":
            xheaders["User-Agent"] = State.useragent

        for header in xheaders:
            h = ("%s: %s\r\n" % (header, xheaders[header])).encode("utf-8")
            self.proxy_socket.sendall(h)
            if header.lower() != "proxy-authorization":
                dprint("Sending extra %s" % h.strip())
            else:
                dprint("Sending extra %s: sanitized len(%d)" % (
                    header, len(xheaders[header])))
        self.proxy_socket.sendall(b"\r\n")

        if self.command in ["POST", "PUT", "PATCH"]:
            if not hasattr(self, "body"):
                dprint("Getting body for POST/PUT/PATCH")
                if cl:
                    self.body = self.rfile.read(cl)
                else:
                    self.body = self.rfile.read()

            dprint("Sending body for POST/PUT/PATCH: %d = %d" % (
                cl or -1, len(self.body)))
            self.proxy_socket.sendall(self.body)

        self.proxy_fp = self.proxy_socket.makefile("rb")

        resp = Response()

        if self.command != "HEAD":
            resp.body = True

        # Response code
        for i in range(2):
            dprint("Reading response code")
            line = self.proxy_fp.readline(State.max_line)
            if line == b"\r\n":
                line = self.proxy_fp.readline(State.max_line)
            try:
                resp.code = int(line.split()[1])
            except (ValueError, IndexError):
                dprint("Bad response %s" % line)
                if line == b"":
                    dprint("Client closed connection")
                    return Response(444)
            if (b"connection established" in line.lower() or
                    resp.code == 204 or resp.code == 304):
                resp.body = False
            dprint("Response code: %d " % resp.code + str(resp.body))

            # Get response again if 100-Continue
            if not (expect and resp.code == 100):
                break

        # Headers
        dprint("Reading response headers")
        while not State.exit:
            line = self.proxy_fp.readline(State.max_line).decode("utf-8")
            if line == b"":
                if self.proxy_socket:
                    self.proxy_socket.shutdown(socket.SHUT_WR)
                    self.proxy_socket.close()
                    self.proxy_socket = None
                dprint("Proxy closed connection: %s" % resp.code)
                return Response(444)
            if line == "\r\n":
                break
            nv = line.split(":", 1)
            if len(nv) != 2:
                dprint("Bad header =>%s<=" % line)
                continue
            name = nv[0].strip()
            value = nv[1].strip()
            resp.headers.append((name, value))
            if name.lower() != "proxy-authenticate":
                dprint("Received %s: %s" % (name, value))
            else:
                dprint("Received %s: sanitized (%d)" % (name, len(value)))

            if name.lower() == "content-length":
                resp.length = int(value)
                if not resp.length:
                    resp.body = False
            elif (name.lower() == "transfer-encoding" and
                    value.lower() == "chunked"):
                resp.chunked = True
                resp.body = True
            elif (name.lower() in ["proxy-connection", "connection"] and
                    value.lower() == "close"):
                resp.close = True

        return resp

    def do_proxy_type(self):
        # Connect to proxy
        if not hasattr(self, "proxy_address"):
            if not self.do_socket_connect():
                return Response(408), None

        State.proxy_type_lock.acquire()
        try:
            # Read State.proxy_type only once and use value for function return
            # if it is not None; State.proxy_type should only be read here to
            # avoid getting None after successfully identifying the proxy type
            # if another thread clears it with load_proxy
            proxy_type = State.proxy_type.get(self.proxy_address, State.auth)
            if proxy_type is None:
                # New proxy, don't know type yet
                dprint("Searching proxy type")
                resp = self.do_socket()

                proxy_auth = ""
                for header in resp.headers:
                    if header[0].lower() == "proxy-authenticate":
                        proxy_auth += header[1] + " "

                for auth in proxy_auth.split():
                    if auth.upper() in ["NTLM", "KERBEROS", "NEGOTIATE", "BASIC"]:
                        proxy_type = auth
                        break

                if proxy_type is not None:
                    # Writing State.proxy_type only once but use local variable
                    # as return value to avoid losing the query result (for the
                    # current request) by clearing State.proxy_type in load_proxy
                    State.proxy_type[self.proxy_address] = proxy_type

                dprint("Auth mechanisms: " + proxy_auth)
                dprint("Selected: " + str(self.proxy_address) + ": " +
                    str(proxy_type))

                return resp, proxy_type

            return Response(407), proxy_type
        finally:
            State.proxy_type_lock.release()

    def do_transaction(self):
        dprint("Entering")

        ipport = self.get_destination()
        if ipport not in [False, True]:
            dprint("Skipping auth proxying")
            resp = self.do_socket(destination=ipport)
        elif ipport:
            # Get proxy type directly from do_proxy_type instead by accessing
            # State.proxy_type do avoid a race condition with clearing
            # State.proxy_type in load_proxy which sometimes led to a proxy type
            # of None (clearing State.proxy_type in one thread was done after
            # another thread's do_proxy_type but before accessing
            # State.proxy_type in the second thread)
            resp, proxy_type = self.do_proxy_type()
            if resp.code == 407:
                # Unknown auth mechanism
                if proxy_type is None:
                    dprint("Unknown auth mechanism expected")
                    return resp

                # Generate auth message
                ntlm = AuthMessageGenerator(proxy_type, self.proxy_address[0])
                ntlm_resp = ntlm.get_response()
                if ntlm_resp is None:
                    dprint("Bad auth response")
                    return Response(503)

                self.fwd_data(resp, flush=True)

                hconnection = ""
                for i in ["connection", "Connection"]:
                    if i in self.headers:
                        hconnection = self.headers[i]
                        del self.headers[i]
                        dprint("Remove header %s: %s" % (i, hconnection))

                # Send auth message
                resp = self.do_socket({
                    "Proxy-Authorization": "%s %s" % (proxy_type, ntlm_resp),
                    "Proxy-Connection": "Keep-Alive"
                })
                if resp.code == 407:
                    dprint("Auth required")
                    ntlm_challenge = ""
                    for header in resp.headers:
                        if (header[0].lower() == "proxy-authenticate" and
                                proxy_type.upper() in header[1].upper()):
                            h = header[1].split()
                            if len(h) == 2:
                                ntlm_challenge = h[1]
                                break

                    if ntlm_challenge:
                        dprint("Challenged")
                        ntlm_resp = ntlm.get_response(ntlm_challenge)
                        if ntlm_resp is None:
                            dprint("Bad auth response")
                            return Response(503)

                        self.fwd_data(resp, flush=True)

                        if hconnection != "":
                            self.headers["Connection"] = hconnection
                            dprint("Restore header Connection: " + hconnection)

                        # Reply to challenge
                        resp = self.do_socket({
                            "Proxy-Authorization": "%s %s" % (
                                proxy_type, ntlm_resp)
                        })
                    else:
                        dprint("Didn't get challenge, auth didn't work")
                else:
                    dprint("No auth required cached")
            else:
                dprint("No auth required")
        else:
            dprint("No proxy server specified and not in noproxy list")
            return Response(501)

        return resp

    def do_HEAD(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PAC(self):
        resp = Response(404)
        if State.proxy_mode in [MODE_PAC, MODE_CONFIG_PAC]:
            pac = State.pac
            if "file://" in State.pac:
                pac = file_url_to_local_path(State.pac)
            dprint(pac)
            try:
                resp.code = 200
                with open(pac) as p:
                    resp.data = p.read().encode("utf-8")
                    resp.body = True
                resp.headers = [
                    ("Content-Length", len(resp.data)),
                    ("Content-Type", "application/x-ns-proxy-autoconfig")
                ]
            except:
                traceback.print_exc(file=sys.stdout)

        return resp

    def do_GET(self):
        dprint("Entering")

        dprint("Path = " + self.path)
        if "/PxPACFile.pac" in self.path:
            resp = self.do_PAC()
        else:
            resp = self.do_transaction()

        if resp.code >= 400:
            dprint("Error %d" % resp.code)

        self.fwd_resp(resp)

        dprint("Done")

    def do_POST(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PUT(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_DELETE(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_PATCH(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_CONNECT(self):
        dprint("Entering")

        for i in ["connection", "Connection"]:
            if i in self.headers:
                del self.headers[i]
                dprint("Remove header " + i)

        cl = 0
        cs = 0
        resp = self.do_transaction()
        if resp.code >= 400:
            dprint("Error %d" % resp.code)
            self.fwd_resp(resp)
        else:
            # Proxy connection may be already closed due to header
            # (Proxy-)Connection: close received from proxy -> forward this to
            # the client
            if self.proxy_socket is None:
                dprint("Proxy connection closed")
                self.send_response(200, "True")
                self.send_header("Proxy-Connection", "close")
                self.end_headers()
            else:
                dprint("Tunneling through proxy")
                self.send_response(200, "Connection established")
                self.send_header("Proxy-Agent", self.version_string())
                self.end_headers()

                # sockets will be removed from these lists, when they are
                # detected as closed by remote host; wlist contains sockets
                # only when data has to be written
                rlist = [self.connection, self.proxy_socket]
                wlist = []

                # data to be written to client connection and proxy socket
                cdata = []
                sdata = []
                idle = State.config.getint("settings", "idle")
                max_idle = time.time() + idle
                while not State.exit and (rlist or wlist):
                    (ins, outs, exs) = select.select(rlist, wlist, rlist, idle)
                    if exs:
                        break
                    if ins:
                        for i in ins:
                            if i is self.proxy_socket:
                                out = self.connection
                                wdata = cdata
                                source = "proxy"
                            else:
                                out = self.proxy_socket
                                wdata = sdata
                                source = "client"

                            data = i.recv(4096)
                            if data:
                                cl += len(data)
                                # Prepare data to send it later in outs section
                                wdata.append(data)
                                if out not in outs:
                                    outs.append(out)
                                max_idle = time.time() + idle
                            else:
                                # No data means connection closed by remote host
                                dprint("Connection closed by %s" % source)
                                # Because tunnel is closed on one end there is
                                # no need to read from both ends
                                del rlist[:]
                                # Do not write anymore to the closed end
                                if i in wlist:
                                    wlist.remove(i)
                                if i in outs:
                                    outs.remove(i)
                    if outs:
                        for o in outs:
                            if o is self.proxy_socket:
                                wdata = sdata
                            else:
                                wdata = cdata
                            data = wdata[0]
                            # socket.send() may sending only a part of the data
                            # (as documentation says). To ensure sending all data
                            bsnt = o.send(data)
                            if bsnt > 0:
                                if bsnt < len(data):
                                    # Not all data was sent; store data not
                                    # sent and ensure select() get's it when
                                    # the socket can be written again
                                    wdata[0] = data[bsnt:]
                                    if o not in wlist:
                                        wlist.append(o)
                                else:
                                    wdata.pop(0)
                                    if not data and o in wlist:
                                        wlist.remove(o)
                                cs += bsnt
                            else:
                                dprint("No data sent")
                        max_idle = time.time() + idle
                    if max_idle < time.time():
                        # No data in timeout seconds
                        dprint("Proxy connection timeout")
                        break

        # After serving the proxy tunnel it could not be used for samething else.
        # A proxy doesn't really know, when a proxy tunnnel isn't needed any
        # more (there is no content length for data). So servings will be ended
        # either after timeout seconds without data transfer or when at least
        # one side closes the connection. Close both proxy and client
        # connection if still open.
        if self.proxy_socket is not None:
            dprint("Cleanup proxy connection")
            self.proxy_socket.shutdown(socket.SHUT_WR)
            self.proxy_socket.close()
            self.proxy_socket = None
        self.close_connection = True

        dprint("%d bytes read, %d bytes written" % (cl, cs))

        dprint("Done")

    def fwd_data(self, resp, flush=False):
        cl = resp.length
        dprint("Reading response data")
        if resp.body:
            if cl:
                dprint("Content length %d" % cl)
                while cl > 0:
                    if cl > 4096:
                        l = 4096
                        cl -= l
                    else:
                        l = cl
                        cl = 0
                    d = self.proxy_fp.read(l)
                    if not flush:
                        self.wfile.write(d)
            elif resp.chunked:
                dprint("Chunked encoding")
                while not State.exit:
                    line = self.proxy_fp.readline(State.max_line)
                    if not flush:
                        self.wfile.write(line)
                    line = line.decode("utf-8").strip()
                    if not len(line):
                        dprint("Blank chunk size")
                        break
                    else:
                        try:
                            csize = int(line, 16) + 2
                            dprint("Chunk of size %d" % csize)
                        except ValueError:
                            dprint("Bad chunk size '%s'" % line)
                            continue
                    d = self.proxy_fp.read(csize)
                    if not flush:
                        self.wfile.write(d)
                    if csize == 2:
                        dprint("No more chunks")
                        break
                    if len(d) < csize:
                        dprint("Chunk size doesn't match data")
                        break
            elif resp.data is not None:
                dprint("Sending data string")
                if not flush:
                    self.wfile.write(resp.data)
            else:
                dprint("Not sure how much")
                while not State.exit:
                    time.sleep(0.1)
                    d = self.proxy_fp.read(1024)
                    if not flush:
                        self.wfile.write(d)
                    if len(d) < 1024:
                        break

        if resp.close and self.proxy_socket:
            dprint("Close proxy connection per header")
            self.proxy_socket.close()
            self.proxy_socket = None

    def fwd_resp(self, resp):
        dprint("Entering")
        self.send_response(resp.code)

        for header in resp.headers:
            dprint("Returning %s: %s" % (header[0], header[1]))
            self.send_header(header[0], header[1])

        self.end_headers()

        self.fwd_data(resp)

        dprint("Done")

    def get_destination(self):
        netloc = self.path
        path = "/"
        if self.command != "CONNECT":
            parse = urlparse.urlparse(self.path, allow_fragments=False)
            if parse.netloc:
                netloc = parse.netloc
            if ":" not in netloc:
                port = parse.port
                if not port:
                    if parse.scheme == "http":
                        port = 80
                    elif parse.scheme == "https":
                        port = 443
                    elif parse.scheme == "ftp":
                        port = 21
                netloc = netloc + ":" + str(port)

            path = parse.path or "/"
            if parse.params:
                path = path + ";" + parse.params
            if parse.query:
                path = path + "?" + parse.query
        dprint(netloc)

        # Check destination for noproxy first, before doing any expensive stuff
        # possibly involving connections
        if State.noproxy.size:
            addr = []
            spl = netloc.split(":", 1)
            try:
                addr = socket.getaddrinfo(spl[0], int(spl[1]))
            except socket.gaierror:
                # Couldn't resolve, let parent proxy try, #18
                dprint("Couldn't resolve host")
            if len(addr) and len(addr[0]) == 5:
                ipport = addr[0][4]
                dprint("%s => %s + %s" % (self.path, ipport, path))

                if ipport[0] in State.noproxy:
                    dprint("Direct connection from noproxy configuration")
                    self.path = path
                    return ipport

        # Get proxy mode and servers straight from load_proxy to avoid
        # threading issues
        (proxy_mode, self.proxy_servers) = load_proxy()
        if proxy_mode in [MODE_AUTO, MODE_PAC, MODE_CONFIG_PAC]:
            proxy_str = find_proxy_for_url(
                ("https://" if "://" not in self.path else "") + self.path)
            if proxy_str == "DIRECT":
                ipport = netloc.split(":")
                ipport[1] = int(ipport[1])
                dprint("Direct connection from PAC")
                self.path = path
                return tuple(ipport)

            if proxy_str:
                dprint("Proxy from PAC = " + str(proxy_str))
                # parse_proxy does not modify State.proxy_server any more,
                # it returns the proxy server tuples instead, because proxy_str
                # contains only the proxy servers for URL served by this thread
                self.proxy_servers = parse_proxy(proxy_str)

        return True if self.proxy_servers else False

###
# Multi-processing and multi-threading

def get_host_ips():
    localips = [ip[4][0] for ip in socket.getaddrinfo(
        socket.gethostname(), 80, socket.AF_INET)]
    localips.insert(0, "127.0.0.1")

    return localips

class PoolMixIn(socketserver.ThreadingMixIn):
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

    if getattr(sys, "frozen", False) != False or "pythonw.exe" in sys.executable:
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
    mainsock = socket.fromshare(pipeout.recv())
    httpd.socket = mainsock

    print_banner()

    serve_forever(httpd)

def run_pool():
    try:
        httpd = ThreadedTCPServer((State.config.get("proxy", "listen").strip(),
                                   State.config.getint("proxy", "port")), Proxy)
    except OSError as exc:
        if "attempt was made" in str(exc):
            print("Px failed to start - port in use")
        else:
            pprint(exc)
        return

    mainsock = httpd.socket

    print_banner()

    if hasattr(socket, "fromshare"):
        workers = State.config.getint("settings", "workers")
        for i in range(workers-1):
            (pipeout, pipein) = multiprocessing.Pipe()
            p = multiprocessing.Process(target=start_worker, args=(pipeout,))
            p.daemon = True
            p.start()
            while p.pid is None:
                time.sleep(1)
            pipein.send(mainsock.share(p.pid))

    serve_forever(httpd)

###
# Proxy detection

class WINHTTP_CURRENT_USER_IE_PROXY_CONFIG(ctypes.Structure):
    _fields_ = [("fAutoDetect", ctypes.wintypes.BOOL),
                # "Automatically detect settings"
                ("lpszAutoConfigUrl", ctypes.wintypes.LPWSTR),
                # "Use automatic configuration script, Address"
                ("lpszProxy", ctypes.wintypes.LPWSTR),
                # "1.2.3.4:5" if "Use the same proxy server for all protocols",
                # else advanced
                # "ftp=1.2.3.4:5;http=1.2.3.4:5;https=1.2.3.4:5;socks=1.2.3.4:5"
                ("lpszProxyBypass", ctypes.wintypes.LPWSTR),
                # ";"-separated list
                # "Bypass proxy server for local addresses" adds "<local>"
               ]

class WINHTTP_AUTOPROXY_OPTIONS(ctypes.Structure):
    _fields_ = [("dwFlags", ctypes.wintypes.DWORD),
                ("dwAutoDetectFlags", ctypes.wintypes.DWORD),
                ("lpszAutoConfigUrl", ctypes.wintypes.LPCWSTR),
                ("lpvReserved", ctypes.c_void_p),
                ("dwReserved", ctypes.wintypes.DWORD),
                ("fAutoLogonIfChallenged", ctypes.wintypes.BOOL), ]

class WINHTTP_PROXY_INFO(ctypes.Structure):
    _fields_ = [("dwAccessType", ctypes.wintypes.DWORD),
                ("lpszProxy", ctypes.wintypes.LPCWSTR),
                ("lpszProxyBypass", ctypes.wintypes.LPCWSTR), ]

# Parameters for WinHttpOpen, http://msdn.microsoft.com/en-us/library/aa384098(VS.85).aspx
WINHTTP_NO_PROXY_NAME = 0
WINHTTP_NO_PROXY_BYPASS = 0
WINHTTP_FLAG_ASYNC = 0x10000000

# dwFlags values
WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001
WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002

# dwAutoDetectFlags values
WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001
WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002

# dwAccessType values
WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0
WINHTTP_ACCESS_TYPE_NO_PROXY = 1
WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3
WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4

# Error messages
WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT = 12167

def winhttp_find_proxy_for_url(
        url, autodetect=False, pac_url=None, autologon=True):
    # Fix issue #51
    ACCESS_TYPE = WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY
    if WIN_VERSION < 6.3:
        ACCESS_TYPE = WINHTTP_ACCESS_TYPE_DEFAULT_PROXY

    ctypes.windll.winhttp.WinHttpOpen.restype = ctypes.c_void_p
    hInternet = ctypes.windll.winhttp.WinHttpOpen(
        ctypes.wintypes.LPCWSTR("Px"),
        ACCESS_TYPE, WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, WINHTTP_FLAG_ASYNC)
    if not hInternet:
        dprint("WinHttpOpen failed: " + str(ctypes.GetLastError()))
        return ""

    autoproxy_options = WINHTTP_AUTOPROXY_OPTIONS()
    if pac_url:
        autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
        autoproxy_options.dwAutoDetectFlags = 0
        autoproxy_options.lpszAutoConfigUrl = pac_url
    elif autodetect:
        autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
        autoproxy_options.dwAutoDetectFlags = (
            WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A)
        autoproxy_options.lpszAutoConfigUrl = 0
    else:
        return ""
    autoproxy_options.fAutoLogonIfChallenged = autologon

    proxy_info = WINHTTP_PROXY_INFO()

    # Fix issue #43
    ctypes.windll.winhttp.WinHttpGetProxyForUrl.argtypes = [ctypes.c_void_p,
        ctypes.wintypes.LPCWSTR, ctypes.POINTER(WINHTTP_AUTOPROXY_OPTIONS),
        ctypes.POINTER(WINHTTP_PROXY_INFO)]
    ok = ctypes.windll.winhttp.WinHttpGetProxyForUrl(
        hInternet, ctypes.wintypes.LPCWSTR(url),
        ctypes.byref(autoproxy_options), ctypes.byref(proxy_info))
    if not ok:
        error = ctypes.GetLastError()
        dprint("WinHttpGetProxyForUrl error %s" % error)
        if error == WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT:
            dprint("Could not download PAC file, trying DIRECT instead")
            return "DIRECT"
        return ""

    if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY:
        # Note: proxy_info.lpszProxyBypass makes no sense here!
        if not proxy_info.lpszProxy:
            dprint('WinHttpGetProxyForUrl named proxy without name')
            return ""
        return proxy_info.lpszProxy.replace(" ", ",").replace(";", ",").replace(
            ",DIRECT", "") # Note: We only see the first!
    if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY:
        return "DIRECT"

    # WinHttpCloseHandle()
    dprint("WinHttpGetProxyForUrl accesstype %s" % (proxy_info.dwAccessType,))
    return ""

def file_url_to_local_path(file_url):
    parts = urlparse.urlparse(file_url)
    path = urlparse.unquote(parts.path)
    if path.startswith('/') and not path.startswith('//'):
        if len(parts.netloc) == 2 and parts.netloc[1] == ':':
            return parts.netloc + path
        return 'C:' + path
    if len(path) > 2 and path[1] == ':':
        return path

def load_proxy(quiet=False):
    # Return if proxies specified in Px config
    if State.proxy_mode in [MODE_CONFIG, MODE_CONFIG_PAC]:
        return (State.proxy_mode, State.proxy_server)

    # Do locking to avoid updating globally shared State object by multiple
    # threads simultaneously
    State.proxy_mode_lock.acquire()
    try:
        proxy_mode = State.proxy_mode
        proxy_servers = State.proxy_server
        # Check if need to refresh
        if (State.proxy_refresh is not None and
                time.time() - State.proxy_refresh <
                State.config.getint("settings", "proxyreload")):
            if not quiet:
                dprint("Skip proxy refresh")
            return (proxy_mode, proxy_servers)

        # Start with clean proxy mode and server list
        proxy_mode = MODE_NONE
        proxy_servers = []

        # Get proxy info from Internet Options
        ie_proxy_config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
        ok = ctypes.windll.winhttp.WinHttpGetIEProxyConfigForCurrentUser(
            ctypes.byref(ie_proxy_config))
        if not ok:
            if not quiet:
                dprint(ctypes.GetLastError())
        else:
            if ie_proxy_config.fAutoDetect:
                proxy_mode = MODE_AUTO
            elif ie_proxy_config.lpszAutoConfigUrl:
                State.pac = ie_proxy_config.lpszAutoConfigUrl
                proxy_mode = MODE_PAC
                if not quiet:
                    dprint("AutoConfigURL = " + State.pac)
            else:
                # Manual proxy
                proxies = []
                proxies_str = ie_proxy_config.lpszProxy or ""
                for proxy_str in proxies_str.lower().replace(
                        ' ', ';').split(';'):
                    if '=' in proxy_str:
                        scheme, proxy = proxy_str.split('=', 1)
                        if scheme.strip() != "ftp":
                            proxies.append(proxy)
                    elif proxy_str:
                        proxies.append(proxy_str)
                if proxies:
                    proxy_servers = parse_proxy(",".join(proxies))
                    proxy_mode = MODE_MANUAL

                # Proxy exceptions into noproxy
                bypass_str = ie_proxy_config.lpszProxyBypass or "" # FIXME: Handle "<local>"
                bypasses = [h.strip() for h in bypass_str.lower().replace(
                    ' ', ';').split(';')]
                for bypass in bypasses:
                    try:
                        ipns = netaddr.IPGlob(bypass)
                        State.noproxy.add(ipns)
                        if not quiet:
                            dprint("Noproxy += " + bypass)
                    except:
                        State.noproxy_hosts.append(bypass)
                        if not quiet:
                            dprint("Noproxy hostname += " + bypass)

        State.proxy_refresh = time.time()
        if not quiet:
            dprint("Proxy mode = " + str(proxy_mode))
        State.proxy_mode = proxy_mode
        State.proxy_server = proxy_servers

        # Clear proxy types on proxy server update
        State.proxy_type = {}

    finally:
        State.proxy_mode_lock.release()

    return (proxy_mode, proxy_servers)

def find_proxy_for_url(url):
    proxy_str = ""
    if State.proxy_mode == MODE_AUTO:
        proxy_str = winhttp_find_proxy_for_url(url, autodetect=True)

    elif State.proxy_mode in [MODE_PAC, MODE_CONFIG_PAC]:
        pac = State.pac
        if "file://" in State.pac or not State.pac.startswith("http"):
            host = State.config.get("proxy", "listen") or "localhost"
            port = State.config.getint("proxy", "port")
            pac = "http://%s:%d/PxPACFile.pac" % (host, port)
            dprint("PAC URL is local: " + pac)
        proxy_str = winhttp_find_proxy_for_url(url, pac_url=pac)

    # Handle edge case if the result is a list that starts with DIRECT. Assume
    # everything should be direct as the string DIRECT is tested explicitly in
    # get_destination
    if proxy_str.startswith("DIRECT,"):
        proxy_str = "DIRECT"

    # If the proxy_str it still empty at this point, then there is no proxy
    # configured. Try to do a direct connection.
    if proxy_str == "":
        proxy_str = "DIRECT"

    dprint("Proxy found: " + proxy_str)
    return proxy_str

###
# Parse settings and command line

def parse_proxy(proxystrs):
    if not proxystrs:
        return []

    servers = []
    for proxystr in [i.strip() for i in proxystrs.split(",")]:
        pserver = [i.strip() for i in proxystr.split(":")]
        if len(pserver) == 1:
            pserver.append(80)
        elif len(pserver) == 2:
            try:
                pserver[1] = int(pserver[1])
            except ValueError:
                pprint("Bad proxy server port: " + pserver[1])
                sys.exit()
        else:
            pprint("Bad proxy server definition: " + proxystr)
            sys.exit()

        if tuple(pserver) not in servers:
            servers.append(tuple(pserver))

    return servers

def parse_ip_ranges(iprangesconfig):
    ipranges = netaddr.IPSet([])

    iprangessplit = [i.strip() for i in iprangesconfig.split(",")]
    for iprange in iprangessplit:
        if not iprange:
            continue

        try:
            if "-" in iprange:
                spl = iprange.split("-", 1)
                ipns = netaddr.IPRange(spl[0], spl[1])
            elif "*" in iprange:
                ipns = netaddr.IPGlob(iprange)
            else:
                ipns = netaddr.IPNetwork(iprange)
            ipranges.add(ipns)
        except:
            pprint("Bad IP definition: %s" % iprangesconfig)
            sys.exit()
    return ipranges

def parse_allow(allow):
    State.allow = parse_ip_ranges(allow)

def parse_noproxy(noproxy):
    State.noproxy = parse_ip_ranges(noproxy)

def set_useragent(useragent):
    State.useragent = useragent

def set_username(username):
    ud = username.split("\\")
    if len(ud) == 2:
        State.username = ud[1]
        State.domain = ud[0]
    else:
        State.username = username

def set_pac(pac):
    if pac == "":
        return

    pacproxy = False
    if pac.startswith("http"):
        pacproxy = True

    elif pac.startswith("file"):
        pac = file_url_to_local_path(pac)

    if os.path.exists(pac):
        pacproxy = True

    if pacproxy:
        State.pac = pac
    else:
        pprint("Unsupported PAC location or file not found: %s" % pac)
        sys.exit()

def set_auth(auth):
    if auth.upper() not in ["NTLM", "KERBEROS", "BASIC", ""]:
        pprint("Bad proxy auth type: %s" % auth)
        sys.exit()
    if auth != "":
        State.auth = auth

def cfg_int_init(section, name, default, override=False):
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

def cfg_float_init(section, name, default, override=False):
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

def cfg_str_init(section, name, default, proc=None, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    State.config.set(section, name, val)

    if proc != None:
        proc(val)

def save():
    with open(State.ini, "w") as cfgfile:
        State.config.write(cfgfile)
    pprint("Saved config to " + State.ini + "\n")
    with open(State.ini, "r") as cfgfile:
        sys.stdout.write(cfgfile.read())

    sys.exit()

def parse_config():
    if "--debug" in sys.argv:
        State.logger = Log(dfile(), "w")

    if getattr(sys, "frozen", False) != False or "pythonw.exe" in sys.executable:
        attach_console()

    if "-h" in sys.argv or "--help" in sys.argv:
        pprint(HELP)
        sys.exit()

    # Load configuration file
    State.config = configparser.ConfigParser()
    State.ini = os.path.join(os.path.dirname(get_script_path()), State.ini)
    for i in range(len(sys.argv)):
        if "=" in sys.argv[i]:
            val = sys.argv[i].split("=")[1]
            if "--config=" in sys.argv[i]:
                State.ini = val
                if not os.path.exists(val) and "--save" not in sys.argv:
                    pprint("Could not find config file: " + val)
                    sys.exit()
    if os.path.exists(State.ini):
        State.config.read(State.ini)

    # [proxy] section
    if "proxy" not in State.config.sections():
        State.config.add_section("proxy")

    cfg_str_init("proxy", "server", "")
    cfg_str_init("proxy", "pac", "", set_pac)
    cfg_int_init("proxy", "port", "3128")
    cfg_str_init("proxy", "listen", "127.0.0.1")
    cfg_str_init("proxy", "allow", "*.*.*.*", parse_allow)
    cfg_int_init("proxy", "gateway", "0")
    cfg_int_init("proxy", "hostonly", "0")
    cfg_str_init("proxy", "noproxy", "", parse_noproxy)
    cfg_str_init("proxy", "useragent", "", set_useragent)
    cfg_str_init("proxy", "username", "", set_username)
    cfg_str_init("proxy", "auth", "", set_auth)

    # [settings] section
    if "settings" not in State.config.sections():
        State.config.add_section("settings")

    cfg_int_init("settings", "workers", "2")
    cfg_int_init("settings", "threads", "5")
    cfg_int_init("settings", "idle", "30")
    cfg_float_init("settings", "socktimeout", "20.0")
    cfg_int_init("settings", "proxyreload", "60")
    cfg_int_init("settings", "foreground", "0")

    cfg_int_init("settings", "log", "0" if State.logger is None else "1")
    if State.config.get("settings", "log") == "1" and State.logger is None:
        State.logger = Log(dfile(), "w")

    # Command line flags
    for i in range(len(sys.argv)):
        if "=" in sys.argv[i]:
            val = sys.argv[i].split("=")[1]
            if "--proxy=" in sys.argv[i] or "--server=" in sys.argv[i]:
                cfg_str_init("proxy", "server", val, None, True)
            elif "--pac=" in sys.argv[i]:
                cfg_str_init("proxy", "pac", val, set_pac, True)
            elif "--listen=" in sys.argv[i]:
                cfg_str_init("proxy", "listen", val, None, True)
            elif "--port=" in sys.argv[i]:
                cfg_int_init("proxy", "port", val, True)
            elif "--allow=" in sys.argv[i]:
                cfg_str_init("proxy", "allow", val, parse_allow, True)
            elif "--noproxy=" in sys.argv[i]:
                cfg_str_init("proxy", "noproxy", val, parse_noproxy, True)
            elif "--useragent=" in sys.argv[i]:
                cfg_str_init("proxy", "useragent", val, set_useragent, True)
            elif "--username=" in sys.argv[i]:
                cfg_str_init("proxy", "username", val, set_username, True)
            elif "--auth=" in sys.argv[i]:
                cfg_str_init("proxy", "auth", val, set_auth, True)
            else:
                for j in ["workers", "threads", "idle", "proxyreload"]:
                    if "--" + j + "=" in sys.argv[i]:
                        cfg_int_init("settings", j, val, True)

                for j in ["socktimeout"]:
                    if "--" + j + "=" in sys.argv[i]:
                        cfg_float_init("settings", j, val, True)

    if "--gateway" in sys.argv:
        cfg_int_init("proxy", "gateway", "1", True)

    if "--hostonly" in sys.argv:
        cfg_int_init("proxy", "hostonly", "1", True)

    if "--foreground" in sys.argv:
        cfg_int_init("settings", "foreground", "1", True)

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

    State.proxy_server = parse_proxy(State.config.get("proxy", "server"))

    if "--install" in sys.argv:
        install()
    elif "--uninstall" in sys.argv:
        uninstall()
    elif "--quit" in sys.argv:
        quit()
    elif "--save" in sys.argv:
        save()

    if State.proxy_server:
        State.proxy_mode = MODE_CONFIG
    elif State.pac:
        State.proxy_mode = MODE_CONFIG_PAC
    else:
        load_proxy(quiet=True)

    if State.proxy_mode == MODE_NONE and not State.config.get(
            "proxy", "noproxy"):
        pprint("No proxy server or noproxy list defined")
        sys.exit()

    socket.setdefaulttimeout(State.config.getfloat("settings", "socktimeout"))

###
# Exit related

def quit(force=False):
    count = 0
    mypids = [os.getpid(), os.getppid()]
    for pid in sorted(psutil.pids(), reverse=True):
        if pid in mypids:
            continue

        try:
            p = psutil.Process(pid)
            if p.exe().lower() == sys.executable.lower():
                count += 1
                if force:
                    p.kill()
                else:
                    p.send_signal(signal.CTRL_C_EVENT)
        except (psutil.AccessDenied, psutil.NoSuchProcess, PermissionError, SystemError):
            pass
        except:
            traceback.print_exc(file=sys.stdout)

    if count != 0:
        if force:
            sys.stdout.write(".")
        else:
            sys.stdout.write("Quitting Px ..")
            time.sleep(4)
        sys.stdout.flush()
        quit(True)
    else:
        if force:
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

    if State.logger != None:
        pprint(tracelog)
    else:
        sys.stderr.write(tracelog)

        # Save to debug.log
        dbg = open(dfile(), 'w')
        dbg.write(tracelog)
        dbg.close()

###
# Install Px to startup

def get_script_path():
    if getattr(sys, "frozen", False) is False:
        # Script mode
        return os.path.normpath(os.path.join(os.getcwd(), sys.argv[0]))

    # Frozen mode
    return sys.executable

def get_script_cmd():
    spath = get_script_path()
    if os.path.splitext(spath)[1].lower() == ".py":
        return sys.executable + ' "%s"' % spath

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
