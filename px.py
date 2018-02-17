from __future__ import print_function

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

# Dependencies
try:
    import concurrent.futures
except ImportError:
    print("Requires modules futures")
    sys.exit()

try:
    import netaddr
except ImportError:
    print("Requires modules netaddr")
    sys.exit()

try:
    import psutil
except ImportError:
    print("Requires modules psutil")
    sys.exit()

# Default to winkerberos for SSPI
# Try pywin32 SSPI if winkerberos missing
# - pywin32 known to fail in Python 3.6+ : https://github.com/genotrance/px/issues/9
try:
    import winkerberos
except ImportError:
    if sys.version_info[0] > 2:
        if sys.version_info[1] > 5:
            print("Requires Python module winkerberos")
            sys.exit()

    # Less than 3.6, can use pywin32
    try:
        import pywintypes
        import sspi
    except ImportError:
        print("Requires Python module pywin32 or winkerberos")
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

class State(object):
    allow = netaddr.IPGlob("*.*.*.*")
    config = None
    exit = False
    logger = None
    noproxy = netaddr.IPSet([])
    proxy_server = None
    stdout = None

    ini = "px.ini"
    max_disconnect = 3
    max_line = 65536 + 1
    max_workers = 2

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
        self.file.flush()
        self.stdout.write(data)
    def flush(self):
        self.file.flush()

def dprint(*objs):
    if State.logger != None:
        print(multiprocessing.current_process().name + ": " + threading.current_thread().name + ": " + str(int(time.time())) + ": " + sys._getframe(1).f_code.co_name + ": ", end="")
        print(*objs)

def dfile():
    return "debug-%s.log" % multiprocessing.current_process().name

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
# NTLM support

class NtlmMessageGenerator:
    def __init__(self):
        if "winkerberos" in sys.modules:
            status, self.ctx = winkerberos.authGSSClientInit("NTLM", gssflags=0, mech_oid=winkerberos.GSS_MECH_OID_SPNEGO)
            self.get_response = self.get_response_wkb
        else:
            self.sspi_client = sspi.ClientAuth("NTLM", os.environ.get("USERNAME"), scflags=0)
            self.get_response = self.get_response_sspi

    def get_response_sspi(self, challenge=None):
        dprint("pywin32 SSPI")
        if challenge:
            try:
                challenge = base64.decodebytes(challenge.encode("utf-8"))
            except AttributeError:
                challenge = base64.decodestring(challenge)
        output_buffer = None
        try:
            error_msg, output_buffer = self.sspi_client.authorize(challenge)
        except pywintypes.error:
            traceback.print_exc(file=sys.stdout)
            return None

        response_msg = output_buffer[0].Buffer
        try:
            response_msg = base64.encodebytes(response_msg.encode("utf-8"))
        except AttributeError:
            response_msg = base64.encodestring(response_msg)
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

###
# Proxy handler

class Proxy(httpserver.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_one_request(self):
        try:
            httpserver.SimpleHTTPRequestHandler.handle_one_request(self)
        except socket.error:
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

    def do_socket(self, xheaders=[], destination=None):
        dprint("Entering")
        if not destination:
            destination = State.proxy_server

        if not hasattr(self, "client_socket") or self.client_socket is None:
            dprint("New connection")
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.client_socket.connect(destination)
            except:
                traceback.print_exc(file=sys.stdout)
                return 503, None, None

        # No chit chat on SSL
        if destination != State.proxy_server and self.command == "CONNECT":
            return  200, None, None

        cl = None
        chk = False
        expect = False
        keepalive = False
        cmdstr = ("%s %s %s\r\n" % (self.command, self.path, self.request_version)).encode("utf-8")
        self.client_socket.send(cmdstr)
        dprint(cmdstr)
        for header in self.headers:
            h = ("%s: %s\r\n" % (header, self.headers[header])).encode("utf-8")
            self.client_socket.send(h)
            dprint("Sending %s" % h)

            if header.lower() == "content-length":
                cl = int(self.headers[header])
            elif header.lower() == "expect" and self.headers[header].lower() == "100-continue":
                expect = True
            elif header.lower() == "proxy-connection":
                keepalive = True
            elif header.lower() == "transfer-encoding" and self.headers[header].lower() == "chunked":
                dprint("CHUNKED data")
                chk = True

        if not keepalive and self.request_version.lower() == "http/1.0":
            xheaders["Proxy-Connection"] = "keep-alive"

        for header in xheaders:
            h = ("%s: %s\r\n" % (header, xheaders[header])).encode("utf-8")
            self.client_socket.send(h)
            dprint("Sending extra %s" % h)
        self.client_socket.send(b"\r\n")

        if self.command in ["POST", "PUT", "PATCH"]:
            if not hasattr(self, "body"):
                dprint("Getting body for POST/PUT/PATCH")
                if cl != None:
                    self.body = self.rfile.read(cl)
                else:
                    self.body = self.rfile.read()

            dprint("Sending body for POST/PUT/PATCH: %d = %d" % (cl or -1, len(self.body)))
            self.client_socket.send(self.body)

        self.client_fp = self.client_socket.makefile("rb")

        resp = 503
        nobody = False
        headers = []
        body = b""

        if self.command == "HEAD":
            nobody = True

        # Response code
        for i in range(2):
            dprint("Reading response code")
            line = self.client_fp.readline(State.max_line)
            if line == b"\r\n":
                line = self.client_fp.readline(State.max_line)
            try:
                resp = int(line.split()[1])
            except ValueError:
                if line == b"":
                    dprint("Client closed connection")
                    return 444, nobody
                dprint("Bad response %s" % line)
            if b"connection established" in line.lower() or resp == 204 or resp == 304:
                nobody = True
            dprint("Response code: %d " % resp + str(nobody))

            # Get response again if 100-Continue
            if not (expect and resp == 100):
                break

        # Headers
        cl = None
        chk = False
        dprint("Reading response headers")
        while not State.exit:
            line = self.client_fp.readline(State.max_line).decode("utf-8")
            if line == b"":
                dprint("Client closed connection: %s" % resp)
                return 444, None, None
            if line == "\r\n":
                break
            nv = line.split(":", 1)
            if len(nv) != 2:
                dprint("Bad header =>%s<=" % line)
                continue
            name = nv[0].strip()
            value = nv[1].strip()
            headers.append((name, value))
            dprint("Received header %s = %s" % (name, value))

            if name.lower() == "content-length":
                cl = int(value)
                if not cl:
                    nobody = True
            elif name.lower() == "transfer-encoding" and value.lower() == "chunked":
                chk = True

        # Data
        dprint("Reading response data")
        if not nobody:
            if cl:
                dprint("Content length %d" % cl)
                body = self.client_fp.read(cl)
            elif chk:
                dprint("Chunked encoding")
                while not State.exit:
                    line = self.client_fp.readline(State.max_line).decode("utf-8").strip()
                    try:
                        csize = int(line.strip(), 16)
                        dprint("Chunk size %d" % csize)
                    except ValueError:
                        dprint("Bad chunk size '%s'" % line)
                        continue
                    if csize == 0:
                        dprint("No more chunks")
                        break
                    d = self.client_fp.read(csize)
                    if len(d) < csize:
                        dprint("Chunk doesn't match data")
                        break
                    body += d
                headers.append(("Content-Length", str(len(body))))
            else:
                dprint("Not sure how much")
                while not State.exit:
                    time.sleep(0.1)
                    d = self.client_fp.read(1024)
                    if len(d) < 1024:
                        break
                    body += d

        return resp, headers, body

    def do_transaction(self):
        dprint("Entering")

        ipport = self.get_destination()
        if ipport != None:
            dprint("Skipping NTLM proxying")
            resp, headers, body = self.do_socket(destination=ipport)
        else:
            # Check for NTLM auth
            ntlm = NtlmMessageGenerator()
            ntlm_resp = ntlm.get_response()
            if ntlm_resp is None:
                dprint("Bad NTLM response")
                return 503, None, None
            resp, headers, body = self.do_socket({
                "Proxy-Authorization": "NTLM %s" % ntlm_resp
            })
            if resp == 407:
                dprint("Auth required")
                ntlm_challenge = ""
                for header in headers:
                    if header[0] == "Proxy-Authenticate" and "NTLM" in header[1]:
                        ntlm_challenge = header[1].split()[1]
                        break

                if ntlm_challenge:
                    dprint("Challenged")
                    ntlm_resp = ntlm.get_response(ntlm_challenge)
                    if ntlm_resp is None:
                        dprint("Bad NTLM response")
                        return 503, None, None
                    resp, headers, body = self.do_socket({
                        "Proxy-Authorization": "NTLM %s" % ntlm_resp
                    })

                    return resp, headers, body
                else:
                    dprint("Didn't get challenge, not NTLM proxy")
            elif resp > 400:
                return resp, None, None
            else:
                dprint("No auth required")

        return resp, headers, body

    def do_HEAD(self):
        dprint("Entering")

        self.do_GET()

        dprint("Done")

    def do_GET(self):
        dprint("Entering")

        resp, headers, body = self.do_transaction()
        if resp >= 400:
            dprint("Error %d" % resp)
            self.send_error(resp)
        else:
            self.fwd_resp(resp, headers, body)

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

        cl = 0
        resp, headers, body = self.do_transaction()
        if resp >= 400:
            dprint("Error %d" % resp)
            self.send_error(resp)
        else:
            dprint("Tunneling through proxy")
            self.send_response(200, "Connection established")
            self.send_header("Proxy-Agent", self.version_string())
            self.end_headers()

            rlist = [self.connection, self.client_socket]
            wlist = []
            count = 0
            max_idle = State.config.getint("settings", "idle")
            while not State.exit:
                count += 1
                (ins, _, exs) = select.select(rlist, wlist, rlist, 1)
                if exs:
                    break
                if ins:
                    for i in ins:
                        if i is self.client_socket:
                            out = self.connection
                        else:
                            out = self.client_socket

                        data = i.recv(4096)
                        if data:
                            out.send(data)
                            count = 0
                            cl += len(data)
                if count == max_idle:
                    break

        dprint("Transferred %d bytes" % cl)

        dprint("Done")

    def fwd_resp(self, resp, headers, body):
        dprint("Entering")
        self.send_response(resp)

        for header in headers:
            if header[0].lower() != "transfer-encoding":
                dprint("Returning %s: %s" % (header[0], header[1]))
                self.send_header(header[0], header[1])

        self.end_headers()

        try:
            self.wfile.write(body)
        except:
            pass

        dprint("Done")

    def get_destination(self):
        if State.noproxy.size:
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
                    netloc = netloc + ":" + str(port)

                path = parse.path or "/"
                if parse.params:
                    path = path + ";" + parse.params
                if parse.query:
                    path = path + "?" + parse.query

            dprint(netloc)
            spl = netloc.split(":", 1)
            addr = socket.getaddrinfo(spl[0], int(spl[1]))
            if len(addr) and len(addr[0]) == 5:
                ipport = addr[0][4]
                dprint("%s => %s + %s" % (self.path, ipport, path))

                if ipport[0] in State.noproxy:
                    self.path = path
                    return ipport

        return None

###
# Multi-processing and multi-threading

class PoolMixIn(socketserver.ThreadingMixIn):
    def process_request(self, request, client_address):
        self.pool.submit(self.process_request_thread, request, client_address)

    def verify_request(self, request, client_address):
        dprint("Client address: %s" % client_address[0])
        if client_address[0] in State.allow:
            return True

        dprint("Client not allowed: %s" % client_address[0])
        return False

class ThreadedTCPServer(PoolMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)

        try:
            # Workaround bad thread naming code in Python 3.6+, fixed in master
            self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=State.config.getint("settings", "threads"), thread_name_prefix="Thread")
        except:
            self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=State.config.getint("settings", "threads"))

def serve_forever(httpd):
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        dprint("Exiting")
        State.exit = True

    httpd.shutdown()

def start_worker(pipeout):
    parsecli()
    httpd = ThreadedTCPServer(
        (State.config.get("proxy", "listen").strip(), State.config.getint("proxy", "port")),
        Proxy, bind_and_activate=False
    )
    mainsock = socket.fromshare(pipeout.recv())
    httpd.socket = mainsock

    serve_forever(httpd)

def runpool():
    try:
        httpd = ThreadedTCPServer(
            (State.config.get("proxy", "listen").strip(), State.config.getint("proxy", "port")), Proxy
        )
    except OSError as exc:
        print(exc)
        return

    mainsock = httpd.socket

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
# Parse settings and command line

def parseproxy(proxystr):
    State.proxy_server = proxystr.split(":")
    if len(State.proxy_server) == 1:
        State.proxy_server.append(80)
    else:
        State.proxy_server[1] = int(State.proxy_server[1])
    State.proxy_server = tuple(State.proxy_server)

def parseipranges(iprangesconfig):
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
            print("Bad IP definition: %s" % iprangesconfig)
            sys.exit()
    return ipranges

def parseallow(allow):
    State.allow = parseipranges(allow)

def parsenoproxy(noproxy):
    State.noproxy = parseipranges(noproxy)

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
        print("Invalid integer value for " + section + ":" + name)

    State.config.set(section, name, str(val))

def cfg_str_init(section, name, default, proc=None, override=False):
    val = default
    if not override:
        try:
            val = State.config.get(section, name).strip()
        except configparser.NoOptionError:
            pass

    State.config.set(section, name, val)

    if proc != None and val != "":
        proc(val)

def parsecli():
    if "--debug" in sys.argv:
        State.logger = Log(dfile(), "w")

    if getattr(sys, "frozen", False) != False:
        attachConsole()

    State.config = configparser.ConfigParser()
    ini = os.path.join(os.path.dirname(get_script_path()), State.ini)
    if os.path.exists(ini):
        State.config.read(ini)

    # [proxy] section
    if "proxy" not in State.config.sections():
        State.config.add_section("proxy")

    cfg_str_init("proxy", "server", "", parseproxy)

    cfg_int_init("proxy", "port", "3128")

    cfg_str_init("proxy", "listen", "127.0.0.1")

    cfg_str_init("proxy", "allow", "*.*.*.*", parseallow)

    cfg_int_init("proxy", "gateway", "0")
    if State.config.getint("proxy", "gateway") == 1:
        State.config.set("proxy", "listen", "")

    cfg_str_init("proxy", "noproxy", "", parsenoproxy)

    # [settings] section
    if "settings" not in State.config.sections():
        State.config.add_section("settings")

    cfg_int_init("settings", "workers", "2")
    cfg_int_init("settings", "threads", "40")
    cfg_int_init("settings", "idle", "30")

    cfg_int_init("settings", "log", "0" if State.logger is None else "1")
    if State.config.get("settings", "log") == "1" and State.logger is None:
        State.logger = Log(dfile(), "w")

    # Command line flags
    for i in range(len(sys.argv)):
        if "=" in sys.argv[i]:
            val = sys.argv[i].split("=")[1]
            if "--proxy=" in sys.argv[i] or "--server=" in sys.argv[i]:
                cfg_str_init("proxy", "server", val, parseproxy, True)
            elif "--listen=" in sys.argv[i]:
                cfg_str_init("proxy", "listen", val, None, True)
            elif "--port=" in sys.argv[i]:
                cfg_int_init("proxy", "port", val, True)
            elif "--allow=" in sys.argv[i]:
                cfg_str_init("proxy", "allow", val, parseallow, True)
            elif "--noproxy=" in sys.argv[i]:
                cfg_str_init("proxy", "noproxy", val, parsenoproxy, True)
            else:
                for j in ["workers", "threads", "idle"]:
                    if "--" + j + "=" in sys.argv[i]:
                        cfg_int_init("settings", j, val, True)

    if "--gateway" in sys.argv:
        State.config.set("proxy", "listen", "")
        State.config.set("proxy", "gateway", "1")

    if "--install" in sys.argv:
        install()
    elif "--uninstall" in sys.argv:
        uninstall()
    elif "--quit" in sys.argv:
        quit()

    if State.proxy_server is None:
        print("No proxy defined")
        sys.exit()

    print("Serving at %s:%d proc %s" % (
        State.config.get("proxy", "listen").strip(),
        State.config.getint("proxy", "port"),
        multiprocessing.current_process().name)
    )

    for section in State.config.sections():
        for option in State.config.options(section):
            dprint(section + ":" + option + " = " + State.config.get(section, option))

    if getattr(sys, "frozen", False) != False:
        detachConsole()

###
# Exit related

def quit():
    count = 0
    mypids = [os.getpid(), os.getppid()]
    for pid in sorted(psutil.pids(), reverse=True):
        if pid in mypids:
            continue

        try:
            p = psutil.Process(pid)
            if p.exe().lower() == sys.executable.lower():
                p.send_signal(signal.CTRL_C_EVENT)
                count += 1
        except:
            pass

    if count != 0:
        print("Quiting Px")
    else:
        print("Px is not running")

    sys.exit()

def handle_exceptions(type, value, tb):
    # Create traceback log
    lst = traceback.format_tb(tb, None) + traceback.format_exception_only(type, value)
    tracelog = '\nTraceback (most recent call last):\n' + "%-20s%s\n" % ("".join(lst[:-1]), lst[-1])

    if State.logger != None:
        print(tracelog)
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
    else:
        # Frozen mode
        return sys.executable

def get_script_cmd():
    spath = get_script_path()
    if spath != sys.executable:
        return sys.executable + ' "%s"' % spath

    return spath

def check_installed():
    ret = True
    runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
    try:
        value = winreg.QueryValueEx(runkey, "Px")
    except:
        ret = False
    winreg.CloseKey(runkey)

    return ret

def install():
    if check_installed() is False:
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
        winreg.SetValueEx(runkey, "Px", 0, winreg.REG_EXPAND_SZ, get_script_cmd())
        winreg.CloseKey(runkey)
        print("Px installed successfully")
    else:
        print("Px already installed")

    sys.exit()

def uninstall():
    if check_installed() is True:
        runkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_WRITE)
        winreg.DeleteValue(runkey, "Px")
        winreg.CloseKey(runkey)
        print("Px uninstalled successfully")
    else:
        print("Px is not installed")

    sys.exit()

###
# Attach/detach console

def attachConsole():
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

        if p.cmdline()[0] == "cmd":
            # Found it
            break

        # Search parent
        pid = p.ppid()

    # Not found, started without console
    if pid == -1:
        return

    dprint("Attaching to console " + str(pid))
    if ctypes.windll.kernel32.AttachConsole(pid) == 0:
        dprint("Attach failed with error " + str(ctypes.windll.kernel32.GetLastError()))
        return

    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
        dprint("Not a console window")
        return

    reopen_stdout()

def detachConsole():
    if ctypes.windll.kernel32.GetConsoleWindow() == 0:
        return

    restore_stdout()

    if not ctypes.windll.kernel32.FreeConsole():
        dprint("Free console failed with error " + str(ctypes.windll.kernel32.GetLastError()))
    else:
        dprint("Freed console successfully")

###
# Startup

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.excepthook = handle_exceptions

    parsecli()

    runpool()
