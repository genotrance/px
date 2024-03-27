"Manage outbound HTTP connections using Curl & CurlMulti"

import ctypes
import hashlib
import io
import os.path
import select
import socket
import sys
import threading
import time

try:
    from . import libcurl
except OSError as exc:
    print("Requires libcurl")
    if sys.platform == "win32":
        print("  Download from https://curl.se/windows and extract DLLs to px/libcurl")
    else:
        print("  Install libcurl with package manager")
    sys.exit(1)

# Debug shortcut
dprint = lambda x: None
MCURL = None

# Merging ideas from:
#   https://github.com/pycurl/pycurl/blob/master/examples/multi-socket_action-select.py
#   https://github.com/fsbs/aiocurl

def sanitized(msg):
    "Hide user sensitive data from debug output"
    lower = msg.lower()
    # Hide auth responses and username
    if "authorization: " in lower or "authenticate: " in lower:
        fspace = lower.find(" ")
        if fspace != -1:
            sspace = lower.find(" ", fspace + 1)
            if sspace != -1:
                return msg[0:sspace] + " sanitized len(%d)" % len(msg[sspace:])
    elif lower.startswith("proxy auth using"):
        fspace = lower.find(" ", len("proxy auth using "))
        if fspace != -1:
            return msg[0:fspace] + " sanitized len(%d)" % len(msg[fspace:])

    return msg

def gethash(easy):
    "Return hash value for easy to allow usage as a dict key"
    return hashlib.sha1(easy).hexdigest()

def getauth(auth):
    """
    Return auth value for specified authentication string

    Supported values can be found here: https://curl.se/libcurl/c/CURLOPT_HTTPAUTH.html

    Skip the CURLAUTH_ portion in input - e.g. getauth("ANY")

    To control which methods are available during proxy detection:
      Prefix NO to avoid method - e.g. NONTLM => ANY - NTLM
      Prefix SAFENO to avoid method - e.g. SAFENONTLM => ANYSAFE - NTLM
      Prefix ONLY to support only that method - e.g ONLYNTLM => ONLY + NTLM
    """
    authval = libcurl.CURLAUTH_NONE
    if auth == "NONE":
        return authval

    if auth.startswith("NO"):
        auth = auth[len("NO"):]
        authval = libcurl.CURLAUTH_ANY & ~(getattr(libcurl, "CURLAUTH_" + auth))
    elif auth.startswith("SAFENO"):
        auth = auth[len("SAFENO"):]
        authval = libcurl.CURLAUTH_ANYSAFE & ~(getattr(libcurl, "CURLAUTH_" + auth))
    elif auth.startswith("ONLY"):
        auth = auth[len("ONLY"):]
        authval = libcurl.CURLAUTH_ONLY | getattr(libcurl, "CURLAUTH_" + auth)
    else:
        authval = getattr(libcurl, "CURLAUTH_" + auth)

    return authval

def save_auth(curl, msg):
    "Find and cache proxy auth mechanism from headers sent by libcurl"
    if curl.proxy in MCURL.proxytype:
        # Already cached
        return True

    if curl.auth is None:
        # No need to cache auth - client will authenticate directly
        return True

    if msg.startswith("Proxy-Authorization:"):
        # Cache auth mechanism from proxy headers
        proxytype = msg.split(" ")[1].upper()
        MCURL.proxytype[curl.proxy] = proxytype
        dprint(f"{curl.easyhash}: Caching proxy auth mechanism for {curl.proxy} as {proxytype}")

        # Cached
        return True

    # Not yet cached
    return False

def save_upstream(curl, msg):
    "Find which server libcurl connected to - upstream proxy or target server"
    if curl.upstream is not None:
        # Already cached
        return True

    if msg.startswith("Connected to"):
        curl.upstream = msg.split(" ")[2]
    elif msg.startswith("Re-using existing connection"):
        curl.upstream = msg.split(" ")[-1]

    if curl.upstream is not None:
        if curl.upstream == "(nil)":
            # Older libcurl workaround
            ret, curl.upstream = curl.get_primary_ip()
        if curl.upstream == "127.0.0.1" and curl.proxy == "localhost":
            # Older libcurl workaround
            curl.upstream = curl.proxy
        dprint(curl.easyhash + ": Upstream server = " + curl.upstream)
        if curl.proxy is not None and curl.upstream == curl.proxy:
            dprint(curl.easyhash + ": Upstream server is proxy")
            curl.is_proxied = True
        return True

    # Not yet cached
    return False

# Active thread running callbacks can print debug output for any other
# thread's easy - cannot assume it is for this thread. All dprint()s
# include easyhash to correlate instead

def yield_msgs(data, size):
    "Generator for curl debug messages"
    msgs = bytes(data[:size]).decode("utf-8").strip()
    if "\r\n" in msgs:
        for msg in msgs.split("\r\n"):
            if len(msg) != 0:
                yield msg
    elif len(msgs) != 0:
        yield msgs

@libcurl.debug_callback
def _debug_callback(easy, infotype, data, size, userp):
    "Prints out curl debug info and headers sent/received"

    del userp
    easyhash = gethash(easy)
    curl = MCURL.handles[easyhash]
    if infotype == libcurl.CURLINFO_TEXT:
        prefix = easyhash + ": Curl info: "
    elif infotype == libcurl.CURLINFO_HEADER_IN:
        prefix = easyhash + ": Received header <= "
    elif infotype == libcurl.CURLINFO_HEADER_OUT:
        prefix = easyhash + ": Sent header => "
    else:
        return libcurl.CURLE_OK

    for msg in yield_msgs(data, size):
        dprint(prefix + sanitized(msg))
        if infotype == libcurl.CURLINFO_HEADER_OUT:
            save_auth(curl, msg)
        elif infotype == libcurl.CURLINFO_TEXT:
            save_upstream(curl, msg)

    return libcurl.CURLE_OK

@libcurl.debug_callback
def _wa_callback(easy, infotype, data, size, userp):
    """
    curl debug callback to get info not provided by libcurl today
    - proxy auth mechanism from sent headers
    - upstream server connected to from curl info
    """

    del userp
    easyhash = gethash(easy)
    curl = MCURL.handles[easyhash]
    if infotype == libcurl.CURLINFO_HEADER_OUT:
        # If sent header
        for msg in yield_msgs(data, size):
            if save_auth(curl, msg):
                # Ignore rest of headers since auth (already) cached
                break
    elif infotype == libcurl.CURLINFO_TEXT:
        # If curl info
        for msg in yield_msgs(data, size):
            if save_upstream(curl, msg):
                # Ignore rest of headers since upstream server found
                break

    return libcurl.CURLE_OK

@libcurl.read_callback
def _read_callback(buffer, size, nitems, userdata):
    tsize = size * nitems
    curl = MCURL.handles[libcurl.from_oid(userdata)]
    if curl.size is not None:
        if curl.size > tsize:
            curl.size -= tsize
        else:
            tsize = curl.size
            curl.size = None
        if curl.client_rfile is not None:
            try:
                data = curl.client_rfile.read(tsize)
                ctypes.memmove(buffer, data, tsize)
            except ConnectionError as exc:
                dprint(curl.easyhash + ": Error reading from client: " + str(exc))
                tsize = 0
        else:
            dprint(curl.easyhash + ": Read expected but no client")
            tsize = 0
    else:
        tsize = 0

    dprint(curl.easyhash + ": Read %d bytes" % tsize)
    return tsize

@libcurl.write_callback
def _write_callback(buffer, size, nitems, userdata):
    tsize = size * nitems
    curl = MCURL.handles[libcurl.from_oid(userdata)]
    if tsize > 0:
        if curl.sentheaders:
            if curl.client_wfile is not None:
                try:
                    tsize = curl.client_wfile.write(bytes(buffer[:tsize]))
                except ConnectionError as exc:
                    dprint(curl.easyhash + ": Error writing to client: " + str(exc))
                    return 0
            else:
                dprint(curl.easyhash + ": Ignored %d bytes" % tsize)
                return tsize
        else:
            dprint(curl.easyhash + ": Skipped %d bytes" % tsize)
            return tsize

    #dprint(curl.easyhash + ": Wrote %d bytes" % tsize)
    return tsize

@libcurl.write_callback
def _header_callback(buffer, size, nitems, userdata):
    tsize = size * nitems
    curl = MCURL.handles[libcurl.from_oid(userdata)]
    if tsize > 0:
        data = bytes(buffer[:tsize])
        if curl.suppress:
            if data == b"\r\n":
                # Stop suppressing headers since done
                dprint(curl.easyhash + ": Resuming headers")
                curl.suppress = False
            return tsize
        else:
            if data == b"\r\n":
                # Done sending headers
                dprint(curl.easyhash + ": Done sending headers")
                curl.sentheaders = True
            elif curl.auth is not None and data[0] == 72 and b"407" in data:
                # Header starts with H and has 407 - HTTP/x.x 407 (issue #148)
                # Px is configured to authenticate so don't send auth related
                # headers from upstream proxy to client
                dprint(curl.easyhash + ": Suppressing headers")
                curl.suppress = True
                return tsize
        if curl.client_hfile is not None:
            try:
                return curl.client_hfile.write(data)
            except ConnectionError as exc:
                dprint(curl.easyhash + ": Error writing header to client: " + str(exc))
                return 0
        else:
            dprint(curl.easyhash + ": Ignored %d bytes" % tsize)
            return tsize

    return 0

class Curl:
    "Helper class to manage a curl easy instance"

    # Data
    easy = None
    easyhash = None
    sock_fd = None

    # For plain HTTP
    client_rfile = None
    client_wfile = None
    client_hfile = None

    # Request info
    auth = None
    headers = None
    method = None
    proxy = None
    request_version = None
    size = None
    url = None
    user = None
    xheaders = None

    # Status
    cerr = libcurl.CURLE_OK
    done = False
    errstr = ""
    resp = 503
    sentheaders = False
    suppress = False
    upstream = None

    # Flags
    is_connect = False
    is_easy = False
    is_patch = False
    is_post = False
    is_proxied = False
    is_tunnel = False
    is_upload = False

    def __init__(self, url, method = "GET", request_version = "HTTP/1.1", connect_timeout = 60):
        """
        Initialize curl instance

        method = GET, POST, PUT, CONNECT, etc.
        request_version = HTTP/1.0, HTTP/1.1, etc.
        """
        self.easy = libcurl.easy_init()
        self.easyhash = gethash(self.easy)
        dprint(self.easyhash + ": New curl instance")

        self._setup(url, method, request_version, connect_timeout)

    def __del__(self):
        "Destructor - clean up resources"
        if self.headers is not None:
            # Free curl headers if any
            libcurl.slist_free_all(self.headers)
        libcurl.easy_cleanup(self.easy)

    def _setup(self, url, method, request_version, connect_timeout):
        "Setup curl instance based on request info"
        dprint(self.easyhash + ": %s %s using %s" % (method, url, request_version))

        # Ignore proxy environment variables
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_PROXY, b"")
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_NOPROXY, b"")

        # Timeouts
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_CONNECTTIMEOUT, int(connect_timeout))
        #libcurl.easy_setopt(self.easy, libcurl.CURLOPT_TIMEOUT, 60)

        # SSL CAINFO
        if sys.platform == "win32":
            cainfo = os.path.join(os.path.dirname(__file__), "libcurl", "curl-ca-bundle.crt")
            if os.path.exists(cainfo):
                libcurl.easy_setopt(self.easy, libcurl.CURLOPT_CAINFO, cainfo.encode("utf-8"))

        # Set HTTP method
        self.method = method
        if method == "CONNECT":
            self.is_connect = True
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_CONNECT_ONLY, True)

            # No proxy yet so setup tunnel for direct CONNECT
            self.set_tunnel()

            if curl_version() < 0x072D00:
                # libcurl < v7.45 does not support CURLINFO_ACTIVESOCKET so it is not possible
                # to reuse existing connections
                libcurl.easy_setopt(self.easy, libcurl.CURLOPT_FRESH_CONNECT, True)
                dprint(self.easyhash + ": Fresh connection requested")

                # Need to know socket assigned for CONNECT since used later in select()
                # CURLINFO_ACTIVESOCKET not available on libcurl < v7.45  so need this
                # hack for older versions
                libcurl.easy_setopt(self.easy, libcurl.CURLOPT_SOCKOPTFUNCTION, _sockopt_callback)
                libcurl.easy_setopt(self.easy, libcurl.CURLOPT_SOCKOPTDATA, id(self.easyhash))

            # We want libcurl to make a simple HTTP connection to auth
            # with the upstream proxy and let client establish SSL
            if "://" not in url:
                url = "http://" + url
        elif method == "GET":
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_HTTPGET, True)
        elif method == "HEAD":
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_NOBODY, True)
        elif method == "POST":
            self.is_post = True
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_POST, True)
        elif method == "PUT":
            self.is_upload = True
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_UPLOAD, True)
        elif method in ["PATCH", "DELETE"]:
            if method == "PATCH":
                self.is_patch = True
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_CUSTOMREQUEST, method.encode("utf-8"))
        else:
            dprint(self.easyhash + ": Unknown method: " + method)
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_CUSTOMREQUEST, method.encode("utf-8"))

        self.url = url
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_URL, url.encode("utf-8"))

        # Set HTTP version to use
        self.request_version = request_version
        version = request_version.split("/")[1].replace(".", "_")
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_HTTP_VERSION,
            getattr(libcurl, "CURL_HTTP_VERSION_" + version))

        # Debug callback default disabled
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_DEBUGFUNCTION, _wa_callback)

        # Need libcurl verbose to save proxy auth mechanism and upstream server
        self.set_verbose()

    def reset(self, url, method = "GET", request_version = "HTTP/1.1", connect_timeout = 60):
        "Reuse existing curl instance for another request"
        dprint(self.easyhash + ": Resetting curl")
        libcurl.easy_reset(self.easy)
        self.sock_fd = None

        self.client_rfile = None
        self.client_wfile = None
        self.client_hfile = None

        self.auth = None
        self.proxy = None
        self.size = None
        self.user = None
        self.xheaders = None

        self.cerr = libcurl.CURLE_OK
        self.done = False
        self.errstr = ""
        self.resp = 503
        self.sentheaders = False
        self.suppress = False
        self.upstream = None

        self.is_connect = False
        self.is_patch = False
        self.is_post = False
        self.is_proxied = False
        self.is_tunnel = False
        self.is_upload = False

        if self.headers is not None:
            # Free curl headers if any
            libcurl.slist_free_all(self.headers)
            self.headers = None

        self._setup(url, method, request_version, connect_timeout)

    def set_tunnel(self, tunnel=True):
        "Set to tunnel through proxy if no proxy or proxy + auth"
        dprint(self.easyhash + ": HTTP proxy tunneling = " + str(tunnel))
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_HTTPPROXYTUNNEL, tunnel)
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_SUPPRESS_CONNECT_HEADERS, tunnel)
        self.is_tunnel = tunnel

    def set_proxy(self, proxy, port = 0, noproxy = None):
        """
        Set proxy options - returns False if this proxy server has auth failures
        """
        if proxy in MCURL.failed:
            dprint(self.easyhash + ": Authentication issues with this proxy server")
            return False

        self.proxy = proxy
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_PROXY, proxy.encode("utf-8"))
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_PROXYPORT, port)
        if noproxy is not None:
            dprint(self.easyhash + ": Set noproxy to " + noproxy)
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_NOPROXY, noproxy.encode("utf-8"))

        if self.is_connect:
            # Proxy but no auth (yet) so just connect and let client tunnel and authenticate
            self.set_tunnel(tunnel=False)

        return True

    def set_auth(self, user, password = None, auth = "ANY"):
        "Set proxy authentication info - call after set_proxy() to enable auth caching"
        if user == ":":
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_PROXYUSERPWD, user.encode("utf-8"))
        else:
            self.user = user
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_PROXYUSERNAME, user.encode("utf-8"))
            if password is not None:
                libcurl.easy_setopt(self.easy, libcurl.CURLOPT_PROXYPASSWORD, password.encode("utf-8"))
            else:
                dprint(self.easyhash + ": Blank password for user")
        if auth is not None:
            if self.proxy in MCURL.proxytype:
                # Use cached value
                self.auth = MCURL.proxytype[self.proxy]
                dprint(f"{self.easyhash}: Using cached proxy auth mechanism {self.auth}")
            else:
                # Use specified value
                self.auth = auth
                dprint(f"{self.easyhash}: Setting proxy auth mechanism to {self.auth}")

            authval = getauth(self.auth)
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_PROXYAUTH, authval)

            if self.is_connect:
                # Proxy + auth so tunnel and authenticate
                self.set_tunnel()

    def set_headers(self, xheaders):
        "Set headers to send"
        self.headers = ctypes.POINTER(libcurl.slist)()
        skip_proxy_headers = True if self.proxy is not None and self.auth is not None else False
        for header in xheaders:
            lcheader = header.lower()
            if skip_proxy_headers and lcheader.startswith("proxy-"):
                # Don't forward proxy headers from client if no upstream proxy
                # or no auth specified (client will authenticate directly)
                dprint(self.easyhash + ": Skipping header =!> %s: %s" % (header, xheaders[header]))
                continue
            elif lcheader == "content-length":
                size = int(xheaders[header])
                if self.is_upload or self.is_post:
                    # Save content-length for PUT/POST later
                    # Turn off Transfer-Encoding since size is known
                    self.size = size
                    self.headers = libcurl.slist_append(self.headers, b"Transfer-Encoding:")
                    self.headers = libcurl.slist_append(self.headers, b"Expect:")
                    if self.is_post:
                        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_POSTFIELDSIZE, size)
                    else:
                        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_INFILESIZE, size)
                elif self.is_patch:
                    # Get data from client - libcurl doesn't seem to use READFUNCTION
                    try:
                        data = self.client_rfile.read(size)
                    except AttributeError as exc:
                        dprint("set_headers() called before buffer()/bridge()?")
                        raise exc
                    libcurl.easy_setopt(self.easy, libcurl.CURLOPT_COPYPOSTFIELDS, data)
            elif lcheader == "user-agent":
                # Forward user agent via setopt
                self.set_useragent(xheaders[header])
                continue
            dprint(self.easyhash + ": Adding header => " + sanitized("%s: %s" % (header, xheaders[header])))
            self.headers = libcurl.slist_append(self.headers,
                ("%s: %s" % (header, xheaders[header])).encode("utf-8"))

        if len(xheaders) != 0:
            if self.is_connect and not self.is_tunnel:
                # Send client headers later in select() - just connect to proxy
                # and let client tunnel and authenticate directly
                dprint(self.easyhash + ": Delaying headers")
                self.xheaders = xheaders
            else:
                dprint(self.easyhash + ": Setting headers")
                libcurl.easy_setopt(self.easy, libcurl.CURLOPT_HTTPHEADER, self.headers)

    def set_insecure(self, enable = True):
        "Set curl to ignore SSL errors"
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_SSL_VERIFYPEER, not enable)
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_SSL_VERIFYHOST, not enable)

    def set_verbose(self, enable = True):
        "Set verbose mode"
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_VERBOSE, enable)

    def set_debug(self, enable = True):
        """
        Enable debug output
          Call after set_proxy() and set_auth() to enable discovery and caching of proxy
          auth mechanism - libcurl does not provide an API to get this today - need to
          find it in sent header debug output
        """
        if enable:
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_DEBUGFUNCTION, _debug_callback)

    def bridge(self, client_rfile = None, client_wfile = None, client_hfile = None):
        """
        Bridge curl reads/writes to sockets specified

        Reads POST/PATCH data from client_rfile
        Writes data back to client_wfile
        Writes headers back to client_hfile
        """
        dprint(self.easyhash + ": Setting up bridge")

        # Setup read/write callbacks
        if client_rfile is not None:
            self.client_rfile = client_rfile
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_READFUNCTION, _read_callback)
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_READDATA, id(self.easyhash))

        if client_wfile is not None:
            self.client_wfile = client_wfile
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_WRITEFUNCTION, _write_callback)
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_WRITEDATA, id(self.easyhash))

        if client_hfile is not None:
            self.client_hfile = client_hfile
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_HEADERFUNCTION, _header_callback)
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_HEADERDATA, id(self.easyhash))
        else:
            self.sentheaders = True

    def buffer(self, data = None):
        "Setup buffers to bridge curl perform"
        dprint(self.easyhash + ": Setting up buffers for bridge")
        rfile = None
        if data is not None:
            rfile = io.BytesIO()
            rfile.write(data)
            rfile.seek(0)

        wfile = io.BytesIO()
        hfile = io.BytesIO()

        self.bridge(rfile, wfile, hfile)

    def set_transfer_decoding(self, enable = False):
        "Set curl to turn off transfer decoding - let client do it"
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_HTTP_TRANSFER_DECODING, enable)

    def set_useragent(self, useragent):
        "Set user agent to send"
        if len(useragent) != 0:
            dprint(self.easyhash + ": Setting user agent to " + useragent)
            libcurl.easy_setopt(self.easy, libcurl.CURLOPT_USERAGENT, useragent.encode("utf-8"))

    def set_follow(self, enable = True):
        "Set curl to follow 3xx responses"
        libcurl.easy_setopt(self.easy, libcurl.CURLOPT_FOLLOWLOCATION, enable)

    def perform(self):
        "Perform the easy handle"

        # Perform as a standalone easy handle, not using multi
        # However, add easyhash to MCURL.handles since it is used in curl callbacks
        MCURL.handles[self.easyhash] = self
        self.cerr = libcurl.easy_perform(self.easy)
        if self.cerr != libcurl.CURLE_OK:
            dprint(self.easyhash + ": Connection failed: " + str(self.cerr) + "; " + self.errstr)
        MCURL.handles.pop(self.easyhash)
        return self.cerr

    # Get status and info after running curl handle

    def get_response(self):
        "Return response code of completed request"
        codep = ctypes.c_int()
        if self.method == "CONNECT":
            ret = libcurl.easy_getinfo(self.easy, libcurl.CURLINFO_HTTP_CONNECTCODE, ctypes.byref(codep))
        else:
            ret = libcurl.easy_getinfo(self.easy, libcurl.CURLINFO_RESPONSE_CODE, ctypes.byref(codep))
        return ret, codep.value

    def get_activesocket(self):
        "Return active socket for this easy instance"
        if sys.platform == "win32":
            sock_fd = ctypes.c_uint()
        else:
            sock_fd = ctypes.c_int()
        ret = libcurl.easy_getinfo(self.easy, libcurl.CURLINFO_ACTIVESOCKET, ctypes.byref(sock_fd))
        return ret, sock_fd.value

    def get_primary_ip(self):
        "Return primary IP address of this easy instance"
        ip = ctypes.c_char_p()
        ret = libcurl.easy_getinfo(self.easy, libcurl.CURLINFO_PRIMARY_IP, ctypes.byref(ip))
        return ret, ip.value.decode("utf-8")

    def get_data(self, encoding = "utf-8"):
        """
        Return data written by curl perform to buffer()

        encoding = "utf-8" by default, change or set to None if bytes preferred
        """
        val = b""
        if isinstance(self.client_wfile, io.BytesIO):
            val = self.client_wfile.getvalue()
        if encoding is not None:
            val = val.decode(encoding)
        return val

    def get_headers(self, encoding = "utf-8"):
        """
        Return headers written by curl perform to buffer()

        encoding = "utf-8" by default, change or set to None if bytes preferred
        """
        val = b""
        if isinstance(self.client_hfile, io.BytesIO):
            val = self.client_hfile.getvalue()
        if encoding is not None:
            val = val.decode(encoding)
        return val

@libcurl.socket_callback
def _socket_callback(easy, sock_fd, ev_bitmask, userp, socketp):
    # libcurl socket callback: add/remove actions for socket events
    del easy, userp, socketp
    if ev_bitmask & libcurl.CURL_POLL_IN or ev_bitmask & libcurl.CURL_POLL_INOUT:
        #dprint("Read sock_fd %d" % sock_fd)
        if sock_fd not in MCURL.rlist:
            MCURL.rlist.append(sock_fd)

    if ev_bitmask & libcurl.CURL_POLL_OUT or ev_bitmask & libcurl.CURL_POLL_INOUT:
        #dprint("Write sock_fd %d" % sock_fd)
        if sock_fd not in MCURL.wlist:
            MCURL.wlist.append(sock_fd)

    if ev_bitmask & libcurl.CURL_POLL_REMOVE:
        #dprint("Remove sock_fd %d" % sock_fd)
        if sock_fd in MCURL.rlist:
            MCURL.rlist.remove(sock_fd)
        if sock_fd in MCURL.wlist:
            MCURL.wlist.remove(sock_fd)

    return libcurl.CURLE_OK

@libcurl.multi_timer_callback
def _timer_callback(multi, timeout_ms, userp):
    # libcurl timer callback: schedule/cancel a timeout action
    #dprint("timeout = %d" % timeout_ms)
    del multi, userp
    if timeout_ms == -1:
        MCURL.timer = None
    else:
        MCURL.timer = timeout_ms / 1000.0

    return libcurl.CURLE_OK

@libcurl.sockopt_callback
def _sockopt_callback(clientp, sock_fd, purpose):
    # Associate new socket with easy handle
    del purpose
    curl = MCURL.handles[libcurl.from_oid(clientp)]
    curl.sock_fd = sock_fd

    return libcurl.CURLE_OK

def print_curl_version():
    "Display curl version information"
    dprint(libcurl.version().decode("utf-8"))
    vinfo = libcurl.version_info(libcurl.CURLVERSION_NOW).contents
    for feature in [
        "CURL_VERSION_SSL", "CURL_VERSION_SSPI", "CURL_VERSION_SPNEGO",
        "CURL_VERSION_GSSAPI", "CURL_VERSION_GSSNEGOTIATE",
        "CURL_VERSION_KERBEROS5", "CURL_VERSION_NTLM", "CURL_VERSION_NTLM_WB"
    ]:
        bit = getattr(libcurl, feature)
        avail = True if (bit & vinfo.features) > 0 else False
        dprint("%s: %s" % (feature, avail))
    dprint("Host: " + vinfo.host.decode("utf-8"))

def curl_version():
    return libcurl.version_info(libcurl.CURLVERSION_NOW).contents.version_num

class MCurl:
    "Helper class to manage a curl multi instance"

    _multi = None
    _lock = None

    handles = None
    proxytype = None
    failed = None # Proxy servers with auth failures
    timer = None
    rlist = None
    wlist = None

    def __init__(self, debug_print = None):
        "Initialize multi interface"
        global dprint
        if debug_print is not None:
            dprint = debug_print
        else:
            sanitized = lambda msg: msg

        # Save as global to enable access via callbacks
        global MCURL
        MCURL = self

        print_curl_version()
        self._multi = libcurl.multi_init()

        # Set a callback for registering or unregistering socket events.
        libcurl.multi_setopt(self._multi, libcurl.CURLMOPT_SOCKETFUNCTION, _socket_callback)

        # Set a callback for scheduling or cancelling timeout actions.
        libcurl.multi_setopt(self._multi, libcurl.CURLMOPT_TIMERFUNCTION, _timer_callback)

        # Init
        self.handles = {}
        self.proxytype = {}
        self.failed = []
        self.rlist = []
        self.wlist = []
        self._lock = threading.Lock()

    def setopt(self, option, value):
        "Configure multi options"
        if option in (libcurl.CURLMOPT_SOCKETFUNCTION, libcurl.CURLMOPT_TIMERFUNCTION):
            raise Exception('Callback options reserved for the event loop')
        libcurl.multi_setopt(self._multi, option, value)

    # Callbacks

    def _socket_action(self, sock_fd, ev_bitmask):
        # Event loop callback: act on ready sockets or timeouts
        #dprint("mask = %d, sock_fd = %d" % (ev_bitmask, sock_fd))
        handle_count = ctypes.c_int()
        _ = libcurl.multi_socket_action(
            self._multi, sock_fd, ev_bitmask, ctypes.byref(handle_count))

        # Check if any handles have finished.
        if handle_count.value != len(self.handles):
            self._update_transfers()

    def _update_transfers(self):
        # Mark finished handles as done
        while True:
            queued = ctypes.c_int()
            msg: ctypes.POINTER(libcurl.CURLMsg) = libcurl.multi_info_read(
                self._multi, ctypes.byref(queued))
            if not msg:
                break

            msg = msg.contents
            if msg.msg == libcurl.CURLMSG_DONE:
                # Always true since only one msg type
                easyhash = gethash(msg.easy_handle)
                curl = self.handles[easyhash]
                curl.done = True

                if msg.data.result != libcurl.CURLE_OK:
                    curl.cerr = msg.data.result
                    curl.errstr = str(msg.data.result) + "; "

    # Adding to multi

    def _add_handle(self, curl: Curl):
        # Add a handle
        dprint(curl.easyhash + ": Add handle")
        if curl.easyhash not in self.handles:
            self.handles[curl.easyhash] = curl
            libcurl.multi_add_handle(self._multi, curl.easy)
            dprint(curl.easyhash + ": Added handle")
        else:
            dprint(curl.easyhash + ": Active handle")

    def add(self, curl: Curl):
        "Add a Curl handle to perform"
        with self._lock:
            dprint(curl.easyhash + ": Handles = %d" % len(self.handles))
            self._add_handle(curl)

    # Removing from multi

    def _remove_handle(self, curl: Curl, errstr = ""):
        # Remove a handle and set status
        if curl.easyhash not in self.handles:
            return

        if curl.done is False:
            curl.done = True

        if len(errstr) != 0:
            curl.errstr += errstr + "; "

        dprint(curl.easyhash + ": Remove handle: " + curl.errstr)
        libcurl.multi_remove_handle(self._multi, curl.easy)

        self.handles.pop(curl.easyhash)

    def remove(self, curl: Curl):
        "Remove a Curl handle once done"
        with self._lock:
            self._remove_handle(curl)

    def stop(self, curl: Curl):
        "Stop a running curl handle and remove"
        with self._lock:
            self._remove_handle(curl, errstr = "Stopped")

    # Executing multi

    def _perform(self):
        # Perform all tasks in the multi instance
        with self._lock:
            rlen = len(self.rlist)
            wlen = len(self.wlist)
            if rlen != 0 or wlen != 0:
                rready, wready, xready = select.select(
                    self.rlist, self.wlist, set(self.rlist) | set(self.wlist), self.timer)
            else:
                rready, wready, xready = [], [], []
                if self.timer is not None:
                    # Sleeping within lock - needs fix
                    time.sleep(self.timer)

            if len(rready) == 0 and len(wready) == 0 and len(xready) == 0:
                #dprint("No activity")
                self._socket_action(libcurl.CURL_SOCKET_TIMEOUT, 0)
            else:
                for sock_fd in rready:
                    #dprint("Ready to read sock_fd %d" % sock_fd)
                    self._socket_action(sock_fd, libcurl.CURL_CSELECT_IN)
                for sock_fd in wready:
                    #dprint("Ready to write sock_fd %d" % sock_fd)
                    self._socket_action(sock_fd, libcurl.CURL_CSELECT_OUT)
                for sock_fd in xready:
                    #dprint("Error sock_fd %d" % sock_fd)
                    self._socket_action(sock_fd, libcurl.CURL_CSELECT_ERR)

    def do(self, curl: Curl):
        "Add a Curl handle and peform until completion"
        if not curl.is_easy:
            self.add(curl)
            while True:
                if curl.done:
                    break
                self._perform()
                time.sleep(0.01)
        else:
            dprint(curl.easyhash + ": Using easy interface")
            curl.perform()

        # Map some libcurl error codes to HTTP errors
        if curl.cerr == libcurl.CURLE_URL_MALFORMAT:
            # Bad request
            curl.resp = 400
            curl.errstr += "URL malformed"
        elif curl.cerr in [libcurl.CURLE_UNSUPPORTED_PROTOCOL,
                           libcurl.CURLE_NOT_BUILT_IN,
                           libcurl.CURLE_FUNCTION_NOT_FOUND]:
            # Not implemented
            curl.resp = 501
            curl.errstr += "Unsupported protocol, not built-in, or function not found"
        elif curl.cerr in [libcurl.CURLE_COULDNT_RESOLVE_PROXY,
                           libcurl.CURLE_COULDNT_RESOLVE_HOST,
                           libcurl.CURLE_COULDNT_CONNECT]:
            # Bad gateway
            curl.resp = 502
            curl.errstr += "Could not resolve or connect to proxy or host"
        elif curl.cerr == libcurl.CURLE_OPERATION_TIMEDOUT:
            # Gateway timeout
            curl.resp = 504
            curl.errstr += "Operation timed out"

        if curl.proxy is not None:
            ret, codep = curl.get_response()
            if ret == 0 and codep == 407:
                # Proxy authentication required
                if curl.cerr == libcurl.CURLE_SEND_FAIL_REWIND:
                    # Issue #199 - POST/PUT rewind not supported
                    out = "POST/PUT rewind not supported (#199)"

                    # Retry since proxy auth not cached yet
                    curl.resp = 503
                    curl.errstr += out + "; "
                elif curl.auth is not None:
                    # Proxy auth did not work for whatever reason
                    out = "Proxy authentication failed: "
                    if curl.user is not None:
                        out += "check user/password or try different auth mechanism"
                    else:
                        out += "single sign-on failed, user/password might be required"

                    curl.resp = 401
                    curl.errstr += out + "; "

                    # Add this proxy to failed list and don't try again
                    with self._lock:
                        self.failed.append(curl.proxy)
                else:
                    # Setup client to authenticate directly with upstream proxy
                    dprint(curl.easyhash + ": Client to authenticate with upstream proxy")
                    if not curl.is_connect:
                        # curl.errstr not set else connection will get closed during auth
                        curl.resp = codep

        if curl.is_connect and curl.sock_fd is None:
            # Need sock_fd for select()
            if curl_version() < 0x072D00:
                # This should never happen since we have set CURLOPT_FRESH_CONNECT = True
                # for CONNECT
                out = "Cannot reuse an SSL connection with libcurl < v7.45 - should never happen"
                dprint(curl.easyhash + ": " + out)
                curl.errstr += out + "; "
                curl.resp = 500
            else:
                # Get the active socket using getinfo() for select()
                dprint(curl.easyhash + ": Getting active socket")
                ret, sock_fd = curl.get_activesocket()
                if ret == libcurl.CURLE_OK:
                    curl.sock_fd = sock_fd
                else:
                    out = "Failed to get active socket: %d, %d" % (ret, sock_fd)
                    dprint(curl.easyhash + ": " + out)
                    curl.errstr += out + "; "
                    curl.resp = 503

        return len(curl.errstr) == 0

    def select(self, curl: Curl, client_sock, idle = 30):
        "Run select loop between client and curl"
        # TODO figure out if IPv6 or IPv4
        if curl.sock_fd is None:
            dprint(curl.easyhash + ": Cannot select() without active socket")
            return

        dprint(curl.easyhash + ": Starting select loop")
        curl_sock = socket.fromfd(curl.sock_fd, socket.AF_INET, socket.SOCK_STREAM)

        if curl.is_connect and (not curl.is_tunnel and curl.is_proxied):
            # Send original headers from client to tunnel and authenticate with
            # upstream proxy
            dprint(curl.easyhash + ": Sending original client headers")
            curl_sock.sendall(f"{curl.method} {curl.url} {curl.request_version}\r\n".encode("utf-8"))
            if curl.xheaders is not None:
                for header in curl.xheaders:
                    curl_sock.sendall(f"{header}: {curl.xheaders[header]}\r\n".encode("utf-8"))
            curl_sock.sendall(b"\r\n")

        # sockets will be removed from these lists, when they are
        # detected as closed by remote host; wlist contains sockets
        # only when data has to be written
        rlist = [client_sock, curl_sock]
        wlist = []

        # data to be written to client connection and proxy socket
        cl = 0
        cs = 0
        cdata = []
        sdata = []
        max_idle = time.time() + idle
        while (rlist or wlist):
            (ins, outs, exs) = select.select(rlist, wlist, rlist, idle)
            if exs:
                dprint(curl.easyhash + ": Exception, breaking")
                break
            if ins:
                for i in ins:
                    if i is curl_sock:
                        out = client_sock
                        wdata = cdata
                        source = "server"
                    else:
                        out = curl_sock
                        wdata = sdata
                        source = "client"

                    try:
                        data = i.recv(4096)
                    except ConnectionError as exc:
                        # Fix #152 - handle connection errors gracefully
                        dprint(curl.easyhash + ": from %s: " % source + str(exc))
                        data = ""
                    datalen = len(data)
                    if datalen != 0:
                        cl += datalen
                        # Prepare data to send it later in outs section
                        wdata.append(data)
                        if out not in outs:
                            outs.append(out)
                        max_idle = time.time() + idle
                    else:
                        # No data means connection closed by remote host
                        dprint(curl.easyhash + ": Connection closed by %s" % source)
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
                    if o is curl_sock:
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
                        dprint(curl.easyhash + ": No data sent")
                max_idle = time.time() + idle
            if max_idle < time.time():
                # No data in timeout seconds
                dprint(curl.easyhash + ": Server connection timeout")
                break

        # After serving the proxy tunnel it could not be used for samething else.
        # A proxy doesn't really know, when a proxy tunnnel isn't needed any
        # more (there is no content length for data). So servings will be ended
        # either after timeout seconds without data transfer or when at least
        # one side closes the connection. Close both proxy and client
        # connection if still open.
        dprint(curl.easyhash + ": %d bytes read, %d bytes written" % (cl, cs))

    # Cleanup multi

    def close(self):
        "Stop any running transfers and close this multi handle"
        dprint("Closing multi")
        for easyhash in tuple(self.handles):
            self.stop(self.handles[easyhash])
        libcurl.multi_cleanup(self._multi)

        global MCURL
        MCURL = None

def tester(multi, url):
    curl = Curl(url)
    curl.set_debug()
    multi.do(curl)
    multi.remove(curl)

def main():
    from . import debug
    dbg = debug.Debug("test.log", "w")
    global dprint
    dprint = dbg.get_print()

    multi = MCurl()

    urls = ["http://www.google.com"]

    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        futures = {executor.submit(tester, multi, url): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            dprint("Done: " + url)

    multi.close()

if __name__ == "__main__":
    main()
