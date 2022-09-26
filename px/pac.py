"PAC file support using quickjs"

import socket
import sys

try:
    import quickjs
except ImportError:
    print("Requires module quickjs")
    sys.exit()

from .mcurl import Curl
from .pacutils import PACUTILS

# Debug shortcut
dprint = lambda x: None

class Pac:
    "Load and run PAC files using quickjs"

    ctxt = None

    def __init__(self, debug_print = None):
        "Initialize a quickjs context with default PAC utility functions"
        global dprint
        if debug_print is not None:
            dprint = debug_print

        self.ctxt = quickjs.Context()

        dprint("Loading PAC utils")

        # Load Python callables
        for func in [self.alert, self.dnsResolve, self.myIpAddress]:
            self.ctxt.add_callable(func.__name__, func)

        # Load PAC js utils
        self.ctxt.eval(PACUTILS)

    def load_jsfile(self, jsfile):
        "Load specified JS file into this context"
        dprint("Loading PAC file: " + jsfile)
        with open(jsfile) as js:
            self.ctxt.eval(js.read())

    def load_url(self, jsurl):
        dprint("Loading PAC url: " + jsurl)
        c = Curl(jsurl)
        c.set_debug()
        c.buffer()
        c.set_follow()
        if c.perform():
            self.ctxt.eval(c.get_data())

    def find_proxy_for_url(self, url, host):
        """
        Return comma-separated list of proxy servers to use for this url
            DIRECT can be returned as one of the options in the response
        """
        try:
            proxies = self.ctxt.eval("FindProxyForURL")(url, host)
        except quickjs.JSException:
            dprint("Could not evaluate PAC file, falling back to DIRECT...")
            return "DIRECT"

        # Fix #160 - convert PAC return values into CURLOPT_PROXY schemes
        for ptype in ["PROXY", "HTTP"]:
            proxies = proxies.replace(ptype + " ", "")
        for ptype in ["HTTPS", "SOCKS4", "SOCKS5"]:
            proxies = proxies.replace(ptype + " ", ptype.lower() + "://")
        proxies = proxies.replace("SOCKS ", "socks5://")

        # Not sure if SOCKS proxies will be used with Px since they are not
        # relevant for NTLM/Kerberos authentication over HTTP but libcurl can
        # deal with it for now

        return proxies.replace(" ", ",").replace(";", ",")

    # Python callables from JS

    def alert(self, msg):
        pass

    def dnsResolve(self, host):
        "Resolve host to IP"
        try:
            return socket.gethostbyname(host)
        except socket.gaierror:
            return ""

    def myIpAddress(self):
        "Get my IP address"
        return self.dnsResolve(socket.gethostname())
