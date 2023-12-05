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

    def load(self, pac_data, pac_encoding):
        "Load PAC data in specified encoding into this context"
        pac_encoding = pac_encoding or "utf-8"
        text = pac_data.decode(pac_encoding)
        try:
            self.ctxt.eval(text)
        except quickjs.JSException as exc:
            dprint(f"PAC file parsing failed - syntax error or file not encoded in {pac_encoding}")
            dprint("Use --pac_encoding or proxy:pac_encoding in px.ini to change")
            raise exc

    def load_jsfile(self, jsfile, pac_encoding):
        "Load specified JS file into this context"
        dprint(f"Loading PAC file: {jsfile}")
        with open(jsfile, "rb") as js:
            self.load(js.read(), pac_encoding)

    def load_url(self, jsurl, pac_encoding):
        dprint(f"Loading PAC url: {jsurl}")
        c = Curl(jsurl)
        c.set_debug()
        c.buffer()
        c.set_follow()
        ret = c.perform()
        if ret == 0:
            self.load(c.get_data(None), pac_encoding)
        else:
            dprint(f"Failed to load PAC url: {jsurl}\n{ret}, {c.errstr}")

    def find_proxy_for_url(self, url, host):
        """
        Return comma-separated list of proxy servers to use for this url
            DIRECT can be returned as one of the options in the response
        """
        proxies = self.ctxt.eval("FindProxyForURL")(url, host)

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
