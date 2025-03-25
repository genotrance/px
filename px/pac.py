"PAC file support using quickjs"

import socket
import sys
import threading

from .pacutils import PACUTILS

import mcurl

try:
    import quickjs
except ImportError:
    print("Requires module quickjs")
    sys.exit(1)


# Debug shortcut
def dprint(_):
    pass


class Pac:
    "Load and run PAC files using quickjs"

    _lock = None

    pac_location = None
    pac_encoding = None
    pac_find_proxy_for_url = None

    def __init__(self, pac_location, pac_encoding="utf-8", debug_print=None):
        "Initialize PAC requirements"
        global dprint
        if debug_print is not None:
            dprint = debug_print

        self._lock = threading.Lock()

        self.pac_location = pac_location
        self.pac_encoding = pac_encoding

    def __del__(self):
        "Release quickjs resources"
        if self._lock is not None:
            if self.pac_find_proxy_for_url is not None:
                with self._lock:
                    self.pac_find_proxy_for_url = None
            self._lock = None

    def _load(self, pac_data):
        "Load PAC data in a quickjs Function"
        try:
            text = pac_data.decode(self.pac_encoding)
        except UnicodeDecodeError as exc:
            dprint(f"PAC file not encoded in {self.pac_encoding}")
            dprint("Use --pac_encoding or proxy:pac_encoding in px.ini to change")
            return

        try:
            self.pac_find_proxy_for_url = quickjs.Function(
                "FindProxyForURL", PACUTILS + "\n\n" + text
            )

            # Load Python callables
            for func in [self.alert, self.dnsResolve, self.myIpAddress]:
                self.pac_find_proxy_for_url.add_callable(func.__name__, func)
        except quickjs.JSException as exc:
            dprint("PAC file parsing error")
            return

        dprint("Loaded PAC script")

    def _load_jsfile(self, jsfile):
        "Load specified PAC file"
        dprint(f"Loading PAC file: {jsfile}")
        with open(jsfile, "rb") as js:
            self._load(js.read())

    def _load_url(self, jsurl):
        "Load specfied PAC URL"
        dprint(f"Loading PAC url: {jsurl}")
        c = mcurl.Curl(jsurl)
        c.set_debug()
        c.buffer()
        c.set_follow()
        ret = c.perform()
        if ret == 0:
            ret, resp = c.get_response()
            if ret == 0 and resp < 400:
                self._load(c.get_data(None))
            else:
                dprint(f"Failed to access PAC url: {jsurl}: {ret}, {resp}")
        else:
            dprint(f"Failed to load PAC url: {jsurl}: {ret}, {c.errstr}")

    def _load_pac(self):
        "Load PAC as configured once across all threads"
        if self.pac_find_proxy_for_url is None:
            with self._lock:
                if self.pac_find_proxy_for_url is None:
                    if self.pac_location.startswith("http"):
                        self._load_url(self.pac_location)
                    else:
                        self._load_jsfile(self.pac_location)

    def find_proxy_for_url(self, url, host):
        """
        Return comma-separated list of proxy servers to use for this url
            DIRECT can be returned as one of the options in the response
            DIRECT is returned if PAC file is not loading
        """
        dprint(f"Finding proxy for {url}")
        proxies = "DIRECT"
        self._load_pac()
        if self.pac_find_proxy_for_url is not None:
            # Fix #246 - handle case where PAC file failed to load
            try:
                proxies = self.pac_find_proxy_for_url(url, host)
            except quickjs.JSException as exc:
                # Return DIRECT - cannot crash Px due to PAC file issues
                # which could happen in reload_proxy()
                dprint(f"FindProxyForURL failed, issues loading PAC file: {exc}")
                dprint("Assuming DIRECT connection as fallback")

        # Fix #160 - convert PAC return values into CURLOPT_PROXY schemes
        for ptype in ["PROXY", "HTTP"]:
            proxies = proxies.replace(ptype + " ", "")
        for ptype in ["HTTPS", "SOCKS4", "SOCKS5"]:
            proxies = proxies.replace(ptype + " ", ptype.lower() + "://")
        proxies = proxies.replace("SOCKS ", "socks5://")

        # Not sure if SOCKS proxies will be used with Px since they are not
        # relevant for NTLM/Kerberos authentication over HTTP but libcurl can
        # deal with it for now

        return proxies.replace(";", ",")

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
