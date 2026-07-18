"PAC file support using quickjs-ng"

import codecs
import socket
import sys
import threading
from typing import ClassVar

import mcurl

from .debug import pprint
from .pacutils import PACUTILS

try:
    import quickjs
except ImportError:
    print("Requires module quickjs-ng")
    sys.exit(1)


# Debug shortcut
def dprint(_):
    pass


class Pac:
    "Load and run PAC files using quickjs-ng"

    _lock = None

    pac_location = None
    pac_encoding = None
    pac_find_proxy_for_url = None

    def __init__(self, pac_location, pac_encoding=None, debug_print=None):
        "Initialize PAC requirements"
        global dprint
        if debug_print is not None:
            dprint = debug_print

        self._lock = threading.Lock()

        self.pac_location = pac_location
        self.pac_encoding = pac_encoding or None

    def __del__(self):
        "Release quickjs resources"
        if self._lock is not None:
            if self.pac_find_proxy_for_url is not None:
                with self._lock:
                    self.pac_find_proxy_for_url = None
            self._lock = None

    # BOM signatures ordered longest-first so UTF-32 is checked before UTF-16
    _BOMS: ClassVar[list[tuple[bytes, str]]] = [
        (codecs.BOM_UTF32_BE, "utf-32-be"),
        (codecs.BOM_UTF32_LE, "utf-32-le"),
        (codecs.BOM_UTF16_BE, "utf-16-be"),
        (codecs.BOM_UTF16_LE, "utf-16-le"),
        (codecs.BOM_UTF8, "utf-8-sig"),
    ]

    # Windows code pages to trial-decode when UTF-8 fails, ordered by global
    # prevalence.  cp1252 (Western European) is the most common Windows default
    # worldwide; cp1251 (Cyrillic) is the second most common and was reported
    # in issue #167.  Latin-1 is the ultimate fallback — it accepts every byte.
    _FALLBACK_ENCODINGS: ClassVar[list[str]] = ["cp1252", "cp1251", "latin-1"]

    @staticmethod
    def _parse_content_type_charset(content_type):
        "Extract charset from a Content-Type header value, or None"
        if not content_type:
            return None
        for part in content_type.split(";"):
            part = part.strip()
            if part.lower().startswith("charset="):
                charset = part[len("charset=") :].strip().strip('"').strip("'")
                if charset:
                    return charset
        return None

    def _detect_encoding(self, pac_data, content_type=None):
        "Auto-detect PAC encoding: Content-Type charset, BOM, UTF-8, then code page cascade"
        # 1. HTTP Content-Type charset (highest priority, like Chromium)
        charset = self._parse_content_type_charset(content_type)
        if charset:
            dprint(f"Using charset from Content-Type header: {charset}")
            return charset

        # 2. BOM detection
        for bom, encoding in self._BOMS:
            if pac_data.startswith(bom):
                dprint(f"Detected PAC encoding from BOM: {encoding}")
                return encoding

        # 3. UTF-8 trial decode
        try:
            pac_data.decode("utf-8")
        except UnicodeDecodeError:
            pass
        else:
            return "utf-8"

        # 4. Windows code page cascade, then Latin-1 fallback
        for encoding in self._FALLBACK_ENCODINGS:
            try:
                pac_data.decode(encoding)
            except UnicodeDecodeError:
                continue
            dprint(f"PAC not valid UTF-8, decoded as {encoding}")
            return encoding

        # Should never reach here — latin-1 accepts every byte
        return "latin-1"

    def _load(self, pac_data, content_type=None):
        "Load PAC data in a quickjs Function"
        encoding = self.pac_encoding if self.pac_encoding is not None else self._detect_encoding(pac_data, content_type)

        try:
            text = pac_data.decode(encoding)
        except (UnicodeDecodeError, LookupError) as exc:
            pprint(f"PAC file decode failed ({encoding}): {exc}")
            pprint("Use --pac_encoding or proxy:pac_encoding in px.ini to specify the correct encoding")
            return

        dprint(f"PAC decoded with encoding: {encoding}")

        try:
            self.pac_find_proxy_for_url = quickjs.Function("FindProxyForURL", PACUTILS + "\n\n" + text)

            # Load Python callables
            for func in [self.alert, self.dnsResolve, self.myIpAddress]:
                self.pac_find_proxy_for_url.add_callable(func.__name__, func)
        except quickjs.JSException:
            pprint("PAC file parsing error")
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
                content_type = c.get_content_type()
                self._load(c.get_data(None), content_type)
            else:
                pprint(f"Failed to access PAC url: {jsurl}: {ret}, {resp}")
        else:
            pprint(f"Failed to load PAC url: {jsurl}: {ret}, {c.errstr}")

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
