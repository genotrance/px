import copy
import socket
import sys

# Python 2.x vs 3.x support
try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

# Proxy modes - source of proxy info
MODE_NONE = 0
MODE_AUTO = 1
MODE_PAC = 2
MODE_MANUAL = 3
MODE_CONFIG = 4
MODE_CONFIG_PAC = 5

DIRECT = ("DIRECT", 80)

dprint = print

def parse_proxy(proxystrs):
    """
    Convert comma separated list of proxy:port into list[tuple(host,port)]
      If no port, default to 80
      Raises ValueError if bad proxy format
    """

    if not proxystrs or len(proxystrs) == 0:
        return []

    servers = []
    for proxystr in [i.strip() for i in proxystrs.split(",")]:
        pserver = [i.strip() for i in proxystr.rsplit(":", 1)]
        if len(pserver) == 1:
            pserver.append(80)
        elif len(pserver) == 2:
            try:
                pserver[1] = int(pserver[1])
            except ValueError as error:
                raise ValueError("Bad proxy server port: " + pserver[1]) from error
        else:
            raise ValueError("Bad proxy server definition: " + proxystr)

        if tuple(pserver) not in servers:
            servers.append(tuple(pserver))

    return servers

if sys.platform == "win32":
    import ctypes
    import ctypes.wintypes
    import netaddr

    # Windows version
    #  6.1 = Windows 7
    #  6.2 = Windows 8
    #  6.3 = Windows 8.1
    # 10.0 = Windows 10
    WIN_VERSION = float(
        str(sys.getwindowsversion().major) + "." +
        str(sys.getwindowsversion().minor))

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
    WINHTTP_ERROR_WINHTTP_AUTODETECTION_FAILED = 12180

    class Wproxy(object):
        """Load proxy information from the operating system"""
        mode = MODE_NONE
        servers = None
        noproxy = None
        noproxy_hosts = None

        def __init__(self, mode = -1, servers = [], noproxy = netaddr.IPSet([]), noproxy_hosts = [], debug_print = print):
            """
            Load proxy information from Windows if mode = -1
              Returns MODE_NONE, MODE_AUTO, MODE_PAC, MODE_MANUAL
            Mode can be set to MODE_CONFIG or MODE_CONFIG_PAC
              MODE_CONFIG expects servers = [(proxy1, port), (proxy2, port)]
              MODE_CONFIG_PAC expects servers = [pac_url]
            """

            global dprint
            dprint = debug_print

            self.noproxy = noproxy
            self.noproxy_hosts = noproxy_hosts

            if mode == -1:
                # Get proxy info from Internet Options
                ie_proxy_config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG()
                ok = ctypes.windll.winhttp.WinHttpGetIEProxyConfigForCurrentUser(
                    ctypes.byref(ie_proxy_config))
                if not ok:
                    dprint("WinHttpGetIEProxyConfigForCurrentUser failed: %s" % str(ctypes.GetLastError()))
                else:
                    if ie_proxy_config.fAutoDetect:
                        # Mode = Auto detect
                        self.mode = MODE_AUTO
                    elif ie_proxy_config.lpszAutoConfigUrl:
                        # Mode = PAC
                        self.mode = MODE_PAC
                        self.servers = [ie_proxy_config.lpszAutoConfigUrl]
                        dprint("AutoConfigURL = " + self.servers[0])
                    else:
                        # Mode = Manual proxy
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
                            self.servers = parse_proxy(",".join(proxies))
                            self.mode = MODE_MANUAL

                        # Proxy exceptions into noproxy
                        bypass_str = ie_proxy_config.lpszProxyBypass or "" # FIXME: Handle "<local>"
                        bypasses = [h.strip() for h in bypass_str.lower().replace(
                            ' ', ';').split(';')]
                        for bypass in bypasses:
                            try:
                                ipns = netaddr.IPGlob(bypass)
                                self.noproxy.add(ipns)
                                dprint("Noproxy += " + bypass)
                            except:
                                self.noproxy_hosts.append(bypass)
                                dprint("Noproxy hostname += " + bypass)
            else:
                self.mode = mode
                self.servers = servers

            dprint("Proxy mode = " + str(self.mode))

        # Find proxy for specified URL using WinHttp API
        #   Used internally for MODE_AUTO, MODE_PAC and MODE_CONFIG_PAC
        def _winhttp_find_proxy_for_url(self, url, autologon=True):
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
            if self.mode in [MODE_PAC, MODE_CONFIG_PAC]:
                autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL
                autoproxy_options.dwAutoDetectFlags = 0
                autoproxy_options.lpszAutoConfigUrl = self.servers[0]
            elif self.mode == MODE_AUTO:
                autoproxy_options.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT
                autoproxy_options.dwAutoDetectFlags = (
                    WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A)
                autoproxy_options.lpszAutoConfigUrl = 0
            else:
                dprint("_winhttp_find_proxy_for_url only applicable for MODE_AUTO, MODE_PAC and MODE_CONFIG_PAC")
                return ""
            autoproxy_options.fAutoLogonIfChallenged = autologon

            proxy_info = WINHTTP_PROXY_INFO()

            ctypes.windll.winhttp.WinHttpGetProxyForUrl.argtypes = [ctypes.c_void_p,
                ctypes.wintypes.LPCWSTR, ctypes.POINTER(WINHTTP_AUTOPROXY_OPTIONS),
                ctypes.POINTER(WINHTTP_PROXY_INFO)]
            ok = ctypes.windll.winhttp.WinHttpGetProxyForUrl(
                hInternet, ctypes.wintypes.LPCWSTR(url),
                ctypes.byref(autoproxy_options), ctypes.byref(proxy_info))
            if not ok:
                error = ctypes.GetLastError()
                if error == WINHTTP_ERROR_WINHTTP_UNABLE_TO_DOWNLOAD_SCRIPT:
                    dprint("Could not download PAC file, trying DIRECT instead")
                    return "DIRECT"
                elif error == WINHTTP_ERROR_WINHTTP_AUTODETECTION_FAILED:
                    dprint("Autodetection failed, trying DIRECT instead")
                    return "DIRECT"
                else:
                    dprint("WinHttpGetProxyForUrl failed: %s" % error)
                    return ""

            if proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY:
                # Note: proxy_info.lpszProxyBypass makes no sense here!
                if not proxy_info.lpszProxy:
                    dprint("WinHttpGetProxyForUrl named proxy without name")
                    return ""
                return proxy_info.lpszProxy.replace(" ", ",").replace(";", ",")
            elif proxy_info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY:
                return "DIRECT"
            else:
                dprint("WinHttpGetProxyForUrl accesstype %s" % (proxy_info.dwAccessType))
                return ""

            # TODO: WinHttpCloseHandle(), GlobalFree() on lpszProxy and lpszProxyBypass

        # Split url into netloc = hostname:port and path
        def _get_netloc(self, url):
            nl = url
            parse = urlparse.urlparse(url, allow_fragments=False)
            if parse.netloc:
                nl = parse.netloc
            if ":" not in nl:
                port = parse.port
                if not port:
                    if parse.scheme == "http":
                        port = 80
                    elif parse.scheme == "https":
                        port = 443
                    elif parse.scheme == "ftp":
                        port = 21
                netloc = (nl, port)
            else:
                spl = nl.rsplit(":", 1)
                netloc = (spl[0], int(spl[1]))

            path = parse.path or "/"
            if parse.params:
                path = path + ";" + parse.params
            if parse.query:
                path = path + "?" + parse.query

            dprint("netloc = %s, path = %s" % (netloc, path))

            return netloc, path

        # Check if url is in noproxy list
        #   Returns (IP, port) or None
        def _check_noproxy_for_url(self, netloc, path):
            if self.noproxy.size:
                addr = []
                try:
                    addr = socket.getaddrinfo(netloc[0], netloc[1])
                except socket.gaierror:
                    # Couldn't resolve, let parent proxy try, px#18
                    dprint("Couldn't resolve host")
                if len(addr) and len(addr[0]) == 5:
                    ipport = addr[0][4]
                    # "%s => %s + %s" % (url, ipport, path)

                    if ipport[0] in self.noproxy:
                        # Direct connection from noproxy configuration
                        return ipport

        # Return list of proxy servers to use for this url
        #   DIRECT can be returned as one of the options in the response
        def find_proxy_for_url(self, url):
            netloc, path = self._get_netloc(url)
            ipport = self._check_noproxy_for_url(netloc, path)
            if not ipport is None:
                # Direct connection since in noproxy list
                return [DIRECT], ipport, path
            elif self.mode == MODE_NONE:
                # Direct connection since no proxy configured
                return [DIRECT], netloc, path
            elif self.mode in [MODE_AUTO, MODE_PAC, MODE_CONFIG_PAC]:
                # Use proxies as resolved via WinHttp
                return parse_proxy(self._winhttp_find_proxy_for_url(url)), netloc, path
            elif self.mode in [MODE_MANUAL, MODE_CONFIG]:
                # Use specific proxies configured
                return copy.deepcopy(self.servers), netloc, path

else:
    pass
