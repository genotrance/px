"Non-blocking DNS resolution for PAC callbacks (stdlib only)"

import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

# Cache TTLs, in seconds
POSITIVE_TTL = 60.0
NEGATIVE_TTL = 10.0

# How long lookup() waits for a fresh/in-flight resolution before giving up
LOOKUP_TIMEOUT = 3.0

# Dedicated pool for DNS lookups - kept separate from the default executor
# (mcurl.do()) and the quickjs worker thread so a slow/hanging lookup never
# blocks PAC evaluation or unrelated connections indefinitely
POOL_WORKERS = 8


@dataclass
class _PendingLookup:
    "Result shared by callers waiting on the same system lookup"

    done: threading.Event
    value: tuple[str, ...] | None = None


def my_ip_address():
    "Get the local IPv4 address without doing any DNS lookups"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # No packets are sent - UDP connect() only picks the local route
            sock.connect(("192.0.2.1", 9))
            return sock.getsockname()[0]
    except OSError:
        pass

    # No route to the internet - fall back to the first up, non-loopback,
    # non-link-local IPv4 address known to this host
    try:
        from . import config

        hostips = config.get_host_ips()
    except Exception:
        return "127.0.0.1"

    for ip in hostips:
        if not ip.is_loopback() and not ip.is_link_local():
            return str(ip)

    return "127.0.0.1"


class Resolver:
    "Thread-safe DNS resolver with a short-lived cache and in-flight de-duplication"

    def __init__(
        self,
        positive_ttl=POSITIVE_TTL,
        negative_ttl=NEGATIVE_TTL,
        workers=POOL_WORKERS,
        clock=time.monotonic,
    ):
        self.positive_ttl = positive_ttl
        self.negative_ttl = negative_ttl
        self.clock = clock

        self._lock = threading.Lock()
        self._cache = {}  # (host, family) -> (expiry, addresses_or_None)
        self._inflight: dict[tuple[str, int], _PendingLookup] = {}
        self._executor = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="px-resolver")

    def close(self):
        "Stop accepting resolver work without waiting for a slow system lookup"
        self._executor.shutdown(wait=False)

    def __del__(self):
        self.close()

    def _literal(self, host, family):
        "Return host unchanged if it is already an IP literal of the requested family, else None"
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            return None

        if family == socket.AF_INET6 and addr.version != 6:
            return None
        if family == socket.AF_INET and addr.version != 4:
            return None

        return str(addr)

    def _cached(self, key):
        "Return (hit, value) for a live cache entry; caller holds self._lock"
        entry = self._cache.get(key)
        if entry is None:
            return False, None

        expiry, value = entry
        if self.clock() >= expiry:
            del self._cache[key]
            return False, None

        return True, value

    def has_immediate_result(self, host, family=socket.AF_INET):
        "Return whether lookup() or lookup_all() can return without waiting for DNS"
        if self._literal(host, family) is not None:
            return True

        with self._lock:
            hit, _value = self._cached((host, family))
            return hit

    def _resolve(self, host, family, pending):
        "Blocking lookup, run on the executor and cached for waiting callers"
        try:
            addrinfo = socket.getaddrinfo(host, None, family)
            addresses = tuple(dict.fromkeys(info[4][0] for info in addrinfo)) or None
        except (OSError, UnicodeError):
            addresses = None

        ttl = self.positive_ttl if addresses is not None else self.negative_ttl
        key = (host, family)
        with self._lock:
            self._cache[key] = (self.clock() + ttl, addresses)
            if self._inflight.get(key) is pending:
                del self._inflight[key]
            pending.value = addresses
            pending.done.set()

        return addresses

    def lookup_all(self, host, family=socket.AF_INET, timeout=LOOKUP_TIMEOUT):
        "Resolve host to every IP address, or None on failure or timeout"
        literal = self._literal(host, family)
        if literal is not None:
            return [literal]

        key = (host, family)
        with self._lock:
            hit, value = self._cached(key)
            if hit:
                return list(value) if value is not None else None

            pending = self._inflight.get(key)
            if pending is None:
                pending = _PendingLookup(threading.Event())
                self._inflight[key] = pending
                self._executor.submit(self._resolve, host, family, pending)

        if pending.done.wait(timeout):
            return list(pending.value) if pending.value is not None else None

        # Straggler keeps running in the background and will populate the
        # cache for the next call.
        return None

    def lookup(self, host, family=socket.AF_INET, timeout=LOOKUP_TIMEOUT):
        "Resolve host to its first IP address, or None on failure or timeout"
        addresses = self.lookup_all(host, family, timeout)
        return addresses[0] if addresses else None
