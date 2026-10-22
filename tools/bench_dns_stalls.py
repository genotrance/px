"""Benchmark how slow or failing DNS affects px latency and throughput.

Runs px against a local upstream with (a) a PAC file calling myIpAddress(),
dnsResolve(), isInNet() and isResolvable() and (b) a --noproxy list with IPs.
Name resolution inside the px process is made slow or failing deterministically
by a sitecustomize hook (no root or real DNS needed). Only lookups issued from
px.pac and px.wproxy are affected, so px's own sockets and the benchmark client
keep working.

Usage (from a directory outside the repo with a clean HOME):
    python tools/bench_dns_stalls.py [--json out.json] [--scenarios pac,noproxy]
        [--modes normal,slow1,slow5,fail] [--concurrency 1,10,50] [--timeout 30]
"""

import argparse
import asyncio
import http.client
import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SITECUSTOMIZE = """
import os, socket, sys, time

_mode = os.environ.get("PX_BENCH_DNS_MODE", "normal")
_delay = float(os.environ.get("PX_BENCH_DNS_DELAY", "0"))
_real_gai = socket.getaddrinfo
_real_ghbn = socket.gethostbyname
_ours = ("px.pac", "px.wproxy")


def _active():
    return sys._getframe(2).f_globals.get("__name__") in _ours


def _stall():
    if _mode == "slow":
        time.sleep(_delay)
    elif _mode == "fail":
        raise socket.gaierror(socket.EAI_NONAME, "benchmark: resolution failed")


def _fake(host):
    return isinstance(host, str) and host.endswith(".test")


def getaddrinfo(host, *a, **kw):
    if _active():
        _stall()
        if _fake(host):
            host = "127.0.0.1"
    return _real_gai(host, *a, **kw)


def gethostbyname(host):
    if _active():
        _stall()
        if _fake(host):
            return "127.0.0.1"
    return _real_ghbn(host)


_real_ghn = socket.gethostname
socket.getaddrinfo = getaddrinfo
socket.gethostbyname = gethostbyname
"""

PAC = """
function FindProxyForURL(url, host) {
    var me = myIpAddress();
    var ip = dnsResolve("pac.bench.test");
    if (isInNet("pac.bench.test", "127.0.0.0", "255.0.0.0")) {}
    if (isResolvable("pac.bench.test")) {}
    return "DIRECT";
}
"""

MODES = {
    "normal": ("normal", 0),
    "slow1": ("slow", 1),
    "slow5": ("slow", 5),
    "fail": ("fail", 0),
}

BODY = b"ok" * 100


async def _upstream_main(port, ready):
    async def handle(reader, writer):
        try:
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(BODY) + BODY)
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", port)
    ready.set()
    await srv.serve_forever()


def start_upstream(port):
    ready = threading.Event()
    threading.Thread(target=lambda: asyncio.run(_upstream_main(port, ready)), daemon=True).start()
    assert ready.wait(10)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_px(scenario, mode, workdir, up_port):
    port = free_port()
    hook = os.path.join(workdir, "hook")
    os.makedirs(hook, exist_ok=True)
    with open(os.path.join(hook, "sitecustomize.py"), "w") as f:
        f.write(SITECUSTOMIZE)
    args = [sys.executable, "-m", "px", f"--port={port}", "--hostonly"]
    if scenario == "pac":
        pac = os.path.join(workdir, "bench.pac")
        with open(pac, "w") as f:
            f.write(PAC)
        args.append("--pac=" + pac)
    else:
        args.append("--noproxy=127.0.0.1,10.0.0.0/8")
    kind, delay = MODES[mode]
    env = {k: v for k, v in os.environ.items() if not k.startswith("PX_")}
    env.update(
        HOME=workdir,
        PX_BENCH_DNS_MODE=kind,
        PX_BENCH_DNS_DELAY=str(delay),
        PYTHONPATH=os.pathsep.join([hook, REPO]),
    )
    log = open(os.path.join(workdir, f"px-{scenario}-{mode}.log"), "w")
    proc = subprocess.Popen(args, env=env, cwd=workdir, stdout=log, stderr=log)
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return proc, port
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("px did not start")


def one_request(px_port, up_port, timeout):
    t = time.perf_counter()
    try:
        c = http.client.HTTPConnection("127.0.0.1", px_port, timeout=timeout)
        c.request("GET", f"http://localhost:{up_port}/", headers={"Host": f"localhost:{up_port}"})
        r = c.getresponse()
        ok = r.status == 200 and r.read() == BODY
        c.close()
    except Exception:
        ok = False
    return time.perf_counter() - t, ok


def run_level(px_port, up_port, conc, timeout):
    "One wave of `conc` simultaneous requests; returns stats"
    res = []
    lock = threading.Lock()

    def worker():
        r = one_request(px_port, up_port, timeout)
        with lock:
            res.append(r)

    ths = [threading.Thread(target=worker) for _ in range(conc)]
    t0 = time.perf_counter()
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    wall = time.perf_counter() - t0
    lat = sorted(x[0] for x in res)
    ok = sum(1 for x in res if x[1])

    def pct(p):
        return lat[min(len(lat) - 1, round(p * (len(lat) - 1)))]

    return {
        "concurrency": conc,
        "ok": ok,
        "failed": conc - ok,
        "wall_s": round(wall, 3),
        "rps": round(ok / wall, 2),
        "mean_s": round(statistics.mean(lat), 3),
        "p50_s": round(pct(0.5), 3),
        "p95_s": round(pct(0.95), 3),
        "max_s": round(lat[-1], 3),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenarios", default="pac,noproxy")
    ap.add_argument("--modes", default="normal,slow1,slow5,fail")
    ap.add_argument("--concurrency", default="1,10,50")
    ap.add_argument("--timeout", type=float, default=30, help="client timeout per request (s)")
    ap.add_argument("--json", help="write results as JSON to this file")
    a = ap.parse_args()

    up_port = free_port()
    start_upstream(up_port)
    results = []
    with tempfile.TemporaryDirectory(prefix="px-bench-") as workdir:
        for scenario in a.scenarios.split(","):
            for mode in a.modes.split(","):
                proc, px_port = start_px(scenario, mode, workdir, up_port)
                try:
                    for conc in [int(c) for c in a.concurrency.split(",")]:
                        r = {"scenario": scenario, "mode": mode, **run_level(px_port, up_port, conc, a.timeout)}
                        results.append(r)
                        print(json.dumps(r), file=sys.stderr, flush=True)
                finally:
                    proc.terminate()
                    try:
                        proc.wait(10)
                    except subprocess.TimeoutExpired:
                        proc.kill()

    hdr = f"{'scenario':9}{'mode':8}{'conc':>5}{'ok':>5}{'fail':>5}{'rps':>8}{'p50 s':>8}{'p95 s':>8}{'max s':>8}"
    print(hdr)
    for r in results:
        print(
            f"{r['scenario']:9}{r['mode']:8}{r['concurrency']:>5}{r['ok']:>5}{r['failed']:>5}"
            f"{r['rps']:>8}{r['p50_s']:>8}{r['p95_s']:>8}{r['max_s']:>8}"
        )
    if a.json:
        with open(a.json, "w") as f:
            json.dump(results, f, indent=1)


if __name__ == "__main__":
    main()
