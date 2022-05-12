"Test Px"

import difflib
import multiprocessing
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import uuid

import distro
import psutil
if sys.platform == "linux":
    import netifaces

from px.version import __version__

PROXY = ""
PORT = 3128
USERNAME = ""
AUTH = ""
BINARY = ""
TESTS = []
STDOUT = None

try:
    ConnectionRefusedError
except NameError:
    ConnectionRefusedError = socket.error

try:
    DEVNULL = subprocess.DEVNULL
except AttributeError:
    DEVNULL = open(os.devnull, 'wb')

def exec(cmd):
    p = subprocess.run(cmd, stdout = subprocess.PIPE, stderr = subprocess.STDOUT, check = False, timeout = 30)
    return p.returncode, p.stdout

def curl(url, method = "GET", data = "", proxy = ""):
    cmd = ["curl", "-s", "-L", "-k", url]
    if method == "HEAD":
        cmd.append("--head")
    else:
        cmd.extend(["-X", method])
    if len(proxy) != 0:
        cmd.extend(["--proxy", proxy])
    if len(data) != 0:
        cmd.extend(["-d", data])

    writeflush(" ".join(cmd) + "\n")

    return exec(cmd)

def waitasync(results):
    ret = True
    while len(results):
        for i in range(len(results)):
            if results[i].ready():
                if not results[i].get():
                    ret = False
                results.pop(i)
                break
        time.sleep(0.1)

    return ret

def filterHeaders(a):
    ignore = [
        "Date:",
        "Proxy-Connection",
        '"origin"',
        "Cache-Control", "Accept-Encoding",
        "X-Amzn", "X-Bluecoat"
    ]
    lines = []
    for line in a.decode("utf-8").split("\n"):
        line = line.rstrip()
        isign = False
        for ign in ignore:
            if ign in line:
                isign = True
                break
        if isign:
            continue
        lines.append(line)
    return lines

def checkMethod(method, port, secure = False):
    testname = "%s %s" % (method, "secured" if secure else "")
    writeflush("Started: %s\n" % testname)

    url = "http"
    if secure:
        url += "s"
    url += "://httpbin.org/"
    if method == "HEAD":
        url += "get"
    else:
        url += method.lower()
    url += "?param1=val1"
    data = ""
    if method in ["PUT", "POST", "PATCH"]:
        data = str(uuid.uuid4())

    aret, adata = curl(url, method, data)
    if aret != 0:
        writeflush("%s: Curl failed direct: %d\n" % (testname, aret))
        return False
    a = filterHeaders(adata)

    bret, bdata = curl(url, method, data, proxy = "localhost:" + str(port))
    if bret != 0:
        writeflush("%s: Curl failed thru proxy: %d\n" % (testname, bret))
        return False
    b = filterHeaders(bdata)

    if a != b:
        for diff in difflib.unified_diff(a, b):
            writeflush(diff + "\n")
        writeflush("%s: Failed for %s\n" % (testname, url))
        return False

    writeflush("%s: Passed\n" % testname)
    if not secure:
        return checkMethod(method, port, True)

    return True

def run(port):
    if not checkPxStart("localhost", port):
        return False

    for method in ["GET", "POST", "PUT", "DELETE", "PATCH"]:
        if not checkMethod(method, port):
            return False

    return True

def writeflush(data):
    STDOUT.write(data)
    STDOUT.flush()

def runTest(test, cmd, count, port):
    global PORT
    global STDOUT

    PORT = port
    if  "--norun" not in sys.argv:
        # Multiple tests in parallel, each on their own port
        PORT += count

    cmd += "--debug --uniqlog --port=%d %s" % (PORT, test[0])

    testproc = test[1]
    ips = test[2]

    # Output to file
    STDOUT = open("test-%d.log" % PORT, "w")
    writeflush("Test %s on port %d\ncmd: %s\n" % (testproc.__name__, PORT, cmd))

    print("Starting test %s on port %d" % (testproc.__name__, PORT))

    if sys.platform == "win32":
        cmd = "cmd /k start /wait /min " + cmd
    if "--norun" not in sys.argv:
        pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        ret = testproc(ips, PORT)

        pxproc = psutil.Process(pipe.pid)
        for child in pxproc.children(recursive=True):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        try:
            pxproc.kill()
        except:
            pass

        time.sleep(0.5)
    else:
        ret = testproc(ips, PORT)

    STDOUT.close()

    return ret

def getips():
    ip_list = []
    if sys.platform == "linux":
        for interface in netifaces.interfaces():
            for link in netifaces.ifaddresses(interface)[socket.AF_INET]:
                ip_list.append(link['addr'])
        return ip_list
    elif sys.platform == "win32":
        ip_list = [ip[4][0] for ip in socket.getaddrinfo(socket.gethostname(), 80, socket.AF_INET)]
        ip_list.insert(0, "127.0.0.1")

    return ip_list

def checkPxStart(ip, port):
    # Make sure Px starts
    retry = 20
    while True:
        try:
            socket.create_connection((ip, port), 2)
            break
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(1)
            retry -= 1
            if retry == 0:
                writeflush("Px didn't start @ %s:%d\n" % (ip, port))
                return False

    return True

# Test --listen and --port, --hostonly, --gateway and --allow
def checkCommon(name, ips, port, checkProc):
    if ips == [""]:
        ips = ["127.0.0.1"]

    if port == "":
        port = "3128"
    port = int(port)

    if not checkPxStart(ips[0], port):
        return False

    localips = getips()
    for lip in localips:
        for pport in set([3000, port]):
            writeflush("Checking %s: %s:%d\n" % (name, lip, pport))
            ret = checkProc(lip, pport)

            writeflush(str(ret) + ": ")
            if ((lip not in ips or port != pport) and ret is False) or (lip in ips and port == pport and ret is True):
                writeflush("Passed\n")
            else:
                writeflush("Failed\n")
                return False

    return True

def checkSocket(ips, port):
    def checkProc(lip, pport):
        try:
            socket.create_connection((lip, pport), 2)
        except (socket.timeout, ConnectionRefusedError):
            return False

        return True

    return checkCommon("checkSocket", ips, port, checkProc)

def checkFilter(ips, port):
    def checkProc(lip, port):
        rcode, _ = curl(url = "http://google.com", proxy = "%s:%d" % (lip, port))
        writeflush("Returned %d\n" % rcode)
        if rcode == 0:
            return True
        elif rcode in [7, 52, 56]:
            return False
        else:
            writeflush("Failed: curl return code is not 0, 7, 52, 56\n")
            sys.exit()

    return checkCommon("checkFilter", ips, port, checkProc)

def remoteTest(port, fail=False):
    lip = 'echo $SSH_CLIENT ^| cut -d \\\" \\\" -f 1,1'
    cmd = os.getenv("REMOTE_SSH")
    if cmd is None:
        writeflush("Skipping: Remote test - REMOTE_SSH not set\n")
        writeflush("  E.g. export REMOTE_SSH=plink user:pass@\n")
        return
    cmd = cmd + " curl --proxy `%s`:%s --connect-timeout 2 -s http://google.com" % (lip, port)
    writeflush("Checking: Remote: %d\n" % port)
    ret = subprocess.call(cmd, stdout=DEVNULL, stderr=DEVNULL)
    if (ret == 0 and fail == False) or (ret != 0 and fail == True) :
        writeflush("Returned %d: Passed\n" % ret)
    else:
        writeflush("Returned %d: Failed\n" % ret)
        return False

    return True

def hostonlyTest(ips, port):
    return checkSocket(ips, port) and remoteTest(port, fail=True)

def gatewayTest(ips, port):
    return checkSocket(ips, port) and remoteTest(port)

def allowTest(ips, port):
    return checkFilter(ips, port) and remoteTest(port)

def allowTestFail(ips, port):
    return checkFilter(ips, port) and remoteTest(port, fail=True)

def listenTestLocal(ip, port):
    return checkSocket([ip], port) and remoteTest(port, fail=True)

def listenTestRemote(ip, port):
    return checkSocket([ip], port) and remoteTest(port)

def httpTest(skip, port):
    del skip
    return run(port)

def getproxyarg():
    proxyarg = ("--proxy=" + PROXY) if len(PROXY) != 0 else ""
    proxyarg += (" --username=" + USERNAME) if len(USERNAME) != 0 else ""
    proxyarg += (" --auth=" + AUTH) if len(AUTH) != 0 else ""
    return proxyarg

def socketTestSetup():
    proxyarg = getproxyarg()
    if "--nohostonly" not in sys.argv:
        TESTS.append((proxyarg + " --hostonly", hostonlyTest, getips()))

    if "--nogateway" not in sys.argv:
        TESTS.append((proxyarg + " --gateway", gatewayTest, getips()))

    if "--noallow" not in sys.argv:
        for ip in getips():
            spl = ip.split(".")
            oct = ".".join(spl[0:2])

            atest = allowTestFail
            if oct in ["172"]:
                atest = allowTest

            TESTS.append((proxyarg + " --gateway --allow=%s.*.*" % oct,
                atest, list(filter(lambda x: oct in x, getips()))))

    if "--nolisten" not in sys.argv:
        localips = getips()
        localips.insert(0, "")
        localips.remove("127.0.0.1")
        for ip in localips[:3]:
            cmd = proxyarg
            if ip != "":
                cmd += " --listen=" + ip

            testproc = listenTestLocal
            if "172" in ip:
                testproc = listenTestRemote

            TESTS.append((cmd, testproc, ip))

def auto():
    if "--norun" not in sys.argv:
        did = distro.id().replace("32", "")
        testdir = "test-%s-%s" % (did, platform.machine().lower())

        # Make temp directory
        while os.path.exists(testdir):
            try:
                shutil.rmtree(testdir)
            except:
                pass
            time.sleep(1)
        try:
            os.makedirs(testdir, exist_ok=True)
        except TypeError:
            try:
                os.makedirs(testdir)
            except WindowsError:
                pass

        os.chdir(testdir)

    # Setup tests
    if "--nosocket" not in sys.argv:
        socketTestSetup()
    proxyargs = set([getproxyarg()])
    if "--nodirect" not in sys.argv:
        proxyargs.add("")
    for proxyarg in proxyargs:
        if "--noproxy" not in sys.argv:
            TESTS.append((proxyarg + " --workers=2", httpTest, None))
        if len(proxyarg):
            if "--nonoproxy" not in sys.argv:
                TESTS.append((proxyarg + " --workers=2 --threads=30 --noproxy=*.*.*.*", httpTest, None))

    workers = get_argval("workers") or "4"
    pool = multiprocessing.Pool(processes = int(workers))

    # Script test
    offset = 0
    results = []
    if "--noscript" not in sys.argv:
        cmd = sys.executable + " ../px.py "
        results = [pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))]

    if "--binary" in sys.argv or len(BINARY) != 0:
        # Nuitka binary test
        did = BINARY or distro.id().replace("32", "")
        outdir = "px.dist-%s-%s" % (did, platform.machine().lower())

        offset += len(TESTS)
        cmd = os.path.join("..", outdir, "px.dist", "px ")
        results.extend([pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))])

    if "--pip" in sys.argv:
        # Wheel pip installed test
        cmd = sys.executable + " -m pip install ../wheel/"
        if sys.platform == "win32":
            cmd += "px_proxy-%s-py3-none-win_amd64.whl" % __version__
        elif sys.platform == "linux":
            cmd += "px_proxy-%s-py2.py3-none-any.whl" % __version__
        os.system(cmd)

        offset += len(TESTS)
        cmd = sys.executable + " -m px "
        results.extend([pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))])

    if not waitasync(results):
        print("Some tests failed")

    if "--pip" in sys.argv:
        cmd = sys.executable + " -m pip uninstall px-proxy -y"
        os.system(cmd)

    if "--norun" not in sys.argv:
        os.system("grep Failed *.log")
        os.system("grep Traceback *.log")
        os.system("grep error -i *.log")

        os.chdir("..")

def get_argval(name):
    for i in range(len(sys.argv)):
        if "=" in sys.argv[i]:
            val = sys.argv[i].split("=")[1]
            if ("--%s=" % name) in sys.argv[i]:
                return val

    return ""

def main():
    """
    python test.py

    --proxy=testproxy.org:80
        Point to the NTLM proxy server that Px should connect through

    --port=3128
        Run Px on this port

    --username=domain\\username
        Use specified username

    --auth=NTLM
        Use specified auth method with proxy

    --binary
        Test Px binary for this distro

    --binary=centos
        Test Px binary in px.dist-centos-{platform}/px.dist/px

    --pip
        Test Px after installing with pip: python -m px

    --noscript
        Skip direct script mode test

    --norun
        If specified, Px is not started and expected to be running

    --nosocket
        Skip all socket tests

    --nohostonly --nogateway --noallow --nolisten
        Skip specific socket tests

    --noproxy
        Skip HTTP(s) tests through proxy

    --nodirect
        Skip HTTP(s) direct tests

    --nonoproxy
        Skip HTTP(s) tests bypassing proxy using noproxy

    --workers=4
        Number of parallel tests to run
    """

    global PROXY
    global PORT
    global USERNAME
    global AUTH
    global BINARY
    PROXY = get_argval("proxy")
    PORT = get_argval("port")
    if len(PORT):
        PORT = int(PORT)
    else:
        PORT = 3128
    USERNAME = get_argval("username")
    AUTH = get_argval("auth")
    BINARY = get_argval("binary")

    if "--help" in sys.argv:
        print(main.__doc__)
        sys.exit()

    auto()

if __name__ == "__main__":
    main()