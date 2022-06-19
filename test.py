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

import psutil
if sys.platform == "linux":
    import netifaces

from px.version import __version__

import tools

COUNT = 0
PROXY = ""
PAC = ""
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

def exec(cmd, port = 0, shell = True):
    global COUNT
    log = "%d-%d.txt" % (port, COUNT)
    COUNT += 1
    with open(log, "wb") as l:
        p = subprocess.run(cmd, shell = shell, stdout = l, stderr = subprocess.STDOUT, check = False, timeout = 60)

    with open(log, "r") as l:
        data = l.read()
    return p.returncode, data

def curlcli(url, port, method = "GET", data = "", proxy = ""):
    cmd = ["curl", "-s", "-k", url]
    if method == "HEAD":
        cmd.append("--head")
    else:
        cmd.extend(["-X", method])
    if len(proxy) != 0:
        cmd.extend(["--proxy", proxy])
    if len(data) != 0:
        cmd.extend(["-d", data])

    writeflush(" ".join(cmd) + "\n")

    try:
        return exec(cmd, port, shell = False)
    except subprocess.TimeoutExpired:
        return -1, "Subprocess timed out"

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
    for line in a.split("\n"):
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

    if "--curlcli" in sys.argv:
        aret, adata = curlcli(url, port, method, data)
    else:
        aret, adata = tools.curl(url, method, data = data)
    if aret != 0:
        writeflush("%s: Curl failed direct: %d\n%s\n" % (testname, aret, adata))
        return False
    a = filterHeaders(adata)

    if "--curlcli" in sys.argv:
        bret, bdata = curlcli(url, port, method, data, proxy = "localhost:" + str(port))
    else:
        bret, bdata = tools.curl(url, method, proxy = "localhost:" + str(port), data = data)
    if bret != 0:
        writeflush("%s: Curl failed thru proxy: %d\n%s\n" % (testname, bret, bdata))
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
    if data[-1] != "\n":
        STDOUT.write("\n")
    STDOUT.flush()

def runTest(test, cmd, offset, port):
    global STDOUT

    if  "--norun" not in sys.argv:
        # Multiple tests in parallel, each on their own port
        port += offset

    cmd += "--debug --uniqlog --port=%d %s" % (port, test[0])

    testproc = test[1]
    data = test[2]

    # Output to file
    STDOUT = open("test-%d.log" % port, "w")
    writeflush("Test %s on port %d\ncmd: %s\n" % (testproc.__name__, port, cmd))

    print("Starting test %s on port %d" % (testproc.__name__, port))

    if sys.platform == "win32":
        cmd = "cmd /c start /wait /min " + cmd
    if "--norun" not in sys.argv:
        subp = subprocess.Popen(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)

        if testproc in [installTest, uninstallTest]:
            # Wait for Px to exit for these tests
            subp.wait()

        ret = testproc(data, port)

        try:
            # Kill Px since runtime test is done
            pxproc = psutil.Process(subp.pid)
            for child in pxproc.children(recursive=True):
                try:
                    child.kill()
                except psutil.NoSuchProcess:
                    pass
            pxproc.kill()
        except psutil.NoSuchProcess:
            pass

        time.sleep(0.5)
    else:
        ret = testproc(data, port)

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
        if "--curlcli" in sys.argv:
            rcode, _ = curlcli(url = "http://google.com", port = port, proxy = "%s:%d" % (lip, port))
        else:
            rcode, _ = tools.curl(url = "http://google.com", proxy = "%s:%d" % (lip, port))
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

def installTest(cmd, port):
    time.sleep(1)
    ret, data = exec("reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Px", port)
    if ret != 0:
        writeflush("Failed: registry query failed: %d\n%s\n" % (ret, data))
        return False
    if cmd.strip().replace("powershell -Command ", "") not in data.replace('"', ""):
        writeflush("Failed: %s --install\n%s\n" % (cmd, data))
        return False
    return True

def uninstallTest(skip, port):
    del skip
    time.sleep(1)
    ret, data = exec("reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Px", port)
    if ret == 0:
        writeflush("reg query passed after uninstall\n%s\n" % data)
        return False
    return True

def quitTest(cmd, port):
    if not checkPxStart("localhost", port):
        writeflush("Px did not start\n")
        return False

    writeflush("cmd: " + cmd + "--quit\n")
    ret, data = exec(cmd + "--quit", port)
    if ret != 0 or "Quitting Px .. DONE" not in data:
        writeflush("Failed: Unable to --quit Px: %d\n%s\n" % (ret, data + "\n"))
        return False

    return True

def getproxyargs():
    proxyargs = []
    proxyarg = ""
    proxyarg += (" --username=" + USERNAME) if len(USERNAME) != 0 else ""
    proxyarg += (" --auth=" + AUTH) if len(AUTH) != 0 else ""

    if "--noserver" not in sys.argv and len(PROXY) != 0:
        proxyargs.append("--proxy=" + PROXY + proxyarg)

    if "--nopac" not in sys.argv and len(PAC) != 0:
        proxyargs.append("--pac=" + PAC + proxyarg)

    if "--nodirect" not in sys.argv:
        proxyargs.append("")

    return proxyargs

def socketTestSetup():
    if "--nohostonly" not in sys.argv:
        TESTS.append(("--hostonly", hostonlyTest, getips()))

    if "--nogateway" not in sys.argv:
        TESTS.append(("--gateway", gatewayTest, getips()))

    if "--noallow" not in sys.argv:
        for ip in getips():
            spl = ip.split(".")
            oct = ".".join(spl[0:2])

            atest = allowTestFail
            if oct in ["172"]:
                atest = allowTest

            TESTS.append(("--gateway --allow=%s.*.*" % oct,
                atest, list(filter(lambda x: oct in x, getips()))))

    if "--nolisten" not in sys.argv:
        localips = getips()
        localips.insert(0, "")
        localips.remove("127.0.0.1")
        for ip in localips[:3]:
            cmd = ""
            if ip != "":
                cmd = "--listen=" + ip

            testproc = listenTestLocal
            if "172" in ip:
                testproc = listenTestRemote

            TESTS.append((cmd, testproc, ip))

def auto():
    osname = tools.get_os()
    if "--norun" not in sys.argv:
        testdir = "test-%s-%d-%s" % (osname, PORT, platform.machine().lower())

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
    if "--noproxy" not in sys.argv:
        for proxyarg in getproxyargs():
            TESTS.append((proxyarg + " --workers=2", httpTest, None))
            if "--nonoproxy" not in sys.argv and len(proxyarg) != 0:
                TESTS.append((proxyarg + " --workers=2 --threads=30 --noproxy=*.*.*.*", httpTest, None))

    workers = tools.get_argval("workers") or "4"
    pool = multiprocessing.Pool(processes = int(workers))

    offset = 0
    results = []
    cmds = []
    if "--noscript" not in sys.argv:
        # Run as script - python px.py
        cmd = sys.executable + " %s " % os.path.abspath("../px.py")
        cmds.append(cmd)
        results = [pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))]
        offset += len(TESTS)

    if "--binary" in sys.argv:
        # Nuitka binary test
        outdir = "px.dist-%s-%s" % (osname, platform.machine().lower())

        cmd = os.path.abspath(os.path.join("..", outdir, "px.dist", "px")) + " "
        cmds.append(cmd)
        results.extend([pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))])
        offset += len(TESTS)

    if "--pip" in sys.argv:
        # Wheel pip installed test

        # Uninstall if already installed
        cmd = sys.executable + " -m pip uninstall px-proxy -y"
        exec(cmd)

        # Install Px
        cmd = sys.executable + " -m pip install ../wheel/"
        if sys.platform == "win32":
            cmd += "px_proxy-%s-py3-none-win_amd64.whl" % __version__
        elif sys.platform == "linux":
            cmd += "px_proxy-%s-py2.py3-none-any.whl" % __version__
        ret, data = exec(cmd)
        if ret != 0:
            print("Failed: pip install: %d\n%s" % (ret, data))
        else:
            # Run as module - python -m px
            cmd = sys.executable + " -m px "
            cmds.append(cmd)
            results.extend([pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))])
            offset += len(TESTS)

            # Run as Python console script
            cmd = shutil.which("px").replace(".EXE", "")
            if len(cmd) != 0:
                cmd += " "
                cmds.append(cmd)
                results.extend([pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))])
                offset += len(TESTS)
            else:
                print("Skipped: console script could not be found")

    if not waitasync(results):
        print("Some tests failed")
    pool.close()

    if "--norun" not in sys.argv:
        # Sequential tests - cannot parallelize
        if sys.platform == "win32" and "--noinstall" not in sys.argv:
            for shell in ["", "powershell -Command "]:
                for cmd in cmds:
                    cmd = shell + cmd
                    runTest(("--install", installTest, cmd), cmd, offset, PORT)
                    offset += 1

                    runTest(("--uninstall", uninstallTest, cmd), cmd, offset, PORT)
                    offset += 1

        if "--noquit" not in sys.argv:
            shell = "powershell -Command "
            for cmd in cmds:
                    runTest(("", quitTest, cmd), cmd, offset, PORT)
                    offset += 1

                    if sys.platform == "win32":
                        runTest(("", quitTest, shell + cmd), cmd, offset, PORT)
                        offset += 1

                        runTest(("", quitTest, cmd), shell + cmd, offset, PORT)
                        offset += 1

                        runTest(("", quitTest, shell + cmd), shell + cmd, offset, PORT)
                        offset += 1

    if "--pip" in sys.argv:
        cmd = sys.executable + " -m pip uninstall px-proxy -y"
        exec(cmd)

    if "--norun" not in sys.argv:
        os.system("grep failed -i *.log")
        os.system("grep traceback -i *.log")
        os.system("grep error -i *.log")

        os.chdir("..")

def main():
    """
    python test.py

    --proxy=testproxy.org:80
        Point to the NTLM proxy server that Px should connect through

    --pac=pacurl
        Point to the PAC file to determine proxy info

    --port=3128
        Run Px on this port

    --username=domain\\username
        Use specified username

    --auth=NTLM
        Use specified auth method with proxy

    --binary
        Test Px binary

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
        Skip all proxy tests

    --noserver
        Skip proxy tests through upstream proxy

    --nodirect
        Skip direct proxy tests

    --nonoproxy
        Skip proxy tests bypassing upstream proxy using noproxy

    --noinstall
        Skip --install tests

    --noquit
        Skip --quit tests

    --workers=4
        Number of parallel tests to run

    --curlcli
        Use curl command line instead of px.mcurl
    """

    global PROXY
    global PAC
    global PORT
    global USERNAME
    global AUTH
    global BINARY
    PROXY = tools.get_argval("proxy")
    PAC = tools.get_argval("pac")
    PORT = tools.get_argval("port")
    if len(PORT):
        PORT = int(PORT)
    else:
        PORT = 3128
    USERNAME = tools.get_argval("username").replace("\\", "\\\\")
    AUTH = tools.get_argval("auth")
    BINARY = tools.get_argval("binary")

    if "--help" in sys.argv:
        print(main.__doc__)
        sys.exit()

    auto()

if __name__ == "__main__":
    main()