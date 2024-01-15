"Test Px"

import difflib
import multiprocessing
import os
import platform
import shlex
import shutil
import socket
import subprocess
import sys
import time
import uuid

import psutil

from px.config import get_host_ips
from px.version import __version__

import tools

COUNT = 0
PROXY = ""
PAC = ""
PORT = 3128
USERNAME = ""
AUTH = ""
TESTS = []
STDOUT = {}

try:
    ConnectionRefusedError
except NameError:
    ConnectionRefusedError = socket.error

try:
    DEVNULL = subprocess.DEVNULL
except AttributeError:
    DEVNULL = open(os.devnull, 'wb')

def exec(cmd, port = 0, shell = True, delete = False):
    global COUNT
    log = "%d-%d.txt" % (port, COUNT)
    COUNT += 1
    with open(log, "wb") as l:
        p = subprocess.run(cmd, shell = shell, stdout = l, stderr = subprocess.STDOUT, check = False, timeout = 60)

    with open(log, "r") as l:
        data = l.read()

    if delete:
        os.remove(log)

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

    writeflush(port, " ".join(cmd) + "\n")

    try:
        return exec(cmd, port, shell = False)
    except subprocess.TimeoutExpired:
        return -1, "Subprocess timed out"

def waitasync(pool, results):
    ret = True
    while len(results):
        for i in range(len(results)):
            if results[i].ready():
                if not results[i].get():
                    ret = False
                results.pop(i)
                break
        time.sleep(0.5)

        if os.system("grep \" 401 \" *.log") == 0:
            # Proxy auth errors - stop all tests
            pool.terminate()
            ret = False
            break

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
    writeflush(port, f"Started: {testname}\n")

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
        writeflush(port, f"{testname}: Curl failed direct: {aret}\n{adata}\n")
        return False
    a = filterHeaders(adata)

    if "--curlcli" in sys.argv:
        bret, bdata = curlcli(url, port, method, data, proxy = "127.0.0.1:" + str(port))
    else:
        bret, bdata = tools.curl(url, method, proxy = "127.0.0.1:" + str(port), data = data)
    if bret != 0:
        writeflush(port, f"{testname}: Curl failed thru proxy: {bret}\n{bdata}\n")
        return False
    b = filterHeaders(bdata)

    if a != b:
        for diff in difflib.unified_diff(a, b):
            writeflush(port, diff + "\n")
        writeflush(port, f"{testname}: Failed for {url}\n")
        return False

    writeflush(port, f"{testname}: Passed\n")
    if not secure:
        return checkMethod(method, port, True)

    return True

def writeflush(port, data):
    if port not in STDOUT:
        return
    STDOUT[port].write(data)
    if data[-1] != "\n":
        STDOUT[port].write("\n")
    STDOUT[port].flush()

def runTest(test, cmd, offset, port):
    global STDOUT

    if  "--norun" not in sys.argv:
        # Multiple tests in parallel, each on their own port
        port += offset

    if "--nodebug" not in sys.argv:
        cmd += f"{test[0]} --port={port} --uniqlog"

    testproc = test[1]
    data = test[2]

    # Output to file
    STDOUT[port] = open("test-%d.log" % port, "w")
    writeflush(port, f"Test {testproc.__name__} on port {port}\ncmd: {cmd}\n")

    print("Starting test %s on port %d" % (testproc.__name__, port))

    if sys.platform == "win32":
        cmd = "cmd /c start /wait /min " + cmd
    if "--norun" not in sys.argv:
        subp = subprocess.Popen(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)

        ret = True
        if testproc in [installTest, uninstallTest, testTest]:
            # Wait for Px to exit for these tests
            retcode = subp.wait()
            if retcode != 0:
                writeflush(port, f"Subprocess failed with {retcode}\n")
                ret = False

        if ret:
            # Subprocess (if applicable) was successful
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

    if not ret:
        writeflush(port, "Test failed")

    STDOUT[port].close()

    return ret

def getips():
    return [str(ip) for ip in get_host_ips()]

def checkPxStart(ip, port):
    # Make sure Px starts
    retry = 20
    if sys.platform == "darwin":
        # Nuitka builds take longer to start on OSX
        retry = 40
    while True:
        try:
            socket.create_connection((ip, port), 2)
            break
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(1)
            retry -= 1
            if retry == 0:
                writeflush(port, f"Px didn't start @ {ip}:{port}\n")
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
            writeflush(port, f"Checking {name}: {lip}:{pport}\n")
            ret = checkProc(lip, pport)

            writeflush(port, str(ret) + ": ")
            if ((lip not in ips or port != pport) and ret is False) or (lip in ips and port == pport and ret is True):
                writeflush(port, "Passed\n")
            else:
                writeflush(port, "Failed\n")
                return False

    return True

def checkSocket(ips, port):
    def checkProc(lip, pport):
        try:
            socket.create_connection((lip, pport), 1)
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
        writeflush(port, f"Returned {rcode}\n")
        if rcode == 0:
            return True
        elif rcode in [7, 52, 56]:
            return False
        else:
            writeflush(port, "Failed: curl return code is not 0, 7, 52, 56\n")
            sys.exit()

    return checkCommon("checkFilter", ips, port, checkProc)

def remoteTest(port, fail=False):
    lip = "\\$(echo \\$SSH_CLIENT | cut -d ' ' -f 1,1)"
    cmd = os.getenv("REMOTE_SSH")
    if cmd is None:
        writeflush(port, "Skipping: Remote test - REMOTE_SSH not set\n")
        writeflush(port, "  E.g. export REMOTE_SSH=plink user:pass@\n")
        writeflush(port, "  E.g. export REMOTE_SSH=ssh -i ~/.ssh/id_rsa_px user@IP\n")
        return True
    cmd = cmd + ' "curl --proxy %s:%s --connect-timeout 2 -s http://google.com"' % (lip, port)
    ret = subprocess.call(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)
    if ret == 255:
        writeflush(port, f"Skipping: Remote test - remote not up\n")
    else:
        writeflush(port, f"Checking: Remote: :{port}\n")
        if (ret == 0 and fail == False) or (ret != 0 and fail == True) :
            writeflush(port, f"Returned {ret}: Passed\n")
        else:
            writeflush(port, f"Returned {ret}: Failed\n")
            return False

    return True

def hostonlyTest(ips, port):
    return checkSocket(ips, port) and remoteTest(port, fail=True)

def gatewayTest(ips, port):
    return checkSocket(ips, port) and remoteTest(port)

def allowTest(ips, port):
    return checkFilter(ips, port) and remoteTest(port)

def allowTestNot(ips, port):
    return checkFilter(ips, port) and remoteTest(port, fail=True)

def listenTestLocal(ip, port):
    return checkSocket([ip], port) and remoteTest(port, fail=True)

def listenTestRemote(ip, port):
    return checkSocket([ip], port) and remoteTest(port)

def chainTest(proxyarg, port):
    if not checkPxStart("127.0.0.1", port):
        return False

    offset = 0
    cmd = sys.executable + " %s " % os.path.abspath("../px.py")
    if "--proxy" not in proxyarg and "--pac" not in proxyarg:
        # Upstream Px is direct
        ret = runTest((f"--test=all --proxy=127.0.0.1:{port}", testTest, None), cmd, offset, port*10)
        if not ret:
            return False
        offset += 1

        ret = runTest((f"--test=all --test-auth --proxy=127.0.0.1:{port}", testTest, None), cmd, offset, port*10)
        if not ret:
            return False
        offset += 1
    else:
        # Upstream Px may go through NTLM proxy
        if "--auth" not in proxyarg:
            # Upstream Px will authenticate
            ret = runTest((f"--test=all --auth=NONE --proxy=127.0.0.1:{port}", testTest, None), cmd, offset, port*10)
            if not ret:
                return False
            offset += 1
        else:
            # Add username to cmd if given to upstream Px
            parg = ""
            for arg in shlex.split(proxyarg):
                if arg.startswith("--username="):
                    parg = arg
                    break

            # Only works on Linux since global var propagated to child process
            parg += (" --auth=" + AUTH) if len(AUTH) != 0 else ""

            # Upstream Px will not authenticate
            ret = runTest((f"--test=all --proxy=127.0.0.1:{port} {parg}", testTest, None), cmd, offset, port*10)
            if not ret:
                return False
            offset += 1

            ret = runTest((f"--test=all --test-auth --proxy=127.0.0.1:{port} {parg}", testTest, None), cmd, offset, port*10)
            if not ret:
                return False
            offset += 1

    return True

def testTest(skip, port):
    return True

def installTest(cmd, port):
    time.sleep(1)
    ret, data = exec("reg query HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Px", port)
    if ret != 0:
        writeflush(port, f"Failed: registry query failed: {ret}\n{data}\n")
        return False
    if cmd.strip().replace("powershell -Command ", "") not in data.replace('"', ""):
        writeflush(port, f"Failed: {cmd} --install\n{data}\n")
        return False
    return True

def uninstallTest(skip, port):
    del skip
    time.sleep(1)
    ret, data = exec("reg query HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Px", port)
    if ret == 0:
        writeflush(port, f"reg query passed after uninstall\n{data}\n")
        return False
    return True

def quitTest(cmd, port):
    if not checkPxStart("127.0.0.1", port):
        writeflush(port, "Px did not start\n")
        return False

    writeflush(port, f"cmd: {cmd} --quit\n")
    ret, data = exec(cmd + "--quit", port)
    if ret != 0 or "Quitting Px .. DONE" not in data:
        writeflush(port, f"Failed: Unable to --quit Px: {ret}\n{data}\n\n")
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

            atest = allowTestNot
            if oct == "10.0":
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
            if "10.0" in ip:
                testproc = listenTestRemote

            TESTS.append((cmd, testproc, ip))

def get_newest_file(path, ext=".py"):
    files = [file for file in os.listdir(path) if file.endswith(ext)]
    latest = max(files, key=lambda file: os.path.getmtime(os.path.join(path, file)))
    return os.path.join(path, latest)

def is_obsolete(testfile):
    "Check if testfile is older than px source code - wheels or px binary are out of date"
    if not os.path.exists(testfile):
        return True

    src = "px"
    if not os.path.exists("px"):
        src = "../px"
    latest = get_newest_file(src)
    latest_date = os.path.getmtime(latest)

    testdate = os.path.getmtime(testfile)
    return testdate < latest_date

def auto():
    prefix = "px.dist"
    osname, machine, _, dist = tools.get_dirs(prefix)
    if "--norun" not in sys.argv:
        if sys.platform == "linux":
            _, distro = exec("cat /etc/os-release | grep ^ID | head -n 1 | cut -d\"=\" -f2 | sed 's/\"//g'", delete = True)
            _, version = exec("cat /etc/os-release | grep ^VERSION_ID | head -n 1 | cut -d\"=\" -f2 | sed 's/\"//g'", delete = True)
            osname += "-%s-%s" % (distro.strip(), version.strip())
        testdir = "test-%s-%d-%s" % (osname, PORT, machine)

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
        # px --test in direct, --proxy and --pac modes + --noproxy and --test-auth
        for proxyarg in getproxyargs():
            TESTS.append((proxyarg + " --test=all", testTest, None))
            TESTS.append((proxyarg + " --test=all --test-auth", testTest, None))
            if "--nonoproxy" not in sys.argv and len(proxyarg) != 0:
                TESTS.append((proxyarg + " --test=all --noproxy=*.*.*.*", testTest, None))
                TESTS.append((proxyarg + " --test=all --test-auth --noproxy=*.*.*.*", testTest, None))

        if "--nochain" not in sys.argv:
            # All above tests through Px in direct, --proxy and --pac modes + --noproxy and --auth=NONE
            for proxyarg in getproxyargs():
                # Through proxy with auth or direct
                TESTS.append((proxyarg, chainTest, proxyarg))

                if len(proxyarg) != 0:
                    # Through proxy with --auth=NONE
                    parg = proxyarg + " --auth=NONE"
                    TESTS.append((parg, chainTest, parg))

                    if "--nonoproxy" not in sys.argv:
                        # Bypass with noproxy
                        TESTS.append((proxyarg + " --noproxy=*.*.*.*", chainTest, proxyarg))

    workers = tools.get_argval("workers") or "8"
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

    # Nuitka binary test
    binfile = os.path.abspath(os.path.join("..", dist, "px"))
    if sys.platform == "win32":
        binfile += ".exe"
    if "--nobin" not in sys.argv and not is_obsolete(binfile):
        cmd = binfile + " "
        cmds.append(cmd)
        results.extend([pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))])
        offset += len(TESTS)

    # Wheel pip installed test
    prefix = "px.dist-wheels"
    _, _, _, wdist = tools.get_dirs(prefix)
    wdist = os.path.join("..", wdist)
    lwhl = get_newest_file(wdist, ".whl")
    if "--nopip" not in sys.argv and not is_obsolete(lwhl):
        # Uninstall if already installed
        cmd = sys.executable + " -m pip uninstall px-proxy -y"
        exec(cmd)

        # Install Px
        cmd = sys.executable + " -m pip install --upgrade px-proxy --no-index -f " + wdist
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
            cmd = shutil.which("px")
            if cmd is not None:
                cmd = cmd.replace(".EXE", "") + " "
                cmds.append(cmd)
                results.extend([pool.apply_async(runTest, args = (TESTS[count], cmd, count + offset, PORT)) for count in range(len(TESTS))])
                offset += len(TESTS)
            else:
                print("Skipped: console script could not be found")

    ret = waitasync(pool, results)
    if not ret:
        print("Some tests failed")
    pool.close()

    if "--norun" not in sys.argv and ret:
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

    if "--nopip" in sys.argv and not is_obsolete(lwhl):
        cmd = sys.executable + " -m pip uninstall px-proxy -y"
        exec(cmd)

    if "--norun" not in sys.argv:
        os.system("grep didn -i *.log")
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

    --nobin
        Skip testing Px binary

    --nopip
        Skip testing Px after installing with pip: python -m px

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

    --nodebug
        Run without turning on --debug

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
    PROXY = tools.get_argval("proxy") or os.getenv("PROXY", "")
    PAC = tools.get_argval("pac") or os.getenv("PAC", "")
    PORT = tools.get_argval("port") or os.getenv("PORT", "")
    if len(PORT):
        PORT = int(PORT)
    else:
        PORT = 3128
    USERNAME = tools.get_argval("username") or (
        os.getenv("OSX_USERNAME", "") if sys.platform == "darwin" else os.getenv("USERNAME", "")
    )
    if sys.platform != "win32":
        if len(USERNAME) == 0:
            print("USERNAME required on non-Windows platforms")
            sys.exit()
        USERNAME = USERNAME.replace("\\", "\\\\")
    AUTH = tools.get_argval("auth") or os.getenv("AUTH", "")

    if "--help" in sys.argv:
        print(main.__doc__)
        sys.exit()

    auto()

if __name__ == "__main__":
    main()