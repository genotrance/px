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


def exec(cmd, port=0, shell=True, delete=False):
    global COUNT
    log = "%d-%d.txt" % (port, COUNT)
    COUNT += 1
    with open(log, "wb") as l:
        p = subprocess.run(cmd, shell=shell, stdout=l,
                           stderr=subprocess.STDOUT, check=False, timeout=60)

    with open(log, "r") as l:
        data = l.read()

    if delete:
        os.remove(log)

    return p.returncode, data


def curlcli(url, port, method="GET", data="", proxy=""):
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
        return exec(cmd, port, shell=False)
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
        time.sleep(2)

        if os.system("grep fail -i *.log") == 0 and "--stoponfail" in sys.argv:
            # Kill all child processes if any - could prevent some logging
            killProcTree(os.getpid(), False)

            sys.exit()

    return ret


def writeflush(port, data):
    if port not in STDOUT:
        return
    STDOUT[port].write(f"{int(time.time())}: {data}")
    if data[-1] != "\n":
        STDOUT[port].write("\n")
    STDOUT[port].flush()


def killProcTree(pid, top=True):
    try:
        pxproc = psutil.Process(pid)
        for child in pxproc.children(recursive=True):
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        if top:
            pxproc.kill()
    except psutil.NoSuchProcess:
        pass


def runPx(name, cmd, args, port):
    cmd += f"{args} --port={port}"
    if "--nodebug" not in sys.argv:
        cmd += " --uniqlog"

    # Output to file
    STDOUT[port] = open("test-%d.log" % port, "w")
    out = f"{port}: {name}"
    print(out)
    writeflush(port, f"{out}\ncmd: {cmd}\n")

    if sys.platform == "win32":
        cmd = "cmd /c start /wait /min " + cmd

    subp = subprocess.Popen(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)

    return cmd, subp


def runTest(test, cmd, offset, port):
    start = time.time()

    if "--norun" not in sys.argv:
        # Multiple tests in parallel, each on their own port
        port += offset

    testproc = test[1]
    name = testproc.__name__
    data = test[2]

    if "--norun" not in sys.argv:
        cmd, subp = runPx(name, cmd, test[0], port)

        ret = True
        if testproc in [installTest, uninstallTest, testTest]:
            # Wait for Px to exit for these tests
            retcode = subp.wait()
            if retcode != 0:
                writeflush(port, f"Subprocess failed with {retcode}\n")
                ret = False
            else:
                writeflush(port, "Px exited\n")

        if ret:
            # Subprocess (if applicable) was successful
            ret = testproc(data, port)
            writeflush(port, f"Test completed with {ret}\n")

        # Quit Px since runtime test is done
        if testproc not in [installTest, uninstallTest, testTest, quitTest]:
            ret = quitPx(cmd, port)
            retcode = subp.wait(0.5)

            if ret == True and retcode is None:
                writeflush(port, f"Subprocess failed to exit\n")
                ret = False

        time.sleep(0.5)
    else:
        ret = testproc(data, port)

    if not ret:
        writeflush(port, "Test failed")

    writeflush(port, f"{port}: {name} took {(time.time() - start):.2f} sec\n")

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
            socket.create_connection((ip, port), 1)
            break
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(1)
            retry -= 1
            if retry == 0:
                writeflush(port, f"Px didn't start @ {ip}:{port}\n")
                return False

    return True


def getUnusedPort(port, step):
    while True:
        try:
            socket.create_connection(("127.0.0.1", port), 1)
            port += step
        except (socket.timeout, ConnectionRefusedError):
            return port


def quitPx(cmd, port):
    cmd = cmd + " --quit"
    if "--port" not in cmd:
        cmd += f" --port={port}"
    cmd = cmd.replace(" --uniqlog", "")

    writeflush(port, f"quit cmd: {cmd}\n")
    ret, data = exec(cmd)
    if ret != 0:
        writeflush(port, f"Failed: Unable to --quit Px: {ret}\n{data}\n\n")
        return False
    else:
        writeflush(port, "Px quit\n")

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
        if lip.startswith("172.1"):
            continue
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
            rcode, _ = curlcli(url="http://google.com",
                               port=port, proxy="%s:%d" % (lip, port))
        else:
            rcode, _ = tools.curl(url="http://google.com",
                                  proxy="%s:%d" % (lip, port))
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
        writeflush(
            port, "  E.g. export REMOTE_SSH=ssh -i ~/.ssh/id_rsa_px user@IP\n")
        return True
    cmd = cmd + \
        ' "curl --proxy %s:%s --connect-timeout 2 -s http://google.com"' % (
            lip, port)
    ret = subprocess.call(cmd, shell=True, stdout=DEVNULL, stderr=DEVNULL)
    if ret == 255:
        writeflush(port, f"Skipping: Remote test - remote not up\n")
    else:
        writeflush(port, f"Checking: Remote: :{port}\n")
        if (ret == 0 and fail == False) or (ret != 0 and fail == True):
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
    testflag = "--test=all"
    HTTPBIN = tools.get_argval("httpbin") or os.getenv("HTTPBIN", "")
    if len(HTTPBIN) != 0:
        # IP of local httpbin server
        testflag += f":{HTTPBIN}"
    if "--proxy" not in proxyarg and "--pac" not in proxyarg:
        # Upstream Px is direct

        # Client -> Px -> [ Px -> Target ]
        ret = runTest((f"{testflag} --proxy=127.0.0.1:{port}",
                      testTest, None), cmd, offset, port*10)
        if not ret:
            return False
        offset += 1

        # Client -> Px --auth=NONE -> [ Px -> Target ]
        ret = runTest((f"{testflag} --test-auth --proxy=127.0.0.1:{port}",
                      testTest, None), cmd, offset, port*10)
        if not ret:
            return False
        offset += 1
    else:
        # Upstream Px may go through NTLM proxy
        if "--auth=" in proxyarg:
            if "--auth=NONE" not in proxyarg:
                # Upstream Px will authenticate
                # Client -> Px --auth=NONE -> [ Px auth -> Px client auth -> Target ]
                ret = runTest(
                    (f"{testflag} --auth=NONE --proxy=127.0.0.1:{port}", testTest, None), cmd, offset, port*10)
                if not ret:
                    return False
                offset += 1
            else:
                # Upstream Px will not authenticate

                # Add username to cmd if given to upstream Px
                parg = ""
                for arg in shlex.split(proxyarg):
                    if arg.startswith("--username="):
                        parg = arg
                        break

                for auth in ["NTLM", "DIGEST", "BASIC"]:
                    # Client -> Px auth -> [ Px --auth=NONE -> Px client auth -> Target ]
                    ret = runTest((f"{testflag} --proxy=127.0.0.1:{port} {parg} --auth={
                                  auth}", testTest, None), cmd, offset, port*10)
                    if not ret:
                        return False
                    offset += 1

                    # Client auth -> Px --auth=NONE -> [ Px --auth=NONE -> Px client auth -> Target ]
                    ret = runTest((f"{testflag} --test-auth --proxy=127.0.0.1:{port} {
                                  parg} --auth={auth}", testTest, None), cmd, offset, port*10)
                    if not ret:
                        return False
                    offset += 1
        else:
            # Upstream Px will bypass proxy
            # Client -> Px -> [ Px bypass proxy -> Target ]
            ret = runTest((f"{testflag} --auth=NONE --proxy=127.0.0.1:{port}",
                          testTest, None), cmd, offset, port*10)
            if not ret:
                return False
            offset += 1

    return True


def testTest(skip, port):
    return True


def installTest(cmd, port):
    time.sleep(0.5)
    ret, data = exec(
        "reg query HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Px", port)
    if ret != 0:
        writeflush(port, f"Failed: registry query failed: {ret}\n{data}\n")
        return False
    if cmd.strip().replace("powershell -Command ", "") not in data.replace('"', ""):
        writeflush(port, f"Failed: {cmd} --install\n{data}\n")
        return False
    return True


def uninstallTest(skip, port):
    del skip
    time.sleep(0.5)
    ret, data = exec(
        "reg query HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Px", port)
    if ret == 0:
        writeflush(port, f"reg query passed after uninstall\n{data}\n")
        return False
    return True


def quitTest(cmd, port):
    if not checkPxStart("127.0.0.1", port):
        writeflush(port, "Px did not start\n")
        return False

    return quitPx(cmd, port)


def getproxyargs():
    proxyargs = []
    proxyarg = ""
    proxyarg += (" --username=" + USERNAME) if len(USERNAME) != 0 else ""

    if "--noserver" not in sys.argv:
        if len(PROXY) != 0:
            # Use specified proxy server
            proxyargs.append("--proxy=" + PROXY + proxyarg)
        else:
            # PORT will be filled later depending on which upstream Px to use
            proxyargs.append("--proxy=127.0.0.1:PORT " + proxyarg)

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
            if ip.startswith("172.1"):
                continue
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
        for ip in localips:
            if ip.startswith("172.1"):
                continue
            cmd = ""
            if ip != "":
                cmd = "--listen=" + ip

            testproc = listenTestLocal
            if "10.0" in ip:
                testproc = listenTestRemote

            TESTS.append((cmd, testproc, ip))


def get_newest_file(path, ext=".py"):
    if not os.path.exists(path):
        return ""
    files = [file for file in os.listdir(path) if file.endswith(ext)]
    latest = max(files, key=lambda file: os.path.getmtime(
        os.path.join(path, file)))
    return os.path.join(path, latest)


def is_obsolete(testfile):
    "Check if testfile is older than px source code - wheels or px binary are out of date"
    if not os.path.exists(testfile):
        return True

    src = "px"
    if not os.path.exists("px"):
        src = "../px"
    latest = get_newest_file(src)
    if len(latest) == 0:
        return True
    latest_date = os.path.getmtime(latest)

    testdate = os.path.getmtime(testfile)
    return testdate < latest_date


def auto():
    if "--norun" not in sys.argv:
        osname = tools.get_os()
        if sys.platform == "linux":
            _, distro = exec(
                "cat /etc/os-release | grep ^ID | head -n 1 | cut -d\"=\" -f2 | sed 's/\"//g'", delete=True)
            _, version = exec(
                "cat /etc/os-release | grep ^VERSION_ID | head -n 1 | cut -d\"=\" -f2 | sed 's/\"//g'", delete=True)
            osname += "-%s-%s" % (distro.strip(), version.strip())
        testdir = f"test-{PORT}-{osname}-{platform.machine().lower()}"

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

    # Setup script, bin and pip command lines
    cmds = []
    subps = []
    client_cmd = "--client-auth=ANY"
    if sys.platform == "win32":
        client_cmd += " --client-nosspi"

    if "--noscript" not in sys.argv:
        # Run as script - python px.py
        cmd = sys.executable + " %s " % os.path.abspath("../px.py")
        cmds.append(cmd)

        # Start client authenticating Px
        if len(PROXY) == 0 and "--noproxy" not in sys.argv:
            subps.append(
                runPx("scriptMode", cmd, client_cmd, PORT+len(cmds)-1))

    # Nuitka binary test
    _, _, dist = tools.get_paths("px.dist")
    binfile = os.path.abspath(os.path.join("..", dist, "px"))
    if sys.platform == "win32":
        binfile += ".exe"
    if "--nobin" not in sys.argv and not is_obsolete(binfile):
        cmd = binfile + " "
        cmds.append(cmd)

        # Start client authenticating Px
        if len(PROXY) == 0 and "--noproxy" not in sys.argv:
            subps.append(runPx("binary", cmd, client_cmd, PORT+len(cmds)-1))
    else:
        binfile = ""

    # Wheel pip installed test
    _, _, wdist = tools.get_paths("px.dist", "wheels")
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

            # Start client authenticating Px
            if len(PROXY) == 0 and "--noproxy" not in sys.argv:
                subps.append(
                    runPx("pipModule", cmd, client_cmd, PORT+len(cmds)-1))

            # Run as Python console script
            cmd = shutil.which("px")
            if cmd is not None:
                cmd = cmd.replace(".EXE", "") + " "
                cmds.append(cmd)

                # Start client authenticating Px
                if len(PROXY) == 0 and "--noproxy" not in sys.argv:
                    subps.append(
                        runPx("pipBinary", cmd, client_cmd, PORT+len(cmds)-1))
            else:
                print("Skipped: console script could not be found")
    else:
        lwhl = ""

    # Setup tests
    if "--nosocket" not in sys.argv:
        socketTestSetup()
    if "--noproxy" not in sys.argv:
        # px --test in direct, --proxy and --pac modes + --noproxy and --test-auth
        testflag = "--test=all"
        if len(HTTPBIN) != 0:
            # IP of local httpbin server
            testflag += f":{HTTPBIN}"
        for proxyarg in getproxyargs():
            if len(proxyarg) != 0:
                for auth in ["NTLM", "DIGEST", "BASIC"]:
                    # Going through proxy with different auth methods

                    # Client -> Px auth -> Px client auth -> Target
                    TESTS.append(
                        (f"{proxyarg} {testflag} --auth={auth}", testTest, None))

                    # Client auth -> Px --auth=NONE -> Px client auth -> Target
                    TESTS.append(
                        (f"{proxyarg} {testflag} --test-auth --auth={auth}", testTest, None))

                if "--nonoproxy" not in sys.argv and len(proxyarg) != 0:
                    # Going through proxy but bypassing it with noproxy - no authentication

                    # Client -> Px auth bypass proxy -> Target
                    TESTS.append(
                        (f"{proxyarg} {testflag} --noproxy=*.*.*.*", testTest, None))

                    # Client auth -> Px bypass proxy -> Target
                    TESTS.append(
                        (f"{proxyarg} {testflag} --test-auth --noproxy=*.*.*.*", testTest, None))
            else:
                # Direct test - no upstream proxy - no authentication
                # Client -> Px -> Target
                TESTS.append((f"{testflag}", testTest, None))

        if "--nochain" not in sys.argv:
            # All above tests through Px in direct, --proxy and --pac modes + --noproxy and --auth=NONE
            for proxyarg in getproxyargs():
                if len(proxyarg) == 0:
                    # Direct test - no authentication
                    # ? -> [ Px -> Target ]
                    TESTS.append((proxyarg, chainTest, proxyarg))
                else:
                    # Through proxy
                    for auth in ["NTLM", "DIGEST", "BASIC"]:
                        # With authentication
                        # ? -> [ Px auth -> Px client auth -> Target ]
                        parg = f"{proxyarg} --auth={auth}"
                        TESTS.append((parg, chainTest, parg))

                    # With --auth=NONE
                    # ? -> [ Px --auth=NONE -> Px client auth -> Target ]
                    parg = proxyarg + " --auth=NONE"
                    TESTS.append((parg, chainTest, parg))

                    if "--nonoproxy" not in sys.argv:
                        # Bypass with noproxy
                        # ? -> [ Px auth bypass proxy -> Target ]
                        TESTS.append(
                            (proxyarg + " --noproxy=*.*.*.*", chainTest, proxyarg))

    time.sleep(1)

    workers = tools.get_argval("workers") or "8"
    pool = multiprocessing.Pool(processes=int(workers))

    def getTests(ncmd):
        if len(PROXY) == 0:
            tests = []
            for test in TESTS:
                tests.append(
                    (test[0].replace("PORT", str(PORT+ncmd)), test[1], test[2]))
        else:
            tests = TESTS

        return tests

    ncmd = 0
    offset = len(cmds)
    results = []
    if "--noscript" not in sys.argv:
        # Run as script - python px.py
        tests = getTests(ncmd)
        cmd = cmds[ncmd]
        ncmd += 1
        results = [pool.apply_async(runTest, args=(
            tests[count], cmd, count + offset, PORT)) for count in range(len(tests))]
        offset += len(TESTS)

    # Nuitka binary test
    if len(binfile) != 0:
        tests = getTests(ncmd)
        cmd = cmds[ncmd]
        ncmd += 1
        results.extend([pool.apply_async(runTest, args=(
            tests[count], cmd, count + offset, PORT)) for count in range(len(tests))])
        offset += len(TESTS)

    # Wheel pip installed test
    if len(lwhl) != 0:
        # Run as module - python -m px
        tests = getTests(ncmd)
        cmd = cmds[ncmd]
        ncmd += 1
        results.extend([pool.apply_async(runTest, args=(
            tests[count], cmd, count + offset, PORT)) for count in range(len(tests))])
        offset += len(TESTS)

        # Run as Python console script
        if len(cmds) != 0:
            tests = getTests(ncmd)
            cmd = cmds[ncmd]
            ncmd += 1
            results.extend([pool.apply_async(runTest, args=(
                tests[count], cmd, count + offset, PORT)) for count in range(len(tests))])
            offset += len(TESTS)

    ret = waitasync(pool, results)
    if not ret:
        print("Some tests failed")
    pool.close()

    # Quit client authenticating Px if any
    for i, cmd in enumerate(cmds):
        port = PORT+i
        quitPx(cmd, port)
    for _, subp in subps:
        retcode = subp.wait(0.5)
        if retcode is None:
            killProcTree(subp.pid)

    if "--norun" not in sys.argv and ret:
        # Sequential tests - cannot parallelize
        if sys.platform == "win32" and "--noinstall" not in sys.argv:
            for shell in ["", "powershell -Command "]:
                for cmd in cmds:
                    cmd = shell + cmd
                    runTest(("--install", installTest, cmd), cmd, offset, PORT)
                    offset += 1

                    runTest(("--uninstall", uninstallTest, cmd),
                            cmd, offset, PORT)
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

                    runTest(("", quitTest, shell + cmd),
                            shell + cmd, offset, PORT)
                    offset += 1

    if len(lwhl) != 0:
        cmd = sys.executable + " -m pip uninstall px-proxy -y"
        exec(cmd)

    if "--norun" not in sys.argv:
        os.system("grep didn -i *.log")
        os.system("grep failed -i *.log")
        os.system("grep traceback -i *.log")
        os.system("grep error -i *.log")

        os.system("grep took -h *.log")

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

    --workers=8
        Number of parallel tests to run

    --httpbin=IPaddress
        IP of local httpbin server running in Docker

    --stoponfail
        Stop on first test failure

    --curlcli
        Use curl command line instead of px.mcurl
    """

    global PROXY
    global PAC
    global PORT
    global USERNAME
    global HTTPBIN
    PROXY = tools.get_argval("proxy") or os.getenv("PROXY", "")
    PAC = tools.get_argval("pac") or os.getenv("PAC", "")
    PORT = tools.get_argval("port") or os.getenv("PORT", "")
    if len(PORT):
        PORT = int(PORT)
    else:
        PORT = getUnusedPort(3128, 200)
    USERNAME = tools.get_argval("username") or (
        os.getenv("OSX_USERNAME", "") if sys.platform == "darwin" else os.getenv(
            "USERNAME", "")
    )
    if sys.platform != "win32":
        if len(USERNAME) == 0:
            print("USERNAME required on non-Windows platforms")
            sys.exit()
        USERNAME = USERNAME.replace("\\", "\\\\")
    HTTPBIN = tools.get_argval("httpbin") or os.getenv("HTTPBIN", "")

    if "--help" in sys.argv:
        print(main.__doc__)
        sys.exit()

    start = time.time()
    auto()
    print(f"Took {(time.time()-start):.2f} sec")


if __name__ == "__main__":
    main()
