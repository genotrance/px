import multiprocessing
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import traceback

import psutil

CURL = 'curl.exe -s -L -k -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36" -H "Accept-Language: en-US"'
CURL_PROXY = ' --proxy-ntlm '

BASEURL = ""
PROXY = ""
TESTS = []

try:
    ConnectionRefusedError
except NameError:
    ConnectionRefusedError = socket.error

def exec_output(cmd):
    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
    if pipe != None:
        output = pipe.read().decode("UTF-8", "ignore")
    else:
        print("Error running curl")
        sys.exit()

    return output

def curl(url, proxy="", ntlm=False, filename="", head=False):
    output = ""
    cmd = CURL
    if filename:
        cmd += " -o " + filename
    if head:
        cmd += ' -I'

    if proxy:
        cmd += " --proxy " + proxy
    if ntlm:
        cmd += ' --proxy-ntlm -U :'

    cmd += ' "%s"' % url

    if "--debug" in sys.argv:
        print(cmd)

    return exec_output(cmd)

def getPyversion(cmd):
    return int(exec_output(cmd + " -V").split(" ")[1].replace(".", ""))

def write(data, file):
    with open(file, "w") as f:
        f.write(data)

def check(url, proxy, port):
    start = time.time()
    a = curl(url, proxy=proxy, ntlm=True)
    end = time.time()

    ta = end - start
    b = curl(url, proxy="localhost:%d" % port)
    tb = time.time() - end

    la = len(a)
    lb = len(b)

    out = 100
    if la < lb:
        out = la / lb * 100
    elif la > lb:
        out = lb / la * 100

    print("  %.2f%%\t%.2fx\t%s" % (out, tb / ta, url))

def waitprocs(procs):
    ret = True
    while len(procs):
        for i in range(len(procs)):
            if not procs[i].is_alive():
                if procs[i].exitcode:
                    ret = False
                procs.pop(i)
                break
        time.sleep(0.1)

    return ret

def run(base, port):
    if not checkPxStart("localhost", port):
        return False

    start = time.time()
    pop = ""
    while True:
        pop = curl(base, proxy="localhost:%d" % port)
        if pop == "":
            time.sleep(0.5)
        else:
            break

    procs = []
    #urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', pop)
    urls = re.findall("http[s]?://[a-zA-Z_./0-9-]+", pop)
    if len(urls) == 0:
        print("No urls found")
        return False

    for url in set(urls):
        p = multiprocessing.Process(target=check, args=(url, PROXY, port))
        #p.daemon = True
        p.start()
        procs.append(p)

        time.sleep(0.5)

    ret = True
    if not waitprocs(procs):
        ret = False

    end = time.time()
    print(("  Time: %.2fs" % (end-start)) + " sec")

    return ret

def runPxTest(cmd, testproc, ips, port, proxy):
    global PROXY
    PROXY = proxy

    pipe = subprocess.Popen("cmd /k start /wait /min " + cmd + " --port=" + str(port), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    ret = testproc(ips, port)

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

    return ret

def runTest(test, python, count):
    port = 3129
    cmd = "px "
    if python:
        port = getPyversion(python) * 10
        cmd = python + " px.py "

    cmd += "--debug --uniqlog " + test[0] + " --port=" + str(port)
    testproc = test[1]
    ips = test[2]

    print("Test %d: \"" % count + test[0] + "\" on port " + str(port))
    p = multiprocessing.Process(target=runPxTest, args=(cmd, testproc, ips, port, PROXY))
    p.start()

    return p

def getips():
    localips = [ip[4][0] for ip in socket.getaddrinfo(socket.gethostname(), 80, socket.AF_INET)]
    localips.insert(0, "127.0.0.1")

    return localips

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
                print("Px didn't start")
                return False

    return True

# Test --listen and --port, --hostonly, --gateway and --allow
def checkCommon(ips, port, checkProc):
    if ips == [""]:
        ips = ["127.0.0.1"]

    if port == "":
        port = "3128"
    port = int(port)

    if not checkPxStart(ips[0], port):
        return False

    localips = getips()
    for lip in localips:
        for pport in set([3128, port]):
            sys.stdout.write("  Checking: " + lip + ":" + str(pport) + " = ")
            ret = checkProc(lip, pport)

            sys.stdout.write(str(ret) + ": ")
            if ((lip not in ips or port != pport) and ret is False) or (lip in ips and port == pport and ret is True):
                print("Passed")
            else:
                print("Failed")
                return False

    return True

def checkSocket(ips, port):
    def checkProc(lip, pport):
        try:
            socket.create_connection((lip, pport), 2)
        except (socket.timeout, ConnectionRefusedError):
            return False

        return True

    return checkCommon(ips, port, checkProc)

def checkFilter(ips, port):
    def checkProc(lip, port):
        rcode = subprocess.call("curl --proxy " + lip + ":" + str(port) + " http://google.com",
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sys.stdout.write(str(rcode) + " ")
        if rcode == 0:
            return True
        elif rcode in [7, 52, 56]:
            return False
        else:
            print("Weird curl return " + str(rcode))
            sys.exit()

    return checkCommon(ips, port, checkProc)

def remoteTest(port, fail=False):
    lip = 'echo $SSH_CLIENT ^| cut -d \\\" \\\" -f 1,1'
    cmd = os.getenv("REMOTE_SSH")
    if cmd is None:
        print("Skipping remote test - REMOTE_SSH not set")
        return
    cmd = cmd + " curl --proxy `%s`:%s --connect-timeout 2 -s http://google.com" % (lip, port)
    sys.stdout.write("  Checking: Remote:" + str(port) + " = ")
    ret = subprocess.call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if (ret == 0 and fail == False) or (ret != 0 and fail == True) :
        print(str(ret) + ": Passed")
    else:
        print(str(ret) + ": Failed")
        return False

    return True

def hostonlyTest(ips, port):
    return checkSocket(ips, port) and remoteTest(port, fail=True)

def gatewayTest(ips, port):
    return checkSocket(ips, port) and remoteTest(port)

def allowTest127(ips, port):
    return checkFilter(ips, port) and remoteTest(port, fail=True)

def allowTest169(ips, port):
    return checkFilter(ips, port) and remoteTest(port, fail=True)

def allowTest192(ips, port):
    return checkFilter(ips, port) and remoteTest(port)

def listenTestLocal(ip, port):
    return checkSocket([ip], port) and remoteTest(port, fail=True)

def listenTestRemote(ip, port):
    return checkSocket([ip], port) and remoteTest(port)

def proxyTest(base, port):
    return run(base, port)

def noproxyTest(base, port):
    return run(base, port)

def socketTestSetup():
    if "--nohostonly" not in sys.argv:
        TESTS.append(("--proxy=" + PROXY + " --hostonly", hostonlyTest, getips()))

    if "--nogateway" not in sys.argv:
        TESTS.append(("--proxy=" + PROXY + " --gateway", gatewayTest, getips()))

    if "--noallow" not in sys.argv:
        TESTS.append(("--proxy=" + PROXY + " --gateway --allow=127.*.*.*",
            allowTest127, [""]))

        TESTS.append(("--proxy=" + PROXY + " --gateway --allow=169.*.*.*",
            allowTest169, list(filter(lambda x: "169" in x, getips()))))

        TESTS.append(("--proxy=" + PROXY + " --gateway --allow=192.*.*.*",
            allowTest192, list(filter(lambda x: "192" in x, getips()))))

    if "--nolisten" not in sys.argv:
        localips = getips()
        localips.insert(0, "")
        localips.remove("127.0.0.1")
        for ip in localips[:3]:
            cmd = "--proxy=" + PROXY
            if ip != "":
                cmd += " --listen=" + ip

            testproc = listenTestLocal
            if "192" in ip:
                testproc = listenTestRemote

            TESTS.append((cmd, testproc, ip))

def auto():
    # Make temp directory
    try:
        shutil.rmtree("testrun")
    except:
        pass
    time.sleep(1)
    try:
        os.makedirs("testrun", exist_ok=True)
    except TypeError:
        try:
            os.makedirs("testrun")
        except WindowsError:
            pass

    os.chdir("testrun")

    # Load base px.ini
    shutil.copy("../px.ini", ".")
    shutil.copy("../px.py", ".")
    shutil.copy("../dist/px.exe", ".")

    # Setup tests
    socketTestSetup()
    if "--noproxy" not in sys.argv:
        TESTS.append(("--workers=4 --proxy=" + PROXY, proxyTest, BASEURL))
    if "--nonoproxy" not in sys.argv:
        TESTS.append(("--workers=4 --threads=30 --noproxy=*.*.*.*", noproxyTest, BASEURL))

    count = 1
    for test in TESTS:
        procs = []

        # Latest version
        procs.append(runTest(test, "c:\\Miniconda\\python", count))
        count += 1

        # Test different versions of Python
        pys = ["27", "34", "35"]
        for py in pys:
            procs.append(runTest(test, "c:\\Miniconda\\envs\\%s\\python" % py, count))
            count += 1

        # Run px.exe
        procs.append(runTest(test, None, count))
        count += 1

        if not waitprocs(procs):
            break

    os.chdir("..")

if __name__ == "__main__":
    """python test.py testproxy.org:80 http://baseurl.com
        Point test.py to the NTLM proxy server that Px should connect through

        Base URL is some base webpage which will be spidered for URLs to
        compare results directly through proxy and through Px"""

    if len(sys.argv) > 1:
        PROXY = sys.argv[1]
    if len(sys.argv) > 2:
        BASEURL = sys.argv[2]

    if PROXY == "" or BASEURL == "":
        sys.exit()

    auto()
