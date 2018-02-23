import multiprocessing
import os
import re
import shutil
import socket
import subprocess
import sys
import time

import psutil

CURL = 'curl.exe -L -k -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36" -H "Accept-Language: en-US"'
CURL_PROXY = ' --proxy-ntlm '

BASEURL = ""
PROXY = ""
TESTS = []

try:
    ConnectionRefusedError
except NameError:
    ConnectionRefusedError = socket.error

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

    pipe = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    if pipe != None:
        output = pipe.read().decode("UTF-8", "ignore")
    else:
        print("Error running curl")
        sys.exit()

    return output

def write(data, file):
    with open(file, "w") as f:
        f.write(data)

def check(url, proxy):
    a = curl(url, proxy=proxy, ntlm=True)
    b = curl(url, proxy="localhost:%d" % 3128)

    la = len(a)
    lb = len(b)

    out = 100
    if la < lb:
        out = la / lb * 100
    elif la > lb:
        out = lb / la * 100

    print("  %.2f%% : %s" % (out, url))

def run(base):
    start = time.time()
    pop = ""
    while True:
        pop = curl(base, proxy="localhost:%d" % 3128)
        if pop == "":
            time.sleep(0.5)
        else:
            break

    procs = []
    #urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', pop)
    urls = re.findall("http[s]?://[a-zA-Z_./0-9-]+", pop)
    if len(urls) == 0:
        print("No urls found")
        return

    for url in set(urls):
        p = multiprocessing.Process(target=check, args=(url, PROXY))
        p.daemon = True
        p.start()
        procs.append(p)

        time.sleep(0.5)

    while len(procs):
        for i in range(len(procs)):
            if not procs[i].is_alive():
                procs.pop(i)
                break
        time.sleep(0.1)

    end = time.time()
    print("  Time: " + str(end-start) + " sec")

def runPxTest(cmd, testproc):
    pipe = subprocess.Popen("cmd /k start /wait /min " + cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    testproc()

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

def getips():
    localips = [ip[4][0] for ip in socket.getaddrinfo(socket.gethostname(), 80, socket.AF_INET)]
    localips.insert(0, "127.0.0.1")

    return localips

# Test --listen and --port
def checkSocket(ip, port):
    if ip == "":
        ip = "127.0.0.1"

    if port == "":
        port = "3128"
    port = int(port)

    # Make sure Px starts
    retry = 10
    while True:
        try:
            socket.create_connection((ip, port), 2)
            break
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(1)
            retry -= 1
            if retry == 0:
                print("Px didn't start")
                sys.exit()

    localips = getips()
    for lip in localips:
        for pport in set([3128, port]):
            sys.stdout.write("  Checking: " + lip + ":" + str(pport) + " = ")
            ret = True
            try:
                socket.create_connection((lip, pport), 2)
            except (socket.timeout, ConnectionRefusedError):
                ret = False

            sys.stdout.write(str(ret) + ": ")
            if ((lip != ip or port != pport) and ret is False) or (lip == ip and port == pport and ret is True):
                print("Passed")
            else:
                print("Failed")
                sys.exit()

def socketTestSetup():
    localips = getips()
    localips.insert(0, "")
    for ip in localips[:3]:
        for port in ["", "3129"]:
            cmd = "--proxy=" + PROXY
            if ip != "":
                cmd += " --listen=" + ip
            if port != "":
                cmd += " --port=" + port

            TESTS.append((cmd, lambda ip=ip, port=port: checkSocket(ip, port)))

def auto():
    # Make temp directory
    try:
        shutil.rmtree("testrun")
    except:
        pass
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
    if "--nosock" not in sys.argv:
        socketTestSetup()
    if "--noproxy" not in sys.argv:
        TESTS.append(("--workers=4 --proxy=" + PROXY, lambda: run(BASEURL)))
    if "--nonoproxy" not in sys.argv:
        TESTS.append(("--workers=4 --threads=30 --proxy=none --noproxy=*.*.*.*", lambda: run(BASEURL)))

    count = 1
    for test in TESTS:
        # Test different versions of Python
        pys = ["27", "35", "362"]
        for py in pys:
            print("Test %d: \"" % count + test[0] + "\" with Python " + py)
            runPxTest(("c:\\Miniconda\\envs\\%s\\python px.py --debug " % py) + test[0], test[1])
            count += 1

        # Run px.exe
        print("Test %d: \"" % count + test[0] + "\" with Px.exe ")
        runPxTest("px --debug " + test[0], test[1])
        count += 1

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
