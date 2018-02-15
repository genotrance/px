import multiprocessing
import os
import re
import shutil
import subprocess
import sys
import time

import psutil

CURL = 'curl.exe -L -k -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36" -H "Accept-Language: en-US"'
CURL_PROXY = ' --proxy-ntlm '

BASEURL = ""
PROXY = ""

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

def check(url):
    a = curl(url, proxy=PROXY, ntlm=True)
    b = curl(url, proxy="localhost:%d" % 3128)

    la = len(a)
    lb = len(b)

    out = 100
    if la < lb:
        out = la / lb * 100
    elif la > lb:
        out = lb / la * 100

    print("%.2f%% : %s" % (out, url))

def run(base):
    pop = ""
    while True:
        pop = curl(base, proxy="localhost:%d" % 3128)
        if pop == "":
            time.sleep(0.5)
        else:
            break

    procs = []
    #urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', pop)
    urls = re.findall("http[s]?://[a-zA-Z_./0-9]+", pop)
    if len(urls) == 0:
        print("No urls found")
        return

    for url in set(urls):
        p = multiprocessing.Process(target=check, args=(url,))
        p.daemon = True
        p.start()
        procs.append(p)

        time.sleep(0.5)

    while len(procs):
        for i in procs:
            if not i.is_alive():
                procs.pop(0)
        time.sleep(0.1)

def runPxTest(cmd):
    pipe = subprocess.Popen("cmd /k start /wait " + cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    run(BASEURL)
    pxproc = psutil.Process(pipe.pid)
    for child in pxproc.children(recursive=True):
        try:
            child.kill()
        except:
            pass
    try:
        pxproc.kill()
    except:
        pass

def auto():
    # Make temp directory
    try:
        shutil.rmtree("testrun")
    except:
        pass
    os.makedirs("testrun", exist_ok=True)
    os.chdir("testrun")

    # Load base px.ini
    shutil.copy("../px.ini", ".")
    shutil.copy("../px.py", ".")
    shutil.copy("../dist/px.exe", ".")

    # Test different versions of Python
    pys = ["27", "35", "362"]
    for py in pys:
        runPxTest(("c:\\Miniconda\\envs\\%s\\python px.py --debug --proxy=" % py) + PROXY)

    # Run px.exe
    runPxTest("px --debug --proxy=" + PROXY)

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
