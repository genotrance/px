from difflib import SequenceMatcher

import multiprocessing
import re
import subprocess
import sys
import time

import px

CURL = 'curl.exe -L -k -A "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36" -H "Accept-Language: en-US"'
CURL_PROXY  = ' --proxy-ntlm '

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
    px.parsecli()

    a = curl(url, proxy="%s:%d" % (px.NTLM_PROXY[0], px.NTLM_PROXY[1]))
    b = curl(url, proxy="localhost:%d" % px.PORT)

    la = len(a)
    lb = len(b)
    
    out = 100
    if la < lb:
        out = la / lb * 100
    elif la > lb:
        out = lb / la * 100

    print("%.2f%% : %s" % (out, url))

def run(base):
    px.parsecli()
    pop = curl(base, proxy="localhost:%d" % px.PORT)
    
    urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', pop)
    for url in set(urls):
        p = multiprocessing.Process(target=check, args=(url,))
        p.daemon = True
        p.start()
        
        time.sleep(0.5)

if __name__ == "__main__":
    """python test.py --proxy=testproxy.org:80 http://baseurl.com
        Point test.py to the same proxy server that Px is connected through
        Base URL is some base webpage which will be spidered for URLs to
        compare results directly through proxy and through Px"""
    for arg in sys.argv[1:]:
        if "--" in arg: continue

        run(arg)