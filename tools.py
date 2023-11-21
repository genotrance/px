import glob
import hashlib
import json
import os
import platform
import re
import shutil
import sys
import time
import zipfile

if "--libcurl" not in sys.argv:
    from px import mcurl
else:
    import urllib.request

from px.version import __version__

REPO = "genotrance/px"

# CLI

def get_argval(name):
    for i in range(len(sys.argv)):
        if "=" in sys.argv[i]:
            val = sys.argv[i].split("=")[1]
            if ("--%s=" % name) in sys.argv[i]:
                return val

    return ""

def get_auth():
    token = get_argval("token")
    if token:
        return {"Authorization": "token %s" % token}

    print("No --token= specified")

    sys.exit(1)

# File utils

def rmtree(dirs):
    for dir in dirs.split(" "):
        while os.path.exists(dir):
            shutil.rmtree(dir, True)
            time.sleep(0.2)

def copy(files, dir):
    for file in files.split(" "):
        shutil.copy(file, dir)

def remove(files):
    for file in files.split(" "):
        if "*" in file:
            for match in glob.glob(file):
                try:
                    os.remove(match)
                except:
                    pass
        else:
            try:
                os.remove(file)
            except:
                pass

def extract(zfile, fileend):
    with zipfile.ZipFile(zfile) as czip:
        for file in czip.namelist():
            if file.endswith(fileend):
                member = czip.open(file)
                with open(os.path.basename(file), "wb") as base:
                    shutil.copyfileobj(member, base)

# OS

def get_os():
    if sys.platform == "linux":
        if os.system("ldd /bin/ls | grep musl > /dev/null") == 0:
            return "linux-musl"
        else:
            return "linux-glibc"
    elif sys.platform == "win32":
        return "windows"
    elif sys.platform == "darwin":
        return "osx"

    return "unsupported"

def get_dirs(prefix):
    osname = get_os()
    outdir = "%s-%s-%s" % (prefix, osname, platform.machine().lower())
    dist = os.path.join(outdir, prefix)

    return osname, outdir, dist

# URL

def curl(url, method = "GET", proxy = None, headers = None, data = None, rfile = None, rfile_size = 0, wfile = None, encoding="utf-8"):
    """
    data - for POST/PUT
    rfile - upload from open file - requires rfile_size
    wfile - download into open file
    """
    if mcurl.MCURL is None:
        mc = mcurl.MCurl(debug_print = None)
    ec = mcurl.Curl(url, method)
    ec.set_debug()

    if proxy is not None:
        ec.set_proxy(proxy)

    if data is not None:
        # POST/PUT
        if headers is None:
            headers = {}
        headers["Content-Length"] = len(data)

        ec.buffer(data.encode("utf-8"))
    elif rfile is not None:
        # POST/PUT file
        if headers is None:
            headers = {}
        headers["Content-Length"] = rfile_size

        ec.bridge(client_rfile = rfile, client_wfile = wfile)
    elif wfile is not None:
        ec.bridge(client_wfile = wfile)
    else:
        ec.buffer()

    if headers is not None:
        ec.set_headers(headers)

    ec.set_useragent("mcurl v" + __version__)
    ret = ec.perform()
    if ret != 0:
        return ret, ec.errstr

    if wfile is not None:
        return 0, ""

    return 0, ec.get_data(encoding)

def get_curl():
    os.chdir("px/libcurl")

    try:
        for bit, ext in {"32": "", "64": "-x64"}.items():
            lcurl = "libcurl%s.dll" % ext
            lcurlzip = "curl%s.zip" % bit
            if not os.path.exists(lcurl):
                if not os.path.exists(lcurlzip):
                    urllib.request.urlretrieve("https://curl.se/windows/latest.cgi?p=win%s-mingw.zip" % bit, lcurlzip)
                extract(lcurlzip, lcurl)

                if not os.path.exists("curl-ca-bundle.crt"):
                    # Extract CAINFO bundle
                    extract(lcurlzip, "curl-ca-bundle.crt")

                while not os.path.exists(lcurl):
                    time.sleep(0.5)

                if shutil.which("strip") is not None:
                    os.system("strip -s " + lcurl)
                if shutil.which("upx") is not None:
                    os.system("upx --best " + lcurl)

                if os.path.exists(lcurl):
                    os.remove(lcurlzip)

    finally:
        os.chdir("../..")

# Build

def wheel():
    rmtree("build wheel")

    for args in ["--universal", "-p win32", "-p win-amd64"]:
        while True:
            rmtree("build")
            if os.system(sys.executable + " setup.py bdist_wheel -d wheel -k %s" % args) == 0:
                break
            time.sleep(0.5)

    # Check wheels
    os.system(sys.executable + " -m twine check wheel/*")

    rmtree("build px_proxy.egg-info")

def pyinstaller():
    _, dist, _ = get_dirs("pyinst")
    rmtree("build dist " + dist)

    os.system("pyinstaller --clean --noupx -w px.py --collect-submodules win32ctypes")
    copy("px.ini HISTORY.txt LICENSE.txt README.md", "dist")

    time.sleep(1)
    os.remove("px.spec")
    rmtree("build")
    os.rename("dist", dist)

def nuitka():
    prefix = "px.dist"
    osname, outdir, dist = get_dirs(prefix)
    rmtree(outdir)

    # Build
    flags = ""
    if sys.platform == "win32":
        # keyring dependency
        flags = "--include-package=win32ctypes"
    os.system(sys.executable + " -m nuitka --standalone %s --prefer-source-code --output-dir=%s px.py" % (flags, outdir))
    copy("px.ini HISTORY.txt LICENSE.txt README.md", dist)
    if sys.platform == "win32":
        pxdir = os.path.join(dist, "px")
        lcdir = os.path.join(pxdir, "libcurl")
        os.mkdir(pxdir)
        os.mkdir(lcdir)
        # 64-bit only for Windows for now
        copy(os.path.join("px", "libcurl", "libcurl-x64.dll"), lcdir)
        copy(os.path.join("px", "libcurl", "curl-ca-bundle.crt"), lcdir)

    time.sleep(1)

    # Compress some binaries
    os.chdir(dist)
    if shutil.which("upx") is not None:
        if sys.platform == "win32":
            os.system("upx --best px.exe python3*.dll libcrypto*.dll")
        else:
            os.rename("px.bin", "px")
            os.system("upx --best px")

    # Create archive
    os.chdir("..")
    archfile = "px-v%s-%s" % (__version__, osname)
    arch = "gztar"
    if sys.platform == "win32":
        arch = "zip"
    shutil.make_archive(archfile, arch, prefix)

    # Create hashfile
    if arch == "gztar":
        arch = "tar.gz"
    archfile += "." + arch
    with open(archfile, "rb") as afile:
        sha256sum = hashlib.sha256(afile.read()).hexdigest()
    with open(archfile + ".sha256", "w") as shafile:
        shafile.write(sha256sum)

    os.chdir("..")

def get_pip(executable = sys.executable):
    # Download get-pip.py
    url = "https://bootstrap.pypa.io/get-pip.py"
    ret, data = curl(url)
    if ret != 0:
        print(f"Failed to download get-pip.py with error {ret}")
        sys.exit()
    with open("get-pip.py", "w") as gp:
        gp.write(data)

    # Run it with Python
    os.system(f"{executable} get-pip.py")

    # Remove get-pip.py
    os.remove("get-pip.py")

def embed():
    # Get wheels path
    wprefix = "px.dist-wheels"
    _, _, wdist = get_dirs(wprefix)
    if not os.path.exists(wdist):
        print(f"Wheels not found at {wdist}, required to embed")
        sys.exit()

    # Destination path
    prefix = "px.dist"
    osname, outdir, dist = get_dirs(prefix)
    rmtree(outdir)
    os.makedirs(dist, exist_ok=True)

    # Get latest releases from web
    ret, data = curl("https://www.python.org/downloads/windows/")

    # Get Python version from CLI if specified
    version = get_argval("tag")

    # Find all URLs for zip files in webpage
    urls = re.findall(r'href=[\'"]?([^\'" >]+\.zip)', data)
    dlurl = ""
    for url in urls:
        # Filter embedded amd64 URLs
        if "embed" in url and "amd64" in url:
            # Get the first or specified version URL
            if len(version) == 0 or version in url:
                dlurl = url
                break

    # Download zip file
    fname = os.path.join(outdir, os.path.basename(dlurl))
    if not os.path.exists(fname):
        ret, data = curl(dlurl, encoding=None)
        if ret != 0:
            print(f"Failed to download {dlurl} with error {ret}")
            sys.exit()

        # Write data to file
        with open(fname, "wb") as f:
            f.write(data)

        # Unzip
        with zipfile.ZipFile(fname, "r") as z:
            z.extractall(dist)

    # Find all files ending with ._pth
    pth = glob.glob(os.path.join(dist, "*._pth"))[0]

    # Update ._pth file
    with open(pth, "r") as f:
        data = f.read()
    if "Lib" not in data:
        with open(pth, "w") as f:
            f.write(data.replace("\n.", "\n.\nLib\nLib\\site-packages"))

    # Setup pip
    if not os.path.exists(os.path.join(dist, "Lib")):
        executable = os.path.join(dist, "python.exe")
        get_pip(executable)

        # Setup px
        os.system(f"{executable} -m pip install px-proxy --no-index -f {wdist} --no-warn-script-location")

        # Remove pip
        os.system(f"{executable} -m pip uninstall setuptools wheel pip -y")

    # Move px.exe and update interpreter path
    pxexe = os.path.join(dist, "px.exe")
    os.rename(os.path.join(dist, "Scripts", "px.exe"), pxexe)

    # Update px.exe
    with open(pxexe, "rb") as f:
        data = f.read()

    dataout = bytearray()
    skip = False
    for i, byte in enumerate(data):
        if byte == 0x23 and data[i+1] == 0x21:  #!
            if (data[i+2] >= 0x41 and data[i+2] <= 0x5a) or \
                (data[i+2] >= 0x61 and data[i+2] <= 0x7a):    # A-Za-z - drive letter
                if data[i+3] == 0x3A: # Colon
                    skip = True
                    continue

        if skip:
            if byte == 0x0A:
                skip = False
                dataout += b"#!python.exe"
            else:
                continue

        dataout.append(byte)

    with open(pxexe, "wb") as f:
        f.write(dataout)

    # Compress some binaries
    os.chdir(dist)
    if shutil.which("upx") is not None:
        os.system("upx --best python3*.dll libcrypto*.dll")

    # Create archive
    os.chdir("..")
    archfile = "px-v%s-%s" % (__version__, osname)
    arch = "zip"
    shutil.make_archive(archfile, arch, prefix)

    # Create hashfile
    archfile += "." + arch
    with open(archfile, "rb") as afile:
        sha256sum = hashlib.sha256(afile.read()).hexdigest()
    with open(archfile + ".sha256", "w") as shafile:
        shafile.write(sha256sum)

    os.chdir("..")

def deps():
    prefix = "px.dist-wheels"
    _, outdir, dist = get_dirs(prefix)
    if "--force" in sys.argv:
        rmtree(outdir)
    os.makedirs(dist, exist_ok=True)

    # Build
    os.system(sys.executable + " -m pip wheel . -w " + dist)

def depspkg():
    prefix = "px.dist-wheels"
    osname, outdir, dist = get_dirs(prefix)

    if sys.platform == "linux":
        # Use strings on Linux to reduce wheel size
        #   Not effective on Windows
        os.chdir(dist)

        for whl in glob.glob("*.whl"):
            size = os.stat(whl).st_size
            wdir = os.path.basename(whl[:-4])
            os.system(sys.executable + " -m zipfile -e " + whl + " " + wdir)

            os.chdir(wdir)
            processed = False
            for so in glob.glob("**/*.so", recursive = True):
                processed = True
                strip = os.system("strip -s " + so)
                if strip != 0:
                    processed = False
                    break

            os.chdir("..")

            if processed:
                os.system(sys.executable + " -m zipfile -c " + whl + ".new " + wdir + "/*")
                new_size = os.stat(whl + ".new").st_size
                if new_size < size:
                    print("%s: size changed from %d to %d" % (whl, size, new_size))
                    os.remove(whl)
                    os.rename(whl + ".new", whl)
                else:
                    os.remove(whl + ".new")

            rmtree(wdir)

        os.chdir("..")
    else:
        os.chdir(outdir)

    # Replace with official Px wheel
    try:
        os.remove(os.path.join(prefix, "px_proxy-%s-py3-none-any.whl" % __version__))
    except:
        pass
    whl = "px_proxy-" + __version__
    if sys.platform == "win32":
        whl += "-py3-none-win_amd64.whl"
    else:
        whl += "-py2.py3-none-any.whl"
    shutil.copy(os.path.join("..", "wheel", whl), prefix)

    # Compress all wheels
    archfile = "px-v%s-%s-wheels" % (__version__, osname)
    arch = "gztar"
    if sys.platform == "win32":
        arch = "zip"
    shutil.make_archive(archfile, arch, prefix)

    # Create hashfile
    if arch == "gztar":
        arch = "tar.gz"
    archfile += "." + arch
    with open(archfile, "rb") as afile:
        sha256sum = hashlib.sha256(afile.read()).hexdigest()
    with open(archfile + ".sha256", "w") as shafile:
        shafile.write(sha256sum)

    os.chdir("..")

def scoop():
    # Delete Python lib
    version = f"{sys.version_info.major}{sys.version_info.minor}"
    persist = os.getenv("USERPROFILE") + f"/scoop/persist/python{version}"
    if os.path.exists(persist):
        shutil.rmtree(persist)

    # Recreate directory structure
    os.makedirs(os.path.join(persist, "Lib", "site-packages"), exist_ok=True)
    os.makedirs(os.path.join(persist, "Scripts"), exist_ok=True)

    get_pip()

# Github related

def get_all_releases():
    ret, data = curl("https://api.github.com/repos/" + REPO + "/releases")
    return json.loads(data)

def get_release_by_tag(tag):
    j = get_all_releases()
    for rel in j:
        if rel["tag_name"] == tag:
            return rel

    return None

def get_release_id(rel):
    return str(rel["id"])

def get_num_downloads(rel, aname="px-v"):
    for asset in rel["assets"]:
        if aname in asset["name"]:
            return asset["download_count"]

def delete_release(rel):
    id = get_release_id(rel)
    ret, data = curl(
        "https://api.github.com/repos/" + REPO + "/releases/" + id,
        method = "DELETE", headers = get_auth())
    if ret != 0:
        print("Failed to delete release " + id + " with " + str(ret))
        print(data)
        sys.exit(2)

    print("Deleted release " + id)

def has_downloads(rel):
    dl = get_num_downloads(rel)
    if dl != 0:
        print("Release has been downloaded " + str(dl) + " times")
        return True

    return False

def edit_release_tag(rel, offset=""):
    new_tag_name = rel["created_at"].split("T")[0] + offset
    sha = get_tag_by_name(rel["tag_name"])["object"]["sha"]
    data = json.dumps({
      "tag_name": new_tag_name,
      "target_commitish": sha
    })

    id = get_release_id(rel)
    ret, data = curl(
        "https://api.github.com/repos/" + REPO + "/releases/" + id,
        method = "PATCH", headers = get_auth(), data = data)
    if ret != 0:
        if offset:
            edit_release_tag(rel, "-1")
        else:
            print("Edit release failed with " + str(ret))
            print(data)
            sys.exit(3)

    print("Edited release tag name to " + rel["created_at"].split("T")[0])

def get_all_tags():
    ret, data = curl("https://api.github.com/repos/" + REPO + "/git/refs/tag")
    return json.loads(data)

def get_tag_by_name(tag):
    j = get_all_tags()
    for tg in j:
        if tag in tg["ref"]:
            return tg

    return None

def delete_tag(tg):
    ref = tg["ref"]
    ret, data = curl(
        "https://api.github.com/repos/" + REPO + "/git/" + ref,
        method = "DELETE", headers = get_auth())
    if ret != 0:
        print("Failed to delete tag with " + str(ret))
        print(data)
        sys.exit(4)

    print("Deleted tag " + ref)

def delete_tag_by_name(tag):
    tg = get_tag_by_name(tag)
    if tg:
        delete_tag(tg)

def get_history():
    h = open("HISTORY.txt", "r").read().split("\n\n")[0]
    h = h[h.find("\n")+1:]

    return h

def create_release(tag, name, body, prerelease):
    data = json.dumps({
      "tag_name": tag,
      "target_commitish": "master",
      "name": name,
      "body": body,
      "draft": False,
      "prerelease": prerelease
    })

    ret, data = curl(
        "https://api.github.com/repos/" + REPO + "/releases",
        method = "POST", headers = get_auth(), data = data)
    if ret != 0:
        print("Create release failed with " + str(ret))
        print(data)
        sys.exit(5)
    j = json.loads(data)
    id = str(j["id"])
    print("Created new release " + id)

    return id

def add_asset_to_release(filename, relid):
    print("Uploading " + filename)
    rfile_size = os.stat(filename).st_size
    with open(filename, "rb") as rfile:
        headers = get_auth()
        headers["Content-Type"] = "application/octet-stream"
        ret, data = curl(
            "https://uploads.github.com/repos/" + REPO + "/releases/" + relid + "/assets?name=" + os.path.basename(filename),
            method = "POST", headers = headers, rfile = rfile, rfile_size = rfile_size)
        if ret != 0:
            print("Asset upload failed with " + str(ret))
            print(data)
            sys.exit(6)
        else:
            print("Asset upload successful")

def check_code_change():
    if "--force" in sys.argv:
        return True

    if os.system("git diff --name-only HEAD~1 HEAD | grep \\.py") == 0:
        return True

    return False

def post():
    tagname = get_argval("tag") or "v" + __version__
    if not check_code_change():
        print("No code changes in commit, skipping post")
        return

    rel = get_release_by_tag(tagname)
    if rel is not None:
        if has_downloads(rel) and "--redo" not in sys.argv:
            edit_release_tag(rel)
        else:
            delete_release(rel)

    delete_tag_by_name(tagname)

    id = create_release(tagname, "Px v" + __version__, get_history(), True)

    for archive in glob.glob("px.dist*/px-v%s*" % __version__):
        add_asset_to_release(archive, id)

# Main
def main():
    # Setup
    if "--libcurl" in sys.argv:
        get_curl()
        sys.exit()

    else:
        # Build
        if "--wheel" in sys.argv:
            wheel()

        if sys.platform == "win32":
            if "--pyinst" in sys.argv:
                pyinstaller()

            if "--embed" in sys.argv:
                embed()

            if "--scoop" in sys.argv:
                scoop()

        if "--nuitka" in sys.argv:
            nuitka()

        if "--deps" in sys.argv:
            deps()

        if "--depspkg" in sys.argv:
            depspkg()

    # Delete
    if "--delete" in sys.argv:
        tag = get_argval("tag") or "v" + __version__
        rel = get_release_by_tag(tag)
        delete_release(rel)
        delete_tag_by_name(tag)

    # Post
    if "--twine" in sys.argv:
        if not os.path.exists("wheel"):
            wheel()

        os.system("twine upload wheel/*.whl")

    if "--post" in sys.argv:
        bins = glob.glob("px.dist*/px-v%s*" % __version__)
        if len(bins) == 0:
            print("No binaries found")
            sys.exit()
        post()

    # Help

    if len(sys.argv) == 1:
        print("""
Setup:
--libcurl	Download and extract libcurl binaries for Windows

Build:
--wheel		Build wheels for pypi.org
--pyinst	Build px.exe using PyInstaller
--nuitka	Build px distribution using Nuitka
--embed     Build px distribution using Python Embeddable distro
  --tag=vX.X.X	Use specified tag
--deps		Build all wheel dependencies for this Python version
--depspkg	Build an archive of all dependencies
--scoop		Clean and initialize Python distro installed via scoop

Post:
--twine		Post wheels to pypi.org
--post		Post Github release
  --redo	Delete existing release if it exists, else updates tag
  --tag=vX.X.X	Use specified tag
  --force	Force post even if no code changes
--delete	Delete existing Github release
  --tag=vX.X.X	Use specified tag

--token=$GITHUB_TOKEN required for Github operations
""")

if __name__ == "__main__":
    main()
