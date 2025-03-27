import glob
import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile

if "--libcurl" not in sys.argv:
    try:
        import mcurl
    except ImportError:
        print("Requires module pymcurl")
        sys.exit()
else:
    import urllib.request

from px.version import __version__

REPO = "genotrance/px"
WHEEL = "px_proxy-" + __version__ + "-py3-none-any.whl"

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
        return "mac"

    return "unsupported"


def get_paths(prefix, suffix=""):
    osname = get_os()
    machine = platform.machine().lower()

    # os-arch[-suffix]
    basename = f"{osname}-{machine}"
    if len(suffix) != 0:
        basename += "-" + suffix

    # px-vX.X.X-os-arch[-suffix]
    archfile = f"px-v{__version__}-{basename}"

    # prefix-os-arch[-suffix]
    outdir = f"{prefix}-{basename}"

    # prefix-os-arch[-suffix]/prefix
    dist = os.path.join(outdir, prefix)

    return archfile, outdir, dist

# URL


def curl(url, method="GET", proxy=None, headers=None, data=None, rfile=None, rfile_size=0, wfile=None, encoding="utf-8"):
    """
    data - for POST/PUT
    rfile - upload from open file - requires rfile_size
    wfile - download into open file
    """
    if mcurl.MCURL is None:
        mc = mcurl.MCurl(debug_print=None)
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

        ec.bridge(client_rfile=rfile, client_wfile=wfile)
    elif wfile is not None:
        ec.bridge(client_wfile=wfile)
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
                    urllib.request.urlretrieve(
                        "https://curl.se/windows/latest.cgi?p=win%s-mingw.zip" % bit, lcurlzip)
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
    # Create wheel
    rmtree("build px_proxy.egg-info")
    if not os.path.exists("wheel/" + WHEEL):
        rmtree("wheel")
        if os.system(sys.executable + " -m build -s -w -o wheel --installer=uv") != 0:
            print("Failed to build wheel")
            sys.exit()

        # Check wheels
        os.system(sys.executable + " -m twine check wheel/*")

        rmtree("build px_proxy.egg-info")


def pyinstaller():
    _, dist, _ = get_paths("pyinst")
    rmtree("build dist " + dist)

    os.system(
        "pyinstaller --clean --noupx -w px.py --collect-submodules win32ctypes")
    copy("px.ini HISTORY.txt LICENSE.txt README.md", "dist")

    time.sleep(1)
    os.remove("px.spec")
    rmtree("build")
    os.rename("dist", dist)


def nuitka():
    prefix = "px.dist"
    archfile, outdir, dist = get_paths(prefix)
    rmtree(outdir)

    # Build
    flags = ""
    if sys.platform == "win32":
        # keyring dependency
        flags = "--include-package=win32ctypes"
    os.system(sys.executable +
              " -m nuitka --standalone %s --prefer-source-code --output-dir=%s px.py" % (flags, outdir))

    # Copy files
    copy("px.ini HISTORY.txt LICENSE.txt README.md", dist)
    if sys.platform != "win32":
        # Copy cacert.pem to dist/mcurl/.
        cacert = os.path.join(os.path.dirname(mcurl.__file__), "cacert.pem")
        mcurl_dir = os.path.join(dist, "mcurl")
        os.makedirs(mcurl_dir, exist_ok=True)
        copy(cacert, mcurl_dir)

    time.sleep(1)

    os.chdir(dist)
    # Fix binary name on Linux/Mac
    try:
        os.rename("px.bin", "px")
    except FileNotFoundError:
        pass

    # Nuitka imports wrong openssl libs on Mac
    if sys.platform == "darwin":
        # Get brew openssl path
        osslpath = subprocess.check_output(
            "brew --prefix openssl", shell=True, text=True).strip()
        for lib in ["libssl.3.dylib", "libcrypto.3.dylib"]:
            shutil.copy(os.path.join(osslpath, "lib", lib), ".")

    # Compress some binaries
    if shutil.which("upx") is not None:
        if sys.platform == "win32":
            os.system("upx --best px.exe python3*.dll libcrypto*.dll")
        elif sys.platform == "darwin":
            if platform.machine() != "arm64":
                os.system("upx --best --force-macos px")
        else:
            os.system("upx --best px")

    # Create archive
    os.chdir("..")
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


def get_pip(executable=sys.executable):
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
    prefix = "px.dist"
    _, _, wdist = get_paths(prefix, "wheels")
    if not os.path.exists(wdist):
        print(f"Wheels not found at {wdist}, required to embed")
        sys.exit()

    # Destination path
    archfile, outdir, dist = get_paths(prefix)
    rmtree(outdir)
    os.makedirs(dist, exist_ok=True)

    # Get latest releases from web
    ret, data = curl(
        "https://www.python.org/downloads/windows/", encoding=None)
    try:
        data = gzip.decompress(data)
    except gzip.BadGzipFile:
        pass
    data = data.decode("utf-8")

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
        os.system(
            f"{executable} -m pip install px-proxy --no-index -f {wdist} --no-warn-script-location")

        # Remove pip
        os.system(f"{executable} -m pip uninstall setuptools wheel pip -y")

    # Move px.exe and pxw.exe to root
    pxexe = os.path.join(dist, "px.exe")
    os.rename(os.path.join(dist, "Scripts", "px.exe"), pxexe)
    pxwexe = os.path.join(dist, "pxw.exe")
    os.rename(os.path.join(dist, "Scripts", "pxw.exe"), pxwexe)

    # Update interpreter path to relative sibling
    for exe in [pxexe, pxwexe]:
        with open(exe, "rb") as f:
            data = f.read()

        dataout = bytearray()
        skip = False
        for i, byte in enumerate(data):
            if byte == 0x23 and data[i+1] == 0x21:  # !
                if (data[i+2] >= 0x41 and data[i+2] <= 0x5a) or \
                        (data[i+2] >= 0x61 and data[i+2] <= 0x7a):    # A-Za-z - drive letter
                    if data[i+3] == 0x3A:  # Colon
                        skip = True
                        continue

            if skip:
                if byte == 0x0A:
                    skip = False
                    dataout += b"#!python.exe"
                else:
                    continue

            dataout.append(byte)

        with open(exe, "wb") as f:
            f.write(dataout)

    # Copy data files
    copy("px.ini HISTORY.txt LICENSE.txt README.md", dist)

    # Delete Scripts directory
    rmtree(os.path.join(dist, "Scripts"))

    # Compress some binaries
    os.chdir(dist)
    if shutil.which("upx") is not None:
        os.system("upx --best python3*.dll libcrypto*.dll")

    # Create archive
    os.chdir("..")
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
    _, outdir, dist = get_paths("px.dist", "wheels")
    if "--force" in sys.argv:
        rmtree(outdir)
    os.makedirs(dist, exist_ok=True)

    # Build
    os.system(sys.executable + f" -m pip wheel . -w {dist} -f mcurllib")


def depspkg():
    prefix = "px.dist"
    archfile, outdir, dist = get_paths(prefix, "wheels")

    if sys.platform == "linux":
        # Use auditwheel to include libraries and --strip
        #   auditwheel not relevant and --strip not effective on Windows
        os.chdir(dist)

        rmtree("wheelhouse")
        for whl in glob.glob("*.whl"):
            if platform.machine().lower() not in whl:
                # Not platform specific wheel
                continue
            if whl.startswith("pymcurl"):
                # pymcurl is already audited
                continue

            if os.system(f"auditwheel repair --strip {whl}") == 0:
                os.remove(whl)
                for fwhl in glob.glob("wheelhouse/*.whl"):
                    os.rename(fwhl, os.path.basename(fwhl))
            rmtree("wheelhouse")

        os.chdir("..")
    else:
        os.chdir(outdir)

    # Replace with official Px wheel
    try:
        os.remove(os.path.join(prefix, WHEEL))
    except:
        pass
    shutil.copy(os.path.join("..", "wheel", WHEEL), prefix)

    # Replace with local pymcurl wheel
    mcurllib = os.path.join("..", "mcurllib")
    if os.path.exists(mcurllib):
        # Delete downloaded pymcurl wheel
        for whl in glob.glob(os.path.join(prefix, "pymcurl*.whl")):
            os.remove(whl)
        newwhl = re.sub(r'(\d+\.\d+\.\d+\.\d+|\d+_\d+)',
                        '*', os.path.basename(whl))
        shutil.copy(glob.glob(os.path.join(mcurllib, newwhl))[0], prefix)

    # Compress all wheels
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


def docker():
    tag = "genotrance/px"
    dbuild = "docker build --network host --build-arg VERSION=" + \
        __version__ + " -f docker/Dockerfile"

    # Build mini image
    mtag = f"{tag}:{__version__}-mini"
    ret = os.system(dbuild + f" -t {mtag} --target=mini .")
    if ret != 0:
        print("Failed to build mini image")
        sys.exit()

    # Tag mini image
    ret = os.system(f"docker tag {mtag} {tag}:latest-mini")
    if ret != 0:
        print("Failed to tag mini image")
        sys.exit()

    # Build full image
    ftag = f"{tag}:{__version__}"
    ret = os.system(dbuild + f" -t {ftag} .")
    if ret != 0:
        print("Failed to build full image")
        sys.exit()

    # Tag full image
    ret = os.system(f"docker tag {ftag} {tag}:latest")
    if ret != 0:
        print("Failed to tag full image")
        sys.exit()

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
        method="DELETE", headers=get_auth())
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
        method="PATCH", headers=get_auth(), data=data)
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
        method="DELETE", headers=get_auth())
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
        method="POST", headers=get_auth(), data=data)
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
            "https://uploads.github.com/repos/" + REPO + "/releases/" +
            relid + "/assets?name=" + os.path.basename(filename),
            method="POST", headers=headers, rfile=rfile, rfile_size=rfile_size)
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
        elif sys.platform == "linux":
            if "--docker" in sys.argv:
                docker()

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

        os.system("twine upload wheel/*")

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
--docker    Build Docker images

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
