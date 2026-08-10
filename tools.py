import contextlib
import glob
import gzip
import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import zipfile

try:
    import mcurl
except ImportError:
    mcurl = None

try:
    from px.version import __version__
except Exception:
    # Fallback when px-proxy is not installed as a package
    with open("pyproject.toml") as f:
        for line in f:
            if line.startswith("version"):
                __version__ = line.split('"')[1]
                break

WHEEL = "px_proxy-" + __version__ + "-py3-none-any.whl"

# CLI


def get_argval(name):
    for i in range(len(sys.argv)):
        if "=" in sys.argv[i]:
            val = sys.argv[i].split("=")[1]
            if (f"--{name}=") in sys.argv[i]:
                return val

    return ""


# File utils


def rmtree(dirs):
    for d in dirs.split(" "):
        retries = 0
        while os.path.exists(d):
            shutil.rmtree(d, True)
            retries += 1
            if retries > 25:
                print(f"Failed to remove {d} after {retries} attempts - check permissions")
                sys.exit(1)
            time.sleep(0.2)


def copy(files, dest):
    for file in files.split(" "):
        shutil.copy(file, dest)


def remove(files):
    for file in files.split(" "):
        if "*" in file:
            for match in glob.glob(file):
                with contextlib.suppress(OSError):
                    os.remove(match)
        else:
            with contextlib.suppress(OSError):
                os.remove(file)


def extract(zfile, fileend):
    with zipfile.ZipFile(zfile) as czip:
        for file in czip.namelist():
            if file.endswith(fileend):
                member = czip.open(file)
                with open(os.path.basename(file), "wb") as base:
                    shutil.copyfileobj(member, base)


def make_archive_with_hash(archfile, arch, root_dir):
    shutil.make_archive(archfile, arch, root_dir)
    ext = "tar.gz" if arch == "gztar" else arch
    archfile += "." + ext
    with open(archfile, "rb") as afile:
        sha256sum = hashlib.sha256(afile.read()).hexdigest()
    with open(archfile + ".sha256", "w") as shafile:
        shafile.write(sha256sum)


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


def curl(
    url, method="GET", proxy=None, headers=None, data=None, rfile=None, rfile_size=0, wfile=None, encoding="utf-8"
):
    """
    data - for POST/PUT
    rfile - upload from open file - requires rfile_size
    wfile - download into open file
    """
    if mcurl is None:
        print("curl() requires pymcurl")
        sys.exit(1)
    if mcurl.MCURL is None:
        mcurl.MCurl(debug_print=None)
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


# Build


def redo_wheel():
    # Get the .whl file in the wheel directory
    wheel_files = glob.glob("wheel/px_proxy*.whl")
    if not wheel_files:
        # No .whl files found - need to rebuild
        return True

    # Get the oldest .whl file mtime
    oldest_wheel_file = min(wheel_files, key=os.path.getmtime)
    wheel_file_mtime = os.path.getmtime(oldest_wheel_file)

    # Get all .py files in the px directory
    py_files = glob.glob("px/*.py")

    # Check if any .py file is newer than the .whl file
    return any(os.path.getmtime(py_file) > wheel_file_mtime for py_file in py_files)


def wheel():
    # Create wheel
    rmtree("build px_proxy.egg-info")
    if redo_wheel():
        rmtree("wheel")
        if os.system(sys.executable + " -m build -s -w -o wheel --installer=uv") != 0:
            print("Failed to build wheel")
            sys.exit(1)

        # Check wheels
        os.system(sys.executable + " -m twine check wheel/*")

        rmtree("build px_proxy.egg-info")


def nuitka():
    prefix = "px.dist"
    archfile, outdir, dist = get_paths(prefix)
    rmtree(outdir)
    os.makedirs(dist, exist_ok=True)

    # Build
    flags = ""
    if sys.platform == "win32":
        # keyring dependency
        flags = "--include-package=win32ctypes"
    else:
        # uvloop is imported inside try/except so Nuitka may not detect it
        flags = "--include-package=uvloop"
    ret = os.system(
        sys.executable + f" -m nuitka --standalone {flags} --prefer-source-code --output-dir={outdir} px.py"
    )
    if ret != 0:
        print(f"Nuitka build failed with exit code {ret}")
        sys.exit(1)

    # Copy files
    copy("px.ini LICENSE.txt README.md", dist)
    if sys.platform != "win32":
        # Copy cacert.pem to dist/mcurl/.
        if mcurl is None:
            print("nuitka() requires pymcurl for cacert.pem")
            sys.exit(1)
        cacert = os.path.join(os.path.dirname(mcurl.__file__), "cacert.pem")
        mcurl_dir = os.path.join(dist, "mcurl")
        os.makedirs(mcurl_dir, exist_ok=True)
        copy(cacert, mcurl_dir)

    time.sleep(1)

    os.chdir(dist)
    # Fix binary name on Linux/Mac
    with contextlib.suppress(FileNotFoundError):
        os.rename("px.bin", "px")

    # Nuitka imports wrong openssl libs on Mac
    if sys.platform == "darwin":
        # Get brew openssl path
        osslpath = subprocess.check_output("brew --prefix openssl", shell=True, text=True).strip()
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
    make_archive_with_hash(archfile, arch, prefix)

    os.chdir("..")


def get_pip(executable=sys.executable):
    # Download get-pip.py
    url = "https://bootstrap.pypa.io/get-pip.py"
    ret, data = curl(url)
    if ret != 0:
        print(f"Failed to download get-pip.py with error {ret}")
        sys.exit(1)
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
        sys.exit(1)

    # Destination path
    archfile, outdir, dist = get_paths(prefix)
    rmtree(outdir)
    os.makedirs(dist, exist_ok=True)

    # Get latest releases from web
    ret, data = curl("https://www.python.org/downloads/windows/", encoding=None)
    with contextlib.suppress(gzip.BadGzipFile):
        data = gzip.decompress(data)
    data = data.decode("utf-8")

    # Get Python version from CLI if specified
    version = get_argval("tag")

    # Find all URLs for zip files in webpage
    urls = re.findall(r'href=[\'"]?([^\'" >]+\.zip)', data)
    dlurl = ""
    for url in urls:
        # Filter embedded amd64 URLs
        # Get the first or specified version URL
        if "embed" in url and "amd64" in url and (len(version) == 0 or version in url):
            dlurl = url
            break

    # Download zip file
    fname = os.path.join(outdir, os.path.basename(dlurl))
    if not os.path.exists(fname):
        ret, data = curl(dlurl, encoding=None)
        if ret != 0:
            print(f"Failed to download {dlurl} with error {ret}")
            sys.exit(1)

        # Write data to file
        with open(fname, "wb") as f:
            f.write(data)

        # Unzip
        with zipfile.ZipFile(fname, "r") as z:
            z.extractall(dist)

    # Find all files ending with ._pth
    pth = glob.glob(os.path.join(dist, "*._pth"))[0]

    # Update ._pth file
    with open(pth) as f:
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
            if (
                byte == 0x23
                and data[i + 1] == 0x21  # !
                and (
                    (data[i + 2] >= 0x41 and data[i + 2] <= 0x5A) or (data[i + 2] >= 0x61 and data[i + 2] <= 0x7A)
                )  # A-Za-z - drive letter
                and data[i + 3] == 0x3A  # Colon
            ):
                skip = True
                continue

            if skip:
                if byte == 0x0A:
                    skip = False
                    pybin = b".exe" if exe == pxexe else b"w.exe"
                    dataout += b"#!python" + pybin
                else:
                    continue

            dataout.append(byte)

        with open(exe, "wb") as f:
            f.write(dataout)

    # Copy data files
    copy("px.ini LICENSE.txt README.md", dist)

    # Delete Scripts directory
    rmtree(os.path.join(dist, "Scripts"))

    # Compress some binaries
    os.chdir(dist)
    if shutil.which("upx") is not None:
        os.system("upx --best python3*.dll libcrypto*.dll")

    # Create archive
    os.chdir("..")
    make_archive_with_hash(archfile, "zip", prefix)

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
    with contextlib.suppress(OSError):
        os.remove(os.path.join(prefix, WHEEL))
    shutil.copy(os.path.join("..", "wheel", WHEEL), prefix)

    # Replace with local pymcurl wheel
    mcurllib = os.path.join("..", "mcurllib")
    if os.path.exists(mcurllib):
        # Delete downloaded pymcurl wheel
        for whl in glob.glob(os.path.join(prefix, "pymcurl*.whl")):
            os.remove(whl)
        newwhl = re.sub(r"(\d+\.\d+\.\d+\.\d+|\d+_\d+)", "*", os.path.basename(whl))
        shutil.copy(glob.glob(os.path.join(mcurllib, newwhl))[0], prefix)

    # Compress all wheels
    arch = "gztar"
    if sys.platform == "win32":
        arch = "zip"
    make_archive_with_hash(archfile, arch, prefix)

    os.chdir("..")


def docker():
    tag = "genotrance/px"
    dbuild = "docker build --network host --build-arg VERSION=" + __version__
    wheels_dir = get_argval("wheels-dir")
    if wheels_dir:
        dbuild += f" --build-arg WHEELS_DIR={wheels_dir}"
    dbuild += " -f docker/Dockerfile"
    push = "--push" in sys.argv

    # Build mini image
    mtag = f"{tag}:{__version__}-mini"
    ltag = f"{tag}:latest-mini"
    ret = os.system(dbuild + f" -t {mtag} -t {ltag} --target=mini .")
    if ret != 0:
        print("Failed to build mini image")
        sys.exit(1)

    if push:
        for t in [mtag, ltag]:
            if os.system(f"docker push {t}") != 0:
                print(f"Failed to push {t}")
                sys.exit(1)

    # Build full image
    ftag = f"{tag}:{__version__}"
    lftag = f"{tag}:latest"
    ret = os.system(dbuild + f" -t {ftag} -t {lftag} .")
    if ret != 0:
        print("Failed to build full image")
        sys.exit(1)

    if push:
        for t in [ftag, lftag]:
            if os.system(f"docker push {t}") != 0:
                print(f"Failed to push {t}")
                sys.exit(1)


def get_history():
    with open("docs/changelog.md") as f:
        h = f.read()
    # Get first version section (between first and second "## v")
    sections = h.split("\n## v")
    if len(sections) > 1:
        h = sections[1]
        h = h[h.find("\n") + 1 :]
        # Stop at next --- separator
        if "\n---" in h:
            h = h[: h.find("\n---")]
    return h.strip()


# Main


def main():
    # Build
    if "--wheel" in sys.argv:
        wheel()

    if sys.platform == "win32":
        if "--embed" in sys.argv:
            embed()
    elif sys.platform == "linux":
        if "--docker" in sys.argv:
            docker()

    if "--nuitka" in sys.argv:
        nuitka()

    if "--deps" in sys.argv:
        deps()

    if "--depspkg" in sys.argv:
        depspkg()

    if "--history" in sys.argv:
        print(get_history())

    # Help

    if len(sys.argv) == 1:
        print("""
Build:
--wheel		Build wheels for pypi.org
--nuitka	Build px distribution using Nuitka
--embed		Build px distribution using Python Embeddable distro
  --tag=vX.X.X	Use specified tag
--deps		Build all wheel dependencies for this Python version
--depspkg	Build an archive of all dependencies
--docker	Build Docker images
  --push	Push images to Docker Hub
  --wheels-dir=DIR	Wheels directory (default: px.dist-linux-musl-x86_64-wheels)
--history	Print latest changelog section
""")


if __name__ == "__main__":
    main()
