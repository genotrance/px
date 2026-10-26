import contextlib
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
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

# CPython minor version bundled in every release binary and Docker image.
# Build tools select their newest available patch version of this minor.
PY_MINOR = "3.13"
PY_FTP = "https://www.python.org/ftp/python/"
PY_EMBED = "python-{}-embed-amd64.zip"

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


# Bundled Python


def fetch_text(url):
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            return resp.read().decode("utf-8")
    except Exception as exc:
        # Fall back to the curl binary when urllib lacks CA certificates
        ret = subprocess.run(["curl", "-fsSL", url], capture_output=True, text=True)
        if ret.returncode != 0:
            print(f"Failed to fetch {url}: {exc}")
            sys.exit(1)
        return ret.stdout


def version_tuple(version):
    return tuple(int(p) for p in version.split("."))


def latest_python(minor=PY_MINOR, asset=None):
    """
    Newest published CPython patch release of a minor version on python.org

    asset - file name template ({} is the version) that the release must ship,
            defaults to the source tarball. Used both to pick the Windows
            embeddable zip to bundle and, by tools/auto_release.py, to detect
            a new upstream patch worth cutting an automatic release for.
    """
    listing = fetch_text(PY_FTP)
    versions = {v for v in re.findall(r'href="(\d+\.\d+\.\d+)/"', listing) if v.rsplit(".", 1)[0] == minor}
    for version in sorted(versions, key=version_tuple, reverse=True):
        name = asset.format(version) if asset else f"Python-{version}.tar.xz"
        if f'href="{name}"' in fetch_text(f"{PY_FTP}{version}/"):
            return version

    print(f"No published CPython {minor}.x release found on {PY_FTP}")
    sys.exit(1)


def check_python():
    """Validate the selected interpreter and warn when python.org is newer."""
    have = platform.python_version()
    newest = latest_python()
    print(f"Bundled CPython {have} ({sys.executable}), newest published {PY_MINOR}.x is {newest}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", have) or have.rsplit(".", 1)[0] != PY_MINOR:
        print(f"ERROR: bundled CPython {have or 'unknown'} is not a {PY_MINOR}.x release")
        sys.exit(1)
    if version_tuple(have) < version_tuple(newest):
        print(f"WARNING: bundled CPython {have} is older than newest published {PY_MINOR}.x release {newest}")


def check_embed():
    """Select the newest Windows embed zip and warn if it lags python.org."""
    newest = latest_python()
    embed = latest_python(asset=PY_EMBED)
    print(f"Windows embed will bundle CPython {embed}, newest published {PY_MINOR}.x is {newest}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", embed) or embed.rsplit(".", 1)[0] != PY_MINOR:
        print(f"ERROR: Windows embed CPython {embed or 'unknown'} is not a {PY_MINOR}.x release")
        sys.exit(1)
    if version_tuple(embed) < version_tuple(newest):
        print(
            f"WARNING: python.org has no {PY_EMBED.format(newest)} for newest "
            f"{PY_MINOR}.x release {newest}; bundling available {embed}"
        )
    return embed


HOST_LIB_PREFIXES = ("/opt/homebrew", "/usr/local")
MACHO_MAGICS = {
    bytes.fromhex(m)
    for m in ("feedface", "feedfacf", "cefaedfe", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca")
}


def is_macho(path):
    "Return True if path is a Mach-O (thin or fat) file"
    try:
        with open(path, "rb") as f:
            return f.read(4) in MACHO_MAGICS
    except OSError:
        return False


def host_lib_refs(path):
    "Return the Homebrew or /usr/local libraries that the Mach-O file path links against"
    out = subprocess.check_output(["otool", "-L", path], text=True)
    refs = []
    for line in out.splitlines():
        if not line.startswith("\t"):
            continue
        lib = line.strip().split(" (compatibility version", 1)[0]
        # A dylib's first entry is its own install name, not a dependency
        if path.endswith(".dylib") and not refs and os.path.basename(lib) == os.path.basename(path):
            continue
        if lib.startswith(HOST_LIB_PREFIXES):
            refs.append(lib)
    return refs


def macho_files(root):
    "Return every non-symlink Mach-O file below root in a stable order"
    files = []
    for dirpath, _, names in os.walk(root):
        for name in names:
            path = os.path.join(dirpath, name)
            if not os.path.islink(path) and is_macho(path):
                files.append(path)
    return sorted(files)


def check_portable(root):
    "Fail if any Mach-O file under root links a library from /opt/homebrew or /usr/local"
    if sys.platform != "darwin":
        print("--check-portable requires macOS (otool)")
        sys.exit(1)
    if not os.path.isdir(root):
        print(f"ERROR: {root} is not a directory")
        sys.exit(1)

    checked = 0
    bad = {}
    for path in macho_files(root):
        checked += 1
        refs = host_lib_refs(path)
        if refs:
            bad[path] = refs

    print(f"Checked {checked} Mach-O files under {root}")
    if checked == 0:
        print(f"ERROR: no Mach-O files found under {root}")
        sys.exit(1)
    if bad:
        for path, refs in sorted(bad.items()):
            for ref in refs:
                print(f"ERROR: {path} links {ref}")
        print("ERROR: the binary depends on libraries that only exist on the build host")
        sys.exit(1)
    print("No Homebrew or /usr/local library references")


def check_ssl():
    "Fail unless ssl, hashlib and spnego import and, on macOS, their extensions do not link host libraries"
    import _hashlib
    import _ssl
    import hashlib
    import ssl

    import spnego  # noqa: F401

    print(f"{ssl.OPENSSL_VERSION} ({sys.executable})")
    hashlib.sha256(b"px").hexdigest()
    ssl.create_default_context()
    if sys.platform == "darwin":
        bad = {}
        for mod in (_ssl, _hashlib):
            path = getattr(mod, "__file__", None)
            if path and is_macho(path) and (refs := host_lib_refs(path)):
                bad[path] = refs
        if bad:
            for path, refs in bad.items():
                print(f"ERROR: {path} links {', '.join(refs)}")
            print(f"ERROR: {sys.executable} is not a self-contained CPython")
            sys.exit(1)


def check_bundled_version(have, target):
    """Validate a bundled interpreter and warn when python.org is newer."""
    newest = latest_python()
    print(f"{target} bundles CPython {have}, newest published {PY_MINOR}.x is {newest}")
    if not re.fullmatch(r"\d+\.\d+\.\d+", have) or have.rsplit(".", 1)[0] != PY_MINOR:
        print(f"ERROR: {target} CPython {have or 'unknown'} is not a {PY_MINOR}.x release")
        sys.exit(1)
    if version_tuple(have) < version_tuple(newest):
        print(f"WARNING: {target} CPython {have} is older than newest published {PY_MINOR}.x release {newest}")


def docker_python(image, target, pull=True):
    """Validate a Docker image's bundled interpreter, pulling only base images."""
    if pull:
        ret = subprocess.run(["docker", "pull", image])
        if ret.returncode != 0:
            print(f"Failed to pull {image}")
            sys.exit(1)
    res = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python",
            image,
            "-c",
            "import platform;print(platform.python_version())",
        ],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        print(f"Failed to get the Python version from {target}: {res.stderr.strip()}")
        sys.exit(1)
    check_bundled_version(res.stdout.strip(), target)


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
        # keyring and winloop dependencies
        flags = "--include-package=win32ctypes --include-package=winloop"
    else:
        # uvloop is imported inside try/except so Nuitka may not detect it
        flags = "--include-package=uvloop"
        # spnego is imported by px.handler inside a try/except, so Nuitka may skip it
        flags += " --include-package=spnego"
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

    # Select the newest PY_MINOR release that has an embeddable zip. A tag is
    # accepted only when it names the version selected above.
    newest = check_embed()
    version = get_argval("tag").lstrip("v") or newest
    if version != newest:
        print(f"ERROR: requested CPython {version}, but newest available Windows embed is {newest}")
        sys.exit(1)
    dlurl = PY_FTP + f"{version}/" + PY_EMBED.format(version)
    print(f"Bundling CPython {version} (Windows embeddable): {dlurl}")

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

    ret = subprocess.run([os.path.join(dist, "python.exe"), "-V"], capture_output=True, text=True)
    print(f"Bundled {ret.stdout.strip()}")
    if ret.stdout.strip() != f"Python {version}":
        print(f"ERROR: embedded python reports {ret.stdout.strip()}, expected {version}")
        sys.exit(1)

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
    dbuild = f"docker build --pull --network host --build-arg VERSION={__version__} --build-arg PYTHON_MINOR={PY_MINOR}"
    wheels_dir = get_argval("wheels-dir")
    if wheels_dir:
        dbuild += f" --build-arg WHEELS_DIR={wheels_dir}"
    dbuild += " -f docker/Dockerfile"
    push = "--push" in sys.argv
    requested_tags = set(filter(None, get_argval("push-tags").split(",")))

    # docker build --pull below always fetches the current tag; log its
    # version before doing either expensive image build.
    docker_python(f"python:{PY_MINOR}-alpine", "Docker base image")

    # Build mini image
    mtag = f"{tag}:{__version__}-mini"
    ltag = f"{tag}:latest-mini"
    ret = os.system(dbuild + f" -t {mtag} -t {ltag} --target=mini .")
    if ret != 0:
        print("Failed to build mini image")
        sys.exit(1)

    # Verify the completed image as well, before pushing anything.
    docker_python(mtag, "Docker image", pull=False)

    if push:
        for t in [mtag, ltag]:
            if requested_tags and t.rsplit(":", 1)[1] not in requested_tags:
                continue
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

    docker_python(ftag, "Docker image", pull=False)

    if push:
        for t in [ftag, lftag]:
            if requested_tags and t.rsplit(":", 1)[1] not in requested_tags:
                continue
            if os.system(f"docker push {t}") != 0:
                print(f"Failed to push {t}")
                sys.exit(1)


def docker_plan(version, inspect=None, run=None):
    def sh(*args):
        r = subprocess.run(args, capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else None

    inspect = inspect or (
        lambda tag: (
            (
                sh(
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    "--format",
                    "{{.Manifest.Digest}}",
                    f"genotrance/px:{tag}",
                )
                or ""
            ).strip()
            or None
        )
    )
    run = run or (lambda tag: sh("docker", "run", "--rm", "--entrypoint", "px", f"genotrance/px:{tag}", "--help"))
    digests = {}

    def digest(tag):
        if tag not in digests:
            digests[tag] = inspect(tag)
        return digests[tag]

    def version_ok(tag):
        out = run(tag) if digest(tag) else None
        return bool(out) and out.splitlines()[:1] == [f"Px v{version}"]

    plan = []
    for latest, vtag in (("latest-mini", f"{version}-mini"), ("latest", version)):
        push_version = not version_ok(vtag)
        if push_version:
            plan.append(vtag)
        if push_version or not digest(latest) or digest(latest) != digest(vtag):
            plan.append(latest)
    return plan


RELEASE_PLATFORMS = (
    "linux-glibc-x86_64",
    "linux-glibc-aarch64",
    "linux-musl-x86_64",
    "linux-musl-aarch64",
    "mac-arm64",
    "windows-amd64",
)


def expected_release_assets(version):
    assets = {f"px_proxy-{version}-py3-none-any.whl", f"px_proxy-{version}.tar.gz"}
    for platform_name in RELEASE_PLATFORMS:
        extension = "zip" if platform_name == "windows-amd64" else "tar.gz"
        for suffix in ("", "-wheels"):
            name = f"px-v{version}-{platform_name}{suffix}.{extension}"
            assets.update((name, f"{name}.sha256"))
    return assets


def _command_json(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def release_lookups(version):
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/px-proxy/{version}/json") as response:
            pypi = response.status == 200
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
        pypi = False

    release = _command_json("gh", "release", "view", f"v{version}", "--repo", "genotrance/px", "--json", "assets")
    assets = {asset["name"] for asset in release["assets"]} if release else set()
    manifest = (
        subprocess.run(
            (
                "gh",
                "api",
                f"repos/microsoft/winget-pkgs/contents/manifests/g/genotrance/px/{version}",
            ),
            capture_output=True,
        ).returncode
        == 0
    )
    prs = _command_json(
        "gh",
        "pr",
        "list",
        "--repo",
        "microsoft/winget-pkgs",
        "--state",
        "open",
        "--search",
        f"genotrance.px {version} in:title",
        "--json",
        "number",
    )
    return {
        "pypi": pypi,
        "github_release": release is not None,
        "assets": assets,
        "docker_tags": docker_plan(version),
        "winget": manifest or bool(prs),
    }


def release_plan(version, forced="auto", dry_run=False, lookup=None):
    state = (lookup or release_lookups)(version)
    expected = expected_release_assets(version)
    missing_assets = sorted(expected - set(state["assets"]))
    complete = (
        state["pypi"]
        and state["github_release"]
        and not missing_assets
        and not state["docker_tags"]
        and state["winget"]
    )
    if forced == "new":
        mode = "new"
    elif forced == "finish":
        mode = "finish"
    elif complete:
        mode = "complete"
    elif state["pypi"] or state["github_release"]:
        mode = "finish"
    else:
        mode = "new"
    return {
        "version": version,
        "mode": mode,
        "dry_run": bool(dry_run),
        "pypi_exists": state["pypi"],
        "github_release_exists": state["github_release"],
        "missing_assets": missing_assets,
        "docker_tags": state["docker_tags"],
        "winget_exists": state["winget"],
    }


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

    if "--check-python" in sys.argv:
        check_python()

    if "--check-embed" in sys.argv:
        check_embed()

    if "--check-ssl" in sys.argv:
        check_ssl()

    if "--check-portable" in sys.argv:
        check_portable(sys.argv[sys.argv.index("--check-portable") + 1])

    if "--nuitka" in sys.argv:
        nuitka()

    if "--deps" in sys.argv:
        deps()

    if "--depspkg" in sys.argv:
        depspkg()

    if "--docker-plan" in sys.argv or any(arg.startswith("--docker-plan=") for arg in sys.argv):
        version = get_argval("docker-plan")
        if not version:
            print("ERROR: --docker-plan requires a version (use --docker-plan=VER)", file=sys.stderr)
            sys.exit(1)
        print(",".join(docker_plan(version)))

    if "--release-plan" in sys.argv or any(arg.startswith("--release-plan=") for arg in sys.argv):
        version = get_argval("release-plan")
        if not version:
            print("ERROR: --release-plan requires a version", file=sys.stderr)
            sys.exit(1)
        print(
            json.dumps(
                release_plan(
                    version,
                    forced=get_argval("mode") or "auto",
                    dry_run=(get_argval("dry-run").lower() == "true"),
                ),
                sort_keys=True,
            )
        )

    if "--history" in sys.argv:
        print(get_history())

    # Help

    if len(sys.argv) == 1:
        print(f"""
Build:
--check-ssl	Fail unless ssl and spnego import and do not link Homebrew or /usr/local libraries (macOS)
--check-portable DIR	Fail if a Mach-O file under DIR links /opt/homebrew or /usr/local
--wheel		Build wheels for pypi.org
--nuitka	Build px distribution using Nuitka
--embed		Build px distribution using Python Embeddable distro
  --tag=X.X.X	Use specified Python version instead of the newest {PY_MINOR}.x
--deps		Build all wheel dependencies for this Python version
--depspkg	Build an archive of all dependencies
--docker	Build Docker images
  --push	Push images to Docker Hub
  --push-tags=TAGS
		Comma-separated Docker tags to push (default: all)
  --wheels-dir=DIR	Wheels directory (default: px.dist-linux-musl-x86_64-wheels)
--docker-plan=VER	Print comma-separated Docker tags that need pushing for VER
--release-plan=VER	Print the release mode and missing publication targets as JSON
--history	Print latest changelog section
""")


if __name__ == "__main__":
    main()
