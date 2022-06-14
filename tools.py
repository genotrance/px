import glob
import json
import os
import platform
import shutil
import sys
import time
import urllib.request
import zipfile

try:
    import requests
except ModuleNotFoundError as exc:
    if "--setup" not in sys.argv:
        raise exc

from px.version import __version__

REPO = "genotrance/px"

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

def rmtree(dirs):
    for dir in dirs.split(" "):
        shutil.rmtree(dir, True)
        time.sleep(0.1)
        if os.path.exists(dir):
            shutil.rmtree(dir, True)

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

def extract(zfile, cfile):
    with zipfile.ZipFile(zfile) as czip:
        for file in czip.namelist():
            if file.endswith(cfile):
                member = czip.open(file)
                with open(cfile, "wb") as dll:
                    shutil.copyfileobj(member, dll)

def get_curl():
    os.chdir("px/libcurl")

    try:
        for bit, ext in {"32": "", "64": "-x64"}.items():
            lcurl = "libcurl%s.dll" % ext
            lcurlzip = "curl%s.zip" % bit
            if not os.path.exists(lcurl):
                if not os.path.exists(lcurlzip):
                    urllib.request.urlretrieve("https://curl.se/windows/curl-win%s-latest.zip" % bit, lcurlzip)
                extract(lcurlzip, lcurl)
                os.remove(lcurlzip)

                if shutil.which("strip") is not None:
                    os.system("strip -s " + lcurl)
                if shutil.which("upx") is not None:
                    os.system("upx --best " + lcurl)

    finally:
        os.chdir("../..")

def wheel():
    rmtree("build wheel")

    get_curl()

    os.system(sys.executable + " setup.py bdist_wheel --universal -d wheel -k")
    rmtree("build")
    os.system(sys.executable + " setup.py bdist_wheel -p win32 -d wheel -k")
    rmtree("build")
    os.system(sys.executable + " setup.py bdist_wheel -p win-amd64 -d wheel -k")

    # Check wheels
    os.system(sys.executable + " -m twine check wheel/*")

    rmtree("build px_proxy.egg-info")

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

def pyinstaller():
    osname = get_os()
    dist = "pyinst-%s-%s" % (osname, platform.machine().lower())
    rmtree("build dist " + dist)

    os.system("pyinstaller --clean --noupx -w px.py")
    copy("px.ini HISTORY.txt LICENSE.txt README.md", "dist")

    time.sleep(1)
    os.remove("px.spec")
    rmtree("build")
    os.rename("dist", dist)

def nuitka():
    osname = get_os()
    outdir = "px.dist-%s-%s" % (osname, platform.machine().lower())
    dist = os.path.join(outdir, "px.dist")
    shutil.rmtree(outdir, True)

    # Build
    flags = ""
    os.system(sys.executable + " -m nuitka --standalone %s --prefer-source-code --output-dir=%s px.py" % (flags, outdir))
    copy("px.ini HISTORY.txt LICENSE.txt README.md", dist)
    if sys.platform == "win32":
        pxdir = os.path.join(dist, "px")
        lcdir = os.path.join(pxdir, "libcurl")
        os.mkdir(pxdir)
        os.mkdir(lcdir)
        # 64-bit only for Windows for now
        copy(os.path.join("px", "libcurl", "libcurl-x64.dll"), lcdir)

    time.sleep(1)

    # Compress some binaries
    os.chdir(dist)
    if shutil.which("upx") is not None:
        if sys.platform == "win32":
            os.system("upx --best px.exe python3*.dll libcrypto*.dll")
        else:
            os.system("upx --best px")

    # Create archive
    os.chdir("..")
    arch = "gztar"
    if sys.platform == "win32":
        arch = "zip"
    shutil.make_archive("px-v%s-%s" % (__version__, osname), arch, "px.dist")
    os.chdir("..")

# Github related

def get_all_releases():
    r = requests.get("https://api.github.com/repos/" + REPO + "/releases")
    j = r.json()

    return j

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
    r = requests.delete("https://api.github.com/repos/" + REPO + "/releases/" + id, headers=get_auth())
    if r.status_code != 204:
        print("Failed to delete release " + id + " with " + str(r.status_code))
        print(r.text)
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
    body = json.dumps({
      "tag_name": new_tag_name,
      "target_commitish": sha
    })

    id = get_release_id(rel)
    r = requests.patch("https://api.github.com/repos/" + REPO + "/releases/" + id, headers=get_auth(), data=body)
    if r.status_code != 200:
        if offset:
            edit_release_tag(rel, "-1")
        else:
            print("Edit release failed with " + str(r.status_code))
            print(r.text)
            sys.exit(3)

    print("Edited release tag name to " + rel["created_at"].split("T")[0])

def get_all_tags():
    r = requests.get("https://api.github.com/repos/" + REPO + "/git/refs/tag")
    j = r.json()

    return j

def get_tag_by_name(tag):
    j = get_all_tags()
    for tg in j:
        if tag in tg["ref"]:
            return tg

    return None

def delete_tag(tg):
    ref = tg["ref"]
    r = requests.delete("https://api.github.com/repos/" + REPO + "/git/" + ref, headers=get_auth())
    if r.status_code != 204:
        print("Failed to delete tag with " + str(r.status_code))
        print(r.text)
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

    r = requests.post("https://api.github.com/repos/" + REPO + "/releases", headers=get_auth(), data=data)
    if r.status_code != 201:
        print("Create release failed with " + str(r.status_code))
        print(r.text)
        sys.exit(5)
    j = r.json()
    id = str(j["id"])
    print("Created new release " + id)

    return id

def add_asset_to_release(filename, relid):
    with open(filename, "rb") as f:
        headers = get_auth()
        headers["Content-Type"] = "application/octet-stream"
        r = requests.post("https://uploads.github.com/repos/" + REPO + "/releases/" +
              relid + "/assets?name=" + os.path.basename(filename), headers=headers, data=f)
        if r.status_code != 201:
            print("Asset upload failed with " + str(r.status_code))
            print(r.text)
            sys.exit(6)
        else:
            print("Asset upload successful")

def check_code_change():
    if "--force" in sys.argv:
        return True

    if os.system("git diff --name-only HEAD~1 HEAD | grep px.py") == 0:
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
    if "--setup" in sys.argv:
        os.system(sys.executable + " -m pip install --upgrade keyring netaddr psutil")
        os.system(sys.executable + " -m pip install --upgrade build nuitka requests twine wheel")
        if sys.platform == "linux":
            os.system(sys.executable + " -m pip install --upgrade keyrings.alt keyring_jeepney netifaces")

        get_curl()

        sys.exit()

    elif "--libcurl" in sys.argv:
        get_curl()
        sys.exit()

    else:
        # Build
        if "--wheel" in sys.argv:
            wheel()

        if sys.platform == "win32":
            if "--pyinst" in sys.argv:
                pyinstaller()

        if "--nuitka" in sys.argv:
            nuitka()

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
            nuitka()
        post()

    # Help

    if len(sys.argv) == 1:
        print("""
Setup:
--setup		Install all px runtime and development dependencies
--libcurl	Download and extract libcurl binaries for Windows

Build:
--wheel		Build wheels for pypi.org
--pyinst	Build px.exe using PyInstaller
--nuitka	Build px distribution using Nuitka

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
