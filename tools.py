import glob
import json
import os
import requests
import shutil
import sys
import time

from px import __version__

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

def wheel():
    rmtree("__pycache__ build dist wheel")

    os.system("python setup.py bdist_wheel --universal -p win32")
    os.system("python setup.py bdist_wheel --universal -p win-amd64")

    time.sleep(1)
    rmtree("__pycache__ build px_proxy.egg-info")
    os.rename("dist", "wheel")

def pyinstaller():
    rmtree("__pycache__ build dist pyinst")

    os.system("pyinstaller --clean --noupx -w -F px.py --hidden-import win32timezone --exclude-module win32ctypes")
    copy("px.ini HISTORY.txt LICENSE.txt README.md", "dist")

    time.sleep(1)
    os.remove("px.spec")
    rmtree("__pycache__ build")
    os.rename("dist", "pyinst")

def nuitka():
    rmtree("__pycache__ px.build px.dist")

    os.system(sys.executable + " -m nuitka --standalone --include-module=win32timezone --nofollow-import-to=win32ctypes --prefer-source-code --remove-output px.py")
    copy("px.ini HISTORY.txt LICENSE.txt README.md", "px.dist")

    time.sleep(1)

    os.chdir("px.dist")
    if len(shutil.which("upx")) != 0:
        os.system("upx --best px.exe python3*.dll")

    remove("_asyncio.pyd _bz2.pyd _decimal.pyd _elementtree.pyd _hashlib.pyd _lzma.pyd _msi.pyd")
    remove("_overlapped.pyd _queue.pyd _ssl.pyd _uuid.pyd _win32sysloader.pyd _zoneinfo.pyd pyexpat.pyd")
    remove("libcrypto*.dll libssl*.dll pythoncom*.dll")

    os.chdir("..")

    shutil.rmtree("__pycache__ px.build", True)

    name = shutil.make_archive("px-v" + __version__, "zip", "px.dist")
    time.sleep(1)
    shutil.move(name, "px.dist")

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

    id = create_release(tagname, "Px for Windows", get_history(), True)

    add_asset_to_release("px.dist/px-v" + __version__ + ".zip", id)

# Main
def main():
    if "--release" in sys.argv:
        sys.argv.extend(["--wheel", "--nuitka", "--twine", "--post"])

    # Setup
    if "--deps" in sys.argv:
        os.system(sys.executable + " -m pip install keyring netaddr ntlm-auth psutil pywin32 winkerberos")

    if "--devel" in sys.argv:
        os.system(sys.executable + " -m pip install --upgrade build twine wheel nuitka pyinstaller")

    # Build
    if "--wheel" in sys.argv:
        wheel()

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
        if not os.path.exists("px.dist/px-v" + __version__ + ".zip"):
            nuitka()
        post()

    # Help

    if len(sys.argv) == 1:
        print("""
Setup:
--deps		Install all px runtime dependencies
--devel		Install development dependencies

Build:
--wheel		Build wheels for pypi.org
--pyinst	Build px.exe using PyInstaller
--nuitka	Build px distro using Nuitka

Post:
--twine		Post wheels to pypi.org
--post		Post Github release
  --redo	Delete existing release if it exists, else updates tag
  --tag=vX.X.X	Use specified tag
  --force	Force post even if no code changes
--delete	Delete existing Github release
  --tag=vX.X.X	Use specified tag

--token=$GITHUB_TOKEN required for Github operations

Release:
--release	Build and release to Github and Pypi.org
""")

if __name__ == "__main__":
    main()
