import json
import os
import requests
import sys

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

def get_num_downloads(rel, aname="px.exe"):
    for asset in rel["assets"]:
        if asset["name"] == aname:
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

# Main
def post(tagname):
    if not check_code_change():
        print("No code changes in commit, skipping post")
        return

    rel = get_release_by_tag(tagname)
    if rel is not None:
        if has_downloads(rel) and "--delete" not in sys.argv:
            edit_release_tag(rel)
        else:
            delete_release(rel)

    delete_tag_by_name(tagname)

    id = create_release(tagname, "Px for Windows", get_history(), True)

    add_asset_to_release("dist/px.exe", id)

def main():
    if "--wheel" in sys.argv:
        os.system("python setup.py bdist_wheel --universal -p win32")
        os.system("python setup.py bdist_wheel --universal -p win-amd64")

    elif "--twine" in sys.argv:
        os.system("twine upload dist/*.whl")

    elif "--post" in sys.argv:
        tag = get_argval("tag") or "vHEAD"
        post(tag)

    elif "--delete" in sys.argv:
        tag = get_argval("tag") or "vHEAD"
        rel = get_release_by_tag(tag)
        delete_release(rel)
        delete_tag_by_name(tag)

    else:
        print("""
Flags:
--wheel
--twine
--post --token=$GITHUB_TOKEN [--delete] [--tag=vX.X.X]
--delete [--tag=vX.X.X]
""")

if __name__ == "__main__":
    main()
