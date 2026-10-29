"""TEMPORARY until pymcurl 8.23.0.3 is on PyPI: check the devel pymcurl is used.

Without arguments, check the installed pymcurl. With a directory argument,
check every pymcurl wheel in it instead. Remove with the mcurl-devel action.
"""

import glob
import importlib.metadata
import os
import sys

MINIMUM = (8, 23, 0, 3)


def parse(version):
    return tuple(int(part) for part in version.split("."))


def require(condition, message):
    if not condition:
        sys.exit(f"ERROR: {message}")


def main():
    if len(sys.argv) > 1:
        wheels = glob.glob(os.path.join(sys.argv[1], "pymcurl-*.whl"))
        require(wheels, f"no pymcurl wheels in {sys.argv[1]}")
        for whl in wheels:
            version = os.path.basename(whl).split("-")[1]
            require(parse(version) >= MINIMUM, f"{whl} is older than {MINIMUM}")
            print(f"pymcurl wheel: {os.path.basename(whl)}")
        return

    import mcurl

    version = importlib.metadata.version("pymcurl")
    require(parse(version) >= MINIMUM, f"pymcurl {version} is older than {MINIMUM}")
    require(hasattr(mcurl.Curl, "get_os_errno"), "pymcurl lacks Curl.get_os_errno")
    require(hasattr(mcurl.Curl, "resume_upload"), "pymcurl lacks Curl.resume_upload")
    require(hasattr(mcurl, "REWIND_ERROR"), "pymcurl lacks REWIND_ERROR")
    print(f"pymcurl version: {version} ({mcurl.__file__})")


if __name__ == "__main__":
    main()
