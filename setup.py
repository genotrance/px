"Setup for PyPi"

import os.path
import sys

from setuptools import setup, find_packages

from px.version import __version__

long_description = ""
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md")) as f:
    long_description = f.read()

data_files = [
    ("lib/site-packages/px", [
        "HISTORY.txt",
        "LICENSE.txt",
        "README.md",
        "px.ico",
        "px.ini"
    ])
]
if "bdist_wheel" in sys.argv:
    dll = ""
    if "win32" in sys.argv:
        dll = "libcurl.dll"
    elif "win-amd64" in sys.argv:
        dll = "libcurl-x64.dll"

    if len(dll) != 0:
        dllpath = os.path.join("px", "libcurl", dll)
        cainfo = os.path.join("px", "libcurl", "curl-ca-bundle.crt")
        if os.path.exists(os.path.join(here, dllpath)):
            data_files.append((
                "lib/site-packages/px/libcurl",
                [dllpath, cainfo]))
        else:
            print(dllpath + " missing, skipping in wheel")

setup(
    name = "px-proxy",
    version = __version__,
    description = "An HTTP proxy server to automatically authenticate through an NTLM proxy",
    long_description = long_description,
    long_description_content_type = "text/markdown",
    url = "https://github.com/genotrance/px",
    author = "Ganesh Viswanathan",
    author_email = "dev@genotrance.com",
    platforms = ["Windows", "Linux", "MacOS X"],
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Win32 (MS Windows)",
        "Environment :: MacOS X",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: Proxy Servers"
    ],
    keywords = "proxy ntlm kerberos pac negotiate http",
    packages = find_packages(),
    install_requires = [
        'futures;python_version<"3.0"',
        "keyring",
        "netaddr",
        "psutil",
        "quickjs",
        'jeepney==0.7.1;platform_system=="Linux"',
        'keyring_jeepney==0.2;platform_system=="Linux"',
        'keyrings.alt;platform_system=="Linux"'
    ],
    data_files = data_files,
    entry_points = {
        "console_scripts": [
            "px=px.main:main"
        ]
    },
    project_urls = {
        "Bug Reports": "https://github.com/genotrance/px/issues",
        "Source": "https://github.com/genotrance/px"
    }
)
