from setuptools import setup

import os.path

version = ""
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "px.py")) as f:
    for line in f.readlines():
        if "__version__" in line:
            version = line.strip().replace('"', '').split()[-1]
            break

long_description = ""
with open(os.path.join(here, "README.md")) as f:
    long_description = f.read().split("\n\n")[2].replace("\n", " ").split("? ")[1]

setup(
    name = "px-proxy",
    version = version,
    description = "An HTTP proxy server to automatically authenticate through an NTLM proxy",
    long_description = long_description,
    url = "https://github.com/genotrance/px",
    author = "Ganesh Viswanathan",
    author_email = "dev@genotrance.com",
    platforms = "Windows",
    classifiers = [
        "Development Status :: 4 - Beta",
        "Environment :: Win32 (MS Windows)",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Topic :: Internet :: Proxy Servers"
    ],
    keywords = "proxy ntlm kerberos",
    py_modules = ["px"],
    install_requires = [
        'futures;python_version<"3.0"',
        "keyring",
        "netaddr",
        "ntlm-auth",
        "psutil",
        "pywin32",
        "winkerberos"
    ],
    data_files = [
        ("lib/site-packages/px-proxy", [
            "HISTORY.txt",
            "LICENSE.txt",
            "README.md",
            "px.ico",
            "px.ini"
        ])
    ],
    entry_points = {
        "console_scripts": [
            "px=px:main"
        ]
    },
    project_urls = {
        "Bug Reports": "https://github.com/genotrance/px/issues",
        "Source": "https://github.com/genotrance/px"
    }
)
