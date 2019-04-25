#!/usr/bin/env bash

temp=$(mktemp -d)
wd="$(pwd)"
cd $temp
curl -fsSL https://www.nuget.org/api/v2/package/python/3.7.3 -o python-nuget.zip
unzip python-nuget.zip -d python-nuget
mv python-nuget/tools ./python
cd python
curl -fsSL https://bootstrap.pypa.io/get-pip.py -O
wine python.exe get-pip.py
wine ./Scripts/pip.exe install keyring netaddr ntlm-auth psutil pywin32 winkerberos futures
wine ./Scripts/pip.exe install pyinstaller
cd "$wd"
wine $temp/python/Scripts/pyinstaller.exe --clean --noupx -w -F -i px.ico px.py --hidden-import win32timezone --exclude-module win32ctypes
rm -rf $temp
