@echo off

rmdir /s /q build
rmdir /s /q __pycache__
rmdir /s /q dist

pyinstaller --clean --noupx -w -F -i px.ico px.py --hidden-import win32timezone --exclude-module win32ctypes
copy px.ini dist\.
copy *.txt dist\.
copy *.md dist\.


del /q px.spec
rmdir /s /q build
rmdir /s /q __pycache__
