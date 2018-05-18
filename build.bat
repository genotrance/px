@echo off

rmdir /s /q build
rmdir /s /q __pycache__
rmdir /s /q dist

pyinstaller --clean --noupx -w -F -i px.ico px.py --hidden-import win32timezone
copy px.ini dist\.
copy *.txt dist\.

del /q px.spec
rmdir /s /q build
rmdir /s /q __pycache__
