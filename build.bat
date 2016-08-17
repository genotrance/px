@echo off

rmdir /s /q dist

pyinstaller -w -i px.ico px.py
copy px.ini dist\px\.
copy README dist\px\README.txt

del dist\px\api-*.dll
del dist\px\ucrtbase.dll
del dist\px\vcrun*.dll
del px.spec
rmdir /s /q build
rmdir /s /q __pycache__
