@echo off

rmdir /s /q build
rmdir /s /q __pycache__
rmdir /s /q dist

pyinstaller -w -i px.ico px.py
copy px.ini dist\px\.
copy README dist\px\README.txt

del /q dist\px\msv*.dll
del /q dist\px\api-*.dll
del /q dist\px\ucrtbase.dll
del /q dist\px\vcrun*.dll
del /q px.spec
rmdir /s /q build
rmdir /s /q __pycache__
