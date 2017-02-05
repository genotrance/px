@echo off

rmdir /s /q build
rmdir /s /q __pycache__
rmdir /s /q dist

pyinstaller --clean --noupx -w -i px.ico px.py
copy px.ini dist\px\.
copy *.txt dist\px\.
upx --best dist\px\*.pyd
upx --best dist\px\py*.dll

del /q px.spec
rmdir /s /q build
rmdir /s /q __pycache__
