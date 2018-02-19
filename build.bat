@echo off

rmdir /s /q build
rmdir /s /q __pycache__
rmdir /s /q dist

pyinstaller --clean --noupx -w -F -i px.ico px.py
copy px.ini dist\.
copy *.txt dist\.
rem upx --best dist\px.exe -o dist\px.tmp
rem move /Y dist\px.tmp dist\px.exe

del /q px.spec
rmdir /s /q build
rmdir /s /q __pycache__
