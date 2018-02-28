@echo off

rmdir /s /q build
rmdir /s /q __pycache__
rmdir /s /q dist

pyinstaller --clean --noupx -w -F -i px.ico --add-data "c:\Miniconda\Lib\site-packages\tld\res\effective_tld_names.dat.txt;tld\res" px.py
copy px.ini dist\.
copy *.txt dist\.

del /q px.spec
rmdir /s /q build
rmdir /s /q __pycache__
