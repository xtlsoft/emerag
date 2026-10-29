@echo off
rem Visual C++ 6.0 build. Run from a VC6 command prompt.
cl /nologo /O2 /DWIN32 /D_CRT_SECURE_NO_WARNINGS common.c crypto.c tls.c emerag.c ws2_32.lib advapi32.lib /Fe:emerag-nano.exe
if errorlevel 1 exit /b 1
echo Built emerag-nano.exe
