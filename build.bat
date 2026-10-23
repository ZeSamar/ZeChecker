@echo off
rem Build ZeChecker.exe with MinGW-w64 (gcc + windres must be in PATH)
setlocal
windres app.rc -O coff -o app_res.o || goto :err
gcc -O2 -mwindows ZeChecker.c app_res.o -o ZeChecker.exe -lws2_32 -lwininet -ldwmapi -luxtheme || goto :err
echo Built ZeChecker.exe
exit /b 0
:err
echo Build failed
exit /b 1
