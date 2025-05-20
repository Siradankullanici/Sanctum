@echo off
setlocal EnableDelayedExpansion

echo [*] Starting sanctum_ppl_runner to validate digital signature...

net.exe start sanctum_ppl_runner >nul 2>&1
set "ERR=!ERRORLEVEL!"

echo Error code: !ERR!
net.exe helpmsg !ERR!

endlocal
exit /b !ERR!
