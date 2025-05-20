@echo off
setlocal

:: ============================================================
:: Script:     sign_ppl_runner.bat
:: Purpose:    Import root cert from PFX, sign PPL runner, verify
:: ============================================================

pushd "%~dp0"

:: Configuration
set SERVICE_BINARY=etw_consumer.exe
set PFX_FILE=sanctum.pfx
set PFX_PASSWORD=password

:: 1) Find signtool.exe
for /f "delims=" %%A in ('where signtool 2^>nul') do set SIGNTOOL=%%A
if not defined SIGNTOOL (
  echo [ERROR] signtool.exe not found. Install Windows SDK.
  exit /b 1
)

:: 2) Pre‑flight checks
if not exist "%PFX_FILE%" (
  echo [ERROR] Certificate file "%PFX_FILE%" not found.
  exit /b 1
)
if not exist "%SERVICE_BINARY%" (
  echo [ERROR] Binary "%SERVICE_BINARY%" not found.
  exit /b 1
)

:: 3) Import the PFX's root cert into Trusted Root
echo [*] Importing root cert from PFX into Root store...
certutil -f -p "%PFX_PASSWORD%" -importPFX Root "%PFX_FILE%"
if errorlevel 1 (
  echo [ERROR] Failed to import PFX to Root.
  exit /b 1
)


:: 4) remove ELAM test cert from driver
echo Removing WDK test signature from %SERVICE_BINARY%...
signtool remove /s "%SERVICE_BINARY%"
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to remove WDK signature.
    exit /b 1
)

:: 5) Sign the binary directly from the PFX (no /s or /n)
echo [*] Signing "%SERVICE_BINARY%"...
"%SIGNTOOL%" sign /fd SHA256 /ph /f "%PFX_FILE%" /p "%PFX_PASSWORD%" /t http://timestamp.digicert.com "%SERVICE_BINARY%"
if errorlevel 1 (
  echo [ERROR] signtool failed to sign.
  exit /b 1
)

:: 6) Verify the signature (kernel-mode policy)
echo [*] Verifying signature...
"%SIGNTOOL%" verify /pa /v "%SERVICE_BINARY%"
if errorlevel 1 (
  echo [ERROR] Signature verification failed.
  exit /b 1
)

echo [SUCCESS] "%SERVICE_BINARY%" signed and verified successfully!

popd
endlocal
exit /b 0
