@echo off
setlocal

:: ======================== Sanctum Setup Script ==========================
:: Performs certificate installation, test mode activation, signing, and deployments
:: ========================================================================

:: === 1) Add ELAM root cert ===
echo [*] Adding sanctum.cer to the Trusted Root Certification Authorities...
certutil -addstore root "sanctum.cer" >nul 2>&1

:: === 2) Enable TestSigning ===
echo [*] Enabling TestSigning mode...
bcdedit /set testsigning on >nul 2>&1

:: === 3) Run signing scripts ===
echo [*] Running signing scripts...

call sign.bat
if not %ERRORLEVEL%==0 goto :ERR_SIGN1

call sign_ppl_runner.bat
if not %ERRORLEVEL%==0 goto :ERR_SIGN2

call sign_etw_consumer.bat
if not %ERRORLEVEL%==0 goto :ERR_SIGN3

:: Final success
echo [SUCCESS] sanctum setup complete!
echo [INFO] A reboot is required to complete setup.
exit /b 0

:: -----------------------------------------------------------------
:: Error labels
:ERR_CERT
echo [ERROR] certutil -addstore failed with error %ERRORLEVEL%.
exit /b %ERRORLEVEL%

:ERR_TESTSIGN
echo [ERROR] bcdedit /set testsigning on failed with error %ERRORLEVEL%.
exit /b %ERRORLEVEL%

:ERR_SIGN1
echo [ERROR] sign.bat failed with error %ERRORLEVEL%.
exit /b %ERRORLEVEL%

:ERR_SIGN2
echo [ERROR] sign_ppl_runner.bat failed with error %ERRORLEVEL%.
exit /b %ERRORLEVEL%

:ERR_SIGN3
echo [ERROR] sign_etw_consumer.bat failed with error %ERRORLEVEL%.
exit /b %ERRORLEVEL%

:ERR_COPY1
echo [ERROR] copying sanctum.sys failed with error %ERRORLEVEL%.
exit /b %ERRORLEVEL%

:ERR_COPY2
echo [ERROR] copying sanctum_ppl_runner.exe failed with error %ERRORLEVEL%.
exit /b %ERRORLEVEL%
