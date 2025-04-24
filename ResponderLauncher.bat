@echo off
:: Elevate if not already running as admin
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% NEQ 0 (
    echo [*] Requesting admin privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo.

:: Call PowerShell to list IPv4-enabled interfaces
echo [*] Detecting network interfaces...
powershell -Command ^
"Get-NetIPAddress -AddressFamily IPv4 -PrefixOrigin Dhcp ^
| Where-Object { $_.IPAddress -ne '127.0.0.1' } ^
| ForEach-Object -Begin { \$i=1 } -Process { Write-Output \"  [\$i] \$($_.InterfaceAlias) - \$($_.IPAddress)\"; \$global:options += ,@(\$i,\$_.IPAddress); \$i++ };" ^
> interfaces.txt

type interfaces.txt
echo.

set /p CHOICE=[*] Select an interface number to use for Responder: 

:: Extract selected IP from the output file
for /f "tokens=2" %%A in ('findstr "[%CHOICE%]" interfaces.txt') do (
    set IP=%%A
)

if "%IP%"=="" (
    echo [!] Invalid choice or no IP detected.
    pause
    exit /b
)

echo.
echo [+] Using IP: %IP%
python responder.py -I ALL -i %IP% -v
