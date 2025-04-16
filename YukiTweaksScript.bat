@echo off
color 70
chcp 65001 >nul

::Title
title Yuki Tweaks

::Version
set Version 2.0

::Enable Delayed Expansion
SetLocal EnableDelayedExpansion

::Set Logfile
echo. > Yuki.txt

::Check For Curl
where curl >> Yuki.txt
if errorlevel 1 (
    echo "curl is not installed. Please install curl and try again."
    pause
    exit /b
)

::Make Directory In Temp
mkdir "%temp%\YukiTweaks" >nul
set "yuki=%temp%\YukiTweaks" >nul

::Set Vars
set "dev=%yuki%\DevManView.exe /disable" >nul

::Download Necessary Files
cls
echo ==============================
echo Downloading Necessary Files...
echo ==============================
curl -L --silent -o "%yuki%\DevManView.exe" "https://raw.githubusercontent.com/YukiWasTake/YukiOS/main/files/DevManView.exe"
curl -L --silent -o "%yuki%\OOSU10.exe" "https://raw.githubusercontent.com/YukiWasTake/YukiOS/main/files/OOSU10.exe"
curl -L --silent -o "%yuki%\ooshutup10.cfg" "https://raw.githubusercontent.com/YukiWasTake/YukiOS/main/files/ooshutup10.cfg"
curl -L --silent -o "%yuki%\yuki.pow" "https://raw.githubusercontent.com/YukiWasTake/YukiOS/main/files/yuki.pow"
curl -L --silent -o "%yuki%\disabledriverpowersaving.ps1" "https://raw.githubusercontent.com/YukiWasTake/YukiOS/main/files/disabledriverpowersaving.ps1"
curl -L --silent -o "%yuki%\nvidiaProfileInspector.exe" "https://raw.githubusercontent.com/YukiWasTake/YukiOS/main/files/nvidiaProfileInspector.exe"
curl -L --silent -o "%yuki%\yuki.nip" "https://raw.githubusercontent.com/YukiWasTake/YukiOS/main/files/yuki.nip"
curl -L --silent -o "%yuki%\readme.bat" "https://raw.githubusercontent.com/YukiWasTake/YukiOS/main/files/readme.bat"
timeout /t 1 /nobreak >nul

::Restore Point
:RestorePoint
cls
echo ===========================================================
echo Would You Like To Create A Restore Point Before Proceeding?
echo ===========================================================
echo                          1. Yes
echo                          2. No
echo ===========================================================
echo.
set /p choice=Choose Your Desired Option Then Press Enter:
if "%choice%"=="1" goto CreateRestorePoint
if "%choice%"=="2" goto BeginTweaks

::Invalid Choice
echo Invalid Option...Try Again
timeout /t 1 /nobreak >nul
goto RestorePoint

::Creating Restore Point
:CreateRestorePoint
cls
echo =========================
echo Creating Restore Point...
echo =========================
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "SystemRestorePointCreationFrequency" /t REG_DWORD /d "0" /f >> Yuki.txt
powershell -ExecutionPolicy Bypass -Command "CheckPoint-Computer -Description 'Yuki Tweaks' -RestorePointType 'MODIFY_SETTINGS'"
goto BeginTweaks

::Begin Script
:BeginTweaks
cls

::Check For Admin
    net session >> Yuki.txt
    if %errorlevel% neq 0 (
        echo This script requires administrator privileges.
        echo Attempting to relaunch with elevated rights...
        powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
        exit /b
    )

::Set Execution Policy Temporarily
powershell -Command "Try {Set-ExecutionPolicy Unrestricted -Scope Process -Force} Catch {}"

::Disable LUA
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f >> Yuki.txt

cls

::Disable Mitigations
call :Tweaks
echo Disabling Process And Kernel Mitigations...
powershell -Command "Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*' -Recurse -ErrorAction SilentlyContinue"
powershell -Command "ForEach($v in (Get-Command -Name 'Set-ProcessMitigation').Parameters['Disable'].Attributes.ValidValues){Set-ProcessMitigation -System -Disable $v.ToString() -ErrorAction SilentlyContinue}"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d 222222222222222222222222222222222222222222222222222222222222222 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "MitigationAuditOptions" /t REG_BINARY /d 222222222222222222222222222222222222222222222222222222222222222 /f >>Yuki.txt
timeout /t 1 /nobreak >nul

::Disabling Other Mitigations
call :Tweaks
echo Disabling Other Mitigations...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "DisableExceptionChainValidation" /t REG_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "KernelSEHOPEnabled" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DEPOff" /t REG_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "ProtectionMode" /t REG_DWORD /d 0 /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::Memory Management
call :Tweaks
echo Memory Management Tweaks...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "EnableCfg" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "MoveImages" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::Disable Maintenance
call :Tweaks
echo Disabling Maintenance...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f >> Yuki.txt
timeout /t 1 /nobreak >nul

:: Disable Fault Tolerant Heap
call :Tweaks
echo Disabling Fault Tolerant Heap...
reg add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d "0" /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::QoL Changes
call :Tweaks
echo Applying Quality of Life Changes...
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold1" /t REG_SZ /d "0" /f >> Yuki.txt
reg add "HKCU\Control Panel\Mouse" /v "MouseThreshold2" /t REG_SZ /d "0" /f >> Yuki.txt
reg add "HKCU\Control Panel\Mouse" /v "MouseSpeed" /t REG_SZ /d "0" /f >> Yuki.txt
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_SZ /d "0" /f >> Yuki.txt
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f >> Yuki.txt
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f >> Yuki.txt
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f >> Yuki.txt
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DontPrettyPath" /t REG_DWORD /d 1 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f >> Yuki.txt
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f >> Yuki.txt
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t "REG_DWORD" /d "100" /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::Firewall Settings
call :Tweaks
echo Firewall Settings...
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile" /v "DefaultInboundAction" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v "DefaultInboundAction" /t REG_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v "DefaultInboundAction" /t REG_DWORD /d 0 /f >> Yuki.txt
netsh advfirewall set allprofiles state off >> Yuki.txt
timeout /t 1 /nobreak >nul

::Boot Parameters
call :Tweaks
echo Boot Parameters...
bcdedit /deletevalue useplatformclock >> Yuki.txt
bcdedit /deletevalue useplatformtick >> Yuki.txt
bcdedit /set isolatedcontext No >> Yuki.txt
bcdedit /set allowedinmemorysettings 0x0 >> Yuki.txt
bcdedit /set disableelamdrivers Yes >> Yuki.txt
bcdedit /set bootmenupolicy Legacy >> Yuki.txt
bcdedit /set hypervisorlaunchtype Off >> Yuki.txt
bcdedit /set disabledynamictick yes >> Yuki.txt
timeout /t 1 /nobreak >nul

::Telemetry
call :Tweaks
echo Disabling Telemetry...
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WSearch" /v "Start" /t REG_DWORD /d "4" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v "POWERSHELL_TELEMETRY_OPTOUT" /t REG_SZ /d "1" /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >> Yuki.txt
::Disable Diag Services
sc stop DiagTrack >nul 2>&1
sc stop dmwappushservice>nul 2>&1
sc delete DiagTrack >nul 2>&1
sc delete dmwappushservice >nul 2>&1
timeout /t 1 /nobreak >nul

::Disable SettingSync
call :Tweaks
echo Disabling SettingSync...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync" /v "SyncPolicy" /t Reg_DWORD /d 5 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Accessibility" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\AppSync" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Browsersettings" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Credentials" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\DesktopTheme" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Language" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\PackageState" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Personalization" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\StartLayout" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\settingSync\Groups\Windows" /v "Enabled" /t Reg_DWORD /d 0 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisablesettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisablesettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableAppSyncsettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableAppSyncsettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableApplicationsettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableApplicationsettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableCredentialssettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableCredentialssettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableDesktopThemesettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableDesktopThemesettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisablePersonalizationsettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisablePersonalizationsettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableStartLayoutsettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableStartLayoutsettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableSyncOnPaidNetwork" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableWebBrowsersettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableWebBrowsersettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableWindowssettingSync" /t Reg_DWORD /d 2 /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\settingSync" /v "DisableWindowssettingSyncUserOverride" /t Reg_DWORD /d 1 /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::Disable Error Reporting
call :Tweaks
echo Disabling Error Reporting...
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::Win32PrioritySeparation
call :Tweaks
echo Setting Win32 Priority Separation...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "36" /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::System Responsiveness
call :Tweaks
echo Setting System Responsiveness...
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::Weak Host Model
call :Tweaks
echo Enabling Weak Host Send and Receive...
powershell -Command "Get-NetAdapter -IncludeHidden | Set-NetIPInterface -WeakHostSend Enabled -WeakHostReceive Enabled -ErrorAction SilentlyContinue"
timeout /t 1 /nobreak >nul

::VBS and NX
call :Tweaks
echo Disabling VBS And NX...
bcdedit /set nx OptOut >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t REG_DWORD /d "0" /f >> Yuki.txt
bcdedit /set vsmlaunchtype Off >> Yuki.txt
timeout /t 1 /nobreak >nul

::Disable Startup Event Traces
call :Tweaks
echo Disabling Startup Event Traces...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Cellcore" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOobe" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DataMarket" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\HolographicDevice" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsClient" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\iclsProxy" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Mellanox-Kernel" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-AssignedAccess-Trace" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Microsoft-Windows-Setup" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NBSMBLOGGER" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\PEAuthLog" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\RdrLog" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SocketHeciServer" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Tpm" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TPMProvisioningService" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WFP-IPsec Trace" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSessionRepro" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WinPhoneCritical" /v "Start" /t REG_DWORD /d "0" /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::Disable Useless Services
call :Tweaks
echo Disabling Useless Services
for %%a in (
  AxInstSV
  tzautoupdates
  BcastDVRUserService_389fd
  DoSvc
  NaturalAuthentication
  MapsBroker
  lfsvc
  SharedAccess
  lltdsvc
  CDPUserSvc
  NetTcpPortSharing
  CscService
  PrintNotify
  QWAVE
  RemoteAccess
  SensorDataService 
  SensrSvc
  SensorService
  ShellHWDetection
  ScDeviceEnum
  SSDPSRV
  WiaRpc
  upnphost
  UserDataSvc
  UevAgentService
  FrameServer
  FrameServerMonitor
  stisvc
  wisvc
  icssvc    
) do (
  reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%a" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
) 

::Disable Useless Devices
call :Tweaks
echo Disabling Useless Devices...
%dev% "Composite Bus Enumerator"
%dev% "System Speaker"
%dev% "Microsoft Virtual Drive Enumerator"
%dev% "Microsoft Hyper-V Virtualization Infrastructure Driver"
%dev% "NDIS Virtual Network Adapter Enumerator"
%dev% "Microsoft Radio Device Enumeration Bus"
%dev% "Microsoft RRAS Root Enumerator"
%dev% "WAN Miniport (IP)"
%dev% "WAN Miniport (IPv6)"
%dev% "WAN Miniport (Network Monitor)"
%dev% "WAN Miniport (PPPOE)"
%dev% "WAN Miniport (SSTP)"
%dev% "WAN Miniport (L2TP)"
%dev% "WAN Miniport (PPTP)"
%dev% "WAN Miniport (IKEv2)"
timeout /t 1 /nobreak >nul

::Power Plan, Driver Power Saving, and Other Power Stuff
call :Tweaks
echo Power Tweaks...
for /f %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum" /s /f "%%i"^| findstr "HKEY"') do (
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnhancedPowerManagementEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "AllowIdleIrpInD3" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableSelectiveSuspend" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "DeviceSelectiveSuspended" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "SelectiveSuspendOn" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnumerationRetryCount" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "ExtPropDescSemaphore" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "WaitWakeEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "D3ColdSupported" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "WdfDirectedPowerTransitionEnable" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "EnableIdlePowerManagement" /t REG_DWORD /d "0" /f >nul 2>&1
    reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters" /v "IdleInWorkingState" /t REG_DWORD /d "0" /f >nul 2>&1
)
powercfg -import "%yuki%\yuki.pow" 7f5875ed-2f22-4ba1-b357-3188ac5702a9 >nul 2>&1
powercfg -setactive 7f5875ed-2f22-4ba1-b357-3188ac5702a9 >nul 2>&1
powercfg -h off >nul 2>&1
start "" /wait powershell -ExecutionPolicy Bypass -File "%yuki%\disabledriverpowersaving.ps1" >nul 2>&1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Executive" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\ModernSleep" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "CoalescingTimerInterval" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "EnergyEstimationEnabled" /t REG_DWORD /d "0" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f >> Yuki.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f >> Yuki.txt
timeout /t 1 /nobreak >nul

::Delete Microsoft Edge
:MSEdge
cls
echo ===========================================
echo Would You Like To Uninstall Microsoft Edge?
echo ===========================================
echo                  1. Yes                   
echo                  2. No                    
echo ===========================================
echo.
set /p choice=Choose Your Desired Option Then Press Enter:
if "%choice%"=="1" goto UninstallEdge
if "%choice%"=="2" goto SvcHostSplitThresholdInKB

::Invalid Choice
echo Invalid Option...Try Again
timeout /t 2 /nobreak >nul
goto MSEdge

:UninstallEdge
call :Tweaks
echo Uninstalling Microsoft Edge...
for /f "tokens=1 delims=," %%x in ('schtasks /query /fo csv ^| find "MicrosoftEdge"') do schtasks /Delete /TN %%x /F
sc config <service_name> start= disabled
if exist "C:\Program Files (x86)\Microsoft\Edge" do (
  Taskkill /f /im msedge.exe >nul 2>&1
  sc stop edgeupdatem >nul 2>&1
  sc stop edgeupdate >nul 2>&1
  sc stop MicrosoftEdgeElevationService >nul 2>&1
  sc delete edgeupdatem >nul 2>&1
  sc delete edgeupdate >nul 2>&1
  sc delete MicrosoftEdgeElevationService >nul 2>&1
  rd /s /q "%LocalAppData%\Microsoft\WindowsApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe" >nul 2>&1
  rd /s /q "%LocalAppData%\Microsoft\Edge" >nul 2>&1
  rd /s /q "C:\Program Files (x86)\Microsoft\Edge" >nul 2>&1
  rd /s /q "C:\Program Files (x86)\Microsoft\EdgeUpdate" >nul 2>&1
  rd /s /q "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk" >nul 2>&1
  rd /s /q "%UserProfile%\Desktop\Microsoft Edge.lnk" >nul 2>&1
  rd /s /q "%Appdata%\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\Microsoft Edge.lnk" >nul 2>&1
  rd /s /q "%Appdata%\Roaming\Microsoft\Internet Explorer\Quick Launch\Microsoft Edge.lnk" >nul 2>&1
  if exist "C:\Program Files (x86)\Microsoft\EdgeCore" do (
    rd /s /q "C:\Program Files (x86)\Microsoft\EdgeCore" >nul 2>&1
    if exist "C:\Program Files (x86)\Microsoft\EdgeWebView" do (
      rd /s /q "C:\Program Files (x86)\Microsoft\EdgeWebView" >nul 2>&1
    )
  )

)

::SvcHostSplitThresholdInKB (No Impact On Performance Just Lowers Process Count)
:SvcHostSplitThresholdInKB
cls 
echo ==========================================
echo        Please Select Your RAM Amount      
echo ==========================================
echo           1. 4 GB      5. 16 GB          
echo           2. 6 GB      6. 24 GB          
echo           3. 8 GB      7. 32 GB          
echo           4. 12 GB     8. 64 GB          
echo ==========================================
echo * If Other, Choose The Closest Number To *
echo.
set /p choice=Choose Your RAM Size:
if "%choice%"=="1" goto 4GB
if "%choice%"=="2" goto 6GB
if "%choice%"=="3" goto 8GB
if "%choice%"=="4" goto 12GB
if "%choice%"=="5" goto 16GB
if "%choice%"=="6" goto 24GB
if "%choice%"=="7" goto 32GB
if "%choice%"=="8" goto 64GB

::Invalid Option
echo Invalid Option...Try Again
timeout /t 2 /nobreak >nul
goto SvcHostSplitThresholdInKB

:4GB
call :Tweaks
echo SvcHostSplitThresholdInKB 4 GB...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "4194304" /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto Visual

:6GB
call :Tweaks
echo SvcHostSplitThresholdInKB 6 GB...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "6291456" /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto Visual

:8GB
call :Tweaks
echo SvcHostSplitThresholdInKB 8 GB...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "8388608" /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto Visual

:12GB
call :Tweaks
echo SvcHostSplitThresholdInKB 12 GB...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "12582912" /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto Visual

:16GB
call :Tweaks
echo SvcHostSplitThresholdInKB 16 GB...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "16777216" /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto Visual

:24GB
call :Tweaks
echo SvcHostSplitThresholdInKB 24 GB...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "25165824" /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto Visual

:32GB
call :Tweaks
echo SvcHostSplitThresholdInKB 32 GB...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "33554432" /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto Visual

:64GB
call :Tweaks
echo SvcHostSplitThresholdInKB 64 GB...
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "67108864" /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto Visual

::Visual Settings
:Visual
cls
echo =======================
echo Opening Visual Settings
echo =======================
echo.
echo =======================================
echo Set To Performance Or Adjust As Desired
echo =======================================
timeout /t 3 /nobreak >nul
sysdm.cpl ,3
echo.
echo ============================
echo Press Any Key To Continue...
echo ============================
pause >nul

::OOSU10 Windows Anti-Spy
:OOSU
cls
echo ===================================
echo Import OOSU Anti-Spy Configuration?
echo ===================================
echo               1. Yes              
echo               2. No               
echo ===================================
echo.
set /p choice=Choose Desired Option Then Press Enter: 
if "%choice%"=="1" goto ImportOOSU
if "%choice%"=="2" goto nvidia
    
::Invalid Choice
echo Invalid Option...Try Again
timeout /t 2 /nobreak >nul
goto OOSU

::Import OOSU Config
:ImportOOSU
cls
echo ===============================
echo Importing Configuration File...
echo ===============================
start "" /wait "%yuki%\OOSU10.exe" "%yuki%\ooshutup10.cfg" >> Yuki.txt
echo.
echo ============================
echo Press Any Key To Continue...
echo ============================
pause >nul

::Nvidia GPU Tweaks
:nvidia
cls
echo ==========================
echo Do you have an Nvidia GPU?
echo ==========================
echo          1. Yes          
echo          2. No           
echo ==========================
echo.
set /p choice=Choose Desired Option Then Press Enter: 
if "%choice%"=="1" goto nvidiatweaks
if "%choice%"=="2" goto finished

::Invalid Choice
echo Invalid Option...Try Again
timeout /t 2 /nobreak >nul
goto nvidia

::NVPI Profile And Disable DynamicPState
:nvidiatweaks
call :Tweaks
echo Importing Nvidia Inspector Profile...
start "" /wait "%yuki%\nvidiaProfileInspector.exe" "%yuki%\yuki.nip" >> Yuki.txt
call :Tweaks
echo Disabling DynamicPState...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDynamicPstate" /t REG_DWORD /d 1 /f >> Yuki.txt
timeout /t 1 /nobreak >nul
call :Tweaks
echo Force Contiguous Memory Allocation In Nvidia Driver...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PreferSystemMemoryContiguous" /t REG_DWORD /d 1 /f >> Yuki.txt
timeout /t 1 /nobreak >nul
goto finished

::Finished
:finished
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "ReadMe" /t REG_SZ /d "%yuki%\readme.bat" /f >nul
call :Tweaks
echo Restarting To Apply Changes.
timeout /t 1 /nobreak >nul
cls
call :Tweaks
echo Restarting To Apply Changes..
timeout /t 1 /nobreak >nul
cls
call :Tweaks
echo Restarting To Apply Changes...
timeout /t 1 /nobreak >nul
cls
shutdown /r /t 0

:eof

:Tweaks
cls
echo =================================
echo            Yuki Tweaks
echo =================================
echo.