@setlocal DisableDelayedExpansion
@echo off &title commence the fondling

:: Thank you to awuctl and lyssa for the ideas
::===============================================================================

:: Re-launch the script with x64 process if it was initiated by x86 process on x64 bit Windows
:: or with ARM64 process if it was initiated by x86/ARM32 process on ARM64 Windows

set "_cmdf=%~f0"
for %%# in (%*) do (
if /i "%%#"=="r1" set r1=1
if /i "%%#"=="r2" set r2=1
)

if exist %SystemRoot%\Sysnative\cmd.exe if not defined r1 (
setlocal EnableDelayedExpansion
start %SystemRoot%\Sysnative\cmd.exe /c ""!_cmdf!" %* r1"
exit /b
)

:: Re-launch the script with ARM32 process if it was initiated by x64 process on ARM64 Windows

if exist %SystemRoot%\SysArm32\cmd.exe if %PROCESSOR_ARCHITECTURE%==AMD64 if not defined r2 (
setlocal EnableDelayedExpansion
start %SystemRoot%\SysArm32\cmd.exe /c ""!_cmdf!" %* r2"
exit /b
)

::  Set Path variable, it helps if it is misconfigured in the system

set "PATH=%SystemRoot%\System32;%SystemRoot%\System32\wbem;%SystemRoot%\System32\WindowsPowerShell\v1.0\"
if exist "%SystemRoot%\Sysnative\reg.exe" (
set "PATH=%SystemRoot%\Sysnative;%SystemRoot%\Sysnative\wbem;%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\;%PATH%"
)

::  Check LF line ending

pushd "%~dp0"
>nul findstr /rxc:".*" "%~nx0"
if not %errorlevel%==0 (
echo:
echo Error: Script either has LF line ending issue, or it failed to read itself.
echo:
popd
ping 127.0.0.1 -n 6 > nul
exit /b
)
popd

::========================================================================================================================================

cls
color 07
title  Microsoft-Fondler

::========================================================================================================================================

set winbuild=1
set "nul=>nul 2>&1"
for /f "tokens=6 delims=[]. " %%G in ('ver') do set winbuild=%%G

set _NCS=1
if %winbuild% LSS 10586 set _NCS=0
if %winbuild% GEQ 10586 reg query "HKCU\Console" /v ForceV2 2>nul | find /i "0x0" 1>nul && (set _NCS=0)

::========================================================================================================================================

if %winbuild% LSS 7600 (
echo Unsupported OS version detected.
echo Fondler is supported only for Windows 7/8/8.1/10/11 and their Server equivalent.
goto FondlerEnd
)

for %%# in (powershell.exe) do @if "%%~$PATH:#"=="" (
echo Unable to find powershell.exe in the system.
echo Aborting...
goto FondlerEnd
)

::========================================================================================================================================

::  Fix for the special characters limitation in path name

set "_work=%~dp0"
if "%_work:~-1%"=="\" set "_work=%_work:~0,-1%"

set "_batf=%~f0"
set "_batp=%_batf:'=''%"

set _PSarg="""%~f0""" -el %_args%

set "_ttemp=%temp%"

setlocal EnableDelayedExpansion

::  Elevate script as admin and pass arguments and preventing loop

>nul fltmc || (
if not defined _elev %nul% powershell.exe "start cmd.exe -arg '/c \"!_PSarg:'=''!\"' -verb runas" && exit /b
echo This script require administrator privileges.
echo To do so, right click on this script and select 'Run as administrator'.
goto FondlerEnd
)

if not exist "%SystemRoot%\Temp\" mkdir "%SystemRoot%\Temp" 1>nul 2>nul

::========================================================================================================================================

whoami /user | findstr /i /c:S-1-5-18 >nul || ( call :RunAsTI "%~f0" %* & exit /b )

:: Disable cortana (not present anyways on modern windows)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaInAAD" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f

:: Disable web and location-based search
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f

:: Remove search box from taskbar and prevent microsoft from randomly putting it back
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "SearchBoxDisabledReason" /t REG_SZ /d FromServer /f

:: Remove search highlights
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d 0 /f

:: Disable Windows Spotlight and ads on lock screen https://www.elevenforum.com/t/enable-or-disable-facts-tips-and-tricks-on-lock-screen-in-windows-11.7079/
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "LockScreenOverlaysDisabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightWindowsWelcomeExperience" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnSettings" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanelt" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d 1 /f


:: Disable about this wallpaper icon on the desktop
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d 1 /f

:: Disable lock screen wallpaper slideshow
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f

:: Set default wallpaper
reg add "HKCU\Control Panel\Desktop" /v "WallPaper" /d "C:\WINDOWS\web\wallpaper\Windows\img0.jpg" /t REG_SZ /f

:: Disable find my device
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d 0 /f

:: Disable advertising IDs for interest-based advertising
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f

:: Don't let websites access locally installed language list
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f

:: Disable Windows tips https://winaero.com/disable-tips-about-windows-10/
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f

:: Disable smartscreen
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /d "Anywhere" /t REG_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f

:: Disable switching to secure desktop during UAC prompt (grayed out background)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f

:: Disable reporting unknown app signatures
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\RemovalTools\MpGears" /v "HeartbeatTrackingIndex" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\RemovalTools\MpGears" /v "SpyNetReportingLocation" /t REG_MULTI_SZ /d "" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f

:: Disable defender nag notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d 1 /f

:: Remove "Scan with Microsoft Defender" from context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f

:: Remove "Cast to device" from context menu
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /d "" /f

:: Remove "Troubleshoot compatibility" from context menu
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f

:: Remove "Include in Library" from context menu
reg delete "HKCR\Folder\ShellEx\ContextMenuHandlers\Library Location" /f

:: Remove bitmap (.bmp) and rtf option from new context menu
reg delete "HKCR\.bmp\ShellNew" /f
reg delete "HKCR\.rtf\ShellNew" /f

:: Remove modern share sheet from context menu
reg delete "HKCR\*\shellex\ContextMenuHandlers\ModernSharing" /f
reg delete "HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\ModernSharing" /f

:: Remove Google Drive FS context menu items
reg delete "HKEY_CLASSES_ROOT\.gdoc\ShellNew" /f
reg delete "HKEY_CLASSES_ROOT\.gsheet\ShellNew" /f
reg delete "HKEY_CLASSES_ROOT\.gslides\ShellNew" /f
reg delete "HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers\GDContextMenu" /f
reg delete "HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers\GDContextMenu" /f
reg delete "HKEY_CLASSES_ROOT\lnkfile\shellex\ContextMenuHandlers\GDContextMenu" /f

:: Don't automatically connect to open hotspots
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f

:: Prevent Kerberos from using DES or RC4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v "SupportedEncryptionTypes" /t REG_DWORD /d 2147483640 /f

:: Cipher suites preference order
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v "Functions" /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256" /t REG_SZ /f

:: Encrypt and sign outgoing secure channel traffic when possible
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "SealSecureChannel" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v "SignSecureChannel" /t REG_DWORD /d 1 /f

:: stuff
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-202913Enabled" /t REG_DWORD /d 0 /f 
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-202914Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280797Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280811Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280812Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280813Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280814Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280815Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280810Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-280817Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310091Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310092Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310094Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314558Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314562Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314566Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314567Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338380Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338381Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338382Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338386Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-346480Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-346481Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353695Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353697Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353699Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000044Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000045Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000105Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000106Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000161Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000162Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000163Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000164Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000165Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-88000166Enabled" /t REG_DWORD /d 0 /f

:: Disable suggested settings https://www.tenforums.com/tutorials/100541-turn-off-suggested-content-settings-app-windows-10-a.html
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f

:: Disable online tips in settings
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowOnlineTips" /v "value" /t REG_DWORD /d 0 /f

:: Disable Aero shake
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d 1 /f

:: Disable OneDrive ads in explorer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f

:: Disable start menu suggested apps https://www.tenforums.com/tutorials/24117-turn-off-app-suggestions-start-windows-10-a.html
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f

:: Disable start menu suggested websites
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecommendedPersonalizedSites" /t REG_DWORD /d 1 /f

:: Disallow automatic app installs and app suggestions (must be applied pre-install or it will only apply for new users and windows updates)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f

:: Disable the "Let's finish setting up your device" nag screen
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /d 1 /f

:: Disable Windows 10 welcome page https://winaero.com/disable-welcome-page-windows-10/
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f

:: Disable Microsoft Experimentation (breaks KIR) https://winaero.com/disabling-experimentation-in-windows-10-also-breaks-known-issue-rollback/
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System" /v "AllowExperimentation" /t REG_DWORD /d 0 /f

:: Disable A/B testing
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "Value" /t REG_DWORD /d 0 /f

:: Stop CDM changing its settings on update
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d 0 /f

:: Show hidden files and file extensions
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ""ShowSuperHidden" /t REG_DWORD /d 1 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ""ShowSuperHidden" /t REG_DWORD /d 1 /f

:: Don't automatically download Microsoft Store updates
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 2 /f

:: Disable Windows settings syncing over your Microsoft account
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d 0 /f

:: Turn desktop wallpaper encoding quality to maximum, although it still looks like garbage because you cant turn off the chroma subsampling (i hate windows if you cant tell already)
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 100 /f

:: Don't show network discoverable popup
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff" /f

:: Disable delay for startup apps (Windows 10 only, Windows 11 uses WaitForIdleState)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f

:: Forcefully close all apps on shutdown
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /d "1" /t REG_SZ /f

:: Disable context menu delay
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /d "0" /t REG_SZ /f

:: Disable mouse hover info delay
reg add "HKCU\Control Panel\Desktop" /v "MouseHoverTime" /d "0" /t REG_SZ /f

:: Show full context menu even with more than 15 items
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "MultipleInvokePromptMinimum" /t REG_DWORD /d 255 /f

:: Restore classic context menu (Windows 11)
reg add "HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /t REG_SZ /d "" /f

:: Always show more details during file transfer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d 1 /f

:: Disable Windows ink workspace
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceAppSuggestionsEnabled" /t REG_DWORD /d 0 /f

:: Disable widgets and remove icon on taskbar (and news and intrests on Windows 10)
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f

:: Hide task view on taskbar
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MultiTaskingView\AllUpView" /v "Enabled" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f

:: Hide Meet Now on taskbar
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "HideSCAMeetNow" /t REG_DWORD /d 1 /f

:: Disable desktop peek on taskbar
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisablePreviewDesktop" /t REG_DWORD /d 1 /f

:: Disable Windows Chat on taskbar
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d 3 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Communications" /v "Capabilities" /t REG_DWORD /d 0 /f

:: Remove settings banner (Windows 11)
reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\ValueBanner.IdealStateFeatureControlProvider" /v "ActivationType" /t REG_DWORD /d 0 /f

:: Disable Copilot
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f

:: Disable Recall
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v "DisableAIDataAnalysis" /t REG_DWORD /d 1 /f

:: Disable Microsoft account sign-in nag in Windows 11
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" /v "EnableAccountNotifications" /t REG_DWORD /d 0 /f

:: Prevent user from signing into Microsoft account
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "NoConnectedUser" /t REG_DWORD /d 1 /f

:: Don't prompt to "fix" usb devices
reg add "HKCU\SOFTWARE\Microsoft\Shell\USB" /v "NotifyOnUsbErrors" /t REG_DWORD /d 1 /f

:: Disable autoplay
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 0xff /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 0xff /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\CameraAlternate" /v "MSTakeNoAction" /t REG_NONE /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\EventHandlersDefaultSelection\StorageOnArrival" /v "MSTakeNoAction" /t REG_NONE /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\CameraAlternate\ShowPicturesOnArrival" /v "MSTakeNoAction" /t REG_NONE /d "" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival" /v "MSTakeNoAction" /t REG_NONE /d "" /f

:: Turn off cloud clipboard
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d 0 /f

:: Disable "Tailored Experiences" with diagnostic data
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f

:: Disable spelling data collection
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f

:: Disable "continuing experiences on other devices" (also used for data collection)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP\SettingsPage" /v "BluetoothLastDisabledNearShare" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "NearShareChannelUserAuthzPolicy" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CDP" /v "CdpSessionUserAuthzPolicy" /t REG_DWORD /d 0 /f

:: Turn off telemetry
sc stop DiagTrack
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableOneSettingsDownloads" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v M"axTelemetryAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "EnableEventTranscript" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" /v "MiniTraceSlotEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\AllowTelemetry" /v "Value" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\TailoredExperiencesWithDiagnosticDataEnabled" /v "Value" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Shell\\TelemetryID" /v TelemetryID /t REG_SZ /d 0000000000000000 /f

:: Disable Customer Experience Improvement Program (more telemetry)
reg add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f

:: Disable Microsoft Office telemetry
reg add "HKCU\Software\Policies\Microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\office\16.0\common" /v "qmenable" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\office\common\clienttelemetry" /v "sendtelemetry" /t REG_DWORD /d 3 /f

:: Disable Sign-in button at the top of office apps
reg add "HKCU\Software\Microsoft\Office\16.0\Common\SignIn" /v "SignInOptions" /t REG_DWORD /d 3 /f

:: Disable Activity Feed in Task View (it's an online feature)
reg add "HKLM\Software\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f

:: Disable app crash telemetry (goes to Microsoft, not app developers)
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontShowUI" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "ShowUI" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "DisableWerReporting" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendGenericDriverNotFoundToWER" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" /v "DisableSendRequestAdditionalSoftwareToWER" /t REG_DWORD /d 1 /f

:: Disable Device Health Attestation Monitoring and Reporting from checking for secure boot, TPM, bitlocker, etc.
reg add "HKLM\SOFTWARE\Policies\Microsoft\DeviceHealthAttestationService" /v "EnableDeviceHealthAttestationService" /t REG_DWORD /d 0 /f

:: Disable tracking of app performance
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnable" /t REG_DWORD /d 0 /f

:: Disable Program Compatibility Assistant telemetry
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

:: Disable Smart App Control https://github.com/Atlas-OS/Atlas/blob/main/src/playbook/Configuration/atlas/components.yml#L8
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v "VerifiedAndReputablePolicyState" /t REG_DWORD /d 0 /f

:: Turn off location servies and location history
reg add "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v "Location" /t REG_SZ /d "Deny" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_UserInControlOfTheseApps" /t REG_MULTI_SZ /d "\0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceAllowTheseApps" /t REG_MULTI_SZ /d "\0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceDenyTheseApps" /t REG_MULTI_SZ /d "\0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E6AD100E-5F4E-44CD-BE0F-2265D88D14F5}" /v "Value" /t REG_SZ /d "Deny" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "ShowGlobalPrompts" /t REG_DWORD /d 0 /f

:: Disable human presence tracking
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessHumanPresence" /t "REG_DWORD" /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessHumanPresence_UserInControlOfTheseApps" /t REG_MULTI_SZ /d "\0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessHumanPresence_ForceAllowTheseApps" /t REG_MULTI_SZ /d "\0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessHumanPresence_ForceDenyTheseApps" /t REG_MULTI_SZ /d "\0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\humanPresence" /v "Value" /t REG_SZ /d "Deny" /f

:: Disable cameras on lock screen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f

:: Disable storing password in memory in cleartext
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v "UseLogonCredential" /t REG_DWORD /d 0 /f

:: Require administrator to install printer drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v "AddPrinterDrivers" /t REG_DWORD /d 1 /f

:: Prevent DevHome from being installed via WU
reg add "HKLM\SOFTWARE\Microsoft\Windows\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate" /v "workCompleted" /t REG_DWORD /d 1 /f

:: Prevent Outlook from being installed via WU
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate" /v "workCompleted" /t REG_DWORD /d 1 /f

:: Disable Windows Insider entirely
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuilds" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ManagePreviewBuildsPolicyValue" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t REG_DWORD /d 1 /f

:: Disable "Fast Startup"
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f

:: Don't update Edge to the chromium version if you have it installed
reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d 1 /f

:: Remove "Search the store" in the open with context menu
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 1 /f

:: Remove the 260 character file path limits
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f

:: Stop Windows Security from bothering you about a Microsoft account
reg add "HKCU\Software\Microsoft\Windows Security Health\State" /v "AccountProtection_MicrosoftAccount_Disconnected" /t REG_DWORD /d 1 /f

:: Disable Onedrive pre-signin (for users running the script before or during install)
reg add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d 1 /f

:: Disable Onedrive
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f

:: Disable Onedrive user folder intrgration
reg add "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v "KFMBlockOptIn" /t REG_DWORD /d 1 /f

:: Stop SPP from validating tickets
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d 1 /f

:: Disable speech and handwriting telemetry when using accessibility features
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f

:: Disable whats basically a keylogger
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

:: Disable inking and typing telemetry
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d 0 /f

:: Never show feedback notifications
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f

:: New boot logo yippee
reg add "HKLM\SYSTEM\CurrentControlSet\Control\BootControl" /v "BootProgressAnimation" /t REG_DWORD /d 1 /f

:: Disable " - Shortcut" text and the end of newly created shortcuts
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates" /v "ShortcutNameTemplate" /d "\"%s.lnk\"" /t REG_SZ /f

:: Add end task to app's taskbar context menu
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v "TaskbarEndTask" /t REG_DWORD /d 1 /f

:: Enable file explorer compact mode (Windows 11)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseCompactMode" /t REG_DWORD /d 1 /f

:: Left-align taskbar (Windows 11)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 0 /f

:: Add seconds to the taskbar clock
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSecondsInSystemClock" /t REG_DWORD /d 1 /f

:: Make taskbar small
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarSi" /t REG_DWORD /d 0 /f

:: Disable most used apps in start menu for all users (Windows 11)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /t REG_DWORD /d 2 /f

:: Disable suggested text actions
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v "Disabled" /t REG_DWORD /d 1 /f

:: Change icon cache maximum size to 32MB
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "MaxCachedIcons" /t REG_DWORD /d 32768 /f

:: Enable taskbar icon cache
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v "AlwaysHibernateThumbnails" /t REG_DWORD /d 1 /f

:: Remove edit with Paint 3D file associations
reg delete "HKCR\SystemFileAssociations\.3mf\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.bmp\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.fbx\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.gif\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.jfif\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.jpe\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.jpeg\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.jpg\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.png\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.tif\Shell\3D Edit" /f
reg delete "HKCR\SystemFileAssociations\.tiff\Shell\3D Edit" /f

:: Disable automatic appx app archiving
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Appx" /v "AllowAutomaticAppArchiving" /t REG_DWORD /d 0 /f

:: Disable Windows Update restart notifications
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetAutoRestartNotificationDisable" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "RestartNotificationsAllowed2" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetUpdateNotificationLevel" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAUAsDefaultShutdownOption" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v "HideMCTLink" /t REG_DWORD /d 1 /f

:: Disable Windows Update auto restart (unless system is logged out)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d 1 /f

:: Install feature updates with known compatibility issues
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWUfBSafeguards" /t REG_DWORD /d 1 /f

:: Disable associated app icons on thumbnails
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTypeOverlay" /t REG_DWORD /d 0 /f

:: Disable Game Bar
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "GamePanelStartupTipIndex" /t REG_DWORD /d 3 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsRuntime\ActivatableClassId\Windows.Gaming.GameBar.PresenceServer.Internal.PresenceWriter" /v "ActivationType" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\ApplicationManagement\AllowGameDVR" /v "value" /t REG_DWORD /d 0 /f

:: Configure MMCSS to allocate all cpu resources to background apps https://learn.microsoft.com/en-us/windows/win32/procthread/multimedia-class-scheduler-service#registry-settings
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 100 /f

:: Windows Search Indexing respects power modes 
reg add "HKLM\Software\Microsoft\Windows Search\Gather\Windows\SystemIndex" /v "RespectPowerModes" /t REG_DWORD /d 1 /f

:: Short quantum, variable, no foreground boost https://docs.google.com/document/d/1c2-lUJq74wuYK1WrA_bIvgb89dUN0sj8-hO3vqmrau4/edit
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 36 /f

:: Disable SMB bandwidth throttling
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d 1 /f

:: Disable LLMNR
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f

:: Remove "3D Objects" folder
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
reg delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
del "%USERPROFILE%\3D Objects"

:: Remove "Gallery" from explorer
reg add "HKCU\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d 0 /f

:: Stop explorer from automatically discovering folder content type
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f

:: Enable verbose log in/out and power on/off messages
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "verbosestatus" /t REG_DWORD /d 0 /f

:: Disable sticky keys and related key shortcuts
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Accessibility\MouseKeys" /v "Flags" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_DWORD /d 0 /f

:: Disable flashes and sounds for sticky keys and other accessibility features
reg add "HKCU\Control Panel\Accessibility" /v "Warning Sounds" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Accessibility" /v "Sound on Activation" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Accessibility\SoundSentry" /v "WindowsEffect" /d "0" /t REG_SZ /f

:: Disable win+volume touch accessibility shortcut
reg add "HKCU\Control Panel\Accessibility\SlateLaunch" /v "LaunchAT" /t REG_DWORD /d 0 /f

:: Disable language bar shortcuts
reg add "HKCU\Control Panel\Input Method\Hot Keys\00000104" /f
reg add "HKCU\Keyboard Layout\Toggle" /v "Layout Hotkey" /t REG_DWORD /d 3 /f
reg add "HKCU\Keyboard Layout\Toggle" /v "Language Hotkey" /t REG_DWORD /d 3 /f
reg add "HKCU\Keyboard Layout\Toggle" /v "Hotkey" /t REG_DWORD /d 3 /f

:: Disable narrator shortcut
reg add "HKCU\Software\Microsoft\Narrator\NoRoam" /v "WinEnterLaunchEnabled" /t REG_DWORD /d 0 /f

:: Revert to classic file explorer search
reg add "HKLM\SOFTWARE\Classes\CLSID\{1d64637d-31e9-4b06-9124-e83fb178ac6e}\TreatAs" /ve /d "{64bc32b5-4eec-4de7-972d-bd8bd0324537}" /t REG_SZ /f
reg add "HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{1d64637d-31e9-4b06-9124-e83fb178ac6e}\TreatAs" /ve /d "{64bc32b5-4eec-4de7-972d-bd8bd0324537}" /t REG_SZ /f
reg add "HKLM\SOFTWARE\WOW6432Node\Classes\CLSID\{1d64637d-31e9-4b06-9124-e83fb178ac6e}\TreatAs" /ve /d "{64bc32b5-4eec-4de7-972d-bd8bd0324537}" /t REG_SZ /f

:: Disable explorer check boxes
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "AutoCheckSelect" /t REG_DWORD /d 0 /f

:: Explorer home page is "This PC"
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 0 /f

:: Disable sharing wizard
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d 0 /f

:: Do not animate minimizing and maximizing windows
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /d "0" /t REG_SZ /f

:: Allow visual effects settings to apply
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9432078010000000 /f

:: File association for .pow power plan files
reg add "HKCR\powerscheme\DefaultIcon" /ve /d "%windir%\System32\powercpl.dll,1" /t REG_SZ /f
reg add "HKCR\powerscheme\Shell\open\command" /ve /d "powercfg /import \"%1\"" /t REG_SZ /f
reg add "HKCR\.pow" /ve /d "powerscheme" /t REG_SZ /f
reg add "HKCR\.pow" /v "FriendlyTypeName" /d "Power Scheme" /t REG_SZ /f

:: Do not auto install teams
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d 0 /f

:: Disallow anonymous account enumeration
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f

:: Fix random issue where non-removable keyboard layouts are added due to an incorrect auto-detected locale
reg delete "HKEY_CURRENT_USER\Control Panel\International\User Profile System Backup" /f

:: Disable window animation when minimizing and restoring
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" /t REG_DWORD /d 1 /f

:: Add additional temporary file definitions, parity with Windows Server
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v Folder /t REG_BINARY /d 2520540045004D0025007C002525005700490049004E0044004900520025005C00540065006D0070007C002525005700490049004E0044004900520025005C004C006F00670073007C002525005700490049004E0044004900520025005C0053007900730074006500740065006D00330032005C004C006F006700460069006C00650073007C002525005700490049004E0044004900520025005C0053007900730074006500740065006D00740070000000 /f

:: Network zone configuration parity with Windows Server
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap" /v "AutoDetect" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "Flags" /t REG_DWORD /d 67 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1" /v "2500" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "Flags" /t REG_DWORD /d 67 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2" /v "MinLevel" /t REG_DWORD /d 10500 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A03" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1001" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1200" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1400" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1402" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1405" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1407" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1601" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1604" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1606" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1608" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1802" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1803" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1804" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A00" /t REG_DWORD /d 65536 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A02" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A05" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1A06" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "1C00" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2000" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2100" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2101" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2106" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2300" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2401" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2600" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2701" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "2704" /t REG_DWORD /d 3 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "CurrentLevel" /t REG_DWORD /d 73728 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "MinLevel" /t REG_DWORD /d 73728 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3" /v "RecommendedLevel" /t REG_DWORD /d 73728 /f

:: Disable funky office and linkedin keyboard shortcuts
reg add "HKCU\Software\Classes\ms-officeapp\Shell\Open\Command" /d "rundll32" /t REG_SZ /f

:: Disable memory dump from devices
reg add "HKLM\System\ControlSet001\Control\CrashControl\StorageTelemetry" /v "DeviceDumpEnabled" /t REG_DWORD /d 0 /f

:: Dont reduce sound volume in calls
reg add "HKCU\SOFTWARE\Microsoft\Multimedia\Audio" /v "UserDuckingPreference" /t REG_DWORD /d 3 /f

:: ewww yucky spell checking
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableAutocorrection" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableDoubleTapSpace" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnablePredictionSpaceInsertion" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableSpellchecking" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\TabletTip\1.7" /v "EnableTextPrediction" /t REG_DWORD /d 0 /f

:: Make control panel godmode
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}" /ve /d "All Tasks" /t REG_SZ /f
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}" /v "InfoTip" /d "View list of all Control Panel tasks" /t REG_SZ /f
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}" /v "System.ControlPanel.Category" /d "5" /t REG_SZ /f
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}\DefaultIcon" /ve /d "%windir%\System32\imageres.dll,-27" /t REG_SZ /f
reg add "HKCR\CLSID\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}\Shell\Open\Command" /ve /d "explorer.exe shell:::{ED7BA470-8E54-465E-825C-99712043E01C}" /t REG_SZ /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel\NameSpace\{D15ED2E1-C75B-443c-BD7C-FC03B2F08C17}" /ve /d "All Tasks" /t REG_SZ /f

:: Drop Windows Platform Binary Tables, which allow hardware to force the loading of software on every boot using an ACPI table
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "DisableWpbtExecution" /t REG_DWORD /d 1 /f

:: Network drives over UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLinkedConnections" /t REG_DWORD /d 1 /f

:: Configure kernel panic to dump useful info
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "AutoReboot" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "LogEvent" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl" /v "DisplayParameters" /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\CrashControl\StorageTelemetry" /v "DeviceDumpEnabled" /t REG_DWORD /d 0 /f

:: Configure storage sense to clean temp files every month https://gist.github.com/he3als/3d9dcf6e796aa920c24a98130165fb17
:: Enable storage sense
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 1 /f
:: Enable storage sense morer
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 1024 /t REG_DWORD /d 1 /f
:: Run every week
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 2048 /t REG_DWORD /d 7 /f
:: Clean temp files
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 04 /t REG_DWORD /d 1 /f
:: Disable download cleanup
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 32 /t REG_DWORD /d 0 /f
:: Disable OneDrive cleanup
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 02 /t REG_DWORD /d 0 /f
:: Disable OneDrive cleanup (more)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 128 /t REG_DWORD /d 0 /f
:: Cleanup recycle bin
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 08 /t REG_DWORD /d 1 /f
:: Clean recycle bin every month
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 256 /t REG_DWORD /d 30 /f
schtasks /Change /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" /ENABLE

:: Delay appx autoremoval until after user logon becaus I dont trust Microsoft to do it right
reg add "HKEY_LOCAL_MACHINE\SYSTEM\Setup\Upgrade\Appx\Applications" /v "NoReRegisterOnUpgrade" /t REG_DWORD /d 1 /f

:: Unrestrict powershell execution policy
reg add "HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" /v "ExecutionPolicy" /d "Unrestricted" /t REG_SZ /f

:: Disable Fault Tolerant Heap https://docs.microsoft.com/en-us/windows/win32/win7appqual/fault-tolerant-heap
rundll32 fthsvc.dll,FthSysprepSpecialize
reg add "HKLM\SOFTWARE\Microsoft\FTH" /v "Enabled" /t REG_DWORD /d 0 /f


:: Telemetry services
sc config OneSyncSvc start= disabled
sc config TrkWks start= disabled
sc config PcaSvc start= disabled
sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config WerSvc start= disabled
sc config wercplsupport start= disabled
sc config UCPD start= disabled
sc config Telemetry start= disabled

:: Location services
sc config lfsvc start= disabled
sc config MapsBroker start= disabled

:: Disable netbios
sc config NetBT start= disabled

:: Configure NTP
sc start w32time
w32tm /config /syncfromflags:manual /manualpeerlist:"time.cloudflare.com 0.us.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org"
w32tm /config /update
w32tm /resync

:: Disable powershell core telemetry
setx POWERSHELL_TELEMETRY_OPTOUT 1

:: Disable .NET CLI telemetry
setx DOTNET_CLI_TELEMETRY_OPTOUT 1

:: Delete telemetry cache
del "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\DiagTrack*" "%ProgramData%\Microsoft\Diagnosis\ETLLogs\ShutdownLogger\DiagTrack*" > nul 2>&1

:: Set ps1 files to open with powershell (duh)
ftype Microsoft.PowerShellScript.1="%windir%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -EP Unrestricted -File "%1" %*

:: Disable 8dot3 character-length file names ttps://ttcshelbyville.wordpress.com/2018/12/02/should-you-disable-8dot3-for-performance-and-security
fsutil 8dot3name set c: 1
fsutil 8dot3name strip /s /v c:
fsutil behavior set disable8dot3 1

:: Make bootloader use actual screen resolution
bcdedit /set {globalsettings} highestmode true

:: Explicitly enable startup repair
bcdedit /set {current} bootstatuspolicy DisplayAllFailures

:: Allow pressing f8 during startup for advanced options
bcdedit /set {bootloadersettings} bootmenupolicy legacy

:: Enable hibernation
powercfg /h on

:: remove defaultuser0 cuz it sucks
net user defaultuser0 /delete

:: Uninstall Onedrive https://github.com/Atlas-OS/Atlas/blob/main/src/playbook/Executables/ONED.cmd

for /f "usebackq delims=" %%a in (`dir /b /a:d "%SystemDrive%\Users"`) do (
	if exist "%SystemDrive%\Users\%%a\OneDrive" (
		dir "%SystemDrive%\Users\%%a\OneDrive" /b | findstr "." > nul 2>&1 && (
			echo Not stripping OneDrive as OneDrive files exist, exiting...
			exit 6000
		)
	)
)

taskkill /f /im OneDrive.exe > nul 2>&1
for %%a in (
	"%windir%\System32\OneDriveSetup.exe"
	"%windir%\SysWOW64\OneDriveSetup.exe"
) do (
	if exist "%%a" (
		"%%a" /uninstall > nul 2>&1
	)
)

:: If the "Volatile Environment" key exists, that means it is a proper user. Built in accounts/SIDs don't have this key.
for /f "usebackq tokens=2 delims=\" %%a in (`reg query HKU ^| findstr /r /x /c:"HKEY_USERS\\S-.*" /c:"HKEY_USERS\\AME_UserHive_[^_]*"`) do (
    reg query "HKU\%%a" | findstr /c:"Volatile Environment" /c:"AME_UserHive_" > nul && (
        echo Making changes for "%%a"...
        call :USERREG "%%a"
    )
)

rmdir /q /s "%ProgramData%\Microsoft OneDrive" > nul 2>&1
rmdir /q /s "%LOCALAPPDATA%\Microsoft\OneDrive" > nul 2>&1

for /f "usebackq delims=" %%a in (`dir /b /a:d "%SystemDrive%\Users"`) do (
	rmdir /q /s "%SystemDrive%\Users\%%a\AppData\Local\Microsoft\OneDrive" > nul 2>&1
	rmdir /q /s "%SystemDrive%\Users\%%a\OneDrive" > nul 2>&1
	del /q /f "%SystemDrive%\Users\%%a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" > nul 2>&1
)

for /f "usebackq delims=" %%a in (`reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" ^| findstr /i /c:"OneDrive"`) do reg delete "%%a" /f > nul 2>&1

for /f "tokens=2 delims=\" %%a in ('schtasks /query /fo list /v ^| findstr /c:"\OneDrive Reporting Task" /c:"\OneDrive Standalone Update Task"') do (
	schtasks /delete /tn "%%a" /f > nul 2>&1
)

exit /b

:USERREG
for /f "usebackq delims=" %%a in (`reg query "HKU\%~1\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\BannerStore" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
	reg delete "%%a" /f > nul 2>&1
)
for /f "usebackq delims=" %%a in (`reg query "HKU\%~1\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\Handlers" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
	reg delete "%%a" /f > nul 2>&1
)
for /f "usebackq delims=" %%a in (`reg query "HKU\%~1\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
	reg delete "%%a" /f > nul 2>&1
)
for /f "usebackq delims=" %%a in (`reg query "HKU\%~1\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" 2^>nul ^| findstr /i /c:"OneDrive" 2^>nul`) do (
	reg delete "%%a" /f > nul 2>&1
)

reg add "HKU\%~1\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f > nul 2>&1
reg add "HKU\%~1\SOFTWARE\Classes\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f > nul 2>&1
reg delete "HKU\%~1\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f > nul 2>&1

reg delete "HKU\%~1\Environment" /v "OneDrive" /f > nul 2>&1
reg delete "HKU\%~1\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f > nul 2>&1

setlocal enabledelayedexpansion

:: Define the list of appx packages to remove
set packages[1]=ActiproSoftware
set packages[2]=AdobeSystemIncorporated. AdobePhotoshop
set packages[3]=Clipchamp.Clipchamp
set packages[4]=Duolingo
set packages[5]=EclipseManager
set packages[6]=king.com.
set packages[7]=Microsoft.BingFinance
set packages[8]=Microsoft.BingNews
set packages[9]=Microsoft.BingSports
set packages[10]=Microsoft.BingWeather
set packages[11]=Microsoft.GetHelp
set packages[12]=Microsoft.Getstarted
set packages[13]=Microsoft.Office.Sway
set packages[14]=Microsoft.Office.OneNote
set packages[15]=Microsoft.MicrosoftOfficeHub
set packages[16]=Microsoft.MicrosoftSolitaireCollection
set packages[17]=Microsoft.MicrosoftStickyNotes
set packages[18]=Microsoft.MixedReality.Portal
set packages[19]=Microsoft.SkypeApp
set packages[20]=Microsoft.Todo
set packages[21]=Microsoft.WindowsAlarms
set packages[22]=microsoft.windowscommunicationsapps
set packages[23]=Microsoft.WindowsFeedbackHub
set packages[24]=Microsoft.WindowsMaps
set packages[25]=Microsoft.WindowsSoundRecorder
set packages[26]=Microsoft.XboxApp
set packages[27]=Microsoft.Xbox.TCUI
set packages[28]=Microsoft.XboxGameOverlay
set packages[29]=Microsoft.XboxGamingOverlay
set packages[30]=Microsoft.YourPhone
set packages[31]=Microsoft.ZuneMusic
set packages[32]=Microsoft.ZuneVideo
set packages[33]=Microsoft.Messaging
set packages[34]=MicrosoftCorporationII.MicrosoftFamily
set packages[35]=Microsoft.OutlookForWindows
set packages[36]=MicrosoftCorporationII.QuickAssist
set packages[37]=Microsoft.MicrosoftNotes
set packages[38]=Microsoft.Microsoft3DViewer
set packages[39]=Microsoft.OneConnect
set packages[40]=Microsoft.Print3D
set packages[41]=Microsoft.Services.Store.Engagement
set packages[42]=Microsoft.Wallet
set packages[43]=Microsoft.WindowsSoundRecorder
set packages[44]=Microsoft.WindowsFeedback
set packages[45]=Microsoft.XboxSpeechToTextOverlay
set packages[46]=Microsoft.549981C3F5F10
set packages[47]=netflix
set packages[48]=PandoraMedia
set packages[49]=SpotifyAB.SpotifyMusic
set packages[50]=.Twitter
set packages[51]=Windows.ContactSupport
set packages[52]=Windows.DevHome
set packages[53]=Microsoft.PowerAutomateDesktop
set packages[54]=MSTeams
set packages[55]=msteams
set packages[56]=MicrosoftTeams
set packages[57]=Microsoft.Copilot
set packages[58]=Disney.37853FC22B2CE
:: This is Paint 3D, NOT the real MS Paint
set packages[59]=Microsoft.MSPaint

set count=1

:: Iterate through the elements of the array to calculate its length
:ArrLoop
if defined packages[%count%] (
    set /a count+=1
    GOTO :ArrLoop
)

echo Removing %count% appx packages.

:: Loop through the packages and remove them, and their provisioned counterparts
for /l %%i in (1,1,%count%-1) do (
    set packageName=!packages[%%i]!
    if defined packageName (
        echo Removing installed package: !packageName!
        powershell -Command "Get-AppxPackage *!packageName!* -AllUsers | Remove-AppxPackage"
        echo Removing provisioned package: !packageName!
        powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like '!packageName!'} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }"
    )
)

endlocal

:: Remove legacy internet explorer if it is installed
powershell -Command "Get-WindowsCapability -Online "Browser.InternetExplorer~~~~0.0.11.0" | Remove-WindowsCapability -NoRestart -Online -ErrorAction 'Continue'"

:: Remove Exchange ActiveSync
powershell -Command "Get-WindowsCapability -Online "OneCoreUAP.OneSync~~~~0.0.1.0" | Remove-WindowsCapability -NoRestart -Online -ErrorAction 'Continue'"

:: Remove TPM Diagnostics app
powershell -Command "Get-WindowsCapability -Online "Tpm.TpmDiagnostics~~~~0.0.1.0" | Remove-WindowsCapability -NoRestart -Online -ErrorAction 'Continue'"

:: Enable DirectPlay (for games)
powershell -Command "Enable-WindowsOptionalFeature -FeatureName 'DirectPlay' -NoRestart -All -Online"

:: Remove defaultuser0 (not needed after installation)
net user defaultuser0 /delete

:: Rebuild performance counters
lodctr /r
lodctr /r
winmgmt /resyncperf

:: Re-register start menu (fixes random error)
powershell -Command "Stop-Process -Name 'StartMenuExperienceHost' -Force"
powershell -Command "Get-AppxPackage -AllUsers Microsoft.Windows.ShellExperienceHost | Foreach {Add-AppxPackage -DisableDevelopmentMode -Register '$($_.InstallLocation)\AppXManifest.xml'}"

:: Disable reserved storage https://www.ntlite.com/community/index.php?threads/discussion-reserved-storage.3327/
dism /Online /Set-ReservedStorageState /State:Disabled

:: Cleanup component store
dism /Online  /Cleanup-Image /StartComponentCleanup

:: Enable TCP BBR2 congestion algorithm (will only work on Windows 11, will throw errors otherwise)
netsh int tcp set supplemental Template=Internet CongestionProvider=bbr2
netsh int tcp set supplemental Template=Datacenter CongestionProvider=bbr2
netsh int tcp set supplemental Template=Compat CongestionProvider=CUBIC
netsh int tcp set supplemental Template=DatacenterCustom CongestionProvider=bbr2
netsh int tcp set supplemental Template=InternetCustom CongestionProvider=bbr2

:FondlerEnd
echo:
echo Press any key to exit...
pause >nul
exit /b

#:RunAsTI snippet to run as TI/System, with innovative HKCU load, ownership privileges, high priority, and explorer support
set ^ #=& set "0=%~f0"& set 1=%*& powershell -c iex(([io.file]::ReadAllText($env:0)-split'#\:RunAsTI .*')[1])& exit /b
function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
}; $A=,$env:1-split'"([^"]+)"|([^ ]+)',2|%{$_.Trim(' ')}; RunAsTI $A[1] $A[2]; #:RunAsTI lean & mean snippet by AveYo, 2023.07.06