@setlocal DisableDelayedExpansion
@echo off &title commence the fondling

:: most of this file is ripped from MAS
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

:: HKCU entries will also be propagated to new users:
reg load HKU\New "%SystemDrive%\Users\Default\NTUSER.DAT" >nul && set "HKU=1" || set "HKU="

:: Disable cortana
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaInAAD /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
@set "rule=v2.25|Action=Block|Active=TRUE|Dir=Out|Protocol=6|App=%systemroot%"
@set "rule=%rule%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\searchUI.exe|Name=Block outbound Cortana|"
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" /f /v {0DE40C8E-C126-4A27-9371-A27DAB1039F7} /d "%rule%" 

:: Disable web and location-based search
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f

:: Disable Windows Spotlight and ads on lock screen
reg add "HKEY_Local_Machine\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v LockScreenOverlaysDisabled /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKU\New\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /f /v DisableWindowsSpotlightFeatures /d 1 /t reg_dword
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v RotatingLockScreenOverlayEnabled /t REG_DWORD /d 0 /f

:: Disable find my device
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FindMyDevice" /v LocationSyncEnabled /t REG_DWORD /d 0 /f

:: Disable advertising IDs for interest-based advertising
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

:: Don't let websites access locally installed language list
reg add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f
reg add "HKU\New\Control Panel\International\User Profile" /f /v HttpAcceptLanguageOptOut /d 1 /t reg_dword

:: Disable Windows tips
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /f /v DisableSoftLanding /d 1 /t reg_dword

:: Disable smartscreen
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /f /v ConfigureAppInstallControlEnabled /d 1 /t reg_dword
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /f /v ConfigureAppInstallControl /d "Anywhere"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f /v EnableSmartScreen /d 0 /t reg_dword
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f

:: Disable reporting unknown app signatures
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f

:: Disable defender nag notifications
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting" /f /v DisableEnhancedNotifications /d 1 /t reg_dword

:: Don't automatically connect to open hotspots
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /f /v AutoConnectAllowedOEM /d 0 /t reg_dword

:: Prevent Kerberos from using DES or RC4
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" /v SupportedEncryptionTypes /t REG_DWORD /d 2147483640 /f

:: Cipher suites preference order
reg add "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002" /v Functions /t REG_SZ /d "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_RSA_WITH_AES_256_CBC_SHA,TLS_RSA_WITH_AES_128_CBC_SHA,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_3DES_EDE_CBC_SHA,TLS_RSA_WITH_NULL_SHA256,TLS_RSA_WITH_NULL_SHA,TLS_PSK_WITH_AES_256_GCM_SHA384,TLS_PSK_WITH_AES_128_GCM_SHA256,TLS_PSK_WITH_AES_256_CBC_SHA384,TLS_PSK_WITH_AES_128_CBC_SHA256,TLS_PSK_WITH_NULL_SHA384,TLS_PSK_WITH_NULL_SHA256" /f

:: Encrypt and sign outgoing secure channel traffic when possible
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel /t REG_DWORD /d 1 /f

:: Opt out of advertising and data collection
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableCloudOptimizedContent /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-202913Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-202914Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-280797Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-280811Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-280812Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-280813Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-280814Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-280815Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-280810Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-280817Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-310091Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-310092Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-310093Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-310094Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-314558Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-314559Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-314562Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-314563Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-314566Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-314567Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-338380Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-338387Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-338381Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-338388Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-338382Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-338389Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-338386Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-338393Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-346480Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-346481Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-353694Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-353695Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-353696Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-353697Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-353698Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-353699Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000044Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000045Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000105Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000106Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000161Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000162Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000163Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000164Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000165Enabled /d 0 /t reg_dword
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /f /v SubscribedContent-88000166Enabled /d 0 /t reg_dword
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SystemPaneSuggestionsEnabled /t REG_DWORD /d 0 /f

:: Disallow automatic app installs and app suggestions (must be applied pre-install or it will only apply for new users)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /d 0 /t reg_dword /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v value /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v AllowInputPersonalization /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /T REG_DWORD /V "AllowTelemetry" /D 0 /F
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet" /t REG_DWORD /v SpyNetReporting /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender\Spynet"  /t REG_DWORD /v SubmitSamplesConsent /d 2 /f

:: Show hidden files and file extensions
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
:: reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
:: reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

:: Turn off various stuff, some qol
reg add "HKLM\SOFTWARE\Policies\Microsoft\WindowsStore" /f /v AutoDownload /d 2 /t reg_dword
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v EnableCdp /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v JPEGImportQuality /t REG_DWORD /d 100 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_SZ /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows Security Health\State" /t REG_DWORD /v AccountProtection_MicrosoftAccount_Disconnected /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\OneDrive" /v PreventNetworkTrafficPreUserSignIn /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f

:: Disable left widgets in Windows 11
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /T REG_DWORD /V "value" /D 0 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Dsh" /T REG_DWORD /V "AllowNewsAndInterests" /D 0 /F

:: Disable Copilot
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /T REG_DWORD /V "TurnOffWindowsCopilot" /D 1 /F
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsCopilot" /T REG_DWORD /V "TurnOffWindowsCopilot" /D 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /T REG_DWORD /V "DisableAIDataAnalysis" /D 1 /F

:: Disable Microsoft account sign-in nag in Windows 11
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /V "Start_AccountNotifications" /D 1 /F

:: Disable autoplay
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /T REG_DWORD /V "DisableAutoplay" /D 1 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /T REG_DWORD /V "DisableAutoplay" /D 1 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /T REG_DWORD /V "NoAutoplayfornonVolume" /D 1 /F
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 0xff /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /T REG_DWORD /V HiberbootEnabled /D 0 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\EdgeUpdate" /v DoNotUpdateToEdgeWithChromium /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v NoUseStoreOpenWith /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

:: Turn off cloud clipboard
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f /v AllowCrossDeviceClipboard /d 0 /t reg_dword

:: Disable "Tailored Experiences" with diagnostic data
reg add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg add "HKU\New\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /f /v DisableTailoredExperiencesWithDiagnosticData /d 1 /t reg_dword
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f

:: Disable spelling data collection
reg add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKU\New\Software\Microsoft\InputPersonalization" /f /v RestrictImplicitInkCollection /d 1 /t reg_dword
reg add "HKU\New\Software\Microsoft\InputPersonalization" /f /v RestrictImplicitTextCollection /d 1 /t reg_dword

:: Disable "continuing experiences on other devices"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /f /v EnableCdp /d 0 /t reg_dword
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f

:: Turn off telemetry
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v DisableOneSettingsDownloads /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

:: Turn off location servies and location history (remove for laptops)
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessLocation /t REG_DWORD /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /v Location /t REG_SZ /d Deny /f

:: Disable LLMNR
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v DisableSmartNameResolution /t REG_DWORD /d 1 /f

:: Disable storing password in memory in cleartext
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0 /f

:: Require administrator to install printer drivers
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers /t REG_DWORD /d 1 /f

:: Uninstall Onedrive
taskkill /f /im OneDrive.exe
%SystemRoot%\System32\OneDriveSetup.exe /uninstall
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall

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

:: Loop through the packages and remove them
for /l %%i in (1,1,51) do (
    set packageName=!packages[%%i]!
    if defined packageName (
        echo Removing installed package: !packageName!
        powershell -Command "Get-AppxPackage *!packageName!* -AllUsers | Remove-AppxPackage"
        echo Removing provisioned package: !packageName!
        powershell -Command "Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -Like '!packageName!'} | ForEach-Object { Remove-AppxProvisionedPackage -Online -PackageName $_.PackageName }"
    )
)

endlocal

:FondlerEnd
echo:
echo Press any key to exit...
pause >nul
exit /b
