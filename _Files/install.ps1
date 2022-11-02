$Host.UI.RawUI.WindowTitle = "Windows_Optimization_Pack"
$WindowsVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
Set-Location $env:temp

function WindowsTweaks_Dienste{
Stop-Service "WpcMonSvc"
Stop-Service "SharedRealitySvc"
Stop-Service "Fax"
Stop-Service "autotimesvc"
Stop-Service "wisvc"
Stop-Service "SDRSVC"
Stop-Service "MixedRealityOpenXRSvc"
Stop-Service "WalletService"
Stop-Service "SmsRouter"
Stop-Service "SharedAccess"
Stop-Service "MapsBroker"
Stop-Service "MNgcSvc"
Stop-Service "PhoneSvc"
Stop-Service "ScDeviceEnum"
Stop-Service "TabletInputService"
Stop-Service "icssvc"
Stop-Service "edgeupdatem"
Stop-Service "edgeupdate"
Stop-Service "MicrosoftEdgeElevationService"
Stop-Service "RetailDemo"
Stop-Service "MessagingService"
Stop-Service "PimIndexMaintenanceSvc"
Stop-Service "DoSvc"
Stop-Service "OneSyncSvc"
Stop-Service "UnistoreSvc"
Stop-Service "DiagTrack"
Stop-Service "dmwappushservice"
Stop-Service "diagnosticshub.standardcollector.service"
Stop-Service "diagsvc"
Stop-Service "WerSvc" 
Stop-Service "wercplsupport" 
Set-Service "WpcMonSvc" -StartupType Disabled
Set-Service "SharedRealitySvc" -StartupType Disabled
Set-Service "Fax" -StartupType Disabled
Set-Service "autotimesvc" -StartupType Disabled
Set-Service "wisvc" -StartupType Disabled
Set-Service "SDRSVC" -StartupType Disabled
Set-Service "MixedRealityOpenXRSvc" -StartupType Disabled
Set-Service "WalletService" -StartupType Disabled
Set-Service "SmsRouter" -StartupType Disabled
Set-Service "SharedAccess" -StartupType Disabled
Set-Service "MapsBroker" -StartupType Disabled
Set-Service "MNgcSvc" -StartupType Disabled
Set-Service "NgcCtnrSvc" -StartupType Disabled
Set-Service "PhoneSvc" -StartupType Disabled
Set-Service "ScDeviceEnum" -StartupType Disabled
Set-Service "TabletInputService" -StartupType Disabled
Set-Service "icssvc" -StartupType Disabled
Set-Service "edgeupdatem" -StartupType Disabled
Set-Service "edgeupdate" -StartupType Disabled
Set-Service "MicrosoftEdgeElevationService" -StartupType Disabled
Set-Service "RetailDemo" -StartupType Disabled
Set-Service "MessagingService" -StartupType Disabled
Set-Service "PimIndexMaintenanceSvc" -StartupType Disabled 
Set-Service "DoSvc" -StartupType Disabled
Set-Service "OneSyncSvc" -StartupType Disabled
Set-Service "UnistoreSvc" -StartupType Disabled
Set-Service "DiagTrack" -StartupType Disabled
Set-Service "dmwappushservice" -StartupType Disabled
Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled
Set-Service "diagsvc" -StartupType Disabled 
Set-Service "WerSvc" -StartupType Disabled
Set-Service "wercplsupport" -StartupType Disabled }

function WindowsTweaks_Registry{
#simeononsecurity / Windows-Optimize-Harden-Debloat
#undergroundwires / privacy.sexy
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseSpeed" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold1" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold2" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseTrails" /T REG_DWORD /D 0 /F
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA" /T REG_DWORD /D 00000000 /F
REG DELETE "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy" /F
REG DELETE "HKCR\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe" /F
New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type "String" -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type "String" -Value 0 -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type "String" -Value 0 -Force
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "SyncDisabled" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type "DWORD" -Value "0" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" -Name "Debugger" -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value "1" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsSpotlightFeatures" -Type "DWORD" -Value "1" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type "DWORD" -Value "1" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FindMyDevice" -Name AllowFindMyDevice -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Maps" -Name AutoDownloadAndUpdateMapData -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Maps" -Name AllowUntriggeredNetworkTrafficOnSettingsPage -Type "DWORD" -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsRunInBackground -Type "DWORD" -Value 2 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowRun" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Name "1" -Type "String" -Value "software_reporter_tool.exe" /f
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\software_reporter_tool.exe" -Name Debugger -Type "String" -Value "%windir%\System32\taskkill.exe" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupEnabled" -Type "String" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "ChromeCleanupReportingEnabled" -Type "String" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Google\Chrome" -Name "MetricsReportingEnabled" -Type "String" -Value 0 -Force}

function WindowsTweaks_Tasks{
Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineCore" | Disable-ScheduledTask
Get-ScheduledTask -TaskName "GoogleUpdateTaskMachineUA" | Disable-ScheduledTask
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /DISABLE }

function WindowsTweaks_Packages{
Get-AppxPackage -alluser Microsoft.MicrosoftEdgeDevToolsClient_1000.22000.1.0_neutral_neutral_8wekyb3d8bbwe | Remove-AppxPackage 
Get-AppxPackage -alluser Microsoft.Windows.CloudExperienceHost_10.0.22000.1_neutral_neutral_cw5n1h2txyewy | Remove-AppxPackage
Get-AppxPackage -alluser Microsoft.Windows.ParentalControls_1000.22000.1.0_neutral_neutral_cw5n1h2txyewy | Remove-AppxPackage 
Get-AppxPackage -alluser Microsoft.AccountsControl_10.0.22000.1_neutral__cw5n1h2txyewy | Remove-AppxPackage 
Get-AppxPackage -alluser Microsoft.OneDriveSync_21220.1024.5.0_neutral__8wekyb3d8bbwe | Remove-AppxPackage 
Get-AppxPackage -alluser WinRAR.ShellExtension_1.0.0.1_x64__s4jet1zx4n14a | Remove-AppxPackage }

function WindowsTweaks_Features{
dism /Online /Disable-Feature /FeatureName:"TelnetClient" /NoRestart
dism /Online /Disable-Feature /FeatureName:"WCF-TCP-PortSharing45" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SmbDirect" /NoRestart
dism /Online /Disable-Feature /FeatureName:"TFTP" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-All" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-Clients" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Tools-All" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-PowerShell" /NoRestart }

function WindowsTweaks_Index{
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='C:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False}
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='D:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False}
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='E:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False}
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='F:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False} }

function SophiaScript{
#Copyright (c) 2014—2022 farag
#Copyright (c) 2019—2022 farag & Inestic
#https://github.com/farag2
#https://github.com/Inestic

function SophiaScript_Win11{
#Version: v6.2.1
ScheduledTasks -Disable
UninstallUWPApps
WindowsFeatures -Disable
WindowsCapabilities -Uninstall
DiagTrackService -Disable
DiagnosticDataLevel -Minimal
ErrorReporting -Disable
FeedbackFrequency -Never
SigninInfo -Disable
LanguageListAccess -Disable
AdvertisingID -Disable
WindowsWelcomeExperience -Hide
WindowsTips -Disable
SettingsSuggestedContent -Hide
AppsSilentInstalling -Disable
WhatsNewInWindows -Disable
TailoredExperiences -Disable
BingSearch -Disable
ThisPC -Hide
CheckBoxes -Disable
HiddenItems -Enable
FileExtensions -Show
MergeConflicts -Show
FileExplorerCompactMode -Disable
OneDriveFileExplorerAd -Hide
SnapAssist -Disable
SnapAssistFlyout -Enable
FileTransferDialog -Detailed
RecycleBinDeleteConfirmation -Enable
QuickAccessRecentFiles -Hide
QuickAccessFrequentFolders -Hide
TaskbarAlignment -Left
TaskbarSearch -Hide
TaskViewButton -Hide
TaskbarWidgets -Hide
TaskbarChat -Hide
UnpinTaskbarShortcuts -Shortcuts Edge, Store
ControlPanelView -Category
WindowsColorMode -Dark
AppColorMode -Dark
FirstLogonAnimation -Disable
JPEGWallpapersQuality -Max
TaskManagerWindow -Expanded
RestartNotification -Show
ShortcutsSuffix -Disable
PrtScnSnippingTool -Enable
AppsLanguageSwitch -Disable
AeroShaking -Enable
OneDrive -Uninstall
StorageSense -Enable
StorageSenseFrequency -Month
StorageSenseTempFiles -Enable
Hibernation -Disable
Win32LongPathLimit -Disable
BSoDStopError -Enable
AdminApprovalMode -Never
MappedDrivesAppElevatedAccess -Enable
DeliveryOptimization -Disable
WaitNetworkStartup -Enable
WindowsManageDefaultPrinter -Disable
UpdateMicrosoftProducts -Enable
PowerPlan -Balanced
NetworkAdaptersSavePower -Disable
IPv6Component -Disable
WinPrtScrFolder -Desktop
RecommendedTroubleshooting -Automatically
FoldersLaunchSeparateProcess -Enable
ReservedStorage -Disable
F1HelpPage -Disable
NumLock -Enable
StickyShift -Disable
Autoplay -Disable
ThumbnailCacheRemoval -Enable
SaveRestartableApps -Disable
NetworkDiscovery -Enable
ActiveHours -Automatically
RestartDeviceAfterUpdate -Enable
DefaultTerminalApp -WindowsTerminal
UnpinAllStartApps
RunPowerShellShortcut -Elevated
StartLayout -ShowMorePins
CortanaAutostart -Disable
TeamsAutostart -Disable
CheckUWPAppsUpdates
XboxGameBar -Disable
XboxGameTips -Disable
GPUScheduling -Enable
CleanupTask -Register
SoftwareDistributionTask -Register
TempTask -Register
NetworkProtection -Disable
PUAppsDetection -Disable
DismissMSAccount
DismissSmartScreenFilter
AuditProcess -Enable
CommandLineProcessAudit -Enable
EventViewerCustomView -Enable
PowerShellModulesLogging -Enable
PowerShellScriptsLogging -Enable
AppsSmartScreen -Disable
SaveZoneInformation -Disable
WindowsSandbox -Disable
DNSoverHTTPS -Enable -PrimaryDNS 1.0.0.1 -SecondaryDNS 1.1.1.1
MSIExtractContext -Show
CABInstallContext -Show
RunAsDifferentUserContext -Hide
CastToDeviceContext -Hide
ShareContext -Hide
EditWithPhotosContext -Hide
CreateANewVideoContext -Hide
PrintCMDContext -Hide
IncludeInLibraryContext -Hide
SendToContext -Hide
CompressedFolderNewContext -Hide
MultipleInvokeContext -Enable
UseStoreOpenWith -Hide
OpenWindowsTerminalContext -Show
OpenWindowsTerminalAdminContext -Enable
Windows10ContextMenu -Disable
UpdateLGPEPolicies
Errors } 

function SophiaScript_Win10{
#Version: v5.14.1
ScheduledTasks -Disable
UninstallUWPApps 
WindowsFeatures -Disable
WindowsCapabilities -Uninstall
DiagTrackService -Disable
DiagnosticDataLevel -Minimal
ErrorReporting -Disable
FeedbackFrequency -Never
SigninInfo -Disable
LanguageListAccess -Disable
AdvertisingID -Disable
WindowsWelcomeExperience -Hide
WindowsTips -Disable
SettingsSuggestedContent -Hide
AppsSilentInstalling -Disable
WhatsNewInWindows -Disable
TailoredExperiences -Disable
BingSearch -Disable
ThisPC -Hide
CheckBoxes -Disable
HiddenItems -Enable
FileExtensions -Show
MergeConflicts -Show
CortanaButton -Hide
OneDriveFileExplorerAd -Hide
SnapAssist -Disable
FileTransferDialog -Detailed
FileExplorerRibbon -Expanded
RecycleBinDeleteConfirmation -Enable
3DObjects -Hide
QuickAccessRecentFiles -Hide
QuickAccessFrequentFolders -Hide
TaskbarSearch -Hide
TaskViewButton -Hide
SearchHighlights -Hide
PeopleTaskbar -Hide
SecondsInSystemClock -Hide
WindowsInkWorkspace -Hide
NotificationAreaIcons -Hide
MeetNow -Hide
NewsInterests -Disable
UnpinTaskbarShortcuts -Shortcuts Edge, Store, Mail
ControlPanelView -Category
WindowsColorMode -Dark
AppColorMode -Dark
NewAppInstalledNotification -Hide
FirstLogonAnimation -Disable
JPEGWallpapersQuality -Max
TaskManagerWindow -Expanded
RestartNotification -Show
ShortcutsSuffix -Disable
PrtScnSnippingTool -Enable
AppsLanguageSwitch -Disable
AeroShaking -Enable
OneDrive -Uninstall
StorageSense -Enable
StorageSenseFrequency -Month
StorageSenseTempFiles -Enable
Hibernation -Disable
Win32LongPathLimit -Disable
BSoDStopError -Enable
AdminApprovalMode -Never
MappedDrivesAppElevatedAccess -Enable
DeliveryOptimization -Disable
WaitNetworkStartup -Enable
UpdateMicrosoftProducts -Enable
PowerPlan -Balanced
NetworkAdaptersSavePower -Disable
IPv6Component -Disable
WinPrtScrFolder -Desktop
RecommendedTroubleshooting -Automatically
FoldersLaunchSeparateProcess -Enable
ReservedStorage -Disable
F1HelpPage -Disable
NumLock -Enable
StickyShift -Disable
Autoplay -Disable
ThumbnailCacheRemoval -Enable
SaveRestartableApps -Disable
NetworkDiscovery -Enable
ActiveHours -Automatically
RestartDeviceAfterUpdate -Enable
UninstallPCHealthCheck
RecentlyAddedApps -Hide
AppSuggestions -Hide
RunPowerShellShortcut -Elevated
PinToStart -UnpinAll
CortanaAutostart -Disable
BackgroundUWPApps -Disable
CheckUWPAppsUpdates
XboxGameBar -Disable
XboxGameTips -Disable
GPUScheduling -Enable
CleanupTask -Register
SoftwareDistributionTask -Register
TempTask -Register
NetworkProtection -Disable
PUAppsDetection -Disable
DefenderSandbox -Disable
DismissMSAccount
DismissSmartScreenFilter
AuditProcess -Enable
CommandLineProcessAudit -Enable
EventViewerCustomView -Enable
PowerShellModulesLogging -Enable
PowerShellScriptsLogging -Enable
AppsSmartScreen -Disable
SaveZoneInformation -Disable
WindowsSandbox -Disable
MSIExtractContext -Show
CABInstallContext -Show
RunAsDifferentUserContext -Hide
CastToDeviceContext -Hide
EditWithPaint3DContext -Hide
EditWithPhotosContext -Hide
CreateANewVideoContext -Hide
ImagesEditContext -Hide
PrintCMDContext -Hide
IncludeInLibraryContext -Hide
SendToContext -Hide
BitmapImageNewContext -Hide
RichTextDocumentNewContext -Hide
CompressedFolderNewContext -Hide
MultipleInvokeContext -Enable
UseStoreOpenWith -Hide
UpdateLGPEPolicies
Errors }

function SophiaScript_Dependencies{
[cmdletbinding()]
param ([parameter(mandatory = $false)]
[string[]]
$functions)
remove-module -name sophia -force -erroraction ignore
import-module -name $env:temp\Sophia_Script\manifest\sophia.psd1 -passthru -force
import-localizeddata -bindingvariable global:localization -basedirectory $env:temp\Sophia_Script\localizations -filename sophia
if ($functions) { invoke-command -scriptblock {checkings}
foreach ($function in $functions)
{invoke-expression -command $function }
invoke-command -scriptblock {errors; refreshenvironment}
exit}}
	
function SophiaScript_Downloade{
Clear-Host
IF($WindowsVersion -eq "Microsoft Windows 11 Home" -Or $WindowsVersion -eq "Microsoft Windows 11 Pro") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.2.1/Sophia.Script.for.Windows.11.v6.2.1.zip" -Destination $env:temp\Sophia.zip
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination $env:temp\Sophia_Script\}
SophiaScript_Dependencies
SophiaScript_Win11
else { IF($WindowsVersion -eq "Microsoft Windows 10 Home" -Or $WindowsVersion -eq "Microsoft Windows 10 Pro") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.2.1/Sophia.Script.for.Windows.10.v5.14.1.zip" -Destination $env:temp\Sophia.zip
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination $env:temp\Sophia_Script\
SophiaScript_Dependencies
SophiaScript_Win10} }
REG ADD "HKLM\SOFTWARE\Windows_Optimisation_Pack\" /V "Sophia_Script" /T REG_DWORD /D 1 /F
Clear-Host } 
SophiaScript_Downloade }

function TakeOwnership{
New-Item "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership" -force -ea SilentlyContinue
New-Item "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command" -force -ea SilentlyContinue
New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership" -force -ea SilentlyContinue
New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -force -ea SilentlyContinue
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'AppliesTo' -Value 'NOT (System.ItemPathDisplay:="C:\Users" OR System.ItemPathDisplay:="C:\ProgramData" OR System.ItemPathDisplay:="C:\Windows" OR System.ItemPathDisplay:="C:\Windows\System32" OR System.ItemPathDisplay:="C:\Program Files" OR System.ItemPathDisplay:="C:\Program Files (x86)")' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;}

function Begruesung{
Clear-Host
" ==========================="
"  Windows Optimization Pack"
" ==========================="
" Schritt 1 - Vorbereitung"
" Schritt 2 - Laufzeitkomponenten"
" Schritt 3 - Extras"
" Schritt 4 - Sophia Script"
" Schritt 5 - o&oShutup"
" Schritt 5 - Windows Optimierungen"
" Schritt 7 - Autostart"
" Schritt 8 - Windows Refresh"
timeout 30
Clear-Host }

function SystemPunkt{
vssadmin delete shadows /all /quiet
Enable-ComputerRestore -Drive "C:\"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /F }

function Pruefungen{
if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){
Write-Warning " Reboot Pending !"
Write-Warning " Das Script wird in 20 Sekunden beendet"
Start-Sleep 20
exit}
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
Write-Warning " Keine benoetigten Admin Rechte vorhanden"
Write-Warning " Das Script wird in 20 Sekunden beendet"
Start-Sleep 20
exit} 
if ((Test-Path "HKLM:\SOFTWARE\Windows_Optimisation_Pack")){
Write-Warning " Das System wurde bereits durch das Windows_Opsimisation_Pack optimiert"
"Moechten sie wirklich fortfahren?"
$weitermachen = Read-Host "Ja oder Nein ?"
IF(!($weitermachen -eq "Ja" -Or $weitermachen -eq "j" -Or $weitermachen -eq "JA" -Or $weitermachen -eq "y" -Or $weitermachen -eq "yes")) {         
Write-Warning " Das Script wird in 20 Sekunden beendet"
Start-Sleep 20
exit}} }

function Autoruns{
Start-BitsTransfer -Source "https://download.sysinternals.com/files/Autoruns.zip" -Destination $env:temp\Autoruns.zip
Expand-Archive $env:temp\Autoruns.zip $env:temp\Autoruns
Start-Process $env:temp\Autoruns\Autoruns64.exe }

function WindowsRefresh{
Clear-Host
gpupdate.exe /force 
Cmd.exe /c Cleanmgr /sagerun:65535
Get-ChildItem -Path $ENV:userprofile\AppData\Local\Temp *.* -Recurse | Remove-Item -Force -Recurse 
Get-ChildItem -Path $env:windir\Prefetch *.* -Recurse | Remove-Item -Force -Recurse SilentlyContinue 
Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse 
Remove-Item -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
Clear-BCCache -Force -ErrorAction SilentlyContinue
lodctr /r
lodctr /r
taskkill /f /im explorer.exe
Start-Process explorer.exe 
Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force SilentlyContinue}


function Laufzeitkomponenten{
Clear-Host
""
" Laufzeitkomponenten installieren..."
Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.3.2691/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination "$env:temp\winget.msixbundle"
Invoke-Expression 'cmd /c start powershell -windowstyle hidden -Command { add-AppxPackage -Path "$env:temp\winget.msixbundle";winget source update}'
Start-Sleep 5
winget install --id=Microsoft.VCRedist.2015+.x64 --exact --accept-source-agreements
winget install --id=Microsoft.VCRedist.2015+.x86 --exact --accept-source-agreements
winget install --id=Microsoft.dotNetFramework --exact --accept-source-agreements
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x64 --exact --accept-source-agreements
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x86 --exact --accept-source-agreements
winget install --id=Microsoft.DirectX --exact --accept-source-agreements}

function SpieleOrdner{
New-Item -Path "C:\Spiele" -ItemType Directory }

function Festplatten_Name{
Label C: Windows }

function Updaten{
winget upgrade --all --accept-source-agreements}

function Programme{
Clear-Host
""
" Programme installieren..."
winget install --id=RARLab.WinRAR --exact --accept-source-agreements}

function Ende{
REG ADD "HKLM\SOFTWARE\Windows_Optimisation_Pack\" /V "Erfolgreich" /T REG_DWORD /D 1 /F
Clear-Host
" Ihr System wurde erforlgreich optimiert"
""
Write-Warning " Der Computer wird in 60 Sekunden automatisch neugestartet !!!"
timeout 60
Restart-Computer }

function Extras{
[reflection.assembly]::LoadWithPartialName( "System.Windows.Forms")
$form = New-Object Windows.Forms.Form
$form.text = "Windows_Optimisation_Pack"
$Titel = New-Object Windows.Forms.Label
$Titel.Location = New-Object Drawing.Point 70,25
$Titel.Size = New-Object Drawing.Point 200,15
$Titel.text = "Windows_Optimisation_Pack"
$Textbox = New-Object System.Windows.Forms.TextBox
$Textbox.Size = New-Object Drawing.Point 160,20
$Textbox.location = New-Object Drawing.Point 60,170
$Username=[Environment]::UserName
$TextBox.Text = $Username+"-Computer"
$button1 = New-Object Windows.Forms.Button
$button1.text = "Process Lasso installieren"
$button1.Location = New-Object Drawing.Point 30,60
$button1.Size = New-Object Drawing.Point 100,35
$button2 = New-Object Windows.Forms.Button
$button2.text = "PS4 Controller installieren"
$button2.Location = New-Object Drawing.Point 140,60
$button2.Size = New-Object Drawing.Point 100,35
$button3 = New-Object Windows.Forms.Button
$button3.text = "AutoActions installieren"
$button3.Location = New-Object Drawing.Point 30,100
$button3.Size = New-Object Drawing.Point 100,35
$button4 = New-Object Windows.Forms.Button
$button4.text = "DLSS Swapper"
$button4.Location = New-Object Drawing.Point 140,100
$button4.Size = New-Object Drawing.Point 100,35
$button5 = New-Object Windows.Forms.Button
$button5.text = "Weiter"
$button5.Location = New-Object Drawing.Point 80,200
$button5.Size = New-Object Drawing.Point 110,40
$button1.add_click({
$Titel.text = "Bitte warten..."
Invoke-WebRequest 'https://dl.bitsum.com/files/processlassosetup64.exe' -OutFile $env:temp\ProcesslassoSetup64.exe
Start-Process -FilePath "$env:temp\ProcesslassoSetup64.exe" -ArgumentList "/S /language=German"
$button1.Enabled = $false
$button1.IsAccessible = $false
$Titel.text = "Windows_Optimisation_Pack"})
$button2.add_click({
$Titel.text = "Bitte warten..."
Invoke-WebRequest 'https://github.com/Ryochan7/DS4Windows/releases/download/v3.1.9/DS4Windows_3.1.9_x64.zip' -OutFile $env:temp\DS4Windows.zip 
Expand-Archive $env:temp\DS4Windows.zip "C:\Program Files\" -force
Remove-Item -Path $env:temp\DS4Windows.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Controller.lnk")
$Shortcut.TargetPath = "C:\Program Files\DS4Windows\DS4Windows.exe"
$Shortcut.Save()
$button2.Enabled = $false
$button2.IsAccessible = $false
$Titel.text = "Windows_Optimisation_Pack"})
$button3.add_click({
$Titel.text = "Bitte warten..."
Invoke-WebRequest 'https://github.com/Codectory/AutoActions/releases/download/1.9.19/Release_AutoActions_1.9.19_x64.zip' -OutFile $env:temp\AutoActions.zip 
Expand-Archive $env:temp\AutoActions.zip "C:\Program Files\AutoActions" -force
Remove-Item -Path $env:temp\AutoActions.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\AutoActions.lnk")
$Shortcut.TargetPath = "C:\Program Files\AutoActions\AutoActions.exe"
$Shortcut.Save()
$button3.Enabled = $false
$button3.IsAccessible = $false
$Titel.text = "Windows_Optimisation_Pack"})
$button4.add_click({
$Titel.text = "Bitte warten..."
winget install "DLSS Swapper" --source msstore  --accept-package-agreements --accept-source-agreements 
$Text.Text = "DLSS Swapper wurde installiert"
$button4.Enabled = $false
$button4.IsAccessible = $false
$Titel.text = "Windows_Optimisation_Pack"})
$button5.Add_Click({
Rename-Computer -NewName $TextBox.Text 
$Form.Close()})
$form.controls.add($Titel)
$form.controls.add($Textbox)
$form.controls.add($button1)
$form.controls.add($button2)
$form.controls.add($button3)
$form.controls.add($button4)
$form.controls.add($button5)
$form.ShowDialog() }

function ooShutup_config{
New-Item $env:temp\ooshutup10.cfg
Set-Content $env:temp\ooshutup10.cfg "
P001	+
P002	+
P003	+
P004	+
P005	+
P006	+
P008	+
P026	+
P027	+
P028	+
P064	+
P065	+
P066	+
P067	+
P070	+
P069	+
P009	+
P010	-
P015	-
P068	-
P016	-
A001	+
A002	+
A003	+
A004	+
A006	+
A005	+
P007	+
P036	+
P025	+
P033	+
P023	+
P056	-
P057	-
P012	-
P034	-
P013	-
P035	-
P062	-
P063	-
P081	-
P047	-
P019	-
P048	+
P049	+
P020	-
P037	-
P011	-
P038	-
P050	-
P051	-
P018	-
P039	-
P021	-
P040	-
P022	-
P041	-
P014	-
P042	-
P052	-
P053	-
P054	-
P055	-
P029	-
P043	-
P030	-
P044	-
P031	-
P045	-
P032	-
P046	-
P058	-
P059	-
P060	-
P061	-
P071	-
P072	-
P073	-
P074	-
P075	-
P076	-
P077	-
P078	-
P079	-
P080	-
P024	-
S001	+
S002	+
S003	+
S008	-
E101	+
E115	+
E118	+
E107	+
E111	+
E112	+
E109	+
E121	+
E103	+
E123	+
E124	+
E119	+
E120	+
E122	+
E106	-
E001	+
E002	+
E003	+
E008	+
E007	+
E010	+
E011	+
E012	+
E009	+
E004	+
E005	+
E013	+
E014	+
E006	-
Y001	+
Y002	+
Y003	+
Y004	+
Y005	+
Y006	+
Y007	+
C012	+
C002	+
C013	+
C007	+
C008	+
C009	+
C010	+
C011	+
C014	+
L001	+
L003	+
L004	+
L005	+
U001	+
U004	+
U005	+
U006	+
U007	+
W001	+
W011	+
W004	-
W005	-
W010	-
W009	-
P017	-
W006	-
W008	-
M006	+
M011	+
M010	+
O003	+
O001	+
S012	+
S013	+
S014	+
K001	+
K002	+
K005	+
M022	+
M001	+
M004	+
M005	+
M003	+
M012	+
M013	+
M014	+
M015	+
M016	+
M017	+
M018	+
M019	+
M020	+
M021	+
N001	-" }

function ooShutup{
Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination $env:temp\OOSU10.exe
ooShutup_config
Set-Location $env:temp
.\OOSU10.exe ooshutup10.cfg \quiet }

Begruesung
Pruefungen
SystemPunkt
Laufzeitkomponenten
Programme
#Updaten
Extras
SophiaScript
ooShutup
SpieleOrdner
Festplatten_Name
WindowsTweaks_Index
WindowsTweaks_Packages
WindowsTweaks_Dienste
WindowsTweaks_Tasks
WindowsTweaks_Registry
WindowsTweaks_Features
TakeOwnership
Autoruns
WindowsRefresh
Ende
# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUnVQqmRbnTCd1ym6S9Tz1xmtY
# enOgggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
# AQsFADAkMSIwIAYDVQQDDBlXaW5kb3dzX09wdGltaXNhdGlvbl9QYWNrMB4XDTIy
# MTAwMzA5NTA0MloXDTMwMTIzMTIyMDAwMFowJDEiMCAGA1UEAwwZV2luZG93c19P
# cHRpbWlzYXRpb25fUGFjazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AMqbrd2/6x589A5LablKK+Ed5zN+CoIBO/0DtWoJ7mxT+4IWA+0d5kWYTUW/MI7Y
# BHS5r7kuUe1SX2E90CVKVKk7HVrbMCv707M+PWWQs+D0Q9vrXqMEcuEmoRcrQH7j
# kTzs+Y4kKAkD/8Je1+5uBpyu6H1FTH9290no+h9bgvCp5UrhzzFJkVyRjCXJLlbV
# NgLEWPDFa0mMEVNoXxa7m9AwnCNSCUMGEVhPzIMameK0W9jEKPTxfPdXhRWTu4lz
# 7vzp5HBvn3XdutyJhH1+txCgc6uNJe/kxZENvHTObRWxkMotq8x3GqjuvNpY3t3O
# MndeMCYiI84GBuixSXeaXf0CAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBSOhOkyv1Z+aPC/kWeVNpKwbI3omjAN
# BgkqhkiG9w0BAQsFAAOCAQEAku31A0acjtrpBqJn7nwifNv5EmiryXeGZm0RCflv
# /JRIyvjHMDvo7Mb9p4VTRciZt2kyIDzefda1XU597frO4TgNlBgH816TxMJ4qZlb
# ScZXc/zhBOu51oA53gt641h0zhp5dJpP/gE8VFhBUV0IVTBPnunEK1hpYmGLftAe
# 3FjiDRQ+b+q/zT0uUbrFdyYHnlyL40bPl3XVDwVaJhDGW7At/s1K4ZA96Xej5Wxa
# ffqIOiTEjscTmVeXLCf44EiyxZ0vF20BWwvCosONptr1MyQXFI5azArQOU9BfhYL
# rJXoqIvVp1G2GWcfqZGLAoxnidVEN1ndnbkEFCpWeNcAkzGCAdkwggHVAgEBMDgw
# JDEiMCAGA1UEAwwZV2luZG93c19PcHRpbWlzYXRpb25fUGFjawIQJBEmIU6B/6pL
# +Icl+8AGsDAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUwl7+qyVtkDyy9lcTRmtZwJPXmWAwDQYJ
# KoZIhvcNAQEBBQAEggEAyoAbPK5Y0c/buRS5olE2wwvl5U2a93IbyodXLrv6fofw
# 5XiQCBAWEnW4d1ia9BPMXKEgp35JVsAY3P0pnZuNZ+GquU7oD8OupgnjsVyO5bIs
# Da0pTVBgo/HERSg1ZJGuB2udBVdMEYA+PY+ovquKzRukjIrcBVndQgZcTSyJZV/I
# MnEcYNFuZykAgov9HUGGLIhTpFba+ViuJ78beDxL3xqZ6rSWi2urYDh3iKvKgrxz
# /2NZZx8NzEO/D0ri3Rb1jGhGJQlwZrfnpcr+4FGo9kBQN4GyhKzqczIbHbJw+BGa
# 2jgndGIP0WVT13Zbd3u6BWsK+7OyJ0LyDn35idf7mg==
# SIG # End signature block
