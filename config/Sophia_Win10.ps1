<#
	Version: v5.14.5

	Copyright (c) 2014—2023 farag
	Copyright (c) 2019—2023 farag & Inestic

	https://github.com/farag2
	https://github.com/Inestic
#>

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string[]]
	$Functions
)

Clear-Host

$Host.UI.RawUI.WindowTitle = "Sophia Script for Windows 10 | $([char]0x00A9) farag & Inestic, 2014$([char]0x2013)2023"

Remove-Module -Name Sophia -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\Manifest\Sophia.psd1 -PassThru -Force

Import-LocalizedData -BindingVariable Global:Localization -BaseDirectory $PSScriptRoot\Localizations -FileName Sophia

if ($Functions)
{
	Invoke-Command -ScriptBlock {Checkings}

	foreach ($Function in $Functions)
	{
		Invoke-Expression -Command $Function
	}

	# The "RefreshEnvironment" and "Errors" functions will be executed at the end
	Invoke-Command -ScriptBlock {Errors; RefreshEnvironment}

	exit
}


# Turn off the diagnostics tracking scheduled tasks
ScheduledTasks -Disable

#Uninstall UWP apps using the pop-up dialog box
UninstallUWPApps 

#Disable the Windows features using the pop-up dialog box
WindowsFeatures -Disable

#Uninstall optional features using the pop-up dialog box
WindowsCapabilities -Uninstall

# Disable the "Connected User Experiences and Telemetry" service (DiagTrack), and block the connection for the Unified Telemetry Client Outbound Traffic
# Disabling the "Connected User Experiences and Telemetry" service (DiagTrack) can cause you not being able to get Xbox achievements anymore
DiagTrackService -Disable

# Set the diagnostic data collection to minimum
DiagnosticDataLevel -Minimal

# Turn off the Windows Error Reporting
ErrorReporting -Disable

# Change the feedback frequency to "Never"
FeedbackFrequency -Never

# Do not use sign-in info to automatically finish setting up device and reopen apps after an update or restart
SigninInfo -Disable

# Do not let websites provide locally relevant content by accessing language list
LanguageListAccess -Disable

# Do not allow apps to use advertising ID to make ads more interresting to you based on your app usage 
AdvertisingID -Disable

# Hide the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested
WindowsWelcomeExperience -Hide

# Do not get tips, tricks, and suggestions as you use Windows
WindowsTips -Disable

# Hide from me suggested content in the Settings app
SettingsSuggestedContent -Hide

# Turn off automatic installing suggested apps
AppsSilentInstalling -Disable

# Do not suggest ways I can finish setting up my device to get the most out of Windows
WhatsNewInWindows -Disable

# Do not let Microsoft offer you tailored expereinces based on the diagnostic data setting you have chosen
TailoredExperiences -Disable

# Disable Bing search in the Start Menu
BingSearch -Disable

# Hide the "This PC" icon on Desktop (default value)
ThisPC -Hide

# Do not use item check boxes
# Не использовать флажки для выбора элементов
CheckBoxes -Disable

# Show hidden files, folders, and drives
HiddenItems -Enable

# Show the file name extensions
FileExtensions -Show

# Show folder merge conflicts
MergeConflicts -Show

# Hide Cortana button on the taskbar
CortanaButton -Hide

# Do not show sync provider notification within File Explorer
OneDriveFileExplorerAd -Hide

# When I snap a window, do not show what I can snap next to it
SnapAssist -Disable

# Show the file transfer dialog box in the detailed mode
FileTransferDialog -Detailed

# Expand the File Explorer ribbon
FileExplorerRibbon -Expanded

# Display the recycle bin files delete confirmation dialog
RecycleBinDeleteConfirmation -Enable

# Hide the "3D Objects" folder in "This PC" and Quick access
3DObjects -Hide

# Hide recently used files in Quick access
QuickAccessRecentFiles -Hide

# Hide frequently used folders in Quick access
QuickAccessFrequentFolders -Hide

# Hide the search on the taskbar
TaskbarSearch -Hide

# Hide the Task View button on the taskbar
TaskViewButton -Hide

# Hide search highlights
SearchHighlights -Hide

# Hide People on the taskbar
PeopleTaskbar -Hide

# Hide seconds on the taskbar clock (default value)
SecondsInSystemClock -Hide

# Hide the Windows Ink Workspace button on the taskbar
WindowsInkWorkspace -Hide

# Hide all icons in the notification area (default value)
NotificationAreaIcons -Hide

# Hide the Meet Now icon in the notification area
MeetNow -Hide

# Disable "News and Interests" on the taskbar
NewsInterests -Disable

# Unpin the "Microsoft Edge", "Microsoft Store", or "Mail" shortcuts from the taskbar
UnpinTaskbarShortcuts -Shortcuts Edge, Store, Mail

# View the Control Panel icons by category (default value)
ControlPanelView -Category

# Set the default Windows mode to dark
WindowsColorMode -Dark

# Set the default app mode to dark
AppColorMode -Dark

# Hide the "New App Installed" indicator
# Скрыть уведомление "Установлено новое приложение"
NewAppInstalledNotification -Hide

# Hide first sign-in animation after the upgrade
FirstLogonAnimation -Disable

# Set the quality factor of the JPEG desktop wallpapers to maximum
JPEGWallpapersQuality -Max

# Start Task Manager in the expanded mode
TaskManagerWindow -Expanded

# Show a notification when your PC requires a restart to finish updating
RestartNotification -Show

# Do not add the "- Shortcut" suffix to the file name of created shortcuts
ShortcutsSuffix -Disable

# Use the Print screen button to open screen snipping
PrtScnSnippingTool -Enable

# Do not use a different input method for each app window (default value)
AppsLanguageSwitch -Disable

# When I grab a windows's title bar and shake it, minimize all other windows (default value)
AeroShaking -Enable

#region OneDrive
# Uninstall OneDrive. The OneDrive user folder won't be removed
OneDrive -Uninstall

# Turn on Storage Sense
StorageSense -Enable

# Run Storage Sense every month
StorageSenseFrequency -Month

# Delete temporary files that apps aren't using
StorageSenseTempFiles -Enable

# Disable hibernation. Do not recommend turning it off on laptops
Hibernation -Disable

# Disable the Windows 260 characters path limit
Win32LongPathLimit -Disable

# Display the Stop error information on the BSoD
BSoDStopError -Enable

# Choose when to be notified about changes to your computer: never notify
AdminApprovalMode -Never

# Turn on access to mapped drives from app running with elevated permissions with Admin Approval Mode enabled
MappedDrivesAppElevatedAccess -Enable

# Turn off Delivery Optimization
DeliveryOptimization -Disable

# Always wait for the network at computer startup and logon for workgroup networks
WaitNetworkStartup -Enable

# Do not let Windows manage my default printer
WindowsManageDefaultPrinter -Disable

# Receive updates for other Microsoft products when you update Windows
UpdateMicrosoftProducts -Enable

# Set power plan on "Balanced" (default value)
PowerPlan -Balanced

# Do not allow the computer to turn off the network adapters to save power
NetworkAdaptersSavePower -Disable

# Disable the Internet Protocol Version 6 (TCP/IPv6) component for all network connections
IPv6Component -Disable

# Save screenshots by pressing Win+PrtScr on the Desktop
WinPrtScrFolder -Desktop

# Run troubleshooter automatically, then notify me
RecommendedTroubleshooting -Automatically

# Launch folder windows in a separate process
FoldersLaunchSeparateProcess -Enable

# Disable and delete reserved storage after the next update installation
ReservedStorage -Disable

# Disable help lookup via F1
F1HelpPage -Disable

# Enable Num Lock at startup
NumLock -Enable

# Do not allow the shortcut key to Start Sticky Keys by pressing the the Shift key 5 times
StickyShift -Disable

# Don't use AutoPlay for all media and devices
Autoplay -Disable

# Enable thumbnail cache removal (default value)
# Включить удаление кэша миниатюр (значение по умолчанию)
ThumbnailCacheRemoval -Enable

# Turn off automatically saving my restartable apps when signing out and restart them after signing in (default value)
SaveRestartableApps -Disable

# Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
NetworkDiscovery -Enable

# Automatically adjust active hours for me based on daily usage
ActiveHours -Automatically

# Restart this device as soon as possible when a restart is required to install an update
RestartDeviceAfterUpdate -Enable

# Uninstall the "PC Health Check" app and prevent it from installing in the future
UninstallPCHealthCheck

# Hide recently added apps in the Start menu
RecentlyAddedApps -Hide

# Hide app suggestions in the Start menu
AppSuggestions -Hide

# Run the Windows PowerShell shortcut from the Start menu as Administrator
RunPowerShellShortcut -Elevated

# Unpin all the Start tiles
PinToStart -UnpinAll

# Disable Cortana autostarting
CortanaAutostart -Disable

# Do not let UWP apps run in the background
BackgroundUWPApps -Disable

# Check for UWP apps updates
CheckUWPAppsUpdates

# Disable Xbox Game Bar
XboxGameBar -Disable

# Disable Xbox Game Bar tips
XboxGameTips -Disable

# Turn on hardware-accelerated GPU scheduling. Restart needed
GPUScheduling -Enable

# Create the "Windows Cleanup" scheduled task for cleaning up Windows unused files and updates
# A native interactive toast notification pops up every 30 days. The task runs every 30 days
CleanupTask -Register

# Create the "SoftwareDistribution" scheduled task for cleaning up the %SystemRoot%\SoftwareDistribution\Download folder
# The task will wait until the Windows Updates service finishes running. The task runs every 90 days
SoftwareDistributionTask -Register

# Create the "Temp" scheduled task for cleaning up the %TEMP% folder
# Only files older than one day will be deleted. The task runs every 60 days
TempTask -Register

# Disable Microsoft Defender Exploit Guard network protection (default value)
NetworkProtection -Disable

# Disable detection for potentially unwanted applications and block them (default value)
PUAppsDetection -Disable

# Disable sandboxing for Microsoft Defender (default value)
DefenderSandbox -Disable

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
DismissMSAccount

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
DismissSmartScreenFilter

# Enable events auditing generated when a process is created (starts)
AuditProcess -Enable

# Include command line in process creation events
CommandLineProcessAudit -Enable

# Create the "Process Creation" сustom view in the Event Viewer to log executed processes and their arguments
EventViewerCustomView -Enable

# Enable logging for all Windows PowerShell modules
PowerShellModulesLogging -Enable

# Enable logging for all PowerShell scripts input to the Windows PowerShell event log
PowerShellScriptsLogging -Enable

# Microsoft Defender SmartScreen doesn't marks downloaded files from the Internet as unsafe
AppsSmartScreen -Disable

# Disable the Attachment Manager marking files that have been downloaded from the Internet as unsafe
SaveZoneInformation -Disable

# Disable Windows Sandbox (default value)
WindowsSandbox -Disable

# Show the "Extract all" item in the Windows Installer (.msi) context menu
MSIExtractContext -Show

# Show the "Install" item in the Cabinet (.cab) filenames extensions context menu
CABInstallContext -Show

# Hide the "Run as different user" item from the .exe filename extensions context menu (default value)
RunAsDifferentUserContext -Hide

# Hide the "Cast to Device" item from the media files and folders context menu
CastToDeviceContext -Hide

# Hide the "Share" item from the context menu
ShareContext -Hide

# Hide the "Edit with Paint 3D" item from the media files context menu
EditWithPaint3DContext -Hide

# Hide the "Edit with Photos" item from the media files context menu
EditWithPhotosContext -Hide

# Hide the "Create a new video" item in the media files context menu
CreateANewVideoContext -Hide

# Hide the "Edit" item from the images context menu
ImagesEditContext -Hide

# Hide the "Print" item from the .bat and .cmd context menu
PrintCMDContext -Hide

# Hide the "Include in Library" item from the folders and drives context menu
IncludeInLibraryContext -Hide

# Hide the "Send to" item from the folders context menu
SendToContext -Hide

# Hide the "Bitmap image" item from the "New" context menu
BitmapImageNewContext -Hide

# Hide the "Rich Text Document" item from the "New" context menu
RichTextDocumentNewContext -Hide

# Hide the "Compressed (zipped) Folder" item from the "New" context menu
CompressedFolderNewContext -Hide

# Enable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
MultipleInvokeContext -Enable

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
UseStoreOpenWith -Hide

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUFHKV7RadhrmZViKOfF5kZjqr
# VGigggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUKpnu7rBp/uHaZYMwuSkjW81Z2wswDQYJ
# KoZIhvcNAQEBBQAEggEAsfdqAgujs0GfhNkgrYuToAEheRIrZptbOQRlbe9Qr+gm
# iBFZTjXGKyo8yIzS9I1gH3c+D82MWSezR3Fwdwx4Vdraw6acrSQhvrntWYvn7yUz
# Z/hFu0xDV9f6y0bkKjEeEhpO+JPcxisdTp9Bp8mJjApcKknUr2eW90M+tU0zq8HQ
# e9RDd8m8uhI6ob+xI7s8KSiVQZsZuhAAxWjBH/XROZa/od0eAmdxgGnb0H6pMEud
# kmXXQUZ8sSKJL++81CrIjpvA6xC4icKpWwg7aDXhNlWYefHjKredgG7MhdeJe2w/
# wjM24HjcP7CHc39QpH3ls/sZ6x8K1HnQb8hYOTSzXQ==
# SIG # End signature block
