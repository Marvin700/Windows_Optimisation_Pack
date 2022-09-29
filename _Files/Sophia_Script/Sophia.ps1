<#
	Version: v6.1.4
	Date: 12.08.2022

	Copyright (c) 2014—2022 farag
	Copyright (c) 2019—2022 farag & Inestic

	https://github.com/farag2
	https://github.com/Inestic
#>

Requires -RunAsAdministrator

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string[]]
	$Functions
)

Clear-Host

$Host.UI.RawUI.WindowTitle = "Sophia Script for Windows 11 v6.1.4 | Made with $([char]::ConvertFromUtf32(0x1F497)) of Windows | $([char]0x00A9) farag & Inestic, 2014$([char]0x2013)2022"

Remove-Module -Name Sophia -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\Manifest\Sophia.psd1 -PassThru -Force


Remove-Module -Name PolicyFileEditor -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\bin\PolicyFileEditor\PolicyFileEditor.psd1 -PassThru -Force

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

# Uninstall UWP apps using the pop-up dialog box
UninstallUWPApps

# Disable the Windows features using the pop-up dialog box
WindowsFeatures -Disable


# Uninstall optional features using the pop-up dialog box
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

# Do not use sign-in info to automatically finish setting up device after an update
SigninInfo -Disable

# Do not let websites provide locally relevant content by accessing language list
LanguageListAccess -Disable

# Do not let apps show me personalized ads by using my advertising ID
AdvertisingID -Disable

# Hide the Windows welcome experiences after updates and occasionally when I sign in to highlight what's new and suggested
WindowsWelcomeExperience -Hide

# Do not get tips and suggestions when I use Windows
WindowsTips -Disable

# Hide from me suggested content in the Settings app
SettingsSuggestedContent -Hide

# Turn off automatic installing suggested apps
AppsSilentInstalling -Disable

# Disable suggestions on how I can set up my device
WhatsNewInWindows -Disable

# Don't let Microsoft use your diagnostic data for personalized tips, ads, and recommendations
TailoredExperiences -Disable

# Disable Bing search in the Start Menu
BingSearch -Disable

# Hide the "This PC" icon on Desktop (default value)
ThisPC -Hide

# Do not use item check boxes
CheckBoxes -Disable

# Show hidden files, folders, and drives
HiddenItems -Enable

# Show the file name extensions
FileExtensions -Show

# Show folder merge conflicts
MergeConflicts -Show

# Disable the File Explorer compact mode (default value)
FileExplorerCompactMode -Disable

# Do not show sync provider notification within File Explorer
OneDriveFileExplorerAd -Hide

# When I snap a window, do not show what I can snap next to it
SnapAssist -Disable

# Show snap layouts when I hover over a windows's maximaze button (default value)
SnapAssistFlyout -Enable

# Show the file transfer dialog box in the detailed mode
FileTransferDialog -Detailed

# Display the recycle bin files delete confirmation dialog
RecycleBinDeleteConfirmation -Enable

# Hide recently used files in Quick access
QuickAccessRecentFiles -Hide

# Hide frequently used folders in Quick access
QuickAccessFrequentFolders -Hide

# Set the taskbar alignment to the left
TaskbarAlignment -Left

# Hide the search button from the taskbar
TaskbarSearch -Hide

# Hide the Task view button from the taskbar
TaskViewButton -Hide

# Hide the widgets icon on the taskbar
TaskbarWidgets -Hide

# Hide the Chat icon (Microsoft Teams) on the taskbar
TaskbarChat -Hide

# Unpin the "Microsoft Edge", "Microsoft Store" shortcuts from the taskbar
UnpinTaskbarShortcuts -Shortcuts Edge, Store

# View the Control Panel icons by category (default value)
ControlPanelView -Category

# Set the default Windows mode to dark
WindowsColorMode -Dark

# Set the default app mode to dark
AppColorMode -Dark

# Hide first sign-in animation after the upgrade
FirstLogonAnimation -Disable

# Set the quality factor of the JPEG desktop wallpapers to maximum
JPEGWallpapersQuality -Max

# Start Task Manager in the expanded mode
TaskManagerWindow -Expanded

# Notify me when a restart is required to finish updating
RestartNotification -Show

# Do not add the "- Shortcut" suffix to the file name of created shortcuts
ShortcutsSuffix -Disable

# Use the Print screen button to open screen snipping
PrtScnSnippingTool -Enable

# Do not use a different input method for each app window (default value)
AppsLanguageSwitch -Disable

# When I grab a windows's title bar and shake it, minimize all other windows
AeroShaking -Enable

# Uninstall OneDrive. The OneDrive user folder won't be removed
OneDrive -Uninstall

# Turn on Storage Sense
StorageSense -Enable

# Run Storage Sense every month
StorageSenseFrequency -Month

# Turn on automatic cleaning up temporary system and app files
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

# Receive updates for other Microsoft products
UpdateMicrosoftProducts -Enable

# Set power plan on "Balanced" (default value)
PowerPlan -Balanced

# Use the latest installed .NET runtime for all apps
LatestInstalled.NET -Enable

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

# Turn off pressing the Shift key 5 times to turn Sticky keys
StickyShift -Disable

# Don't use AutoPlay for all media and devices
Autoplay -Disable

# Enable thumbnail cache removal (default value)
ThumbnailCacheRemoval -Enable

# Turn off automatically saving my restartable apps and restart them when I sign back in (default value)
SaveRestartableApps -Disable

# Enable "Network Discovery" and "File and Printers Sharing" for workgroup networks
NetworkDiscovery -Enable

# Automatically adjust active hours for me based on daily usage
ActiveHours -Automatically

# Restart as soon as possible to finish updating
RestartDeviceAfterUpdate -Enable

# Set Windows Terminal as default terminal app to host the user interface for command-line applications
DefaultTerminalApp -WindowsTerminal

# Unpin all Start apps
UnpinAllStartApps

# Run the Windows PowerShell shortcut from the Start menu as Administrator
RunPowerShellShortcut -Elevated

# Show more pins on Start (for 22509+ build only)
StartLayout -ShowMorePins

# Disable Cortana autostarting
CortanaAutostart -Disable

# Disable Microsoft Teams autostarting
TeamsAutostart -Disable

# Check for UWP apps updates
CheckUWPAppsUpdates

# Disable Xbox Game Bar
XboxGameBar -Disable

# Disable Xbox Game Bar tips
# Отключить советы Xbox Game Bar
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

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
DismissMSAccount

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
DismissSmartScreenFilter

# Enable events auditing generated when a process is created (starts)
AuditProcess -Enable

# Include command line in process creation events
CommandLineProcessAudit -Enable

# Create the "Process Creation" сustom view in the Event Viewer to log executed processes and their arguments
# In order this feature to work events auditing (AuditProcess -Enable) and command line (CommandLineProcessAudit -Enable) in process creation events will be enabled
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

# Enable DNS-over-HTTPS for IPv4
# The valid IPv4 addresses: 1.0.0.1, 1.1.1.1, 149.112.112.112, 8.8.4.4, 8.8.8.8, 9.9.9.9
DNSoverHTTPS -Enable -PrimaryDNS 1.0.0.1 -SecondaryDNS 1.1.1.1

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

# Hide the "Edit with Photos" item from the media files context menu
EditWithPhotosContext -Hide

# Hide the "Create a new video" item in the media files context menu
CreateANewVideoContext -Hide

# Hide the "Print" item from the .bat and .cmd context menu
PrintCMDContext -Hide

# Hide the "Include in Library" item from the folders and drives context menu
IncludeInLibraryContext -Hide

# Hide the "Send to" item from the folders context menu
SendToContext -Hide

# Hide the "Compressed (zipped) Folder" item from the "New" context menu
CompressedFolderNewContext -Hide

# Enable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
MultipleInvokeContext -Enable

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
UseStoreOpenWith -Hide

# Show the "Open in Windows Terminal" item in the folders context menu (default value)
OpenWindowsTerminalContext -Show

# Open Windows Terminal in context menu as administrator by default
OpenWindowsTerminalAdminContext -Enable

# Disable the Windows 10 context menu style (default value)
Windows10ContextMenu -Disable

# Update Local Group Policy Editor (gpedit.msc) to make all manually created policy keys in the registry visible in the snap-in
UpdateLGPEPolicies
#endregion Update Policies

# Errors output
Errors

# SIG # Begin signature block
# MIIbmwYJKoZIhvcNAQcCoIIbjDCCG4gCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUO1PHUvpatrnuf8PQlAexVSkC
# KLagghYTMIIDAjCCAeqgAwIBAgIQT8FbBxqWzplE/avBXNrG9zANBgkqhkiG9w0B
# AQsFADAZMRcwFQYDVQQDDA5Tb3BoaWEgUHJvamVjdDAeFw0yMjA4MTMxMzE1MDda
# Fw0yNDA4MTMxMzI0NThaMBkxFzAVBgNVBAMMDlNvcGhpYSBQcm9qZWN0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr9tjZi5zD5hHltwn4J3mVv0mSERf
# RerBpK92tHIAs22wogMPWU0L5gMj+47flabmMKgPLwPzJVhH/KU78IhbUMCqinM2
# Xf0FAy11GZUY/+aP7Ip6NI9pzbtcLrhv9Vy8RkbJ4q5ITSdOCE7EDH6eeaDYmOaT
# waaACmSZ5t60NeKJE4WRphzI93RIJR3/mFhC0V/v3XpcJ3oCwj+fC2ttZ9r/YCjp
# IxfQkS7Fomdbp/P+J2f3Ashao65CIQpams/4YuXF5cgm5bYPtRl4UIqDZHJXMcc1
# NzXxAPHqTUHVdTuFT93vbKroXj16obu/EUHoCGowDVrwuF/pjEavW8tfhQIDAQAB
# o0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwHQYDVR0O
# BBYEFLmj5x/jigGKQ19Ggv+YoqmEuq74MA0GCSqGSIb3DQEBCwUAA4IBAQAufjzN
# FAb3d6d6gCEvpTu7oGkQDLEoYvrcG/rncvHk2w9M1WFdchlryqgdbwuEK/E9PqC4
# uHN4+MCNOvjfJrPumwTLMlpLgKy/fKMDfX+u4QML4brR+YWBoCjKxG8LiEXg+0NC
# HJE5/2VfiCSrzBtnJSPur0DGsAylQSsB25G2+juBSpAN+2kj25nv8twnZcaz2RCD
# G64agZZ7c0G6t/rhBP1yzx74kyUlkVBXHntBoOBlMBogCvaRNuHrIGMlYbOps1Xd
# OJLiMLWZmrXOLuS9AkzvtelRN4tsJb3M9TMHxIX1veeqwXg02myUJdtnCDm53WBO
# o2rovwPACe1sTnvaMIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkq
# hkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5j
# MRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBB
# c3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5
# WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQL
# ExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJv
# b3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1K
# PDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2r
# snnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C
# 8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBf
# sXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGY
# QJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8
# rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaY
# dj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+
# wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw
# ++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+N
# P8m800ERElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7F
# wI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUw
# AwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAU
# Reuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEB
# BG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsG
# AQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1
# cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAow
# CDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/
# Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLe
# JLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE
# 1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9Hda
# XFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbO
# byMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIG
# rjCCBJagAwIBAgIQBzY3tyRUfNhHrP0oZipeWzANBgkqhkiG9w0BAQsFADBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# HhcNMjIwMzIzMDAwMDAwWhcNMzcwMzIyMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFRydXN0
# ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAxoY1BkmzwT1ySVFVxyUDxPKRN6mXUaHW0oPR
# nkyibaCwzIP5WvYRoUQVQl+kiPNo+n3znIkLf50fng8zH1ATCyZzlm34V6gCff1D
# tITaEfFzsbPuK4CEiiIY3+vaPcQXf6sZKz5C3GeO6lE98NZW1OcoLevTsbV15x8G
# ZY2UKdPZ7Gnf2ZCHRgB720RBidx8ald68Dd5n12sy+iEZLRS8nZH92GDGd1ftFQL
# IWhuNyG7QKxfst5Kfc71ORJn7w6lY2zkpsUdzTYNXNXmG6jBZHRAp8ByxbpOH7G1
# WE15/tePc5OsLDnipUjW8LAxE6lXKZYnLvWHpo9OdhVVJnCYJn+gGkcgQ+NDY4B7
# dW4nJZCYOjgRs/b2nuY7W+yB3iIU2YIqx5K/oN7jPqJz+ucfWmyU8lKVEStYdEAo
# q3NDzt9KoRxrOMUp88qqlnNCaJ+2RrOdOqPVA+C/8KI8ykLcGEh/FDTP0kyr75s9
# /g64ZCr6dSgkQe1CvwWcZklSUPRR8zZJTYsg0ixXNXkrqPNFYLwjjVj33GHek/45
# wPmyMKVM1+mYSlg+0wOI/rOP015LdhJRk8mMDDtbiiKowSYI+RQQEgN9XyO7ZONj
# 4KbhPvbCdLI/Hgl27KtdRnXiYKNYCQEoAA6EVO7O6V3IXjASvUaetdN2udIOa5kM
# 0jO0zbECAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FLoW2W1NhS9zKXaaL3WMaiCPnshvMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/n
# upiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3Bggr
# BgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQB9
# WY7Ak7ZvmKlEIgF+ZtbYIULhsBguEE0TzzBTzr8Y+8dQXeJLKftwig2qKWn8acHP
# HQfpPmDI2AvlXFvXbYf6hCAlNDFnzbYSlm/EUExiHQwIgqgWvalWzxVzjQEiJc6V
# aT9Hd/tydBTX/6tPiix6q4XNQ1/tYLaqT5Fmniye4Iqs5f2MvGQmh2ySvZ180HAK
# fO+ovHVPulr3qRCyXen/KFSJ8NWKcXZl2szwcqMj+sAngkSumScbqyQeJsG33irr
# 9p6xeZmBo1aGqwpFyd/EjaDnmPv7pp1yr8THwcFqcdnGE4AJxLafzYeHJLtPo0m5
# d2aR8XKc6UsCUqc3fpNTrDsdCEkPlM05et3/JWOZJyw9P2un8WbDQc1PtkCbISFA
# 0LcTJM3cHXg65J6t5TRxktcma+Q4c6umAU+9Pzt4rUyt+8SVe+0KXzM5h0F4ejjp
# nOHdI/0dKNPH+ejxmF/7K9h+8kaddSweJywm228Vex4Ziza4k9Tm8heZWcpw8De/
# mADfIBZPJ/tgZxahZrrdVcA6KYawmKAr7ZVBtzrVFZgxtGIJDwq9gdkT/r+k0fNX
# 2bwE+oLeMt8EifAAzV3C+dAjfwAL5HYCJtnwZXZCpimHCUcr5n8apIUP/JiW9lVU
# Kx+A+sDyDivl1vupL0QVSucTDh3bNzgaoSv27dZ8/DCCBsYwggSuoAMCAQICEAp6
# SoieyZlCkAZjOE2Gl50wDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVk
# IEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTAeFw0yMjAzMjkwMDAw
# MDBaFw0zMzAzMTQyMzU5NTlaMEwxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjEkMCIGA1UEAxMbRGlnaUNlcnQgVGltZXN0YW1wIDIwMjIgLSAy
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAuSqWI6ZcvF/WSfAVghj0
# M+7MXGzj4CUu0jHkPECu+6vE43hdflw26vUljUOjges4Y/k8iGnePNIwUQ0xB7pG
# bumjS0joiUF/DbLW+YTxmD4LvwqEEnFsoWImAdPOw2z9rDt+3Cocqb0wxhbY2rzr
# svGD0Z/NCcW5QWpFQiNBWvhg02UsPn5evZan8Pyx9PQoz0J5HzvHkwdoaOVENFJf
# D1De1FksRHTAMkcZW+KYLo/Qyj//xmfPPJOVToTpdhiYmREUxSsMoDPbTSSF6IKU
# 4S8D7n+FAsmG4dUYFLcERfPgOL2ivXpxmOwV5/0u7NKbAIqsHY07gGj+0FmYJs7g
# 7a5/KC7CnuALS8gI0TK7g/ojPNn/0oy790Mj3+fDWgVifnAs5SuyPWPqyK6BIGtD
# ich+X7Aa3Rm9n3RBCq+5jgnTdKEvsFR2wZBPlOyGYf/bES+SAzDOMLeLD11Es0Md
# I1DNkdcvnfv8zbHBp8QOxO9APhk6AtQxqWmgSfl14ZvoaORqDI/r5LEhe4ZnWH5/
# H+gr5BSyFtaBocraMJBr7m91wLA2JrIIO/+9vn9sExjfxm2keUmti39hhwVo99Rw
# 40KV6J67m0uy4rZBPeevpxooya1hsKBBGBlO7UebYZXtPgthWuo+epiSUc0/yUTn
# gIspQnL3ebLdhOon7v59emsCAwEAAaOCAYswggGHMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMCAGA1UdIAQZMBcw
# CAYGZ4EMAQQCMAsGCWCGSAGG/WwHATAfBgNVHSMEGDAWgBS6FtltTYUvcyl2mi91
# jGogj57IbzAdBgNVHQ4EFgQUjWS3iSH+VlhEhGGn6m8cNo/drw0wWgYDVR0fBFMw
# UTBPoE2gS4ZJaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3Rl
# ZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNybDCBkAYIKwYBBQUHAQEE
# gYMwgYAwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBYBggr
# BgEFBQcwAoZMaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0UlNBNDA5NlNIQTI1NlRpbWVTdGFtcGluZ0NBLmNydDANBgkqhkiG9w0B
# AQsFAAOCAgEADS0jdKbR9fjqS5k/AeT2DOSvFp3Zs4yXgimcQ28BLas4tXARv4QZ
# iz9d5YZPvpM63io5WjlO2IRZpbwbmKrobO/RSGkZOFvPiTkdcHDZTt8jImzV3/ZZ
# y6HC6kx2yqHcoSuWuJtVqRprfdH1AglPgtalc4jEmIDf7kmVt7PMxafuDuHvHjiK
# n+8RyTFKWLbfOHzL+lz35FO/bgp8ftfemNUpZYkPopzAZfQBImXH6l50pls1klB8
# 9Bemh2RPPkaJFmMga8vye9A140pwSKm25x1gvQQiFSVwBnKpRDtpRxHT7unHoD5P
# ELkwNuTzqmkJqIt+ZKJllBH7bjLx9bs4rc3AkxHVMnhKSzcqTPNc3LaFwLtwMFV4
# 1pj+VG1/calIGnjdRncuG3rAM4r4SiiMEqhzzy350yPynhngDZQooOvbGlGglYKO
# KGukzp123qlzqkhqWUOuX+r4DwZCnd8GaJb+KqB0W2Nm3mssuHiqTXBt8CzxBxV+
# NbTmtQyimaXXFWs1DoXW4CzM4AwkuHxSCx6ZfO/IyMWMWGmvqz3hz8x9Fa4Uv4px
# 38qXsdhH6hyF4EVOEhwUKVjMb9N/y77BDkpvIJyu2XMyWQjnLZKhGhH+MpimXSuX
# 4IvTnMxttQ2uR2M4RxdbbxPaahBuH0m3RFu0CAqHWlkEdhGhp3cCExwxggTyMIIE
# 7gIBATAtMBkxFzAVBgNVBAMMDlNvcGhpYSBQcm9qZWN0AhBPwVsHGpbOmUT9q8Fc
# 2sb3MAkGBSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqG
# SIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3
# AgEVMCMGCSqGSIb3DQEJBDEWBBRNvJ/yVB/usLpZoWUQO+3be90spDANBgkqhkiG
# 9w0BAQEFAASCAQCVSXC8CT8Sw+p0s8eJT1CxTNTJXcRkPSm7BqD7XWYxkVzMQKSg
# cRsx2gB785TDDO5JyhMuT/bRO/80OEmfL+F4tQ71z2DZ4IhIraO3ERsQ+B6wS6Oq
# JJv6z2BP+a67VJR0FOnsuN9vcv6q7sfYI/9qYj91wSYFMqujGHrq0vhVfoh75S4X
# +GlzvdmjbnmYmMDxSHyu3Mg7BPGd8Slpvqi5ckxTcZ0IY37ikn77uJj45yo3J5kQ
# ZihZMJ1Pa91kfF+OBz0b35VvoSrPYlswBB/m0wDbr811SVy3ok7/uX8q8tTWgYUV
# kT1BotzG7mEhTlHxCuFuwzVb5m6p02XH34qHoYIDIDCCAxwGCSqGSIb3DQEJBjGC
# Aw0wggMJAgEBMHcwYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVzdGVkIEc0IFJTQTQwOTYgU0hBMjU2
# IFRpbWVTdGFtcGluZyBDQQIQCnpKiJ7JmUKQBmM4TYaXnTANBglghkgBZQMEAgEF
# AKBpMBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIy
# MDgxMzEzMjUxNlowLwYJKoZIhvcNAQkEMSIEINAcQRsPCyX9BWnIrMmyWbnLG/4y
# 6iYsYKR6YqJ7qo4NMA0GCSqGSIb3DQEBAQUABIICAJy7BS+vGKoXZowcgLGdxN8P
# i7xE3TfRWmWV0n1M0hPEYzqufxZ62ih/4AryNmlrVCQS5ZzeH8kYPxKSRu4AE7rr
# JSpZl/KawICQIc+zJ76FMZrvTG8d6FwldADIvBP1wWB1LALB0x1oCqVLnku8lfk8
# udF+/GIllRJE/837cEc9KsO/DE3/E05K7OwFaKnC/fHr5Y6cSkqjZU/YBkAXP5kD
# eAdTfOLPaVNiprrffLrQFn3vp2tloDsg+t+p7REQVQDPnr0iCVdvX1Bv1J3P1Ps/
# xiWe+Pcq9DeXhKqN79tnGlG1uec59NFoyB6UfCOb/DnvJ2T+OT6P3y3tx7HPpqIN
# ostv1sd2thikQtoyZz8BfTpgpGDiCXARkWXSwsqHBndRu8163P9Jpel7J+mdRxJy
# OqLeMK5a32KpHxaQULTgo0GvrFfd8KhlUxNxA7+VTD2BghCyfv59nDdlxusc/bn3
# DdSSNL3uZb/ZXsGzbnHyb4QAXyiH5rhnC/4cuwquWJRPoKAOwTR+ZFI8b+9APPor
# mIBSzm64CZYIbNITkmHK093IjogyIXZX1lsuYJigbu/eBbJ/sEcptTFXeT/zSRyd
# 0nC71OJdk5YCA0CpO+uqJZiAnJqebgVWKnkEDdCB7kot0jJsbBm81kVvlw4rNb9k
# 4+71GePHCaGsJ/sFnL8s
# SIG # End signature block
