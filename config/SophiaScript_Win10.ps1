# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

<#
	Version: 6.1.1

	(c) 2014—2026 Team Sophia

	https://github.com/farag2
	https://github.com/Inestic
	https://github.com/lowl1f3

#>

Clear-Host

$Global:Failed = $false
Get-ChildItem function: | Where-Object {$_.ScriptBlock.File -match "Sophia_Script_for_Windows"} | Remove-Item -Force
Remove-Module -Name SophiaScript -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\Manifest\SophiaScript.psd1 -PassThru -Force
Get-ChildItem -Path $PSScriptRoot\Module\private | Foreach-Object -Process {. $_.FullName}

$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack Sophia Script | $([char]0x00A9) Team Sophia 2014$([char]0x2013)2026"

# The mandatory checks
InitialActions

# Disable the "Connected User Experiences and Telemetry" service (DiagTrack), and block the connection for the Unified Telemetry Client Outbound Traffic
# Disabling the "Connected User Experiences and Telemetry" service (DiagTrack) can cause you not being able to get Xbox achievements anymore
DiagTrackService -Disable

# Turn off the diagnostics tracking scheduled tasks
ScheduledTasks -Disable

# Disable the Windows features using the pop-up dialog box
WindowsFeatures -Disable

# Uninstall optional features using the pop-up dialog box
WindowsCapabilities -Uninstall

# Uninstall UWP apps using the pop-up dialog box
UninstallUWPApps -ForAllUsers

# Set the diagnostic data collection to minimum
DiagnosticDataLevel -Minimal

# Turn off the Windows Error Reporting
ErrorReporting -Disable

# Change the feedback frequency to "Never"
FeedbackFrequency -Never

#Expand the File Explorer ribbon
FileExplorerRibbon -Expanded

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

# Do not use item check boxes
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

# Display the recycle bin files delete confirmation dialog
RecycleBinDeleteConfirmation -Enable

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

# Hide seconds on the taskbar clock
SecondsInSystemClock -Hide

# Hide the Windows Ink Workspace button on the taskbar
WindowsInkWorkspace -Hide

# Hide all icons in the notification area
NotificationAreaIcons -Hide

# Hide the Meet Now icon in the notification area
MeetNow -Hide

# Disable "News and Interests" on the taskbar
NewsInterests -Disable

# View the Control Panel icons by category
ControlPanelView -Category

# Set the default Windows mode to dark
WindowsColorMode -Dark

# Set the default app mode to dark
AppColorMode -Dark

# Hide the "New App Installed" indicator
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

# Do not use a different input method for each app window
AppsLanguageSwitch -Disable

# When I grab a windows's title bar and shake it, minimize all other windows
AeroShaking -Enable

# Do not group files and folder in the Downloads folder
FolderGroupBy -None

# Uninstall OneDrive. The OneDrive user folder won't be removed
OneDrive -Uninstall

# Turn on Storage Sense
StorageSense -Enable

# Disable hibernation. Do not recommend turning it off on laptops
IF(!(Get-WmiObject -Class win32_systemenclosure | Where-Object { $_.chassistypes -eq 8 -or $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 14 -or $_.chassistypes -eq 30}))
{Hibernation -Disable}

# Disable the Windows 260 characters path limit
Win32LongPathLimit -Disable

# Turn off Delivery Optimization
DeliveryOptimization -Disable

# Do not let Windows manage my default printer
WindowsManageDefaultPrinter -Disable

# Receive updates for other Microsoft products when you update Windows
UpdateMicrosoftProducts -Enable

# Set power plan on "Balanced"
PowerPlan -Balanced

# Do not allow the computer to turn off the network adapters to save power
NetworkAdaptersSavePower -Disable

# Save screenshots by pressing Win+PrtScr on the Desktop
WinPrtScrFolder -Desktop

# Run troubleshooter automatically, then notify me
RecommendedTroubleshooting -Automatically

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

# Enable thumbnail cache removal
ThumbnailCacheRemoval -Enable

# Automatically adjust active hours for me based on daily usage
ActiveHours -Automatically

# Restart this device as soon as possible when a restart is required to install an update
RestartDeviceAfterUpdate -Enable

# Uninstall the "PC Health Check" app and prevent it from installing in the future
UninstallPCHealthCheck

# List Microsoft Edge channels to prevent desktop shortcut creation upon its' update
PreventEdgeShortcutCreation -Channels Stable, Beta, Dev, Canary

# Hide recently added apps in the Start menu
RecentlyAddedApps -Hide

# Hide recently added apps on Start
RecentlyAddedStartApps -Hide

# Hide most used apps in Start (default value)
MostUsedStartApps -Hide

# Не отображать на начальном экране уведомления, касающиеся учетной записи Microsoft
StartAccountNotifications -Hide

# Hide app suggestions in the Start menu
AppSuggestions -Hide

# Disable Cortana autostarting
CortanaAutostart -Disable

# Do not let UWP apps run in the background
BackgroundUWPApps -Disable

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

#region Microsoft Defender & Security
# Enable Microsoft Defender Exploit Guard network protection
NetworkProtection -Enable

# Enable detection for potentially unwanted applications and block them
PUAppsDetection -Enable

# Show the "Extract all" item in the Windows Installer (.msi) context menu
MSIExtractContext -Show

# Show the "Install" item in the Cabinet (.cab) filenames extensions context menu
CABInstallContext -Show

# Hide the "Share" item from the context menu
ShareContext -Hide

# Hide the "Edit with Paint 3D" item from the media files context menu
EditWithPaint3DContext -Hide

# Hide the "Edit" item from the images context menu
ImagesEditContext -Hide

# Hide the "Print" item from the .bat and .cmd context menu
PrintCMDContext -Hide

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