# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

<#
	Version: v6.8.3

	(c) 2014—2025 Team Sophia

	https://github.com/farag2
	https://github.com/Inestic
	https://github.com/lowl1f3

#>

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false)]
	[string[]]
	$Functions
)

Clear-Host

$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack Sophia Script | $([char]0x00A9) Team Sophia 2014$([char]0x2013)2025"

Remove-Module -Name Sophia -Force -ErrorAction Ignore
Import-Module -Name $PSScriptRoot\Manifest\Sophia.psd1 -PassThru -Force -ErrorAction Stop
Import-LocalizedData -BindingVariable Global:Localization -UICulture $PSUICulture -BaseDirectory $PSScriptRoot\Localizations -FileName Sophia -ErrorAction Stop

if ($Functions){
Invoke-Command -ScriptBlock {InitialActions}
foreach ($Function in $Functions){
Invoke-Expression -Command $Function}
exit}

# The mandatory checks
InitialActions

# Turn off the diagnostics tracking scheduled tasks
ScheduledTasks -Disable

# Disable the Windows features using the pop-up dialog box
WindowsFeatures -Disable

# Uninstall optional features using the pop-up dialog box
WindowsCapabilities -Uninstall

# Uninstall UWP apps using the pop-up dialog box
UninstallUWPApps -ForAllUsers

# Uninstall OneDrive. The OneDrive user folder won't be removed
OneDrive -Uninstall

# Disable the "Connected User Experiences and Telemetry" service (DiagTrack), and block the connection for the Unified Telemetry Client Outbound Traffic
# Disabling the "Connected User Experiences and Telemetry" service (DiagTrack) can cause you not being able to get Xbox achievements anymore
DiagTrackService -Disable

# Set the diagnostic data collection to minimum
DiagnosticDataLevel -Minimal

# Turn off the Windows Error Reporting
ErrorReporting -Disable

# Change the feedback frequency to "Never"
FeedbackFrequency -Never

# Do not show recommendations for tips, shortcuts, new apps, and more in Start menu
StartRecommendationsTips -Hide

# Do not show Microsoft account-related notifications on Start Menu in Start menu
StartAccountNotifications -Hide

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

# Do not use item check boxes
CheckBoxes -Disable

# Show hidden files, folders, and drives
HiddenItems -Enable

# Show the file name extensions
FileExtensions -Show

# Show folder merge conflicts
MergeConflicts -Show

# Disable the File Explorer compact mode
FileExplorerCompactMode -Disable

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

# Set the taskbar alignment to the left
TaskbarAlignment -Left

# Hide the search button from the taskbar
TaskbarSearch -Hide

# Hide search highlights
SearchHighlights -Hide

# Hide the Task view button from the taskbar
TaskViewButton -Hide

# Hide the widgets icon on the taskbar
TaskbarWidgets -Hide

# Combine taskbar buttons and always hide labels
TaskbarCombine -Always

# Enable end task in taskbar by right click
TaskbarEndTask -Enable

# View the Control Panel icons by category
ControlPanelView -Category

# Set the default Windows mode to dark
WindowsColorMode -Dark

# Set the default app mode to dark
AppColorMode -Dark

# Hide first sign-in animation after the upgrade
FirstLogonAnimation -Disable

# Set the quality factor of the JPEG desktop wallpapers to maximum
JPEGWallpapersQuality -Max

# Notify me when a restart is required to finish updating
RestartNotification -Show

# Do not add the "- Shortcut" suffix to the file name of created shortcuts
ShortcutsSuffix -Disable

# Use the Print screen button to open screen snipping
PrtScnSnippingTool -Enable

# Do not use a different input method for each app window
AppsLanguageSwitch -Disable

# Remove Recommended section in Start Menu. Not applicable to Home edition
StartRecommendedSection -Hide

# When I grab a windows's title bar and shake it, minimize all other windows
AeroShaking -Enable

# Do not group files and folder in the Downloads folder
FolderGroupBy -None

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

# Receive updates for other Microsoft products
UpdateMicrosoftProducts -Enable

# Set power plan on "Balanced"
PowerPlan -Balanced

# Do not allow the computer to turn off the network adapters to save power
NetworkAdaptersSavePower -Disable

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

# Enable thumbnail cache removal
ThumbnailCacheRemoval -Enable

# Turn off automatically saving my restartable apps and restart them when I sign back in
SaveRestartableApps -Disable

# Automatically adjust active hours for me based on daily usage
ActiveHours -Automatically

# Do not get the latest updates as soon as they're available (default value)
WindowsLatestUpdate -Disable

# Restart as soon as possible to finish updating
RestartDeviceAfterUpdate -Enable

# Set Windows Terminal as default terminal app to host the user interface for command-line applications
DefaultTerminalApp -WindowsTerminal

# List Microsoft Edge channels to prevent desktop shortcut creation upon its' update
PreventEdgeShortcutCreation -Channels Stable, Beta, Dev, Canary

# Show more pins on Start (for 22509+ build only)
StartLayout -ShowMorePins

# Disable Cortana autostarting
CortanaAutostart -Disable

#Disable Game Bar tips
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
NetworkProtection -Enable

# Enable detection for potentially unwanted applications and block them
PUAppsDetection -Enable

# Dismiss Microsoft Defender offer in the Windows Security about signing in Microsoft account
DismissMSAccount

# Dismiss Microsoft Defender offer in the Windows Security about turning on the SmartScreen filter for Microsoft Edge
DismissSmartScreenFilter

# Enable DNS-over-HTTPS for IPv4
DNSoverHTTPS -Enable -PrimaryDNS 1.0.0.1 -SecondaryDNS 1.1.1.1

# Show the "Extract all" item in the Windows Installer (.msi) context menu
MSIExtractContext -Show

# Show the "Install" item in the Cabinet (.cab) filenames extensions context menu
CABInstallContext -Show

# Hide the "Edit with Clipchamp" item from the media files context menu
EditWithClipchampContext -Hide

# Hide the "Edit with Photos" item from the media files context menu
EditWithPhotosContext -Hide

# Hide the "Edit with Paint" item from the media files context menu
EditWithPaintContext -Hide

# Hide the "Print" item from the .bat and .cmd context menu
PrintCMDContext -Hide

# Hide the "Compressed (zipped) Folder" item from the "New" context menu
CompressedFolderNewContext -Hide

# Enable the "Open", "Print", and "Edit" context menu items for more than 15 items selected
MultipleInvokeContext -Enable

# Hide the "Look for an app in the Microsoft Store" item in the "Open with" dialog
UseStoreOpenWith -Hide

# Show the "Open in Windows Terminal" item in the folders context menu
OpenWindowsTerminalContext -Show

# Open Windows Terminal in context menu as administrator by default
OpenWindowsTerminalAdminContext -Enable