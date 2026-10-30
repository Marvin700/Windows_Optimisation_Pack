# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

### Version ###
$DDUVersion = "18.1.6.2"

### Title ###
$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack GPU Cleaner | $([char]0x00A9) Marvin700"
$ScriptFolder = "$env:temp\Windows_Optimisation_Pack"

# Check for Pending Reboot
IF((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){Write-Warning " Reboot Pending ! You can Reinstall GPU Driver after PC Restart";Start-Sleep 10;exit}

Write-Host " Download and Prepare DDU"

#Create Folder
Remove-Item "$ScriptFolder\DDU" -Recurse -Force -ErrorAction SilentlyContinue
IF(!(Test-Path $ScriptFolder)){New-Item -Path $ScriptFolder -ItemType Directory | Out-Null}
    
# Download and Extract DDU
Start-BitsTransfer -Source "https://download.wagnardsoft.com/DDU/DDU%20v$DDUVersion.exe" -Destination "$ScriptFolder\DDU.exe"
Start-Process "$ScriptFolder\DDU.exe" -ArgumentList "-o`"$ScriptFolder`" -y" -Wait
Remove-Item "$ScriptFolder\DDU.exe" -Force -ErrorAction SilentlyContinue
Get-ChildItem $ScriptFolder -Directory -Filter "DDU v*" | Select-Object -First 1 | Rename-Item -NewName "DDU"
IF(!(Test-Path "$ScriptFolder\DDU\Display Driver Uninstaller.exe")){Write-Warning " DDU Download failed ! Aborting";Start-Sleep 10;exit}

# Write DDU Settings
New-Item -Path "$ScriptFolder\DDU\settings" -ItemType Directory -Force | Out-Null
@"
<?xml version="1.0" encoding="utf-8"?>
<DisplayDriverUninstaller Version="$DDUVersion">
	<Settings>
		<SelectedLanguage>de-DE</SelectedLanguage>
		<RemoveMonitors>True</RemoveMonitors>
		<RemoveCrimsonCache>True</RemoveCrimsonCache>
		<RemoveAMDDirs>True</RemoveAMDDirs>
		<RemoveAudioBus>True</RemoveAudioBus>
		<RemoveAMDKMPFD>True</RemoveAMDKMPFD>
		<RemoveNvidiaDirs>True</RemoveNvidiaDirs>
		<RemovePhysX>True</RemovePhysX>
		<Remove3DTVPlay>True</Remove3DTVPlay>
		<RemoveGFE>True</RemoveGFE>
		<RemoveNVBROADCAST>True</RemoveNVBROADCAST>
		<RemoveNVCP>True</RemoveNVCP>
		<RemoveNvidiaCache>True</RemoveNvidiaCache>
		<RemoveINTELCP>True</RemoveINTELCP>
		<RemoveINTELIGS>True</RemoveINTELIGS>
		<RemoveOneAPI>True</RemoveOneAPI>
		<RemoveEnduranceGaming>True</RemoveEnduranceGaming>
		<RemoveIntelNpu>True</RemoveIntelNpu>
		<RemoveAMDCP>True</RemoveAMDCP>
		<UseRoamingConfig>False</UseRoamingConfig>
		<CheckUpdates>False</CheckUpdates>
		<CreateRestorePoint>True</CreateRestorePoint>
		<SaveLogs>True</SaveLogs>
		<RemoveVulkan>True</RemoveVulkan>
		<ShowOffer>False</ShowOffer>
		<EnableSafeModeDialog>False</EnableSafeModeDialog>
		<PreventWinUpdate>False</PreventWinUpdate>
		<UsedBCD>False</UsedBCD>
		<UseDarkTheme>True</UseDarkTheme>
		<KeepNVCPopt>False</KeepNVCPopt>
		<RememberLastChoice>False</RememberLastChoice>
		<LastSelectedGPUIndex>0</LastSelectedGPUIndex>
		<LastSelectedTypeIndex>0</LastSelectedTypeIndex>
	</Settings>
</DisplayDriverUninstaller>
"@ | Set-Content "$ScriptFolder\DDU\settings\Settings.xml" -Encoding UTF8

# Pause Windows Update for 1 Day to prevent auto Driver Install
$pause = (Get-Date).AddDays(1); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause
$pause = (Get-Date).AddDays(1); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause
# Set Reboot Pending
Add-Type -Namespace Win32 -Name Kernel32 -MemberDefinition '[DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)] public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);'
$RebootFile = "$env:SystemRoot\Temp\Windows_Optimisation_Pack.reboot"
New-Item -Path $RebootFile -ItemType File -Force | Out-Null
[Win32.Kernel32]::MoveFileEx($RebootFile, $null, 4) | Out-Null
# Enable Safemode
cmd.exe /c "bcdedit /set {current} safeboot minimal"
# On next Start, set Safemode to Disabled
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Normal_Boot" -Value 'cmd.exe /c "bcdedit /deletevalue {current} safeboot"'
# On next Start, Start DDU
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Driver_Cleaner" -Value "Powershell.exe -command `"Set-Location '$ScriptFolder\DDU';& '.\Display Driver Uninstaller.exe' -silent -removemonitors -removephysx -removegfe -removenvbroadcast -cleanallgpus -removenvcp -removeintelcp -removeamdcp -removeamddirs -restart`""
# On next Start, Show Powershell Message to Wait
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Uninstall_Message" -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -command 'Driver is Uninstalling. Please Wait... ( Can take up to 10 Min )'"
Write-Warning "Please Restart PC to execute DDU NOW"