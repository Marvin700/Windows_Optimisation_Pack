# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

$Branch = "Beta"

# Check for Pending Reboot
IF((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){Write-Warning " Reboot Pending ! You can Reinstall GPU Driver after PC Restart";Start-Sleep 10}else{
# Download and Extract DDU
Start-BitsTransfer -Source "https://github.com/Marvin700/Windows_Optimisation_Pack/raw/$Branch/config/DDU.zip" -Destination "$env:temp\DDU.zip"
Expand-Archive $env:temp\DDU.zip $env:temp
# Pause Windows Update for 1 Day to prevent auto Driver Install
$pause = (Get-Date).AddDays(1); $pause = $pause.ToUniversalTime().ToString( "yyyy-MM-ddTHH:mm:ssZ" ); Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'PauseUpdatesExpiryTime' -Value $pause
# Enable Safemode
cmd.exe /c "bcdedit /set {current} safeboot minimal"
# On next Start, set Safemode to Disabled
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Normal_Boot" -Value 'cmd.exe /c "bcdedit /deletevalue {current} safeboot"'
# On next Start, Start DDU
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Driver_Cleaner" -Value 'Powershell.exe -command "Set-Location $env:temp\DDU\;& .\DisplayDriverUninstaller.exe -silent -removemonitors -removephysx -removegfe -removenvbroadcast -cleanallgpus -removenvcp -removeintelcp -removeamdcp -removeamddirs -restart"'
# On next Start, Show Powershell Massage to Wait
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Uninstall_Message" -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -command 'Driver is Unnstalling. Please Wait... ( Can take up to 10 Min )'"}