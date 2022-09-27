Clear-Host
"==========================="
"Windows Optimization Pack"
"==========================="
#Administrator Pruefung
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	Write-Warning "Keine BenÃ¶tigten Admin Rechte vorhanden"
    	Write-Warning "Das Script wird in 20 Sekunden beendet"
    sleep 20
    exit
}
"Schritt 0   - Download benoetigter Dateien"
"Schritt 1   - Wiederherstellungspunkt erstellen"
"Schritt 2   - Autostart und Tasks deaktivieren"
"Schritt 3   - Schnellstart deaktiveren"
"Schritt 4   - Registry Werte aendern"
"Schritt 5   - Sophia Script"
"Schritt 6   - o&oShutup"
"Schritt 7   - Performance Counter"
"Schritt 8   - Winget installieren"
"Schritt 8.1 - C++ 2008-2019 installieren "
"Schritt 8.2 - Direct X Installieren"
"Schritt 8.3 - Net-Framework Installieren"
"Schritt 8.4 - Alle Programme Updaten"
"Schritt 8.5 - Nuetzliche Programme installieren"
"Schritt 9   - Explorer neustarten"
""
""
"Automatischer start in 30 Sekunden..."
timeout 30
Clear-Host


"----------------------------"
"Schritt 0 - Download benoetigter Dateien"
"----------------------------"
#Windows Version bestimmen
$WindowsVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
Invoke-WebRequest 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe' -OutFile C:\Windows_Optimisation_Pack\_Files\ooShutup\OOSU10.exe
Invoke-WebRequest 'https://download.sysinternals.com/files/Autoruns.zip' -OutFile C:\Windows_Optimisation_Pack\_Files\Autoruns.zip
Invoke-WebRequest 'https://github.com/microsoft/winget-cli/releases/download/v1.3.2091/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' -OutFile C:\Windows_Optimisation_Pack\_Files\winget.msixbundle
Expand-Archive 'C:\Windows_Optimisation_Pack\_Files\Autoruns.zip' 'C:\Windows_Optimisation_Pack\_Files\Autoruns'
Remove-Item -Path C:\Windows_Optimisation_Pack\_Files\Autoruns.zip -Force -Recurse
Move-Item -Path "C:\Windows_Optimisation_Pack\_Files\Autoruns\Autoruns64.exe" -Destination "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe" -Force
Remove-Item "C:\Windows_Optimisation_Pack\_Files\Autoruns\" -force -Recurse
Clear-Host

"----------------------------"
"Schritt 1 - Wiederherstellungspunkt erstellen"
"----------------------------"
Enable-ComputerRestore -Drive "C:\"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /F
Clear-Host

"---------------------------"
"Schritt 2 - Autostart und Tasks deaktivieren"
"---------------------------"
#Start-Process ms-settings:startupapps
Start-Process "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe"
Clear-Host

"---------------------------"
"Schritt 3 - Schnellstart deaktiveren"
"---------------------------"
powercfg -h off
Clear-Host

"---------------------------"
"Schritt 4 Registry Werte aendern"
"---------------------------"
reg import "C:\Windows_Optimisation_Pack\_Files\Registry.reg"
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA" /T REG_DWORD /D 00000000 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseSpeed" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold1" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold2" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseTrails" /T REG_DWORD /D 0 /F
Clear-Host

"---------------------------"
"Schritt 8 - Winget installieren"
"---------------------------"
Add-AppxPackage "C:\Windows_Optimisation_Pack\_Files\WinGet.msixbundle"
winget source update

"---------------------------"
"Schritt 5 - Sophia Script"
"---------------------------"
IF($WindowsVersion -eq 'Microsoft Windows 11 Pro') {
Powershell.exe -executionpolicy remotesigned -File "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\Sophia.ps1"
}
IF($WindowsVersion -eq 'Microsoft Windows 11 Home') {
Powershell.exe -executionpolicy remotesigned -File "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\Sophia.ps1"
}
IF($WindowsVersion -eq 'Microsoft Windows 10 Pro') {
Powershell.exe -executionpolicy remotesigned -File "C:\Windows_Optimisation_Pack\_Files\Sophia_Script_Win10\Sophia.ps1"
}
IF($WindowsVersion -eq 'Microsoft Windows 10 Home') {
Powershell.exe -executionpolicy remotesigned -File "C:\Windows_Optimisation_Pack\_Files\Sophia_Script_Win10\Sophia.ps1"
}
Clear-Host

"---------------------------"
"Schritt 6 - o&oShutup"
"---------------------------"
C:\Windows_Optimisation_Pack\_Files\ooShutup\OOSU10.exe C:\Windows_Optimisation_Pack\_Files\ooShutup\ooshutup10.cfg /quiet
Clear-Host

" ---------------------------"
"Schritt 7 - Performance Counter"
"---------------------------"
lodctr /r
lodctr /r
Clear-Host


"---------------------------"
"Schritt 8.1 - C++ installieren"
"---------------------------"
winget install --id=Microsoft.VC++2015-2019Redist-x86  -e 
winget install --id=Microsoft.VC++2015-2019Redist-x64  -e
""
"---------------------------"
"Schritt 8.2 - Direct X Installieren"
"---------------------------"
winget install --id=Microsoft.DirectX  -e
""
"---------------------------"
"Schritt 8.3 - .Net-Framework Installieren"
"---------------------------"
winget install --id=Microsoft.dotNetFramework -e 
""
"---------------------------"
"Schritt 8.4 - Alle Programme Updaten"
"---------------------------"
winget upgrade --all --include-unknown
Clear-Host
"---------------------------"
"Schritt 8.5 - Nuetzliche Programme installieren"
"---------------------------"
winget install --id=RARLab.WinRAR -e
winget install --id=Notepad++.Notepad++ -e
winget install --id=REALiX.HWiNFO -e 
Stop-Process -Name HWiNFO64
winget install --id=VideoLAN.VLC -e
Clear-Host

"---------------------------"
"Schritt 9 - Explorer neustarten"
"---------------------------"
taskkill /f /im explorer.exe
Start-Process explorer.exe

Clear-Host
"==========================="
"Windows Optimization Pack"
"==========================="
Write-Warning "Ihr System wurde erforlgreich optimiert"
Write-Warning "Bitte starten sie ihr windows neu."
sleep 20
exit
