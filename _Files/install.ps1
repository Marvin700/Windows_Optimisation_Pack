Clear-Host
"--- WCHICHTIG ---"
"Bitte erst Windows Updaten"
"Der Ornder Windows_Optimisation_Pack muss unter C liegen."
"Muss als Admin ausgefuert werden"
"--- WCHICHTIG ---"
""
"==========================="
"Windows Optimization Pack"
"==========================="
"Schritt 0   - Wiederherstellungspunkt erstellen"
"Schritt 1   - Autostart und Tasks deaktivieren"
"Schritt 2   - o&oShutup"
"Schritt 3   - Registry Werte aendern"
"Schritt 4   - Schnellstart deaktiveren"
"Schritt 5   - Performance Counter"
"Schritt 6   - Winget installieren"
"Schritt 6.1 - C++ 2008-2019 installieren "
"Schritt 6.2 - Direct X Installieren"
"Schritt 6.3 - Net-Framework Installieren"
"Schritt 6.4 - Alle Programme Updaten"
"Schritt 6.5 - Nuetzliche Programme installieren"
"Schritt 7   - Sophia Script"
""
""
"Automatischer start in 30 Sekunden..."
timeout 30
Clear-Host

"----------------------------"
"Schritt 0 - Wiederherstellungspunkt erstellen"
"-----------------------"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
Clear-Host

"---------------------------"
"Schritt 1 - Autostart und Tasks deaktivieren"
"---------------------------"
Start-Process ms-settings:startupapps
Start-Process "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe"
Clear-Host

"---------------------------"
"Schritt 2 - o&oShutup"
"---------------------------"
Invoke-WebRequest 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe' -OutFile C:\Windows_Optimisation_Pack\_Files\oShutup\OOSU10.exe
Start-Process "C:\Windows_Optimisation_Pack\_Files\OOSU10.exe"
Clear-Host

"---------------------------"
"Schritt 3 Registry Werte ändern"
"---------------------------"
reg import "C:\Windows_Optimisation_Pack\_Files\Registry.reg"
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA" /T REG_DWORD /D 00000000 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseSpeed" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold1" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold2" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseTrails" /T REG_DWORD /D 0 /F
Clear-Host

"---------------------------"
"Schritt 5 - Schnellstart deaktiveren"
"---------------------------"
powercfg -h off
Clear-Host

" ---------------------------"
"Schritt 6 - Performance Counter"
"---------------------------"
lodctr /r
lodctr /r
Clear-Host

"---------------------------"
"Schritt 7 - Winget installieren"
"---------------------------"
Invoke-WebRequest 'https://github.com/microsoft/winget-cli/releases/download/v1.3.2091/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' -OutFile C:\Windows_Optimisation_Pack\_Files\winget.msixbundle
Add-AppxPackage "C:\Windows_Optimisation_Pack\_Files\WinGet.msixbundle"
winget source update
Clear-Host

"---------------------------"
"Schritt 7 - Sophia Script"
"---------------------------"
Powershell.exe -executionpolicy remotesigned -File "C:\Windows_Optimisation_Pack\_Files\Sophia Script\Sophia.ps1"
Clear-Host

"---------------------------"
"Schritt 6.1 - C++ installieren"
"---------------------------"
"Nun wird C++ installiert"
winget install --id=Microsoft.VC++2008Redist-x86  -e
winget install --id=Microsoft.VC++2008Redist-x64  -e
winget install --id=Microsoft.VC++2010Redist-x86  -e
winget install --id=Microsoft.VC++2010Redist-x64  -e
winget install --id=Microsoft.VC++2012Redist-x86  -e
winget install --id=Microsoft.VC++2012Redist-x64  -e
winget install --id=Microsoft.VC++2013Redist-x86  -e
winget install --id=Microsoft.VC++2013Redist-x64  -e
winget install --id=Microsoft.VC++2015-2019Redist-x86  -e 
winget install --id=Microsoft.VC++2015-2019Redist-x64  -e
""
"---------------------------"
"Schritt 6.2 - Direct X Installieren"
"---------------------------"
"nun wird Direct X installiert"
winget install --id=Microsoft.DirectX  -e
""
"---------------------------"
"Schritt 6.3 - .Net-Framework Installieren"
"---------------------------"
"nun wird .Net-Framework installiert"
winget install --id=Microsoft.dotNetFramework -e 
""
"---------------------------"
"Schritt 6.4 - Alle Programme Updaten"
"---------------------------"
"Nun werden alle Programme auf den aktuellstens stand gebracht"
winget upgrade --all --include-unknown
""
"---------------------------"
"Schritt 6.5 - Nuetzliche Programme installieren"
"---------------------------"
winget install --id=RARLab.WinRAR -e
winget install --id=VideoLAN.VLC -e
winget install --id=Notepad++.Notepad++ -e
winget install --id=REALiX.HWiNFO -e 
Clear-Host

"---------------------------"
"Schritt 8 - Explorer neustarten"
"---------------------------"
taskkill /f /im explorer.exe
Start-Process explorer.exe

pause
