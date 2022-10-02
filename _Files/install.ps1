#Testversion
Remove-Item -Path C:\Windows_Optimisation_Pack\_Files\img\ -Force -Recurse

Clear-Host
$Host.UI.RawUI.WindowTitle = "Windows Optimization Pack"

If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	Write-Warning " Keine benoetigten Admin Rechte vorhanden"
    	Write-Warning " Das Script wird in 20 Sekunden beendet"
    sleep 20
    exit
}

" ==========================="
"  Windows Optimization Pack"
" ==========================="
"Schritt 1   - Vorbereitung der Komponenten"
"Schritt 2   - Sophia Script"
"Schritt 3   - o&oShutup"
"Schritt 4   - Windows Optimierungen"
"Schritt 6   - Autostart und Tasks deaktivieren"
"Schritt 6   - Laufzeitkomponenten installieren"
"Schritt 7   - Windows Refresh"
"Schritt 8   - Extras"
""
timeout 30
Clear-Host

" ---------------------------"
" Schritt 1 - Vorbereitung"
" ---------------------------"
Enable-ComputerRestore -Drive "C:\"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /F

$WindowsVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
IF($WindowsVersion -eq "Microsoft Windows 11 Home" -Or $WindowsVersion -eq "Microsoft Windows 11 Pro") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.1.4/Sophia.Script.for.Windows.11.v6.1.4.zip" -Destination "$env:temp\Sophia.zip"
}
else { IF($WindowsVersion -eq "Microsoft Windows 10 Home" -Or $WindowsVersion -eq "Microsoft Windows 10 Pro") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.1.4/Sophia.Script.for.Windows.10.v5.13.4.zip" -Destination "$env:temp\Sophia.zip"
}}
Expand-Archive "$env:temp\Sophia.zip" "$env:temp" -force
Move-Item -Path $env:temp\"Sophia Script *" -Destination "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\"
Move-Item -Path "C:\Windows_Optimisation_Pack\_Files\config\Sophia.ps1" -Destination "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\Sophia.ps1" -force
Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.3.2091/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination "$env:temp\winget.msixbundle"
Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination "C:\Windows_Optimisation_Pack\_Files\OOSU10.exe"
Start-BitsTransfer -Source "https://download.sysinternals.com/files/Autoruns.zip" -Destination "$env:temp\Autoruns.zip"
Invoke-Expression 'cmd /c start powershell -windowstyle hidden -Command { add-AppxPackage -Path "$env:temp\winget.msixbundle";winget install --id=Microsoft.dotNetFramework --exact --accept-source-agreements;winget source update}'
Expand-Archive "$env:temp\Autoruns.zip" "$env:temp\Autoruns"
Move-Item -Path "$env:temp\Autoruns\Autoruns64.exe" -Destination "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe" -Force
$Computername=$(Read-Host -Prompt ' Wie soll der neue Computername lauten')
Rename-Computer -NewName $Computername
New-Item -Path "C:\Spiele" -ItemType Directory
Clear-Host

# Sophia Script
Powershell.exe -executionpolicy remotesigned -File "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\Sophia.ps1"

# o&oShutup
C:\Windows_Optimisation_Pack\_Files\OOSU10.exe C:\Windows_Optimisation_Pack\_Files\config\ooshutup10.cfg /quiet

# Windows Optimierungen"
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA" /T REG_DWORD /D 00000000 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseSpeed" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold1" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold2" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseTrails" /T REG_DWORD /D 0 /F
Set-Service -Name "WpcMonSvc" -StartupType Disabled
Set-Service -Name "SharedRealitySvc" -StartupType Disabled
Set-Service -Name "Fax" -StartupType Disabled
Set-Service -Name "autotimesvc" -StartupType Disabled
Set-Service -Name "wisvc" -StartupType Disabled
Set-Service -Name "SDRSVC" -StartupType Disabled
Set-Service -Name "MixedRealityOpenXRSvc" -StartupType Disabled
Set-Service -Name "WalletService" -StartupType Disabled
Set-Service -Name "SmsRouter" -StartupType Disabled
Set-Service -Name "MapsBroker" -StartupType Disabled
Set-Service -Name "RetailDemo" -StartupType Disabled

# Autoruns
Start-Process "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe"
Clear-Host

" ----------------------------------------------"
" Schritt 7 - Laufzeitkomponenten installieren"
" ----------------------------------------------"
Invoke-WebRequest 'https://aka.ms/vs/17/release/VC_redist.x64.exe' -OutFile $env:temp\VC_redist.x64.exe
Start-Process -FilePath "$env:temp\VC_redist.x64.exe" -ArgumentList "/install /passive /norestart" -Wait
""
Invoke-WebRequest 'https://aka.ms/vs/17/release/VC_redist.x86.exe' -OutFile $env:temp\VC_redist.x86.exe
Start-Process -FilePath "$env:temp\VC_redist.x86.exe" -ArgumentList "/install /passive /norestart" -Wait
""
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x64 --exact --accept-source-agreements
""
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x86 --exact --accept-source-agreements
""
winget install --id=Microsoft.DirectX --exact --accept-source-agreements
""
winget install --id=RARLab.WinRAR --exact --accept-source-agreements
""
winget install --id=VideoLAN.VLC --exact --accept-source-agreements
""
winget upgrade --all
Clear-Host

" -------------------------------"
" Schritt 8 - Windows Refresh"
" -------------------------------"
Remove-Item -Path C:\Windows_Optimisation_Pack\_Files\config\  -Force -Recurse
gpupdate.exe /force
Get-ChildItem -Path "C:\Windows\Prefetch" *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path "$ENV:userprofile\AppData\Local\Temp" *.* -Recurse | Remove-Item -Force -Recurse
lodctr /r
lodctr /r
taskkill /f /im explorer.exe
Start-Process explorer.exe
Clear-Host

" ---------------------------"
" Schritt 9 - Extras"
" ---------------------------"

[reflection.assembly]::LoadWithPartialName( "System.Windows.Forms")
Clear-Host

" ==========================="
" Windows Optimization Pack"
" ==========================="
$form = New-Object Windows.Forms.Form
$form.text = "Windows_Optimisation_Pack"

$Titel = New-Object Windows.Forms.Label
$Titel.Location = New-Object Drawing.Point 70,25
$Titel.Size = New-Object Drawing.Point 200,15
$Titel.text = "Windows Optimisation Pack"

$Text = New-Object Windows.Forms.Label
$Text.Location = New-Object Drawing.Point 60,170
$Text.Size = New-Object Drawing.Point 200,15
$Text.text = ""

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

$button1.add_click({
$Text.Text = "Bitte warten..."
winget install --id=BitSum.ProcessLasso --accept-source-agreements
$Text.Text = "Processlasso wurde installiert"
$button1.text = ""
})

$button2.add_click({
$Text.Text = "Bitte warten..."
Invoke-WebRequest 'https://github.com/Ryochan7/DS4Windows/releases/download/v3.1.6/DS4Windows_3.1.6_x86.zip' -OutFile $env:temp\DS4Windows.zip 
Expand-Archive $env:temp\DS4Windows.zip "C:\Program Files\" -force
Remove-Item -Path $env:temp\DS4Windows.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Controller.lnk")
$Shortcut.TargetPath = "C:\Program Files\DS4Windows\DS4Windows.exe"
$Shortcut.Save()
$Text.Text = "DS4Windows wurde installiert"
$button2.text = ""
})

$button3.add_click({
$Text.Text = "Bitte warten..."
Invoke-WebRequest 'https://github.com/Codectory/AutoActions/releases/download/1.9.19/Release_AutoActions_1.9.19_x64.zip' -OutFile $env:temp\AutoActions.zip 
Expand-Archive $env:temp\AutoActions.zip "C:\Program Files\AutoActions" -force
Remove-Item -Path $env:temp\AutoActions.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\AutoActions.lnk")
$Shortcut.TargetPath = "C:\Program Files\AutoActions\AutoActions.exe"
$Shortcut.Save()
$Text.Text = "AutoActions wurde installiert"
$button3.text = ""
})

$button4.add_click({
$Text.Text = "Bitte warten..."
winget install "DLSS Swapper" --source msstore  --accept-package-agreements --accept-source-agreements 
$Text.Text = "DLSS Swapper wurde installiert"
$button3.text = ""
})

$form.controls.add($Titel)
$form.controls.add($Text)
$form.controls.add($button1)
$form.controls.add($button2)
$form.controls.add($button3)
$form.controls.add($button4)
$form.ShowDialog()

Get-ChildItem -Path "$ENV:userprofile\AppData\Local\Temp" *.* -Recurse | Remove-Item -Force -Recurse
Clear-Host


" ==========================="
" Windows Optimization Pack"
" ==========================="
""
" Ihr System wurde erforlgreich optimiert"
""
Write-Warning " Der Computer wird in 60 Sekunden automatisch neugestartet !!!"
timeout 60
Restart-Computer
