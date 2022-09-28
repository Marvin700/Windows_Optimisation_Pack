#Testversion
Remove-Item -Path C:\Windows_Optimisation_Pack\_Files\Titelbild.png -Force -Recurse
Remove-Item -Path C:\Windows_Optimisation_Pack\_Files\DownloadButton.png -Force -Recurse

Clear-Host
"==========================="
"Windows Optimization Pack"
"==========================="
#Administrator Pruefung
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	Write-Warning "Keine benoetigten Admin Rechte vorhanden"
    	Write-Warning "Das Script wird in 20 Sekunden beendet"
    sleep 20
    exit
}
"Schritt 0   - Wiederherstellungspunkt erstellen"
"Schritt 1   - Download und installation benoetigter Pakete"
"Schritt 1.1 - Computernamen vergeben"
"Schritt 2   - Autostart und Tasks deaktivieren"
"Schritt 3   - Sophia Script"
"Schritt 4   - o&oShutup"
"Schritt 5   - Registry Werte aendern"
"Schritt 6   - Dienste deaktivieren"
"Schritt 7   - Performance Counter"
"Schritt 8   - Explorer neustarten"
"Schritt 9.1 - C++ 2008-2019 installieren"
"Schritt 9.2 - Direct X Installieren"
"Schritt 9.3 - Net-Framework Installieren"
"Schritt 9.4 - Alle Programme Updaten"
"Schritt 9.5 - Nuetzliche Programme installieren"
"Schritt 10  - Extras"
""
""
"Automatischer start in 30 Sekunden..."
timeout 30
Clear-Host

"---------------------------------------------"
"Schritt 0 - Wiederherstellungspunkt erstellen"
"---------------------------------------------"
Enable-ComputerRestore -Drive "C:\"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /F
Clear-Host

"--------------------------------------------------------"
"Schritt 1 - Download und installation benoetigter Pakete"
"--------------------------------------------------------"
#Windows Version bestimmen
$WindowsVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
Invoke-WebRequest 'https://github.com/microsoft/winget-cli/releases/download/v1.3.2091/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' -OutFile C:\Windows_Optimisation_Pack\_Files\winget.msixbundle
invoke-expression 'cmd /c start powershell -Command { add-AppxPackage -Path C:\Windows_Optimisation_Pack\_Files\WinGet.msixbundle;winget source update}'
Invoke-WebRequest 'https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe' -OutFile C:\Windows_Optimisation_Pack\_Files\ooShutup\OOSU10.exe
Invoke-WebRequest 'https://download.sysinternals.com/files/Autoruns.zip' -OutFile $env:temp\Autoruns.zip
Expand-Archive $env:temp\Autoruns.zip $env:temp\Autoruns
Remove-Item -Path $env:temp\Autoruns.zip -Force -Recurse
Move-Item -Path "$env:temp\Autoruns\Autoruns64.exe" -Destination "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe" -Force
Remove-Item "$env:temp\Autoruns\" -force -Recurse
Clear-Host

"------------------------------------"
"Schritt 1.1 - Computernamen vergeben"
"------------------------------------"
$Computername=$(Read-Host -Prompt 'Wie soll der neue Computername lauten')
Rename-Computer -NewName $Computername
Clear-Host

"---------------------------"
"Schritt 2 - Autostart und Tasks deaktivieren"
"---------------------------"
#Start-Process ms-settings:startupapps
Start-Process "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe"
Clear-Host

"---------------------------"
"Schritt 3 - Sophia Script"
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
"Schritt 4 - o&oShutup"
"---------------------------"
C:\Windows_Optimisation_Pack\_Files\ooShutup\OOSU10.exe C:\Windows_Optimisation_Pack\_Files\ooShutup\ooshutup10.cfg /quiet
Clear-Host

"---------------------------"
"Schritt 5 Registry Werte aendern"
"---------------------------"
reg import "C:\Windows_Optimisation_Pack\_Files\Registry.reg"
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA" /T REG_DWORD /D 00000000 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseSpeed" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold1" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold2" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseTrails" /T REG_DWORD /D 0 /F
Clear-Host

"---------------------------"
"Schritt 6 - Dienste deaktivieren"
"---------------------------"
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
Clear-Host

"---------------------------"
"Schritt 7 - Performance Counter"
"---------------------------"
lodctr /r
lodctr /r
Clear-Host

"-------------------------------"
"Schritt 8 - Explorer neustarten"
"-------------------------------"
taskkill /f /im explorer.exe
Start-Process explorer.exe
Clear-Host

"------------------------------"
"Schritt 9.1 - C++ installieren"
"------------------------------"
""
winget install --id=Microsoft.VC++2015-2022Redist-x64 --exact --accept-source-agreements
""
winget install --id=Microsoft.VC++2015-2022Redist-x86 --exact --accept-source-agreements
""
"-----------------------------------"
"Schritt 9.2 - Direct X Installieren"
"-----------------------------------"
""
winget install --id=Microsoft.DirectX --exact --accept-source-agreements
""
"-----------------------------------------"
"Schritt 9.3 - .Net-Framework Installieren"
"-----------------------------------------"
""
winget install --id=Microsoft.dotNetFramework --exact --accept-source-agreements
""
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x64 --exact --accept-source-agreements
""
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x86 --exact --accept-source-agreements
""
"------------------------------------"
"Schritt 9.4 - Alle Programme Updaten"
"------------------------------------"
""
winget upgrade --all
""
"-----------------------------------------------"
"Schritt 9.5 - Nuetzliche Programme installieren"
"-----------------------------------------------"
winget install --id=RARLab.WinRAR --exact --accept-source-agreements
""
winget install --id=Notepad++.Notepad++ --accept-source-agreements
""
winget install --id=REALiX.HWiNFO --exact --accept-source-agreements
Stop-Process -Name HWiNFO64
""
winget install --id=VideoLAN.VLC --exact --accept-source-agreements
""
Clear-Host

"-----------------------------------------------"
"Schritt 10 - Extras"
"-----------------------------------------------"

[reflection.assembly]::LoadWithPartialName( "System.Windows.Forms")
Clear-Host

"==========================="
"Windows Optimization Pack"
"==========================="
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

# $button4 = New-Object Windows.Forms.Button
# $button4.text = ""
# $button4.Location = New-Object Drawing.Point 140,100
# $button4.Size = New-Object Drawing.Point 100,35

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

# $button4.add_click({
# 
# })

$form.controls.add($Titel)
$form.controls.add($Text)
$form.controls.add($button1)
$form.controls.add($button2)
$form.controls.add($button3)
# $form.controls.add($button4)
$form.ShowDialog()
Clear-Host


"==========================="
"Windows Optimization Pack"
"==========================="
"Ihr System wurde erforlgreich optimiert"
""
Remove-Item "$env:temp\WinGet\" -force -Recurse
Write-Warning "Der Computer wird in 60 Sekunden automatisch neugestartet !!!"
sleep 60
Restart-Computer
