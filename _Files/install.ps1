$Host.UI.RawUI.WindowTitle = "Windows_Optimization_Pack"


function Begruesung{
Clear-Host
" ==========================="
"  Windows Optimization Pack"
" ==========================="
" Schritt 1   - Vorbereitung"
" Schritt 2   - Laufzeitkomponenten"
" Schritt 3   - Extras"
" Schritt 4   - Sophia Script"
" Schritt 5   - o&oShutup"
" Schritt 5   - Windows Optimierungen"
" Schritt 7   - Autostart"
" Schritt 8   - Windows Refresh"
""
timeout 30
}

function Restart{
Clear-Host
" Ihr System wurde erforlgreich optimiert"
""
Write-Warning " Der Computer wird in 60 Sekunden automatisch neugestartet !!!"
timeout 60
Restart-Computer
}

function AdminPrüfung{
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
	Write-Warning " Keine benoetigten Admin Rechte vorhanden"
    	Write-Warning " Das Script wird in 20 Sekunden beendet"
    sleep 20
    exit
}}

function SystemPunkt{
Enable-ComputerRestore -Drive "C:\"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /F
}

function SpieleOrdner{
New-Item -Path "C:\Spiele" -ItemType Directory
}

function SophiaScript{
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
Powershell.exe -executionpolicy Bypass "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\Sophia.ps1"
Clear-Host
}

function ooShutup{
Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination "C:\Windows_Optimisation_Pack\_Files\OOSU10.exe"
C:\Windows_Optimisation_Pack\_Files\OOSU10.exe C:\Windows_Optimisation_Pack\_Files\config\ooshutup10.cfg /quiet
}

function WindowsTweaks{
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
}

function Autoruns{
Start-BitsTransfer -Source "https://download.sysinternals.com/files/Autoruns.zip" -Destination "$env:temp\Autoruns.zip"
Expand-Archive "$env:temp\Autoruns.zip" "$env:temp\Autoruns"
Move-Item -Path "$env:temp\Autoruns\Autoruns64.exe" -Destination "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe" -Force
Start-Process "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe"
}

function WindowsRefresh{
Remove-Item -Path C:\Windows_Optimisation_Pack\_Files\config\  -Force -Recurse
gpupdate.exe /force
Get-ChildItem -Path "C:\Windows\Prefetch" *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path "C:\Windows\Temp" *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path "$ENV:userprofile\AppData\Local\Temp" *.* -Recurse | Remove-Item -Force -Recurse
lodctr /r
lodctr /r
taskkill /f /im explorer.exe
Start-Process explorer.exe
}

function Laufzeitkomponenten{
Clear-Host
""
" Laufzeitkomponenten installieren..."
Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.3.2091/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination "$env:temp\winget.msixbundle"
Invoke-Expression 'cmd /c start powershell -windowstyle hidden -Command { add-AppxPackage -Path "$env:temp\winget.msixbundle";winget source update}'
Start-BitsTransfer -Source "https://aka.ms/vs/17/release/VC_redist.x64.exe" -Destination "$env:temp\VC_redist.x64.exe"
Start-BitsTransfer -Source "https://aka.ms/vs/17/release/VC_redist.x86.exe" -Destination "$env:temp\VC_redist.x86.exe"
Start-Process -FilePath "$env:temp\VC_redist.x64.exe" -ArgumentList "/install /passive /norestart" -Wait
Start-Process -FilePath "$env:temp\VC_redist.x86.exe" -ArgumentList "/install /passive /norestart" -Wait
winget install --id=Microsoft.dotNetFramework --exact --accept-source-agreements
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x64 --exact --accept-source-agreements
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x86 --exact --accept-source-agreements
winget install --id=Microsoft.DirectX --exact --accept-source-agreements
winget upgrade --all --accept-source-agreements
}

function Programme{
" Programme installieren..."
winget install --id=RARLab.WinRAR --exact --accept-source-agreements
winget install --id=VideoLAN.VLC --exact --accept-source-agreements
}

function Extras{
[reflection.assembly]::LoadWithPartialName( "System.Windows.Forms")
$form = New-Object Windows.Forms.Form
$form.text = "Windows_Optimisation_Pack"
$Titel = New-Object Windows.Forms.Label
$Titel.Location = New-Object Drawing.Point 70,25
$Titel.Size = New-Object Drawing.Point 200,15
$Titel.text = "Windows_Optimisation_Pack"
$Textbox = New-Object System.Windows.Forms.TextBox
$Textbox.Size = New-Object Drawing.Point 160,20
$Textbox.location = New-Object Drawing.Point 60,170
$Textbox.Font = New-Object System.Drawing.Font('Microsoft Sans Serif',10)
$Username=[Environment]::UserName
$TextBox.Text = $Username+"-Computer"
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
$button5 = New-Object Windows.Forms.Button
$button5.text = "Weiter"
$button5.Location = New-Object Drawing.Point 80,200
$button5.Size = New-Object Drawing.Point 110,40
$button1.add_click({
$Titel.text = "Bitte warten..."
winget install --id=BitSum.ProcessLasso --accept-source-agreements
timeout 2
$button1.Enabled = $false
$button1.IsAccessible = $false
$Titel.text = "Windows_Optimisation_Pack"})
$button2.add_click({
$Titel.text = "Bitte warten..."
Invoke-WebRequest 'https://github.com/Ryochan7/DS4Windows/releases/download/v3.1.6/DS4Windows_3.1.6_x86.zip' -OutFile $env:temp\DS4Windows.zip 
Expand-Archive $env:temp\DS4Windows.zip "C:\Program Files\" -force
Remove-Item -Path $env:temp\DS4Windows.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Controller.lnk")
$Shortcut.TargetPath = "C:\Program Files\DS4Windows\DS4Windows.exe"
$Shortcut.Save()
$button2.Enabled = $false
$button2.IsAccessible = $false
$Titel.text = "Windows_Optimisation_Pack"})
$button3.add_click({
$Titel.text = "Bitte warten..."
Invoke-WebRequest 'https://github.com/Codectory/AutoActions/releases/download/1.9.19/Release_AutoActions_1.9.19_x64.zip' -OutFile $env:temp\AutoActions.zip 
Expand-Archive $env:temp\AutoActions.zip "C:\Program Files\AutoActions" -force
Remove-Item -Path $env:temp\AutoActions.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\AutoActions.lnk")
$Shortcut.TargetPath = "C:\Program Files\AutoActions\AutoActions.exe"
$Shortcut.Save()
$button3.Enabled = $false
$button3.IsAccessible = $false
$Titel.text = "Windows_Optimisation_Pack"})
$button4.add_click({
$Titel.text = "Bitte warten..."
winget install "DLSS Swapper" --source msstore  --accept-package-agreements --accept-source-agreements 
$Text.Text = "DLSS Swapper wurde installiert"
$button4.Enabled = $false
$button4.IsAccessible = $false
$Titel.text = "Windows_Optimisation_Pack"})
$button5.Add_Click({
Rename-Computer -NewName $TextBox.Text 
$Form.Close()})
$form.controls.add($Titel)
$form.controls.add($Textbox)
$form.controls.add($button1)
$form.controls.add($button2)
$form.controls.add($button3)
$form.controls.add($button4)
$form.controls.add($button5)
$form.ShowDialog()
}

Begruesung
AdminPrüfung
SystemPunkt
Laufzeitkomponenten
Extras
SpieleOrdner
SophiaScript
ooShutup
WindowsTweaks
Autoruns
Programme
WindowsRefresh
Restart

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUmyOwIeBpWlOFIZazrd6JrXA
# S6GgggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUrsr3FDpaz0W2QgE5cmeYxIGMwVcwDQYJ
# KoZIhvcNAQEBBQAEggEAe2HtIX8R4qqrVfk5Y6E7OU8Iwau6pdEsZvVZDKmfoX6Y
# GlnsQS9XTQhIP90z67rcRQ0O7J6XS9Te8j641hvZvzzJQmsx83C3yVYiU5ckTZ0k
# 6UTlRab/Lz+fVK/ExAubiv4wyZUDsOJcH8BUIORcKq0MzF/DBiI2bvkF+RwSyVhR
# II1vW3/KUHIfJ13WO3mlcxv3WyU6vA6rhEkLaSFudmnEt1pIRxd2JxnmHGbUkqcb
# vhSyl+CLl74Ax1tVdUyjCEFm8Bxu7B7tGivc6/RKv/NKzfC365BfhuRi4ygACwBd
# rFIzSxoGfrV/7AaTFMYSxjkMf8TGbC7zQLGwityP6A==
# SIG # End signature block
