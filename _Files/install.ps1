$Host.UI.RawUI.WindowTitle = "Windows_Optimization_Pack"

function Begruesung{
Clear-Host
" ==========================="
"  Windows Optimization Pack"
" ==========================="
" Schritt 1 - Vorbereitung"
" Schritt 2 - Laufzeitkomponenten"
" Schritt 3 - Extras"
" Schritt 4 - Sophia Script"
" Schritt 5 - o&oShutup"
" Schritt 5 - Windows Optimierungen"
" Schritt 7 - Autostart"
" Schritt 8 - Windows Refresh"
timeout 30
Clear-Host }

function Pruefungen{
if (!(Test-Path "C:\Windows_Optimisation_Pack")) {
Write-Warning " Das Script liegt nicht im korrekten Ordner !"
Write-Warning " Das Script wird in 20 Sekunden beendet"
Start-Sleep 20
exit}
if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){
Write-Warning " Reboot Pending !"
Write-Warning " Das Script wird in 20 Sekunden beendet"
Start-Sleep 20
exit}
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
Write-Warning " Keine benoetigten Admin Rechte vorhanden"
Write-Warning " Das Script wird in 20 Sekunden beendet"
Start-Sleep 20
exit} 
if ((Test-Path "HKLM:\SOFTWARE\Windows_Optimisation_Pack")){
Write-Warning " Das System wurde bereits durch das Windows_Opsimisation_Pack optimiert"
"Moechten sie wirklich fortfahren?"
$weitermachen = Read-Host "Ja oder Nein ?"
IF(!($weitermachen -eq "Ja" -Or $weitermachen -eq "j" -Or $weitermachen -eq "JA" -Or $weitermachen -eq "y" -Or $weitermachen -eq "yes")) {         
Write-Warning " Das Script wird in 20 Sekunden beendet"
Start-Sleep 20
exit}} }

function SystemPunkt{
Enable-ComputerRestore -Drive "C:\"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /F }

function SophiaScript{
$WindowsVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
IF($WindowsVersion -eq "Microsoft Windows 11 Home" -Or $WindowsVersion -eq "Microsoft Windows 11 Pro") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.2.0/Sophia.Script.for.Windows.11.v6.2.0.zip" -Destination "$env:temp\Sophia.zip"
Expand-Archive "$env:temp\Sophia.zip" "$env:temp" -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\"
Move-Item -Path "C:\Windows_Optimisation_Pack\_Files\config\Sophia.ps1" -Destination "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\Sophia.ps1" -force }
else { IF($WindowsVersion -eq "Microsoft Windows 10 Home" -Or $WindowsVersion -eq "Microsoft Windows 10 Pro") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.2.0/Sophia.Script.for.Windows.10.v5.14.0.zip" -Destination "$env:temp\Sophia.zip"
Expand-Archive "$env:temp\Sophia.zip" "$env:temp" -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\"
Move-Item -Path "C:\Windows_Optimisation_Pack\_Files\config\Sophia_Win10.ps1" -Destination "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\Sophia.ps1" -force} }
Powershell.exe -executionpolicy Bypass "C:\Windows_Optimisation_Pack\_Files\Sophia_Script\Sophia.ps1"
REG ADD "HKLM\SOFTWARE\Windows_Optimisation_Pack\" /V "Sophia_Script" /T REG_DWORD /D 1 /F
Clear-Host }

function ooShutup{
Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination "C:\Windows_Optimisation_Pack\_Files\OOSU10.exe"
C:\Windows_Optimisation_Pack\_Files\OOSU10.exe C:\Windows_Optimisation_Pack\_Files\config\ooshutup10.cfg /quiet }

function WindowsTweaks_Dienste{
Stop-Service "WpcMonSvc"
Stop-Service "SharedRealitySvc"
Stop-Service "Fax"
Stop-Service "autotimesvc"
Stop-Service "wisvc"
Stop-Service "SDRSVC"
Stop-Service "MixedRealityOpenXRSvc"
Stop-Service "WalletService"
Stop-Service "SmsRouter"
Stop-Service "SharedAccess"
Stop-Service "MapsBroker"
Stop-Service "MNgcSvc"
Stop-Service "NgcCtnrSvc"
Stop-Service "PhoneSvc"
Stop-Service "ScDeviceEnum"
Stop-Service "TabletInputService"
Stop-Service "icssvc"
Stop-Service "edgeupdatem"
Stop-Service "edgeupdate"
Stop-Service "MicrosoftEdgeElevationService"
Stop-Service "RetailDemo"
Stop-Service "UnistoreSvc"
Stop-Service "OneSyncSvc"
Stop-Service "DoSvc"
Stop-Service "wlidsvc"
Stop-Service "PimIndexMaintenanceSvc"
Stop-Service "MessagingService"
Set-Service "WpcMonSvc" -StartupType Disabled
Set-Service "SharedRealitySvc" -StartupType Disabled
Set-Service "Fax" -StartupType Disabled
Set-Service "autotimesvc" -StartupType Disabled
Set-Service "wisvc" -StartupType Disabled
Set-Service "SDRSVC" -StartupType Disabled
Set-Service "MixedRealityOpenXRSvc" -StartupType Disabled
Set-Service "WalletService" -StartupType Disabled
Set-Service "SmsRouter" -StartupType Disabled
Set-Service "SharedAccess" -StartupType Disabled
Set-Service "MapsBroker" -StartupType Disabled
Set-Service "MNgcSvc" -StartupType Disabled
Set-Service "NgcCtnrSvc" -StartupType Disabled
Set-Service "PhoneSvc" -StartupType Disabled
Set-Service "ScDeviceEnum" -StartupType Disabled
Set-Service "TabletInputService" -StartupType Disabled
Set-Service "icssvc" -StartupType Disabled
Set-Service "edgeupdatem" -StartupType Disabled
Set-Service "edgeupdate" -StartupType Disabled
Set-Service "MicrosoftEdgeElevationService" -StartupType Disabled
Set-Service "RetailDemo" -StartupType Disabled 
Set-Service "UnistoreSvc" -StartupType Disabled
Set-Service "OneSyncSvc" -StartupType Disabled
Set-Service "DoSvc" -StartupType Disabled
Set-Service "wlidsvc" -StartupType Disabled
Set-Service "PimIndexMaintenanceSvc" -StartupType Disabled
Set-Service "MessagingService" -StartupType Disabled }

function WindowsTweaks_Registry{
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA" /T REG_DWORD /D 00000000 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseSpeed" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold1" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseThreshold2" /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\Control Panel\Mouse" /V "MouseTrails" /T REG_DWORD /D 0 /F
New-Item -Path "HKLM:\Software\policies\Microsoft\Windows NT\" -Name "DNSClient" -Force
Set-ItemProperty -Path "HKLM:\Software\policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Type "DWORD" -Value 0 -Force
Write-Output "Disable Insider Preview Builds"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\PreviewBuilds" -Name AllowBuildPreview -Type "DWORD" -Value 0 -Force
Write-Output "IE Optimizations"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter" -Name EnabledV9 -Type "DWORD" -Value 0 -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Geolocation" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Geolocation" -Name PolicyDisableGeolocation -Type "DWORD" -Value 1 -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\" -Name "AutoComplete" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" -Name AutoSuggest -Type "String" -Value no -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer" -Name AllowServicePoweredQSA -Type "DWORD" -Value 0 -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "Suggested Sites" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Suggested Sites" -Name Enabled -Type "DWORD" -Value 0 -Force
New-Item -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\" -Name "FlipAhead" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\FlipAhead" -Name Enabled -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds" -Name BackgroundSyncStatus -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name AllowOnlineTips -Type "DWORD" -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy" -Name LetAppsRunInBackground -Type "DWORD" -Value 2 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value "1" -Force
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\FindMyDevice" -Name AllowFindMyDevice -Type "DWORD" -Value 0 -Force }

function WindowsTweaks_Tasks{
Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue 
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask }

function WindowsTweaks_Index{
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='C:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False}
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='D:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False}
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='E:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False}
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='F:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False} }

function WindowsTweaks_Packages{
Get-AppxPackage -alluser Microsoft.MicrosoftEdgeDevToolsClient_1000.22000.1.0_neutral_neutral_8wekyb3d8bbwe | Remove-AppxPackage 
Get-AppxPackage -alluser Microsoft.Windows.CloudExperienceHost_10.0.22000.1_neutral_neutral_cw5n1h2txyewy | Remove-AppxPackage
Get-AppxPackage -alluser Microsoft.Windows.ParentalControls_1000.22000.1.0_neutral_neutral_cw5n1h2txyewy | Remove-AppxPackage 
Get-AppxPackage -alluser Microsoft.AccountsControl_10.0.22000.1_neutral__cw5n1h2txyewy | Remove-AppxPackage 
Get-AppxPackage -alluser Microsoft.OneDriveSync_21220.1024.5.0_neutral__8wekyb3d8bbwe | Remove-AppxPackage 
Get-AppxPackage -alluser WinRAR.ShellExtension_1.0.0.1_x64__s4jet1zx4n14a | Remove-AppxPackage }

function Autoruns{
Start-BitsTransfer -Source "https://download.sysinternals.com/files/Autoruns.zip" -Destination "$env:temp\Autoruns.zip"
Expand-Archive "$env:temp\Autoruns.zip" "$env:temp\Autoruns"
Move-Item -Path "$env:temp\Autoruns\Autoruns64.exe" -Destination "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe" -Force
Start-Process "C:\Windows_Optimisation_Pack\_Files\Autoruns.exe" }

function WindowsRefresh{
Clear-Host
gpupdate.exe /force
Cmd.exe /c Cleanmgr /sagerun:65535
Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:windir\Prefetch *.* -Recurse | Remove-Item -Force -Recurse
Get-ChildItem -Path $ENV:userprofile\AppData\Local\Temp *.* -Recurse | Remove-Item -Force -Recurse
Remove-Item -Path C:\Windows_Optimisation_Pack\_Files\config\  -Force -Recurse
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
Clear-BCCache -Force -ErrorAction SilentlyContinue
reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f
vssadmin delete shadows /all /quiet
lodctr /r
lodctr /r
taskkill /f /im explorer.exe
Start-Process explorer.exe }

function Laufzeitkomponenten{
Clear-Host
""
" Laufzeitkomponenten installieren..."
Start-BitsTransfer -Source "https://github.com/microsoft/winget-cli/releases/download/v1.3.2091/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle" -Destination "$env:temp\winget.msixbundle"
Invoke-Expression 'cmd /c start powershell -windowstyle hidden -Command { add-AppxPackage -Path "$env:temp\winget.msixbundle";winget source update}'
Start-Sleep 5
winget install --id=Microsoft.VCRedist.2015+.x64 --exact --accept-source-agreements
winget install --id=Microsoft.VCRedist.2015+.x86 --exact --accept-source-agreements
winget install --id=Microsoft.dotNetFramework --exact --accept-source-agreements
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x64 --exact --accept-source-agreements
winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x86 --exact --accept-source-agreements
winget install --id=Microsoft.DirectX --exact --accept-source-agreements }

function TakeOwnership{
New-Item "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership" -force -ea SilentlyContinue
New-Item "HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command" -force -ea SilentlyContinue
New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership" -force -ea SilentlyContinue
New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command" -force -ea SilentlyContinue
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" && icacls \"%1\" /grant *S-1-3-4:F /c /l'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'AppliesTo' -Value 'NOT (System.ItemPathDisplay:="C:\Users" OR System.ItemPathDisplay:="C:\ProgramData" OR System.ItemPathDisplay:="C:\Windows" OR System.ItemPathDisplay:="C:\Windows\System32" OR System.ItemPathDisplay:="C:\Program Files" OR System.ItemPathDisplay:="C:\Program Files (x86)")' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership' -Name 'Position' -Value 'middle' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name '(default)' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\TakeOwnership\command' -Name 'IsolatedCommand' -Value 'powershell -windowstyle hidden -command "Start-Process cmd -ArgumentList ''/c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant *S-1-3-4:F /c /l /q'' -Verb runAs' -PropertyType String -Force -ea SilentlyContinue;}

function Updaten{
winget upgrade --all --accept-source-agreements}

function Programme{
Clear-Host
""
" Programme installieren..."
winget install --id=RARLab.WinRAR --exact --accept-source-agreements}

function SpieleOrdner{
New-Item -Path "C:\Spiele" -ItemType Directory }
    
function Festplatten_Name{
Label C: Windows }

function Ende{
REG ADD "HKLM\SOFTWARE\Windows_Optimisation_Pack\" /V "Erfolgreich" /T REG_DWORD /D 1 /F
Clear-Host
" Ihr System wurde erforlgreich optimiert"
""
Write-Warning " Der Computer wird in 60 Sekunden automatisch neugestartet !!!"
timeout 60
Restart-Computer }

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
Invoke-WebRequest 'https://dl.bitsum.com/files/processlassosetup64.exe' -OutFile $env:temp\ProcesslassoSetup64.exe
Start-Process -FilePath "$env:temp\ProcesslassoSetup64.exe" -ArgumentList "/S /language=German"
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
$form.ShowDialog() }

Begruesung
Pruefungen
SystemPunkt
Laufzeitkomponenten
Updaten
Extras
SophiaScript
ooShutup
SpieleOrdner
Festplatten_Name
WindowsTweaks_Index
WindowsTweaks_Registry
WindowsTweaks_Dienste
WindowsTweaks_Tasks
WindowsTweaks_Packages
TakeOwnership
Autoruns
Programme
WindowsRefresh
Ende

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4B4uGhDTQ29345/f2FFQPN1X
# As+gggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQURH2CFJuKyhzfof3o5CtkkNcDGfEwDQYJ
# KoZIhvcNAQEBBQAEggEAMoUtI6iHqXkchj9YXhM6VkCky4lfpSf22qhGRy2gI2aj
# cLKCyfIQIo1/J3vsfbBLB8fKvLOneOdQqbpi0l6igR6TnSXd8X/cy84lkQiP6GJ2
# zZJ9iLvkfbqyzTg2IOfPWJGzAXxFJkO25lvHk+VdQTrWTwGy0VMiuorgWyVjr7sK
# ih/JX4x97FACpdC9uhC6fiMZZ1i7poAfvKYukRk2MhrtUU3O1OqlM2qPrKezRp2g
# RuwCJpW1nQ/ixY/D6lkoYOz3f3YI4KEutk1KcHlTQ+JE2Ch53Jkic5x/YWmVtbUk
# 2hlPkmyugZaLAxhWc2Wfpy7CLkNY90R8GRkO6dlFWg==
# SIG # End signature block
