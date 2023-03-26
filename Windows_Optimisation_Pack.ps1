$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack | $([char]0x00A9) Marvin700"
$hash = [hashtable]::Synchronized(@{}) 
IF (!(Test-Path $env:temp\Windows_Optimisation_Pack)){New-Item -Path $env:temp\Windows_Optimisation_Pack -ItemType Directory | Out-Null}
else {Get-ChildItem -Path $env:temp\Windows_Optimisation_Pack -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse | Out-Null}
$ScriptFolder = "$env:temp\Windows_Optimisation_Pack"
$InstalledSoftware = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*).DisplayName
$WindowsVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption

function WindowsTweaks_Services{
$services = @(
"WpcMonSvc",
"SharedRealitySvc",
"Fax",
"autotimesvc",
"wisvc",
"SDRSVC",
"MixedRealityOpenXRSvc",
"WalletService",
"SmsRouter",
"SharedAccess",
"MapsBroker",
"PhoneSvc",
"ScDeviceEnum",
"TabletInputService",
"icssvc",
"edgeupdatem",
"edgeupdate",
"MicrosoftEdgeElevationService",
"RetailDemo",
"MessagingService",
"PimIndexMaintenanceSvc",
"OneSyncSvc",
"UnistoreSvc",
"DiagTrack",
"dmwappushservice",
"diagnosticshub.standardcollector.service",
"diagsvc",
"WerSvc",
"wercplsupport")
foreach ($service in $services){
Stop-Service $service -ErrorAction SilentlyContinue
Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue}}

function WindowsTweaks_Registry{
# MarkC Mouse Acceleration Fix
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" ([byte[]](0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00,
0x00, 0x00, 0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" ([byte[]](0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type "DWORD" -Value 10 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type "DWORD" -Value 0 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseTrails" -Type "DWORD" -Value 0 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type "DWORD" -Value 0 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type "DWORD" -Value 00000005 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "NetworkThrottlingIndex" -Type "DWORD" -Value 268435455 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "SystemResponsiveness" -Type "DWORD" -Value 00000000 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type "DWORD" -Value 00000006 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force }
        
function WindowsTweaks_Tasks{
Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask -ErrorAction SilentlyContinue
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE 
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE }

function WindowsTweaks_Features{
$features = @(
"TFTP",
"TelnetClient",
"WCF-TCP-PortSharing45",
"Microsoft-Hyper-V-All",
"Microsoft-Hyper-V-Management-Clients",
"Microsoft-Hyper-V-Tools-All",
"Microsoft-Hyper-V-Management-PowerShell")
foreach ($feature in $features) {dism /Online /Disable-Feature /FeatureName:$feature /NoRestart}}
            
function WindowsTweaks_Index {
Label C: Windows
$drives = @('C:', 'D:', 'E:', 'F:', 'G:')
foreach ($drive in $drives) {Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$drive'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null}}
                
function SophiaScript{
Clear-Host
IF($WindowsVersion -match "Microsoft Windows 11"){
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.4.2/Sophia.Script.for.Windows.11.v6.4.2.zip" -Destination $env:temp\Sophia.zip
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination $ScriptFolder\Sophia_Script\
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/Beta/config/SophiaScript_Win11.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1" }
else { IF($WindowsVersion -match "Microsoft Windows 10") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.4.2/Sophia.Script.for.Windows.10.v5.16.2.zip" -Destination $env:temp\Sophia.zip
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination $ScriptFolder\Sophia_Script\
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/Beta/config/SophiaScript_Win10.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1" } }
Powershell.exe -executionpolicy Bypass $ScriptFolder\Sophia_Script\Sophia.ps1 }

function ooShutup{
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/Beta/config/ooshutup.cfg" -Destination "$ScriptFolder\ooshutup.cfg"
Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination $ScriptFolder\OOSU10.exe
Set-Location $ScriptFolder
.\OOSU10.exe ooshutup.cfg /quiet}

function SystemPoint{
Clear-Host
" Compatibility checks and preparation are performed ..."
if($hash.System_Maintance){vssadmin delete shadows /all /quiet | Out-Null}
Enable-ComputerRestore -Drive "C:\"
New-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type "DWORD" -Value 0 -Force | Out-Null
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /F | Out-Null }

function Checks{
IF(!($WindowsVersion -match "Microsoft Windows 11")) {
IF(!($WindowsVersion -match "Microsoft Windows 10")) {
Write-Warning " No supported operating system! Windows 10 or Windows 11 required"
Write-Warning " The script will be closed in 20 seconds"
Start-Sleep 20;exit}} 
IF(!(Test-Connection 1.1.1.1 -ErrorAction SilentlyContinue)){
Write-Warning " No internet connection available"
Write-Warning " The Script cant Apply all Tweaks !!!"
Start-Sleep 20}
IF((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){
Write-Warning " Reboot Pending !"
Write-Warning " The script will be closed in 20 seconds"
Start-Sleep 20;exit}
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
Write-Warning " No admin rights available"
Write-Warning " The script will be closed in 20 seconds"
Start-Sleep 20;exit}
Remove-Variable * -ErrorAction SilentlyContinue; Remove-Module *; $error.Clear()
New-Item "HKLM:\SOFTWARE\Windows_Optimisation_Pack\" -force | Out-Null
New-Item -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows_Optimisation_Pack -Force | Out-Null
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows_Optimisation_Pack -Name ShowInActionCenter -PropertyType DWord -Value 1 -Force | Out-Null
New-Item -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Windows_Optimisation_Pack -Force | Out-Null
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Windows_Optimisation_Pack -Name DisplayName -Value Windows_Optimisation_Pack -PropertyType String -Force | Out-Null
New-ItemProperty -Path Registry::HKEY_CLASSES_ROOT\AppUserModelId\Windows_Optimisation_Pack -Name ShowInSettings -Value 0 -PropertyType DWord -Force | Out-Null
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null}

function Autoruns{
Start-BitsTransfer -Source "https://download.sysinternals.com/files/Autoruns.zip" -Destination $env:temp\Autoruns.zip
Expand-Archive $env:temp\Autoruns.zip  $env:temp
Start-Process $env:temp\Autoruns64.exe }

function Windows_Cleaner{
$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack Windows_Cleaner | $([char]0x00A9) Marvin700"
Clear-Host
ipconfig /flushdns
$Key = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches
ForEach($result in $Key)
{If($result.name -eq "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder"){}Else{
$Regkey = 'HKLM:' + $result.Name.Substring( 18 )
New-ItemProperty -Path $Regkey -Name 'StateFlags0001' -Value 2 -PropertyType DWORD -Force -EA 0 | Out-Null}}
Clear-BCCache -Force -ErrorAction SilentlyContinue
$paths = @(
"$env:windir\..\MSOCache",
"$env:temp",
"$env:windir\Temp",
"$env:windir\Prefetch",
"$env:SystemRoot\SoftwareDistribution\Download",
"$env:ProgramData\Microsoft\Windows\RetailDemo",
"$env:LOCALAPPDATA\CrashDumps",
"$env:LOCALAPPDATA\NVIDIA\DXCache",
"$env:LOCALAPPDATA\NVIDIA\GLCache",
"$env:APPDATA\..\locallow\Intel\ShaderCache",
"$env:windir\..AMD",
"$env:LOCALAPPDATA\AMD",
"$env:APPDATA\..\locallow\AMD")
foreach ($path in $paths) {Get-ChildItem -Path $path -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse}
IF((Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\EscapeFromTarkov")){
IF(Get-Process EscapeFromTarkov.exe -ErrorAction SilentlyContinue){taskkill /F /IM EscapeFromTarkov.exe}
$EscapefromTarkov = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\EscapeFromTarkov' -Name 'InstallLocation').InstallLocation 
Get-ChildItem -Path $EscapefromTarkov\Logs -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
Get-ChildItem -Path $env:temp\"Battlestate Games" -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse}
IF((Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 1938090")){
IF(Get-Process cod.exe -ErrorAction SilentlyContinue){taskkill /F /IM cod.exe}
$CallofDutyMW2_Steam = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 1938090' -Name 'InstallLocation').InstallLocation 
Get-ChildItem -Path $CallofDutyMW2_Steam\shadercache -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse}
IF((Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Call of Duty")){
IF(Get-Process cod.exe -ErrorAction SilentlyContinue){taskkill /F /IM cod.exe}
$CallofDutyMW2_Battlenet = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Call of Duty' -Name 'InstallLocation').InstallLocation 
Get-ChildItem -Path $CallofDutyMW2_Battlenet\shadercache -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse}
Clear-Host
gpupdate.exe /force 
lodctr /r
lodctr /r}
function System_Maintance{
Clear-Host
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore /NoRestart
Dism.exe /Online /Cleanup-Image /spsuperseded /NoRestart
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart
Start-Process cleanmgr.exe /sagerun:1
Start-Process -FilePath "cmd.exe" -ArgumentList '/c title Windows_Optimisation_Pack && mode con cols=40 lines=12 && echo Background tasks are processed... && echo This Step can run up to 1 Hour && echo _ && echo You can go on with your stuff :) && %windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks'}

function Runtime{
winget source update | Out-Null
winget install --id=Microsoft.dotNetFramework --exact --accept-source-agreements 
IF(!($InstalledSoftware -Contains "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.34.31931")){winget install --id=Microsoft.VCRedist.2015+.x64 --exact --accept-source-agreements}
IF(!($InstalledSoftware -Contains "Microsoft Windows Desktop Runtime - 6.0.14 (x64)")){winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x64 --exact --accept-source-agreements}
IF(!($InstalledSoftware -Contains "Microsoft Windows Desktop Runtime - 7.0.3 (x64)")){winget install --id=Microsoft.DotNet.DesktopRuntime.7 --architecture x64 --exact --accept-source-agreements}
winget install --id=Microsoft.DirectX --exact --accept-source-agreements}

function Fan_Control{
Start-BitsTransfer -Source "https://github.com/Rem0o/FanControl.Releases/releases/download/V145/FanControl_net_7_0.zip" -Destination $env:temp\FanControl.zip 
Expand-Archive $env:temp\FanControl.zip "C:\Program Files\FanControl" -force
Remove-Item -Path $env:temp\FanControl.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\FanControl.lnk")
$Shortcut.TargetPath = "C:\Program Files\FanControl\FanControl.exe"
$Shortcut.Save() }
   
function Controller{
Start-BitsTransfer -Source "https://github.com/Ryochan7/DS4Windows/releases/download/v3.2.8/DS4Windows_3.2.8_x64.zip" -Destination "$env:temp\DS4Windows.zip "
Expand-Archive $env:temp\DS4Windows.zip "C:\Program Files\" -force
Remove-Item -Path $env:temp\DS4Windows.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Controller.lnk")
$Shortcut.TargetPath = "C:\Program Files\DS4Windows\DS4Windows.exe"
$Shortcut.Save() }
    
function Process_Lasso{
Start-BitsTransfer -Source "https://dl.bitsum.com/files/processlassosetup64.exe" -Destination $env:temp\ProcesslassoSetup64.exe
Start-Process -FilePath "$env:temp\ProcesslassoSetup64.exe" -ArgumentList "/S /language=German"}

function Remove_ASUS{
Start-BitsTransfer -Source "https://dlcdnets.asus.com/pub/ASUS/mb/14Utilities/UninstallAI3Tool_1.00.04.zip?model=ROG%20STRIX%20X570-E%20GAMING" -Destination "$env:temp\UninstallAI3Tool.zip"
Start-BitsTransfer -Source "https://dlcdnets.asus.com/pub/ASUS/mb/14Utilities/Armoury_Crate_Uninstall_Tool.zip?model=ROG%20STRIX%20X570-E%20GAMING" -Destination "$env:temp\Armoury_Crate_Uninstall_Tool.zip"
Expand-Archive $env:temp\UninstallAI3Tool.zip $env:temp -force
Expand-Archive $env:temp\Armoury_Crate_Uninstall_Tool.zip $env:temp -force
Start-Process $env:temp\UninstallAI3Tool*\RemoveAI3Files.exe
Start-Process $env:temp\"Armoury Crate Uninstall Tool *"\"Armoury Crate Uninstall Tool.exe" }

function Winrar{winget install --id=RARLab.WinRAR --exact --accept-source-agreements}

function Driver_Cleaner{
$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack GPU Driver-Cleaner | $([char]0x00A9) Marvin700" 
Start-BitsTransfer -Source "https://github.com/Marvin700/Windows_Optimisation_Pack/raw/main/DDU.zip" -Destination $env:temp\DDU.zip
Expand-Archive $env:temp\DDU.zip $env:temp
Set-Location $env:temp\DDU\
& '.\Display Driver Uninstaller.exe' -silent -removemonitors -cleannvidia -cleanamd -cleanintel -removephysx -removegfe -removenvbroadcast -removenvcp -removeintelcp -removeamdcp -restart
}

function Finish{
Set-ItemProperty -Path "HKLM:\SOFTWARE\Windows_Optimisation_Pack" -Name "Successful" -Type "DWORD" -Value 1 | Out-Null
[xml]$ToastTemplate = @"
<toast duration="Long">
<visual>
<binding template="ToastGeneric">
<text>The Optimisation is done :)</text>
</binding>
</visual>
<audio src="ms-winsoundevent:notification.default" />
</toast>
"@
$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
$ToastXml.LoadXml($ToastTemplate.OuterXml)
$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New($ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Windows_Optimisation_Pack").Show($ToastMessage)
if($hash.System_Maintance){System_Maintance}
if($hash.Driver_Cleaner){Driver_Cleaner}
exit}

function GUI{
Invoke-WebRequest 'https://user-images.githubusercontent.com/98750428/194409138-97880567-7645-4dc3-b031-74e2dae6da35.png' -OutFile $ScriptFolder\Picture.png
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
$hash.Cancel = $true
$handler_BUTTON_Start_Click={   
$hash.Cancel = $false
if ($BOX_Checks.Checked)                    {$hash.Checks = $true}
if ($BOX_SystemPoint.Checked)               {$hash.SystemPoint = $true} 
if ($BOX_Windows_Cleaner.Checked)           {$hash.Windows_Cleaner = $true} 
if ($BOX_SophiaScript.Checked)              {$hash.SophiaScript = $true}
if ($BOX_ooShutup.Checked)                  {$hash.ooShutup = $true}    
if ($BOX_WindowsTweaks_Registry.Checked)    {$hash.WindowsTweaks_Registry = $true}    
if ($BOX_WindowsTweaks_Tasks.Checked)       {$hash.WindowsTweaks_Tasks = $true}   
if ($BOX_WindowsTweaks_Features.Checked)    {$hash.WindowsTweaks_Features = $true}   
if ($BOX_WindowsTweaks_Services.Checked)    {$hash.WindowsTweaks_Services = $true}
if ($BOX_WindowsTweaks_Index.Checked)       {$hash.WindowsTweaks_Index = $true}
if ($BOX_System_Maintance.Checked)          {$hash.System_Maintance = $true}    
if ($BOX_Scheduled_Maintance.Checked)       {$hash.Scheduled_Maintance = $true}  
if ($BOX_Driver_Cleaner.Checked)      		{$hash.Driver_Cleaner = $true}  
if ($BOX_Runtime.Checked)      		        {$hash.Runtime = $true}   
if ($BOX_Remove_ASUS.Checked)               {$hash.Remove_ASUS = $true} 
if ($BOX_Autoruns.Checked)                  {$hash.Autoruns = $true} 
if ($BOX_Winrar.Checked)                    {$hash.Winrar = $true}    
if ($BOX_Fan_Control.Checked)               {$hash.Fan_Control = $true}  
if ($BOX_Process_Lasso.Checked)             {$hash.Process_Lasso = $true}     
if ($BOX_Controller.Checked)                {$hash.Controller = $true} 
$Form.Close()}
$form = New-Object System.Windows.Forms.Form
$form.Size = New-Object Drawing.Point 710,509
$form.text = "Windows_Optimisation_Pack | $([char]0x00A9) Marvin700"
$form.StartPosition = "CenterScreen" 
$form.ForeColor='#aaaaaa'
$form.BackColor='#212121'
$form.MinimizeBox = $false
$form.MaximizeBox = $false
$Image = new-object Windows.Forms.PictureBox
$img = [System.Drawing.Image]::Fromfile("$ScriptFolder\Picture.png")
$Image.Width = $img.Size.Width
$Image.Height = $img.Size.Height
$Image.Location=New-Object System.Drawing.Point(68,20)
$Image.Image = $img
$Titel_Essentials = New-Object Windows.Forms.Label
$Titel_Essentials.Size = New-Object Drawing.Point 135,25
$Titel_Essentials.Location = New-Object Drawing.Point 50,215
$Titel_Essentials.text = "Essentials"
$Titel_Essentials.ForeColor='#aaaaaa'
$Titel_Tweaks = New-Object Windows.Forms.Label
$Titel_Tweaks.Size = New-Object Drawing.Point 135,25
$Titel_Tweaks.Location = New-Object Drawing.Point 223,215
$Titel_Tweaks.text = "Tweaks"
$Titel_Tweaks.ForeColor='#aaaaaa'
$Titel_Extras = New-Object Windows.Forms.Label
$Titel_Extras.Size = New-Object Drawing.Point 135,25
$Titel_Extras.Location = New-Object Drawing.Point 393,215
$Titel_Extras.text = "Extras"
$Titel_Extras.ForeColor='#aaaaaa'
$Titel_Software = New-Object Windows.Forms.Label
$Titel_Software.Size = New-Object Drawing.Point 135,25
$Titel_Software.Location = New-Object Drawing.Point 566,215
$Titel_Software.text = "Software"
$Titel_Software.ForeColor='#aaaaaa'
$BOX_SystemPoint = New-Object System.Windows.Forms.CheckBox
$BOX_SystemPoint.Size = New-Object Drawing.Point 135,25
$BOX_SystemPoint.Location = New-Object Drawing.Point 27,248
$BOX_SystemPoint.Text = "Restore Point" 
$BOX_SystemPoint.ForeColor='#aaaaaa'
$BOX_SystemPoint.Checked = $true 
$BOX_SystemPoint.Enabled = $false 
$BOX_Checks = New-Object System.Windows.Forms.CheckBox
$BOX_Checks.Size = New-Object Drawing.Point 135,25
$BOX_Checks.Location = New-Object Drawing.Point 27,279
$BOX_Checks.Text = "Compability Checks"
$BOX_Checks.ForeColor='#aaaaaa'
$BOX_Checks.Checked = $true
$BOX_Checks.Enabled = $false 
$BOX_SophiaScript = New-Object System.Windows.Forms.CheckBox
$BOX_SophiaScript.Size = New-Object Drawing.Point 135,25
$BOX_SophiaScript.Location = New-Object Drawing.Point 27,310
$BOX_SophiaScript.Text = "Sophia Script" 
$BOX_SophiaScript.ForeColor='#aaaaaa'
$BOX_SophiaScript.Checked = $true 
$BOX_ooShutup = New-Object System.Windows.Forms.CheckBox
$BOX_ooShutup.Size = New-Object Drawing.Point 135,25
$BOX_ooShutup.Location = New-Object Drawing.Point 27,341
$BOX_ooShutup.Text = "O&O ShutUp"
$BOX_ooShutup.ForeColor='#aaaaaa'
$BOX_ooShutup.Checked = $true
$BOX_Windows_Cleaner = New-Object System.Windows.Forms.CheckBox
$BOX_Windows_Cleaner.Size = New-Object Drawing.Point 135,25
$BOX_Windows_Cleaner.Location = New-Object Drawing.Point 27,372
$BOX_Windows_Cleaner.Text = "Windows Cleaner" 
$BOX_Windows_Cleaner.ForeColor='#aaaaaa'
$BOX_Windows_Cleaner.Checked = $true 
$BOX_WindowsTweaks_Registry = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Registry.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Registry.Location = New-Object Drawing.Point 200,248
$BOX_WindowsTweaks_Registry.Text = "Registry Tweaks"
$BOX_WindowsTweaks_Registry.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Registry.Checked = $true
$BOX_WindowsTweaks_Tasks = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Tasks.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Tasks.Location = New-Object Drawing.Point 200,279
$BOX_WindowsTweaks_Tasks.Text = "Deaktivate Tasks"
$BOX_WindowsTweaks_Tasks.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Tasks.Checked = $true
$BOX_WindowsTweaks_Features = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Features.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Features.Location = New-Object Drawing.Point 200,310
$BOX_WindowsTweaks_Features.Text = "Disable Features"
$BOX_WindowsTweaks_Features.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Features.Checked = $true
$BOX_WindowsTweaks_Services = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Services.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Services.Location = New-Object Drawing.Point 200,341
$BOX_WindowsTweaks_Services.Text = "Disable Services"  
$BOX_WindowsTweaks_Services.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Services.Checked = $true  
$BOX_WindowsTweaks_Index = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Index.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Index.Location = New-Object Drawing.Point 200,372
$BOX_WindowsTweaks_Index.Text = "Disable Indexing"  
$BOX_WindowsTweaks_Index.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Index.Checked = $true  
$BOX_System_Maintance= New-Object System.Windows.Forms.CheckBox
$BOX_System_Maintance.Size = New-Object Drawing.Point 135,25
$BOX_System_Maintance.Location = New-Object Drawing.Point 373,248
$BOX_System_Maintance.Text = "System Maintance"
$BOX_System_Maintance.ForeColor='#aaaaaa'
$BOX_System_Maintance.Checked = $false
$BOX_Scheduled_Maintance = New-Object System.Windows.Forms.CheckBox
$BOX_Scheduled_Maintance.Size = New-Object Drawing.Point 135,25
$BOX_Scheduled_Maintance.Location = New-Object Drawing.Point 373,279
$BOX_Scheduled_Maintance.Text = "Scheduled Maintance" 
$BOX_Scheduled_Maintance.ForeColor='#aaaaaa'
$BOX_Scheduled_Maintance.Checked = $false
$BOX_Scheduled_Maintance.Enabled = $false 
$BOX_Driver_Cleaner= New-Object System.Windows.Forms.CheckBox
$BOX_Driver_Cleaner.Size = New-Object Drawing.Point 135,25
$BOX_Driver_Cleaner.Location = New-Object Drawing.Point 373,310
$BOX_Driver_Cleaner.Text = "Driver Cleaner"
$BOX_Driver_Cleaner.ForeColor='#aaaaaa'
$BOX_Driver_Cleaner.Checked = $false
$BOX_Runtime = New-Object System.Windows.Forms.CheckBox
$BOX_Runtime.Size = New-Object Drawing.Point 145,25
$BOX_Runtime.Location = New-Object Drawing.Point 373,341
$BOX_Runtime.Text = "Runtime Components"
$BOX_Runtime.ForeColor='#aaaaaa'
$BOX_Runtime.Checked = $true  
$BOX_Remove_ASUS = New-Object System.Windows.Forms.CheckBox
$BOX_Remove_ASUS.Size = New-Object Drawing.Point 135,25
$BOX_Remove_ASUS.Location = New-Object Drawing.Point 373,372
$BOX_Remove_ASUS.Text = "Remove Asus Bloat"
$BOX_Remove_ASUS.ForeColor='#aaaaaa'
$BOX_Remove_ASUS.Checked = $false
$BOX_Autoruns = New-Object System.Windows.Forms.CheckBox
$BOX_Autoruns.Size = New-Object Drawing.Point 135,25
$BOX_Autoruns.Location = New-Object Drawing.Point 546,248
$BOX_Autoruns.Text = "Autoruns" 
$BOX_Autoruns.ForeColor='#aaaaaa'
$BOX_Autoruns.Checked = $false
$BOX_Winrar = New-Object System.Windows.Forms.CheckBox
$BOX_Winrar.Size = New-Object Drawing.Point 135,25
$BOX_Winrar.Location = New-Object Drawing.Point 546,279
$BOX_Winrar.Text = "Winrar"
$BOX_Winrar.ForeColor='#aaaaaa'
$BOX_Winrar.Checked = $true
$BOX_Fan_Control = New-Object System.Windows.Forms.CheckBox
$BOX_Fan_Control.Size = New-Object Drawing.Point 135,25
$BOX_Fan_Control.Location = New-Object Drawing.Point 546,310
$BOX_Fan_Control.Text = "Fan Control"
$BOX_Fan_Control.ForeColor='#aaaaaa'
$BOX_Fan_Control.Checked = $false  
$BOX_Process_Lasso = New-Object System.Windows.Forms.CheckBox
$BOX_Process_Lasso.Size = New-Object Drawing.Point 135,25
$BOX_Process_Lasso.Location = New-Object Drawing.Point 546,341
$BOX_Process_Lasso.Text = "Process Lasso"
$BOX_Process_Lasso.ForeColor='#aaaaaa'
$BOX_Process_Lasso.Checked = $false  
$BOX_Controller = New-Object System.Windows.Forms.CheckBox
$BOX_Controller.Size = New-Object Drawing.Point 135,25
$BOX_Controller.Location = New-Object Drawing.Point 546,372
$BOX_Controller.Text =  "Controller Support"
$BOX_Controller.ForeColor='#aaaaaa'
$BOX_Controller.Checked = $false 
$Titel_Compability = New-Object Windows.Forms.Label
$Titel_Compability.Size = New-Object Drawing.Point 160,25
$Titel_Compability.Location = New-Object Drawing.Point 520,422
$Titel_Compability.ForeColor='#aaaaaa'
$BOX_Reboot = New-Object System.Windows.Forms.CheckBox
$BOX_Reboot.Size = New-Object Drawing.Point 135,25
$BOX_Reboot.Location = New-Object Drawing.Point 423,422
$BOX_Reboot.Text = "Reboot"
$BOX_Reboot.ForeColor='#aaaaaa'
$BOX_Reboot.Checked = $false
$BUTTON_Start = New-Object System.Windows.Forms.Button
$BUTTON_Start.Text = "Start"
$BUTTON_Start.Size = New-Object Drawing.Point 75,24
$BUTTON_Start.Location = New-Object Drawing.Point 225,422
$BUTTON_Start.ForeColor='#aaaaaa'
$BUTTON_Start.add_Click($handler_button_Start_Click)
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{$BUTTON_Start.Enabled = $false
$Titel_Compability.text = "NO ADMIN AVAILABLE" }
$BUTTON_Cancel = New-Object System.Windows.Forms.Button
$BUTTON_Cancel.Size = New-Object Drawing.Point 75,24
$BUTTON_Cancel.Location = New-Object Drawing.Point 320,422
$BUTTON_Cancel.ForeColor='#aaaaaa'
$BUTTON_Cancel.Text = "Cancel"
$BUTTON_Cancel.add_click{$hash.Cancel = $true; $Form.Close()}
$form.controls.add($Image)
$form.controls.add($Titel_Compability)
$form.controls.add($Titel_Essentials)
$form.controls.add($Titel_Tweaks)
$form.controls.add($Titel_Extras)
$form.controls.add($Titel_Software)
$form.Controls.Add($BOX_Checks)
$form.Controls.Add($BOX_SystemPoint)
$form.Controls.Add($BOX_SophiaScript)
$form.Controls.Add($BOX_ooShutup)
$form.Controls.Add($BOX_Windows_Cleaner)
$form.Controls.Add($BOX_WindowsTweaks_Registry)
$form.Controls.Add($BOX_WindowsTweaks_Tasks)
$form.Controls.Add($BOX_WindowsTweaks_Features)
$form.Controls.Add($BOX_WindowsTweaks_Services)
$form.Controls.Add($BOX_WindowsTweaks_Index)
$form.Controls.Add($BOX_System_Maintance)
$form.Controls.Add($BOX_Scheduled_Maintance)
$form.Controls.Add($BOX_Runtime)
$form.Controls.Add($BOX_Driver_Cleaner)
$form.Controls.Add($BOX_Remove_ASUS)
$form.Controls.Add($BOX_Autoruns)
$form.Controls.Add($BOX_Winrar)
$form.Controls.Add($BOX_Fan_Control)
$form.Controls.Add($BOX_Process_Lasso)
$form.Controls.Add($BOX_Controller)
$form.Controls.Add($BUTTON_Start)
$form.Controls.Add($BUTTON_Cancel)
$form.ShowDialog() } Out-Null

function Choice { 
if($hash.Cancel){exit}
if($hash.SystemPoint){SystemPoint}
if($hash.Checks){Checks}
if($hash.SophiaScript){SophiaScript}
if($hash.ooShutup){ooShutup}
if($hash.WindowsTweaks_Registry){WindowsTweaks_Registry}
if($hash.WindowsTweaks_Tasks){WindowsTweaks_Tasks} 
if($hash.WindowsTweaks_Features){WindowsTweaks_Features} 
if($hash.WindowsTweaks_Services){WindowsTweaks_Services}
if($hash.WindowsTweaks_Index){WindowsTweaks_Index}
if($hash.Runtime){Runtime}   
if($hash.Scheduled_Maintance){Scheduled_Maintance}
if($hash.Remove_ASUS){Remove_ASUS}
if($hash.Autoruns){Autoruns}    
if($hash.Winrar){Winrar}    
if($hash.Fan_Control){Fan_Control}
if($hash.Controller){Controller} 
if($hash.Process_Lasso){Process_Lasso}
if($hash.Windows_Cleaner){Windows_Cleaner}}

GUI
Choice
Finish

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUymPzgXtb3IsRrGMhEw7IqZ0
# 8qSgggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU7fgV5GPSAkzvX1S6zSGMxc4ic1kwDQYJ
# KoZIhvcNAQEBBQAEggEAm7uRntq7gmmy6euGRV19CsdwK0VKYMmE0uzYW4sLCgoa
# r6fZpcDU26Fd74SROl6zDw5DtGTmaqiosoHiRGrDs8LiepJpw0x1a/kQSdZBXJnK
# DeifA58C5+4gfCMRZUOA677dFOQviNwyhr51GKakDAHWzBJnErBENZo5+8BQKAcN
# CPoOfGzcVFxS2ErVpaEeq3aB5Fm4AjkzYuc5PCk1ZtSVgZ38Iqomcrsg5v+wN/9S
# Malg0mvTqlfdObX+/l0qlDnRzLB/EunSrOrI3F0ADegyfUlwzWAuZSm3zKAncY/j
# CMEwd2oaT8FbZQdYwMER3/xBvVUgTbcgNE6+wOLKgA==
# SIG # End signature block
