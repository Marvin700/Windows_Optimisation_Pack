# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

$Branch = "Beta"
$Version = "1.9.1"

$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack | $([char]0x00A9) Marvin700"
$hash = [hashtable]::Synchronized(@{})
$Administrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
$ScriptFolder = "$env:temp\Windows_Optimisation_Pack"
$WindowsVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$BuildNumber = (Get-CimInstance -Class CIM_OperatingSystem).BuildNumber
IF(Test-Connection https://github.com/Marvin700/Windows_Optimisation_Pack -Count 1 -ErrorAction SilentlyContinue){$InternetConnection = $True}else{$InternetConnection = $False}
IF(!(Test-Path $ScriptFolder)){New-Item -Path $ScriptFolder -ItemType Directory | Out-Null}
else{Get-ChildItem -Path $ScriptFolder -ErrorAction SilentlyContinue | Remove-Item -Recurse -exclude "Picture.png" | Out-Null}

function WindowsTweaks_Services{
$service = @("WpcMonSvc","SharedRealitySvc","Fax","autotimesvc","wisvc","SDRSVC","MixedRealityOpenXRSvc","WalletService","SmsRouter","SharedAccess","MapsBroker","PhoneSvc"
"ScDeviceEnum","TabletInputService","icssvc","edgeupdatem","edgeupdate","MicrosoftEdgeElevationService","RetailDemo","MessagingService","PimIndexMaintenanceSvc","OneSyncSvc"
"UnistoreSvc","DiagTrack","dmwappushservice","diagnosticshub.standardcollector.service","diagsvc","WerSvc","wercplsupport","SCardSvr","SEMgrSvc")
foreach($service in $service){
Stop-Service $service -ErrorAction SilentlyContinue
Set-Service $service -StartupType Disabled -ErrorAction SilentlyContinue}}

function WindowsTweaks_Features{
$features = @("TFTP","TelnetClient","WCF-TCP-PortSharing45","SmbDirect","MicrosoftWindowsPowerShellV2Root"
"Printing-XPSServices-Features","WorkFolders-Client","MSRDC-Infrastructure","MicrosoftWindowsPowerShellV2")
foreach($feature in $features){dism /Online /Disable-Feature /FeatureName:$feature /NoRestart}
$capability = @("App.StepsRecorder*","App.Support.QuickAssist*","Browser.InternetExplore*","Hello.Face*","MathRecognizer*","Microsoft.Windows.PowerShell.ISE*","OpenSSH*","Language.Handwriting")
foreach($capability in $capability){Get-WindowsCapability -online | where-object {$_.name -like $capability} | Remove-WindowsCapability -online -ErrorAction SilentlyContinue}}

function WindowsTweaks_Tasks{
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
$task = @("ProgramDataUpdater","Proxy","Consolidator","Microsoft-Windows-DiskDiagnosticDataCollector","MapsToastTask","MapsUpdateTask","FamilySafetyMonitor"
"FODCleanupTask","FamilySafetyRefreshTask","XblGameSaveTask","UsbCeip","DmClient","DmClientOnScenarioDownload")
foreach($task in $task){Get-ScheduledTask -TaskName $task | Disable-ScheduledTask -ErrorAction SilentlyContinue}}

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
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type "DWORD" -Value 10 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseTrails" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type "DWORD" -Value 00000005 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "NetworkThrottlingIndex" -Type "DWORD" -Value 268435455 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "SystemResponsiveness" -Type "DWORD" -Value 00000000 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type "DWORD" -Value 00000006 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force
ForEach($result in Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"){
If(!($result.name -eq "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder")){
New-ItemProperty -Path "'HKLM:' + $result.Name.Substring( 18 )" -Name 'StateFlags0001' -Value 2 -PropertyType DWORD -Force -EA 0}}}
            
function WindowsTweaks_Index{
Label $env:SystemDrive Windows
$drives = Get-WmiObject Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
foreach($drive in $drives) {Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$drive'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False}}}
                
function SophiaScript{
$LatestGitHubRelease = (Invoke-RestMethod "https://api.github.com/repos/farag2/Sophia-Script-for-Windows/releases/latest").tag_name
IF($WindowsVersion -match "Microsoft Windows 11"){
$LatestRelease = (Invoke-RestMethod "https://raw.githubusercontent.com/farag2/Sophia-Script-for-Windows/master/sophia_script_versions.json").Sophia_Script_Windows_11_PowerShell_5_1
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/$LatestGitHubRelease/Sophia.Script.for.Windows.11.v$LatestRelease.zip" -Destination "$env:temp\Sophia.zip"
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination "$ScriptFolder\Sophia_Script\"
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/$Branch/config/SophiaScript_Win11.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1"}
IF($WindowsVersion -match "Microsoft Windows 10"){
$LatestRelease = (Invoke-RestMethod "https://raw.githubusercontent.com/farag2/Sophia-Script-for-Windows/master/sophia_script_versions.json").Sophia_Script_Windows_10_PowerShell_5_1
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/$LatestGitHubRelease/Sophia.Script.for.Windows.10.v$LatestRelease.zip" -Destination "$env:temp\Sophia.zip"
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination "$ScriptFolder\Sophia_Script\"
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/$Branch/config/SophiaScript_Win10.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1"}
Move-Item -Path $env:temp\"Sophia_Script*" -Destination "$ScriptFolder\Sophia_Script\"
Powershell.exe -executionpolicy Bypass $ScriptFolder\Sophia_Script\Sophia.ps1}

function ooShutup{
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/$Branch/config/ooshutup.cfg" -Destination "$ScriptFolder\ooshutup.cfg"
Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination "$ScriptFolder\OOSU10.exe"
Start-Process powershell "Set-Location $ScriptFolder;.\OOSU10.exe ooshutup.cfg /quiet"}

function SystemPoint{
IF($hash.Windows_Cleanup){vssadmin delete shadows /all /quiet | Out-Null}
Enable-ComputerRestore -Drive $env:SystemDrive
New-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type "DWORD" -Value 0 -Force | Out-Null
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" | Out-Null}

function Checks{
 " Compatibility checks and preparations are performed..."
IF(!([System.Environment]::Is64BitOperatingSystem)){
Write-Warning " You need an 64-Bit System"
Start-Sleep 20;exit}
IF(!($WindowsVersion -match "Microsoft Windows 11" -Or $WindowsVersion -match "Microsoft Windows 10")){
Write-Warning " No supported operating system! Windows 10 or Windows 11 required"
Start-Sleep 20;exit}
IF(!(Test-Connection 1.1.1.1 -ErrorAction SilentlyContinue)){
Write-Warning " No internet connection available"
Start-Sleep 20}
IF((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){
Write-Warning " Reboot Pending !"
Start-Sleep 20;exit}
IF(!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
Write-Warning " PowerShell is not started as an Administrator"
Start-Sleep 20;exit}}

function Preperations{
New-PSDrive -Name "HKCR" -PSProvider Registry -Root "HKEY_CLASSES_ROOT" | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Windows_Optimisation_Pack\" -Force | Out-Null
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows_Optimisation_Pack" -Force | Out-Null
New-Item -Path "HKCR:\AppUserModelId\Windows_Optimisation_Pack" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Windows_Optimisation_Pack" -Name "Version" -Type "STRING" -Value $Version -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows_Optimisation_Pack" -Name "ShowInActionCenter" -Type "DWORD" -Value 1 -Force | Out-Null
Set-ItemProperty -Path "HKCR:\AppUserModelId\Windows_Optimisation_Pack" -Name "DisplayName" -Value "Windows_Optimisation_Pack" -Type "STRING" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\AppUserModelId\Windows_Optimisation_Pack" -Name "ShowInSettings" -Value 0 -Type "STRING" -Force | Out-Null
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null}

function Windows_Cleanup{
Clear-Host
ipconfig /flushdns
Clear-BCCache -Force -ErrorAction SilentlyContinue
$path = @("$env:windir\..\MSOCache\","$env:windir\Prefetch\","$env:SystemRoot\SoftwareDistribution\Download\","$env:ProgramData\Microsoft\Windows\RetailDemo\","$env:LOCALAPPDATA\CrashDumps\","$env:windir\Temp\","$env:temp\"
"$env:LOCALAPPDATA\NVIDIA\DXCache\","$env:LOCALAPPDATA\NVIDIA\GLCache\","$env:APPDATA\..\locallow\Intel\ShaderCache\","$env:SystemDrive\AMD\","$env:LOCALAPPDATA\AMD\","$env:APPDATA\..\locallow\AMD\","C:\ProgramData\Package Cache")
foreach($path in $path){Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Remove-Item -Recurse}
IF((Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\EscapeFromTarkov")){
$EscapefromTarkov = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\EscapeFromTarkov' -Name 'InstallLocation').InstallLocation 
IF(Get-Process EscapeFromTarkov.exe -ErrorAction SilentlyContinue){taskkill /F /IM EscapeFromTarkov.exe}
Get-ChildItem -Path $EscapefromTarkov\Logs -ErrorAction SilentlyContinue | Remove-Item -Recurse
Get-ChildItem -Path $env:temp\"Battlestate Games" -ErrorAction SilentlyContinue | Remove-Item -Recurse}
IF((Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 1938090")){
$CallofDutyMW2_Steam = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 1938090' -Name 'InstallLocation').InstallLocation     
IF(Get-Process cod.exe -ErrorAction SilentlyContinue){taskkill /F /IM cod.exe};Get-ChildItem -Path $CallofDutyMW2_Steam\_retail_\shadercache -ErrorAction SilentlyContinue | Remove-Item -Recurse}
IF((Test-Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Call of Duty")){
$CallofDutyMW2_Battlenet = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Call of Duty' -Name 'InstallLocation').InstallLocation 
IF(Get-Process cod.exe -ErrorAction SilentlyContinue){taskkill /F /IM cod.exe};Get-ChildItem -Path $CallofDutyMW2_Battlenet\_retail_\shadercache -ErrorAction SilentlyContinue | Remove-Item -Recurse}
Clear-Host
gpupdate.exe /force 
lodctr /r;lodctr /r
Clear-Host
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore /NoRestart
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart
Dism.exe /Online /Cleanup-Image /spsuperseded /NoRestart
Start-Process cleanmgr.exe /sagerun:1
Start-Process -FilePath "cmd.exe" -ArgumentList '/c title Windows_Optimisation_Pack && mode con cols=40 lines=12 && echo Background tasks are processed... && echo This Step can run up to 1 Hour && echo _ && echo You can continue with your stuff :) && %windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks'}

function Driver_Cleaner{
Clear-Host
IF((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){Write-Warning " Reboot Pending ! You can Reinstall GPU Driver after PC Restart";Start-Sleep 10}else{
Start-BitsTransfer -Source "https://github.com/Marvin700/Windows_Optimisation_Pack/raw/$Branch/config/DDU.zip" -Destination "$env:temp\DDU.zip"
Expand-Archive $env:temp\DDU.zip $env:temp
cmd.exe /c "bcdedit /set {current} safeboot minimal"
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Normal_Boot" -Value 'cmd.exe /c "bcdedit /deletevalue {current} safeboot"'
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Driver_Cleaner" -Value 'Powershell.exe -command "Set-Location $env:temp\DDU\;& .\DisplayDriverUninstaller.exe -silent -removemonitors -removephysx -removegfe -removenvbroadcast -cleanallgpus -removenvcp -removeintelcp -removeamdcp -removeamddirs -restart"'
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*!Uninstall_Message" -Value "c:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -command 'Driver is Unnstalling. Please Wait...'"
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms");[System.Windows.Forms.MessageBox]::Show("For Driver Reinstallation restart the PC","Windows_Optimisation_Pack",0,[System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null}}

function Runtime{
winget source update | Out-Null
winget install --id=Microsoft.VCRedist.2015+.x64 --exact --accept-source-agreements
winget install dotnet-runtime-6 --exact --accept-source-agreements
winget install dotnet-runtime-7 --exact --accept-source-agreements
winget install dotnet-runtime-8 --exact --accept-source-agreements
winget install --id=Microsoft.DirectX --exact --accept-source-agreements}

function Remove_ASUS{
Start-BitsTransfer -Source "https://dlcdnets.asus.com/pub/ASUS/mb/14Utilities/Armoury_Crate_Uninstall_Tool.zip?model=Armoury%20Crate" -Destination "$env:temp\Armoury_Crate_Uninstall_Tool.zip"
Expand-Archive "$env:temp\Armoury_Crate_Uninstall_Tool.zip" "$env:temp" -Force
Start-Process $env:temp\"Armoury Crate Uninstall Tool *"\"Armoury Crate Uninstall Tool.exe"}

function Fan_Control{
IF(Get-WmiObject -Class win32_systemenclosure | Where-Object { $_.chassistypes -eq 8 -or $_.chassistypes -eq 9 -or $_.chassistypes -eq 10 -or $_.chassistypes -eq 14 -or $_.chassistypes -eq 30}){
Start-BitsTransfer -Source "https://github.com/hirschmann/nbfc/releases/download/1.6.3/NoteBookFanControl.1.6.3.setup.exe" -Destination "$env:temp\NoteBookFanControl.exe"
Start-Process "$env:temp\NoteBookFanControl.exe"} 
else { Start-BitsTransfer -Source "https://github.com/Rem0o/FanControl.Releases/releases/download/V181/FanControl_181__8_0_Installer.exe" -Destination "$env:temp\FanControl.exe"
Start-Process "$env:temp\FanControl.exe"}}
   
function Controller{
Start-BitsTransfer -Source "https://github.com/Ryochan7/DS4Windows/releases/download/v3.3.3/DS4Windows_3.3.3_x64.zip" -Destination "$env:temp\DS4Windows.zip"
Expand-Archive $env:temp\DS4Windows.zip "$env:SystemDrive\Program Files\" -Force
Remove-Item -Path $env:temp\DS4Windows.zip -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Controller.lnk")
$Shortcut.TargetPath = "$env:SystemDrive\Program Files\DS4Windows\DS4Windows.exe"
$Shortcut.Save()}

function Autoruns{
Start-BitsTransfer -Source "https://download.sysinternals.com/files/Autoruns.zip" -Destination "$env:temp\Autoruns.zip"
Expand-Archive $env:temp\Autoruns.zip  $env:temp
Start-Process $env:temp\Autoruns64.exe}

function Google_Chrome{winget install --id=Google.Chrome --exact --accept-source-agreements}

function Winrar{winget install --id=RARLab.WinRAR --exact --accept-source-agreements}

function Finish{
Set-ItemProperty -Path "HKLM:\SOFTWARE\Windows_Optimisation_Pack" -Name "Successful" -Type "DWORD" -Value 1 | Out-Null
[xml]$ToastTemplate = @"
<toast duration="Long"><visual><binding template="ToastGeneric">
<text>Your Windows is now optimised :)</text></binding></visual>
<audio src="ms-winsoundevent:notification.default" /></toast>
"@
$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
$ToastXml.LoadXml($ToastTemplate.OuterXml)
$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New($ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Windows_Optimisation_Pack").Show($ToastMessage)
exit}

function GUI{
IF(!(Test-Path $ScriptFolder\Picture.png)){Invoke-WebRequest "https://user-images.githubusercontent.com/98750428/232198728-be7449b4-1d64-4f83-9fb1-2337af52b0c2.png" -OutFile "$ScriptFolder\Picture.png"}
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
$hash.Exit = $true
$handler_BUTTON_Start_Click=
{
$hash.Exit = $false
IF($BOX_Checks.Checked)                 {$hash.Checks = $true}
IF($BOX_SystemPoint.Checked)            {$hash.SystemPoint = $true}
IF($BOX_Windows_Cleanup.Checked)        {$hash.Windows_Cleanup = $true} 
IF($BOX_SophiaScript.Checked)           {$hash.SophiaScript = $true}
IF($BOX_ooShutup.Checked)               {$hash.ooShutup = $true}    
IF($BOX_WindowsTweaks_Registry.Checked) {$hash.WindowsTweaks_Registry = $true}    
IF($BOX_WindowsTweaks_Tasks.Checked)    {$hash.WindowsTweaks_Tasks = $true}   
IF($BOX_WindowsTweaks_Features.Checked) {$hash.WindowsTweaks_Features = $true}   
IF($BOX_WindowsTweaks_Services.Checked) {$hash.WindowsTweaks_Services = $true}
IF($BOX_WindowsTweaks_Index.Checked)    {$hash.WindowsTweaks_Index = $true}
IF($BOX_Scheduled_Maintance.Checked)    {$hash.Scheduled_Maintance = $true}  
IF($BOX_Driver_Cleaner.Checked)         {$hash.Driver_Cleaner = $true}  
IF($BOX_Runtime.Checked)                {$hash.Runtime = $true}   
IF($BOX_Remove_ASUS.Checked)            {$hash.Remove_ASUS = $true} 
if($BOX_Autoruns.Checked)               {$hash.Autoruns = $true} 
IF($BOX_Winrar.Checked)                 {$hash.Winrar = $true}    
IF($BOX_Fan_Control.Checked)            {$hash.Fan_Control = $true}  
IF($BOX_Google_Chrome.Checked)          {$hash.Google_Chrome = $true}     
IF($BOX_Controller.Checked)             {$hash.Controller = $true} 
$Form.Close()
}
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
$Titel_Compability = New-Object Windows.Forms.Label
$Titel_Compability.Size = New-Object Drawing.Point 300,25
$Titel_Compability.Location = New-Object Drawing.Point 500,422
$Titel_Compability.ForeColor='#e8272f'

##Choice
$Text_Info = New-Object Windows.Forms.Label
$Text_Info.Size = New-Object Drawing.Point 150,150
$Text_Info.Location = New-Object Drawing.Point 150,215
$Text_Info.ForeColor='#aaaaaa'
$Text_Info.text = "
Version $Version

$WindowsVersion
Build $BuildNumber 

Administrator Permission
$Administrator

Github Connection
$InternetConnection
"
$BUTTON_Optimise = New-Object System.Windows.Forms.Button
$BUTTON_Optimise.Text = "Optimise Windows"
$BUTTON_Optimise.Size = New-Object Drawing.Point 169,54
$BUTTON_Optimise.Location = New-Object Drawing.Point 370,220
$BUTTON_Optimise.ForeColor='#aaaaaa'
$BUTTON_Optimise.add_Click{GUI_Optimise}
$BUTTON_Maintance = New-Object System.Windows.Forms.Button
$BUTTON_Maintance.Text = "Maintance Windows"
$BUTTON_Maintance.Size = New-Object Drawing.Point 169,54
$BUTTON_Maintance.Location = New-Object Drawing.Point 370,300
$BUTTON_Maintance.ForeColor='#aaaaaa'
$BUTTON_Maintance.Enabled = $false
$BUTTON_Maintance.add_Click{GUI_Maintance}
$BUTTON_Exit = New-Object System.Windows.Forms.Button
$BUTTON_Exit.Size = New-Object Drawing.Point 113,36
$BUTTON_Exit.Location = New-Object Drawing.Point 270,410
$BUTTON_Exit.ForeColor='#aaaaaa'
$BUTTON_Exit.Text = "Exit"
$BUTTON_Exit.add_Click{$hash.Exit = $true; $Form.Close()}

##Optimisation
IF(!($Administrator -eq "True")){$Titel_Compability.text = "PowerShell is not Administrator"}
$Titel_Essentials = New-Object Windows.Forms.Label
$Titel_Essentials.Size = New-Object Drawing.Point 135,25
$Titel_Essentials.Location = New-Object Drawing.Point 50,215
$Titel_Essentials.text = "Essentials"
$Titel_Essentials.ForeColor='#aaaaaa'
$Titel_Tweaks = New-Object Windows.Forms.Label
$Titel_Tweaks.Size = New-Object Drawing.Point 135,25
$Titel_Tweaks.Location = New-Object Drawing.Point 210,215
$Titel_Tweaks.text = "Advaced Tweaks"
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
$BOX_ooShutup.Text = "OO ShutUp10"
$BOX_ooShutup.ForeColor='#aaaaaa'
$BOX_ooShutup.Checked = $true
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
$BOX_WindowsTweaks_Features.Checked = $false
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
$BOX_Windows_Cleanup = New-Object System.Windows.Forms.CheckBox
$BOX_Windows_Cleanup.Size = New-Object Drawing.Point 135,25
$BOX_Windows_Cleanup.Location = New-Object Drawing.Point 373,248
$BOX_Windows_Cleanup.Text = "Windows Cleanup" 
$BOX_Windows_Cleanup.ForeColor='#aaaaaa'
$BOX_Windows_Cleanup.Checked = $true 
$BOX_Runtime = New-Object System.Windows.Forms.CheckBox
$BOX_Runtime.Size = New-Object Drawing.Point 145,25
$BOX_Runtime.Location = New-Object Drawing.Point 373,279
$BOX_Runtime.Text = "Runtime Components"
$BOX_Runtime.ForeColor='#aaaaaa'
$BOX_Runtime.Checked = $true  
$BOX_Remove_ASUS = New-Object System.Windows.Forms.CheckBox
$BOX_Remove_ASUS.Size = New-Object Drawing.Point 135,25
$BOX_Remove_ASUS.Location = New-Object Drawing.Point 373,310
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
$BOX_Winrar.Checked = $false
$BOX_Fan_Control = New-Object System.Windows.Forms.CheckBox
$BOX_Fan_Control.Size = New-Object Drawing.Point 135,25
$BOX_Fan_Control.Location = New-Object Drawing.Point 546,310
$BOX_Fan_Control.Text = "Fan Control"
$BOX_Fan_Control.ForeColor='#aaaaaa'
$BOX_Fan_Control.Checked = $false  
$BOX_Google_Chrome = New-Object System.Windows.Forms.CheckBox
$BOX_Google_Chrome.Size = New-Object Drawing.Point 135,25
$BOX_Google_Chrome.Location = New-Object Drawing.Point 546,341
$BOX_Google_Chrome.Text = "Google Chrome"
$BOX_Google_Chrome.ForeColor='#aaaaaa'
$BOX_Google_Chrome.Checked = $false  
$BOX_Controller = New-Object System.Windows.Forms.CheckBox
$BOX_Controller.Size = New-Object Drawing.Point 135,25
$BOX_Controller.Location = New-Object Drawing.Point 546,372
$BOX_Controller.Text =  "Controller Support"
$BOX_Controller.ForeColor='#aaaaaa'
$BOX_Controller.Checked = $false 
$BUTTON_Start = New-Object System.Windows.Forms.Button
$BUTTON_Start.Text = "Start"
$BUTTON_Start.Size = New-Object Drawing.Point 75,24
$BUTTON_Start.Location = New-Object Drawing.Point 265,422
$BUTTON_Start.ForeColor='#aaaaaa'
$BUTTON_Start.add_Click($handler_button_Start_Click)
IF(!($Administrator -eq "True")){$BUTTON_Start.Enabled = $false}
$BUTTON_Cancel = New-Object System.Windows.Forms.Button
$BUTTON_Cancel.Size = New-Object Drawing.Point 75,24
$BUTTON_Cancel.Location = New-Object Drawing.Point 360,422
$BUTTON_Cancel.ForeColor='#aaaaaa'
$BUTTON_Cancel.Text = "Cancel"
$BUTTON_Cancel.add_Click{GUI_Choice}


function GUI_Choice
{
$form.Controls.Clear()
$form.controls.add($Image)
$form.controls.add($Text_Info)
$form.controls.add($Titel_Compability)
$form.Controls.add($BUTTON_Optimise)
$form.Controls.add($BUTTON_Maintance)
$form.Controls.add($BUTTON_Exit)
}

function GUI_Optimise
{
    $form.Controls.Clear()
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
    $form.Controls.Add($BOX_WindowsTweaks_Registry)
    $form.Controls.Add($BOX_WindowsTweaks_Tasks)
    $form.Controls.Add($BOX_WindowsTweaks_Features)
    $form.Controls.Add($BOX_WindowsTweaks_Services)
    $form.Controls.Add($BOX_WindowsTweaks_Index)
    $form.Controls.Add($BOX_Windows_Cleanup)
    $form.Controls.Add($BOX_Runtime)
    $form.Controls.Add($BOX_Remove_ASUS)
    $form.Controls.Add($BOX_Autoruns)
    $form.Controls.Add($BOX_Winrar)
    $form.Controls.Add($BOX_Fan_Control)
    $form.Controls.Add($BOX_Google_Chrome)
    $form.Controls.Add($BOX_Controller)
    $form.Controls.Add($BUTTON_Start)
    $form.Controls.Add($BUTTON_Cancel)
}

GUI_Choice
$form.ShowDialog() | Out-Null }


function Choice{ 
IF($hash.Exit){exit}
IF($hash.SystemPoint){SystemPoint}
IF($hash.Checks){Checks}
IF($hash.Checks){Preperations}
IF($hash.SophiaScript){SophiaScript}
IF($hash.ooShutup){ooShutup}
IF($hash.WindowsTweaks_Services){WindowsTweaks_Services}
IF($hash.WindowsTweaks_Tasks){WindowsTweaks_Tasks} 
IF($hash.WindowsTweaks_Registry){WindowsTweaks_Registry}
IF($hash.WindowsTweaks_Features){WindowsTweaks_Features}
IF($hash.WindowsTweaks_Index){WindowsTweaks_Index}
IF($hash.Scheduled_Maintance){Scheduled_Maintance}
IF($hash.Runtime){Runtime}   
IF($hash.Autoruns){Autoruns}   
IF($hash.Winrar){Winrar} 
IF($hash.Fan_Control){Fan_Control}
IF($hash.Controller){Controller} 
IF($hash.Google_Chrome){Google_Chrome}
IF($hash.Remove_ASUS){Remove_ASUS}
IF($hash.Windows_Cleanup){Windows_Cleanup}
IF($hash.Driver_Cleaner){Driver_Cleaner}}

GUI
Choice
Finish