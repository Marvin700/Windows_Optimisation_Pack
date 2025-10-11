# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

### Version ###
$Branch = "Beta"
$Version = "2.0"

### Title ###
$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack | $([char]0x00A9) Marvin700"
$ScriptFolder = "$env:temp\Windows_Optimisation_Pack"

### Functions ###
$hash = [hashtable]::Synchronized(@{})

function SystemPoint{
# Delete all previous restore points when the function is activated
IF($hash.Extended_Cleanup){vssadmin delete shadows /all /quiet | Out-Null}
# Temporarily modify to create a restore point.
Enable-ComputerRestore -Drive $env:SystemDrive
New-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" -Type "DWORD" -Value 0 -Force | Out-Null
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" -Name "SystemRestorePointCreationFrequency" | Out-Null}

function Checks_and_Preperations{
# Checks to Run Script
Clear-Host
 " Compatibility checks and preparation are performed..."
$WindowsVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
IF(!($WindowsVersion -like "Microsoft Windows 11*" -Or $WindowsVersion -like "Microsoft Windows 10*")){
Write-Warning " No supported operating system! Windows 10 or Windows 11 required"
Start-Sleep 20;exit}
IF((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){
Write-Warning " Reboot Pending !"
Start-Sleep 20;exit}
#Regkey for Script
New-Item -Path "HKLM:\SOFTWARE\Windows_Optimisation_Pack\" -Force | Out-Null}

### Menu: Optimise Windows ###

function WindowsTweaks_Services{
# Disable unnecessary tasks
$services = @("WpcMonSvc","SharedRealitySvc","Fax","autotimesvc","wisvc","SDRSVC","MixedRealityOpenXRSvc","WalletService","SmsRouter","SharedAccess","MapsBroker","PhoneSvc"
"ScDeviceEnum","TabletInputService","icssvc","edgeupdatem","edgeupdate","MicrosoftEdgeElevationService","RetailDemo","MessagingService","PimIndexMaintenanceSvc","OneSyncSvc"
"UnistoreSvc","DiagTrack","dmwappushservice","diagnosticshub.standardcollector.service","diagsvc","WerSvc","wercplsupport","SCardSvr","SEMgrSvc")
$services | ForEach-Object {
Stop-Service $_ -ErrorAction SilentlyContinue
Set-Service $_ -StartupType Disabled -ErrorAction SilentlyContinue}}

function WindowsTweaks_Features{
# Disable unnecessary Features
$features = @("TFTP","TelnetClient","WCF-TCP-PortSharing45","SmbDirect","MicrosoftWindowsPowerShellV2Root","Recall"
"Printing-XPSServices-Features","WorkFolders-Client","MSRDC-Infrastructure","MicrosoftWindowsPowerShellV2")
$features | ForEach-Object {dism /Online /Disable-Feature /FeatureName:$_ /NoRestart}

# Disable unnecessary Features
$capability = @("App.StepsRecorder*","App.Support.QuickAssist*","Browser.InternetExplore*","Hello.Face*","MathRecognizer*","Microsoft.Windows.PowerShell.ISE*","OpenSSH*","Language.Handwriting")
foreach($capability in $capability){Get-WindowsCapability -online | where-object {$_.name -like $capability} | Remove-WindowsCapability -online -ErrorAction SilentlyContinue}}

function WindowsTweaks_Tasks{
# Disable unnecessary Tasks
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
$tasks = @("ProgramDataUpdater","Proxy","Consolidator","Microsoft-Windows-DiskDiagnosticDataCollector","MapsToastTask","MapsUpdateTask","FamilySafetyMonitor"
"FODCleanupTask","FamilySafetyRefreshTask","XblGameSaveTask","UsbCeip","DmClient","DmClientOnScenarioDownload")
$tasks | ForEach-Object {Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue}}

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

# Disable Windows Telemetry
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force

# Gaming Tweaks
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type "DWORD" -Value 00000005 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "NetworkThrottlingIndex" -Type "DWORD" -Value 268435455 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\" -Name "SystemResponsiveness" -Type "DWORD" -Value 00000000 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Type "DWORD" -Value 00000006 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Force}
            
function WindowsTweaks_Index{
# Disable Windows Indexing
Label $env:SystemDrive Windows
$drives = Get-WmiObject Win32_LogicalDisk | Select-Object -ExpandProperty DeviceID
$drives | ForEach-Object{Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$_'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False}}}

function SophiaScript{
# Download Sophia Script Windows 10
$LatestGitHubRelease = (Invoke-RestMethod "https://api.github.com/repos/farag2/Sophia-Script-for-Windows/releases/latest").tag_name
IF($WindowsVersion -match "Microsoft Windows 11"){
$LatestRelease = (Invoke-RestMethod "https://raw.githubusercontent.com/farag2/Sophia-Script-for-Windows/master/sophia_script_versions.json").Sophia_Script_Windows_11_PowerShell_5_1
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/$LatestGitHubRelease/Sophia.Script.for.Windows.11.v$LatestRelease.zip" -Destination "$env:temp\Sophia.zip"
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination "$ScriptFolder\Sophia_Script\"
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/$Branch/config/SophiaScript_Win11.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1"}
# Download Sophia Script Windows 11
IF($WindowsVersion -match "Microsoft Windows 10"){
$LatestRelease = (Invoke-RestMethod "https://raw.githubusercontent.com/farag2/Sophia-Script-for-Windows/master/sophia_script_versions.json").Sophia_Script_Windows_10_PowerShell_5_1
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/$LatestGitHubRelease/Sophia.Script.for.Windows.10.v$LatestRelease.zip" -Destination "$env:temp\Sophia.zip"
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination "$ScriptFolder\Sophia_Script\"
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/$Branch/config/SophiaScript_Win10.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1"}
# Start Sophia Script
Powershell.exe -executionpolicy Bypass $ScriptFolder\Sophia_Script\Sophia.ps1}

function ooShutup{
# O&O ShutUp10++
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/$Branch/config/ooshutup.cfg" -Destination "$ScriptFolder\ooshutup.cfg"
Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination "$ScriptFolder\OOSU10.exe"
Start-Process powershell "Set-Location $ScriptFolder;.\OOSU10.exe ooshutup.cfg /quiet" -WindowStyle Hidden}

function Clear_Cache{
Clear-Host
Write-Output "Removing Cache Files..."
# Clear DNS Cache
ipconfig /flushdns > $null
Clear-BCCache -Force -ErrorAction SilentlyContinue
# Clear Multiple Cache Foleder
$path = @("$env:windir\..\MSOCache\","$env:windir\Prefetch\","$env:SystemRoot\SoftwareDistribution\Download\","$env:ProgramData\Microsoft\Windows\RetailDemo\","$env:LOCALAPPDATA\CrashDumps\","$env:windir\Temp\","$env:temp\"
"$env:LOCALAPPDATA\NVIDIA\DXCache\","$env:LOCALAPPDATA\NVIDIA\GLCache\","$env:APPDATA\..\locallow\Intel\ShaderCache\","$env:SystemDrive\AMD\","$env:LOCALAPPDATA\AMD\","$env:APPDATA\..\locallow\AMD\","C:\ProgramData\Package Cache")
foreach($path in $path){Get-ChildItem -Path $path -ErrorAction SilentlyContinue | Remove-Item -Recurse -ErrorAction SilentlyContinue}
# Rebuild Performance Couters
lodctr /r}

function Extended_Cleanup{
# Cleanup Windows Components
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore /NoRestart
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /NoRestart
Dism.exe /Online /Cleanup-Image /spsuperseded /NoRestart
# Maximizes Disk Cleanup settings
ForEach($result in Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"){
If(!($result.name -eq "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder")){
New-ItemProperty -Path "'HKLM:' + $result.Name.Substring( 18 )" -Name 'StateFlags0001' -Value 2 -PropertyType DWORD -Force -EA 0}}
Start-Process cleanmgr.exe /sagerun:1}

function Idle_Tasks{
Start-Process -FilePath "cmd.exe" -ArgumentList '/c title Windows_Optimisation_Pack && mode con cols=40 lines=12 && echo Background tasks are processed... && echo This Step can run up to 1 Hour && echo _ && echo You can continue with your stuff :) && %windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks'}

function Finish{
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\" -Name "RebootPending" -Value 1
# Reg Entry for Toast
New-PSDrive -Name "HKCR" -PSProvider Registry -Root "HKEY_CLASSES_ROOT" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Windows_Optimisation_Pack" -Name "Version" -Type "STRING" -Value $Version -Force | Out-Null
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows_Optimisation_Pack" -Force | Out-Null
New-Item -Path "HKCR:\AppUserModelId\Windows_Optimisation_Pack" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows_Optimisation_Pack" -Name "ShowInActionCenter" -Type "DWORD" -Value 1 -Force | Out-Null
Set-ItemProperty -Path "HKCR:\AppUserModelId\Windows_Optimisation_Pack" -Name "DisplayName" -Value "Windows_Optimisation_Pack" -Type "STRING" -Force | Out-Null
Set-ItemProperty -Path "HKCR:\AppUserModelId\Windows_Optimisation_Pack" -Name "ShowInSettings" -Value 0 -Type "STRING" -Force | Out-Null
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
# Toast
[xml]$ToastTemplate = @"
<toast duration="Long"><visual><binding template="ToastGeneric">
<text>Your Windows is now debloated and optimised</text></binding></visual>
<audio src="ms-winsoundevent:notification.default" /></toast>
"@
$ToastXml = [Windows.Data.Xml.Dom.XmlDocument]::New()
$ToastXml.LoadXml($ToastTemplate.OuterXml)
$ToastMessage = [Windows.UI.Notifications.ToastNotification]::New($ToastXML)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("Windows_Optimisation_Pack").Show($ToastMessage)
exit}

function GUI{
## GUI 

#Funktion um Fenster zu verstecken / anzuzeigen
Add-Type -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);' -Name WinAPI -Namespace User32
$HideWindow = (Get-Process -Id $PID).MainWindowHandle

# GUI Preperations
$WindowsVersion = (Get-WmiObject -Class Win32_OperatingSystem).Caption
$BuildNumber = (Get-CimInstance -Class CIM_OperatingSystem).BuildNumber
IF(Invoke-WebRequest -Uri https://github.com/Marvin700/Windows_Optimisation_Pack -Method Head -ErrorAction SilentlyContinue){$InternetConnection = $True}else{$InternetConnection = $False}
IF(!(Test-Path $ScriptFolder)){New-Item -Path $ScriptFolder -ItemType Directory | Out-Null}
else{Get-ChildItem -Path $ScriptFolder -ErrorAction SilentlyContinue | Remove-Item -Recurse -exclude "Picture.png" | Out-Null}
$Administrator = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
IF(!(Test-Path $ScriptFolder\Picture.png)){Invoke-WebRequest "https://user-images.githubusercontent.com/98750428/232198728-be7449b4-1d64-4f83-9fb1-2337af52b0c2.png" -OutFile "$ScriptFolder\Picture.png"}
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null

# Hide Window 
[User32.WinAPI]::ShowWindow($HideWindow, 6)

# GUI Checkbox Buttton Handler
$hash.Exit = $true
$handler_BUTTON_Start_Click=
{
$hash.Exit = $false
IF($BOX_Checks.Checked)                 {$hash.Checks = $true}
IF($BOX_SystemPoint.Checked)            {$hash.SystemPoint = $true}
IF($BOX_SophiaScript.Checked)           {$hash.SophiaScript = $true}
IF($BOX_ooShutup.Checked)               {$hash.ooShutup = $true}    
IF($BOX_WindowsTweaks_Registry.Checked) {$hash.WindowsTweaks_Registry = $true}    
IF($BOX_WindowsTweaks_Tasks.Checked)    {$hash.WindowsTweaks_Tasks = $true}   
IF($BOX_WindowsTweaks_Features.Checked) {$hash.WindowsTweaks_Features = $true}   
IF($BOX_WindowsTweaks_Services.Checked) {$hash.WindowsTweaks_Services = $true}
IF($BOX_WindowsTweaks_Index.Checked)    {$hash.WindowsTweaks_Index = $true}
IF($BOX_Clear_Cache.Checked)            {$hash.Clear_Cache = $true} 
IF($BOX_Extended_Cleanup.Checked)       {$hash.Extended_Cleanup = $true}   
IF($BOX_Idle_Tasks.Checked)             {$hash.Idle_Tasks = $true} 

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
$Titel_Warning = New-Object Windows.Forms.Label
$Titel_Warning.Size = New-Object Drawing.Point 200,25
$Titel_Warning.Location = New-Object Drawing.Point 50,422
$Titel_Warning.ForeColor='#e8272f'
IF($Administrator -ne $True){$Titel_Warning.text = "PowerShell is not Administrator"}

## GUI Main

$Text_Info = New-Object Windows.Forms.Label
$Text_Info.Size = New-Object Drawing.Point 150,150
$Text_Info.Location = New-Object Drawing.Point 150,215
$Text_Info.ForeColor='#aaaaaa'
$Text_Info.text = "
Pack Version
$Branch $Version

$WindowsVersion
Build $BuildNumber

GitHub Connection
$InternetConnection

Administrator Permission
$Administrator
"
$BUTTON_Optimise = New-Object System.Windows.Forms.Button
$BUTTON_Optimise.Text = "Debloat and Optimise"
$BUTTON_Optimise.Size = New-Object Drawing.Point 169,54
$BUTTON_Optimise.Location = New-Object Drawing.Point 370,230
$BUTTON_Optimise.ForeColor='#aaaaaa'
$BUTTON_Optimise.add_Click{GUI_Optimise}
$BUTTON_Maintenance = New-Object System.Windows.Forms.Button
$BUTTON_Maintenance.Text = "Maintenance and Tools"
$BUTTON_Maintenance.Size = New-Object Drawing.Point 169,54
$BUTTON_Maintenance.Location = New-Object Drawing.Point 370,310
$BUTTON_Maintenance.ForeColor='#aaaaaa'
$BUTTON_Maintenance.Enabled = $true
$BUTTON_Maintenance.add_Click{GUI_Maintenance}#
$BUTTON_Exit = New-Object System.Windows.Forms.Button
$BUTTON_Exit.Size = New-Object Drawing.Point 113,36
$BUTTON_Exit.Location = New-Object Drawing.Point 270,410
$BUTTON_Exit.ForeColor='#aaaaaa'
$BUTTON_Exit.Text = "Exit"
$BUTTON_Exit.add_Click{$hash.Exit = $true; $Form.Close()}

## GUI Optimisation
$Titel_Essentials = New-Object Windows.Forms.Label
$Titel_Essentials.Size = New-Object Drawing.Point 135,25
$Titel_Essentials.Location = New-Object Drawing.Point 50,215
$Titel_Essentials.text = "Essentials"
$Titel_Essentials.ForeColor='#aaaaaa'
$Titel_Tweaks = New-Object Windows.Forms.Label
$Titel_Tweaks.Size = New-Object Drawing.Point 135,25
$Titel_Tweaks.Location = New-Object Drawing.Point 200,215
$Titel_Tweaks.text = "Tweaks"
$Titel_Tweaks.ForeColor='#aaaaaa'
$Titel_Extras = New-Object Windows.Forms.Label
$Titel_Extras.Size = New-Object Drawing.Point 135,25
$Titel_Extras.Location = New-Object Drawing.Point 370,215
$Titel_Extras.text = "Cleanup"
$Titel_Extras.ForeColor='#aaaaaa'
$Titel_Presets = New-Object Windows.Forms.Label
$Titel_Presets.Size = New-Object Drawing.Point 135,25
$Titel_Presets.Location = New-Object Drawing.Point 530,215
$Titel_Presets.text = "Presets"
$Titel_Presets.ForeColor='#aaaaaa'

# Essentials
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
$BOX_Checks.Text = "System Check"
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
$BOX_ooShutup.Text = "O&&O ShutUp10"
$BOX_ooShutup.ForeColor='#aaaaaa'
$BOX_ooShutup.Checked = $true

# Tweaks
$BOX_WindowsTweaks_Registry = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Registry.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Registry.Location = New-Object Drawing.Point 180,248
$BOX_WindowsTweaks_Registry.Text = "Registry Tweaks"
$BOX_WindowsTweaks_Registry.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Registry.Checked = $true
$BOX_WindowsTweaks_Tasks = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Tasks.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Tasks.Location = New-Object Drawing.Point 180,279
$BOX_WindowsTweaks_Tasks.Text = "Deaktivate Tasks"
$BOX_WindowsTweaks_Tasks.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Tasks.Checked = $true
$BOX_WindowsTweaks_Features = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Features.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Features.Location = New-Object Drawing.Point 180,310
$BOX_WindowsTweaks_Features.Text = "Disable Features"
$BOX_WindowsTweaks_Features.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Features.Checked = $false
$BOX_WindowsTweaks_Services = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Services.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Services.Location = New-Object Drawing.Point 180,341
$BOX_WindowsTweaks_Services.Text = "Disable Services"  
$BOX_WindowsTweaks_Services.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Services.Checked = $true  
$BOX_WindowsTweaks_Index = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsTweaks_Index.Size = New-Object Drawing.Point 135,25
$BOX_WindowsTweaks_Index.Location = New-Object Drawing.Point 180,372
$BOX_WindowsTweaks_Index.Text = "Disable Indexing"  
$BOX_WindowsTweaks_Index.ForeColor='#aaaaaa'
$BOX_WindowsTweaks_Index.Checked = $true  

# Extras
$BOX_Clear_Cache = New-Object System.Windows.Forms.CheckBox
$BOX_Clear_Cache.Size = New-Object Drawing.Point 135,25
$BOX_Clear_Cache.Location = New-Object Drawing.Point 350,248
$BOX_Clear_Cache.Text = "Clear Cache" 
$BOX_Clear_Cache.ForeColor='#aaaaaa'
$BOX_Clear_Cache.Checked = $true 
$BOX_Extended_Cleanup = New-Object System.Windows.Forms.CheckBox
$BOX_Extended_Cleanup.Size = New-Object Drawing.Point 145,25
$BOX_Extended_Cleanup.Location = New-Object Drawing.Point 350,279
$BOX_Extended_Cleanup.Text = "Extended Cleanup"
$BOX_Extended_Cleanup.ForeColor='#aaaaaa'
$BOX_Extended_Cleanup.Checked = $false  
$BOX_Idle_Tasks = New-Object System.Windows.Forms.CheckBox
$BOX_Idle_Tasks.Size = New-Object Drawing.Point 135,25
$BOX_Idle_Tasks.Location = New-Object Drawing.Point 350,310
$BOX_Idle_Tasks.Text = "Run Idle Tasks"
$BOX_Idle_Tasks.ForeColor='#aaaaaa'
$BOX_Idle_Tasks.Checked = $false

# Presets
$BUTTON_Preset_Minimal = New-Object System.Windows.Forms.Button
$BUTTON_Preset_Minimal.Size = New-Object Drawing.Point 110,35
$BUTTON_Preset_Minimal.Location = New-Object Drawing.Point 507,255
$BUTTON_Preset_Minimal.ForeColor='#aaaaaa'
$BUTTON_Preset_Minimal.Text = "Minimal"
$BUTTON_Preset_Minimal.add_Click{GUI_Optimise_Minimal}

$BUTTON_Preset_Standard = New-Object System.Windows.Forms.Button
$BUTTON_Preset_Standard.Size = New-Object Drawing.Point 110,35
$BUTTON_Preset_Standard.Location = New-Object Drawing.Point 507,305
$BUTTON_Preset_Standard.ForeColor='#aaaaaa'
$BUTTON_Preset_Standard.Text = "Standard"
$BUTTON_Preset_Standard.add_Click{GUI_Optimise_Standard}

$BUTTON_Preset_Enhanced = New-Object System.Windows.Forms.Button
$BUTTON_Preset_Enhanced.Size = New-Object Drawing.Point 110,35
$BUTTON_Preset_Enhanced.Location = New-Object Drawing.Point 507,355
$BUTTON_Preset_Enhanced.ForeColor='#aaaaaa'
$BUTTON_Preset_Enhanced.Text = "Enhanced"
$BUTTON_Preset_Enhanced.add_Click{GUI_Optimise_Enhanced}


# Menu Button
$BUTTON_Menu = New-Object System.Windows.Forms.Button
$BUTTON_Menu.Size = New-Object Drawing.Point 75,24
$BUTTON_Menu.Location = New-Object Drawing.Point 265,422
$BUTTON_Menu.ForeColor='#aaaaaa'
$BUTTON_Menu.Text = "Menu"
$BUTTON_Menu.add_Click{GUI_Menu}
$BUTTON_Start = New-Object System.Windows.Forms.Button
$BUTTON_Start.Text = "Start"
$BUTTON_Start.Size = New-Object Drawing.Point 75,24
$BUTTON_Start.Location = New-Object Drawing.Point 360,422
$BUTTON_Start.ForeColor='#aaaaaa'
$BUTTON_Start.add_Click($handler_button_Start_Click)
IF(!($Administrator -eq "True")){$BUTTON_Start.Enabled = $false}

# Maintance
$Titel_Placeholder = New-Object Windows.Forms.Label
$Titel_Placeholder.Size = New-Object Drawing.Point 275,75
$Titel_Placeholder.Location = New-Object Drawing.Point 200,300
$Titel_Placeholder.text = "Development :)

use the scripts in the config Folder"
$Titel_Placeholder.ForeColor='#aaaaaa'

function GUI_Menu
{
    $form.Controls.Clear()
    $form.controls.add($Image)
    $form.controls.add($Text_Info)
    $form.controls.add($Titel_Warning)
    $form.Controls.add($BUTTON_Optimise)
    $form.Controls.add($BUTTON_Maintenance)
    $form.Controls.add($BUTTON_Exit)
}

function GUI_Optimise
{
    $form.Controls.Clear()
    $form.controls.add($Image)
    $form.controls.add($Titel_Warning)
    $form.controls.add($Titel_Essentials)
    $form.controls.add($Titel_Tweaks)
    $form.controls.add($Titel_Extras)
    $form.controls.add($Titel_Presets)
    $form.Controls.Add($BOX_Checks)
    $form.Controls.Add($BOX_SystemPoint)
    $form.Controls.Add($BOX_SophiaScript)
    $form.Controls.Add($BOX_ooShutup)
    $form.Controls.Add($BOX_WindowsTweaks_Registry)
    $form.Controls.Add($BOX_WindowsTweaks_Tasks)
    $form.Controls.Add($BOX_WindowsTweaks_Features)
    $form.Controls.Add($BOX_WindowsTweaks_Services)
    $form.Controls.Add($BOX_WindowsTweaks_Index)
    $form.Controls.Add($BOX_Clear_Cache)
    $form.Controls.Add($BOX_Extended_Cleanup)
    $form.Controls.Add($BOX_Idle_Tasks)
    $form.Controls.Add($BUTTON_Preset_Minimal)
    $form.Controls.Add($BUTTON_Preset_Standard)
    $form.Controls.Add($BUTTON_Preset_Enhanced)
    $form.Controls.Add($BUTTON_Start)
    $form.Controls.Add($BUTTON_Menu)
}

function GUI_Optimise_Minimal
{
    $BOX_SophiaScript.Checked = $false
    $BOX_ooShutup.Checked = $true
    $BOX_WindowsTweaks_Registry.Checked = $false
    $BOX_WindowsTweaks_Tasks.Checked = $true
    $BOX_WindowsTweaks_Features.Checked = $false
    $BOX_WindowsTweaks_Services.Checked = $true
    $BOX_WindowsTweaks_Index.Checked = $true
    $BOX_Clear_Cache.Checked = $true
    $BOX_Extended_Cleanup.Checked = $false
    $BOX_Idle_Tasks.Checked = $false
    $form.Refresh
}

function GUI_Optimise_Standard
{
    $BOX_SophiaScript.Checked = $true
    $BOX_ooShutup.Checked = $true
    $BOX_WindowsTweaks_Registry.Checked = $true
    $BOX_WindowsTweaks_Tasks.Checked = $true
    $BOX_WindowsTweaks_Features.Checked = $false
    $BOX_WindowsTweaks_Services.Checked = $true
    $BOX_WindowsTweaks_Index.Checked = $true
    $BOX_Clear_Cache.Checked = $true
    $BOX_Extended_Cleanup.Checked = $false
    $BOX_Idle_Tasks.Checked = $false
    $form.Refresh
}

function GUI_Optimise_Enhanced
{
    $BOX_SophiaScript.Checked = $true
    $BOX_ooShutup.Checked = $true
    $BOX_WindowsTweaks_Registry.Checked = $true
    $BOX_WindowsTweaks_Tasks.Checked = $true
    $BOX_WindowsTweaks_Features.Checked = $true
    $BOX_WindowsTweaks_Services.Checked = $true
    $BOX_WindowsTweaks_Index.Checked = $true
    $BOX_Clear_Cache.Checked = $true
    $BOX_Extended_Cleanup.Checked = $true
    $BOX_Idle_Tasks.Checked = $true
    $form.Refresh
}



function GUI_Maintenance
{
    $form.Controls.Clear()
    $form.controls.add($Image)
    $form.controls.add($Titel_Placeholder)
    $form.Controls.Add($BUTTON_Menu)
}


GUI_Menu
$form.ShowDialog() | Out-Null

#Show Window
[User32.WinAPI]::ShowWindow($HideWindow, 9)

}


function GUI_Menu{ 
IF($hash.Exit){exit}
IF($hash.SystemPoint){SystemPoint}
IF($hash.Checks){Checks_and_Preperations}
IF($hash.WindowsTweaks_Services){WindowsTweaks_Services}
IF($hash.ooShutup){ooShutup}
IF($hash.SophiaScript){SophiaScript}
IF($hash.WindowsTweaks_Tasks){WindowsTweaks_Tasks} 
IF($hash.WindowsTweaks_Registry){WindowsTweaks_Registry}
IF($hash.WindowsTweaks_Features){WindowsTweaks_Features}
IF($hash.WindowsTweaks_Index){WindowsTweaks_Index}
IF($hash.Clear_Cache){Clear_Cache}
IF($hash.Extended_Cleanup){Extended_Cleanup}   
IF($hash.Idle_Tasks){Idle_Tasks}
IF($hash.Driver_Cleaner){Driver_Cleaner}}

GUI
GUI_Menu
Finish