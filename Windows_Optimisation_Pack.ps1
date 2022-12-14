$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack | $([char]0x00A9) Marvin700"
$hash = [hashtable]::Synchronized(@{}) 
$ScriptFolder = "$env:temp\Windows_Optimisation_Pack"
$WindowsVersion = (Get-WmiObject -class Win32_OperatingSystem).Caption
$InstalledSoftware = (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*).DisplayName
if (!(Test-Path $env:temp\Windows_Optimisation_Pack)) {New-Item -Path $env:temp\Windows_Optimisation_Pack -ItemType Directory} 


function WindowsTweaks_Services{
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
Stop-Service "PhoneSvc"
Stop-Service "ScDeviceEnum"
Stop-Service "icssvc"
Stop-Service "edgeupdatem"
Stop-Service "edgeupdate"
Stop-Service "MicrosoftEdgeElevationService"
Stop-Service "RetailDemo"
Stop-Service "MessagingService"
Stop-Service "PimIndexMaintenanceSvc"
Stop-Service "OneSyncSvc"
Stop-Service "UnistoreSvc"
Stop-Service "DiagTrack"
Stop-Service "dmwappushservice"
Stop-Service "diagnosticshub.standardcollector.service"
Stop-Service "diagsvc"
Stop-Service "WerSvc" 
Stop-Service "wercplsupport" 
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
Set-Service "PhoneSvc" -StartupType Disabled
Set-Service "ScDeviceEnum" -StartupType Disabled
Set-Service "TabletInputService" -StartupType Disabled
Set-Service "icssvc" -StartupType Disabled
Set-Service "edgeupdatem" -StartupType Disabled
Set-Service "edgeupdate" -StartupType Disabled
Set-Service "MicrosoftEdgeElevationService" -StartupType Disabled
Set-Service "RetailDemo" -StartupType Disabled
Set-Service "MessagingService" -StartupType Disabled 
Set-Service "PimIndexMaintenanceSvc" -StartupType Disabled 
Set-Service "OneSyncSvc" -StartupType Disabled
Set-Service "UnistoreSvc" -StartupType Disabled
Set-Service "DiagTrack" -StartupType Disabled
Set-Service "dmwappushservice" -StartupType Disabled
Set-Service "diagnosticshub.standardcollector.service" -StartupType Disabled
Set-Service "diagsvc" -StartupType Disabled 
Set-Service "WerSvc" -StartupType Disabled
Set-Service "wercplsupport" -StartupType Disabled }

function WindowsTweaks_Registry{
#GPU MPO FIx for Flickering
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -Type "DWORD" -Value "00000005" -Force
OverlayTestMode
# MarkC Mouse Acceleration Fix
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" ([byte[]](0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" ([byte[]](0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Type "DWORD" -Value 10 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Type "DWORD" -Value 0 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseTrails" -Type "DWORD" -Value 0 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Type "DWORD" -Value 0 -Force
New-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" -Name "Value" -Value "Deny" -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name "Start" -Type "DWORD" -Value 4 -Force 
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\diagnosticshub.standardcollector.service" -Name "Start" -Type "DWORD" -Value 4 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Value 0 -Type "DWORD" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "LimitEnhancedDiagnosticDataWindowsAnalytics" -Type "DWORD" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type "DWORD" -Value 0 -Force 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" -Name "HideInsiderPage" -Type "DWORD" -Value "1" -Force }
        
function WindowsTweaks_Tasks{
Get-ScheduledTask -TaskName Consolidator | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName UsbCeip | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClient | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName DmClientOnScenarioDownload | Disable-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" | Disable-ScheduledTask
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE }

function WindowsTweaks_Features{
dism /Online /Disable-Feature /FeatureName:"TelnetClient" /NoRestart
dism /Online /Disable-Feature /FeatureName:"WCF-TCP-PortSharing45" /NoRestart
dism /Online /Disable-Feature /FeatureName:"SmbDirect" /NoRestart
dism /Online /Disable-Feature /FeatureName:"TFTP" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-All" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-Clients" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Tools-All" /NoRestart
dism /Online /Disable-Feature /FeatureName:"Microsoft-Hyper-V-Management-PowerShell" /NoRestart }
            
function WindowsTweaks_Index{
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='C:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='D:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='E:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='F:'" | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null }

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
                
function SophiaScript{
Clear-Host
IF($WindowsVersion -eq "Microsoft Windows 11 Home" -Or $WindowsVersion -eq "Microsoft Windows 11 Pro" -Or $WindowsVersion -eq "Microsoft Windows 11 Enterprise") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.2.5/Sophia.Script.for.Windows.11.v6.2.5.zip" -Destination $env:temp\Sophia.zip
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination $ScriptFolder\Sophia_Script\
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/main/config/Sophia_Win11.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1" }
else { IF($WindowsVersion -eq "Microsoft Windows 10 Home" -Or $WindowsVersion -eq "Microsoft Windows 10 Pro" -Or $WindowsVersion -eq "Microsoft Windows 11 Enterprise") {
Start-BitsTransfer -Source "https://github.com/farag2/Sophia-Script-for-Windows/releases/download/6.2.5/Sophia.Script.for.Windows.10.v5.14.5.zip" -Destination $env:temp\Sophia.zip
Expand-Archive $env:temp\Sophia.zip $env:temp -force
Move-Item -Path $env:temp\"Sophia_Script*" -Destination $ScriptFolder\Sophia_Script\
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/main/config/Sophia_Win10.ps1" -Destination "$ScriptFolder\Sophia_Script\Sophia.ps1" } }
Powershell.exe -executionpolicy Bypass $ScriptFolder\Sophia_Script\Sophia.ps1 } 

function ooShutup{
Start-BitsTransfer -Source "https://raw.githubusercontent.com/Marvin700/Windows_Optimisation_Pack/main/config/ooshutup10.cfg" -Destination "$ScriptFolder\ooshutup10.cfg"
Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination $ScriptFolder\OOSU10.exe
Set-Location $ScriptFolder
.\OOSU10.exe ooshutup10.cfg /quiet }

function SystemPoint{
if($hash.WindowsCleanup){vssadmin delete shadows /all /quiet}
Enable-ComputerRestore -Drive "C:\"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F
Checkpoint-Computer -Description "Windows_Optimisation_Pack" -RestorePointType MODIFY_SETTINGS
REG DELETE "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /F }

function Checks{
IF(!($WindowsVersion -eq "Microsoft Windows 11 Home" -Or $WindowsVersion -eq "Microsoft Windows 11 Pro" -Or $WindowsVersion -eq "Microsoft Windows 11 Enterprise")) {
IF(!($WindowsVersion -eq "Microsoft Windows 10 Home" -Or $WindowsVersion -eq "Microsoft Windows 10 Pro" -Or $WindowsVersion -eq "Microsoft Windows 11 Enterprise")) {
Write-Warning " No supported operating system! Windows 10 or Windows 11 required"
Write-Warning " The script will be closed in 20 seconds"
Start-Sleep 20;exit}} 
if ((Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")){
Write-Warning " Reboot Pending !"
Write-Warning " The script will be closed in 20 seconds"
Start-Sleep 20;exit}
If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")){
Write-Warning " No admin rights available"
Write-Warning " The script will be closed in 20 seconds"
Start-Sleep 20;exit}}

function Autoruns{
Start-BitsTransfer -Source "https://download.sysinternals.com/files/Autoruns.zip" -Destination $env:temp\Autoruns.zip
Expand-Archive $env:temp\Autoruns.zip  $env:temp
Start-Process $env:temp\Autoruns64.exe }

function WindowsCleanup{
Clear-Host
gpupdate.exe /force 
$Key = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches
ForEach($result in $Key)
{If($result.name -eq "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder"){}Else{
$Regkey = 'HKLM:' + $result.Name.Substring( 18 )
New-ItemProperty -Path $Regkey -Name 'StateFlags0001' -Value 2 -PropertyType DWORD -Force -EA 0 | Out-Null}}
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
Dism.exe /Online /Cleanup-Image /spsuperseded
Dism.exe /online /Cleanup-Image /StartComponentCleanup
Clear-BCCache -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:temp -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse 
Get-ChildItem -Path $env:windir\Temp -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse 
Get-ChildItem -Path $env:windir\Prefetch -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse 
Get-ChildItem -Path $env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
Get-ChildItem -Path $env:LOCALAPPDATA\AMD -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
Get-ChildItem -Path $env:windir/../AMD/ -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse 
Get-ChildItem -Path $env:LOCALAPPDATA\NVIDIA\DXCache -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
Get-ChildItem -Path $env:LOCALAPPDATA\NVIDIA\GLCache -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
Get-ChildItem -Path $env:APPDATA\..\locallow\Intel\ShaderCache -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
lodctr /r
lodctr /r
Start-Process cleanmgr.exe /sagerun:1 -Wait }
          
function Runtime{
winget source update | Out-Null
winget install --id=Microsoft.dotNetFramework --exact --accept-source-agreements 
IF(!($InstalledSoftware -Contains "Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.34.31931")){winget install --id=Microsoft.VCRedist.2015+.x64 --exact --accept-source-agreements}
IF(!($InstalledSoftware -Contains "Microsoft Windows Desktop Runtime - 6.0.11 (x64)")){winget install --id=Microsoft.DotNet.DesktopRuntime.6 --architecture x64 --exact --accept-source-agreements}
IF(!($InstalledSoftware -Contains "Microsoft Windows Desktop Runtime - 7.0.0 (x64)")){winget install --id=Microsoft.DotNet.DesktopRuntime.7 --architecture x64 --exact --accept-source-agreements}
winget install --id=Microsoft.DirectX --exact --accept-source-agreements}

function Fan_Control{
Start-BitsTransfer -Source "https://github.com/Rem0o/FanControl.Releases/releases/download/V140/FanControl_net_7_0.zip" -Destination $env:temp\FanControl.zip 
Expand-Archive $env:temp\FanControl.zip "C:\Program Files\FanControl" -force
Remove-Item -Path $env:temp\FanControl.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\FanControl.lnk")
$Shortcut.TargetPath = "C:\Program Files\FanControl\FanControl.exe"
$Shortcut.Save() }

function AutoActions{
Start-BitsTransfer -Source "https://github.com/Codectory/AutoActions/releases/download/1.9.19/Release_AutoActions_1.9.19_x64.zip" -Destination $env:temp\AutoActions.zip 
Expand-Archive $env:temp\AutoActions.zip "C:\Program Files\AutoActions" -force
Remove-Item -Path $env:temp\AutoActions.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\AutoActions.lnk")
$Shortcut.TargetPath = "C:\Program Files\AutoActions\AutoActions.exe"
$Shortcut.Save() }
    
function Controller{
Start-BitsTransfer -Source "https://github.com/Ryochan7/DS4Windows/releases/download/v3.1.12/DS4Windows_3.1.12_x64.zip" -Destination "$env:temp\DS4Windows.zip "
Expand-Archive $env:temp\DS4Windows.zip "C:\Program Files\" -force
Remove-Item -Path $env:temp\DS4Windows.zip  -Force -Recurse
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Controller.lnk")
$Shortcut.TargetPath = "C:\Program Files\DS4Windows\DS4Windows.exe"
$Shortcut.Save() }
    
function Process_Lasso{
Start-BitsTransfer -Source "https://dl.bitsum.com/files/processlassosetup64.exe" -Destination $env:temp\ProcesslassoSetup64.exe
Start-Process -FilePath "$env:temp\ProcesslassoSetup64.exe" -ArgumentList "/S /language=German"}

function Rename_HDD{Label C: Windows}

function Winrar{winget install --id=RARLab.WinRAR --exact --accept-source-agreements}

function Finish{
REG ADD "HKLM\SOFTWARE\Windows_Optimisation_Pack\" /V "Successful" /T REG_DWORD /D 1 /F | Out-Null
Clear-Host
"Your system has been successfully optimised by the Windows_Optimisation_Pack" 
if($hash.Reboot){Reboot}}

function Reboot{
Write-Warning " The computer will restart automatically in 120 seconds !!!"
Start-Sleep 120
Restart-Computer }

function GUI {
Invoke-WebRequest 'https://user-images.githubusercontent.com/98750428/194409138-97880567-7645-4dc3-b031-74e2dae6da35.png' -OutFile $ScriptFolder\Picture.png
[reflection.assembly]::loadwithpartialname("System.Windows.Forms") | Out-Null
[reflection.assembly]::loadwithpartialname("System.Drawing") | Out-Null
$hash.Cancel = $true
$handler_BUTTON_Start_Click= {   
$hash.Cancel = $false
if ($BOX_Checks.Checked)                    {$hash.Checks = $true}
if ($BOX_SystemPoint.Checked)               {$hash.SystemPoint = $true} 
if ($BOX_SophiaScript.Checked)              {$hash.SophiaScript = $true}
if ($BOX_ooShutup.Checked)                  {$hash.ooShutup = $true}    
if ($BOX_WindowsTweaks_Registry.Checked)    {$hash.WindowsTweaks_Registry = $true}    
if ($BOX_WindowsTweaks_Tasks.Checked)       {$hash.WindowsTweaks_Tasks = $true}   
if ($BOX_WindowsTweaks_Features.Checked)    {$hash.WindowsTweaks_Features = $true}   
if ($BOX_WindowsTweaks_Services.Checked)    {$hash.WindowsTweaks_Services = $true}
if ($BOX_WindowsTweaks_Index.Checked)       {$hash.WindowsTweaks_Index = $true}
if ($BOX_Runtime.Checked)      		        {$hash.Runtime = $true}   
if ($BOX_WindowsCleanup.Checked)            {$hash.WindowsCleanup = $true}    
if ($BOX_Rename_HDD.Checked)                {$hash.Rename_HDD = $true} 
if ($BOX_TakeOwnership.Checked)             {$hash.TakeOwnership = $true}    
if ($BOX_Autoruns.Checked)                  {$hash.Autoruns = $true} 
if ($BOX_Winrar.Checked)                    {$hash.Winrar = $true}    
if ($BOX_Fan_Control.Checked)               {$hash.Fan_Control = $true}  
if ($BOX_AutoActions.Checked)               {$hash.AutoActions = $true}
if ($BOX_Process_Lasso.Checked)             {$hash.Process_Lasso = $true}     
if ($BOX_Controller.Checked)                {$hash.Controller = $true} 
if ($BOX_Reboot.Checked)                    {$hash.Reboot = $true} $Form.Close()}
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
$Titel_Install = New-Object Windows.Forms.Label
$Titel_Install.Size = New-Object Drawing.Point 135,25
$Titel_Install.Location = New-Object Drawing.Point 566,215
$Titel_Install.text = "Install"
$Titel_Install.ForeColor='#aaaaaa'
$BOX_Checks = New-Object System.Windows.Forms.CheckBox
$BOX_Checks.Size = New-Object Drawing.Point 135,25
$BOX_Checks.Location = New-Object Drawing.Point 27,248
$BOX_Checks.Text = "Compability Checks"
$BOX_Checks.ForeColor='#aaaaaa'
$BOX_Checks.Checked = $true
$BOX_Checks.Enabled = $false 
$BOX_SystemPoint = New-Object System.Windows.Forms.CheckBox
$BOX_SystemPoint.Size = New-Object Drawing.Point 135,25
$BOX_SystemPoint.Location = New-Object Drawing.Point 27,279
$BOX_SystemPoint.Text = "Restore Point" 
$BOX_SystemPoint.ForeColor='#aaaaaa'
$BOX_SystemPoint.Checked = $true 
$BOX_SophiaScript = New-Object System.Windows.Forms.CheckBox
$BOX_SophiaScript.Size = New-Object Drawing.Point 135,25
$BOX_SophiaScript.Location = New-Object Drawing.Point 27,310
$BOX_SophiaScript.Text = "Sophia Script" 
$BOX_SophiaScript.ForeColor='#aaaaaa'
$BOX_SophiaScript.Checked = $true 
$BOX_ooShutup = New-Object System.Windows.Forms.CheckBox
$BOX_ooShutup.Size = New-Object Drawing.Point 135,25
$BOX_ooShutup.Location = New-Object Drawing.Point 27,341
$BOX_ooShutup.Text = "O&O ShutUp10++"
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
$BOX_Runtime = New-Object System.Windows.Forms.CheckBox
$BOX_Runtime.Size = New-Object Drawing.Point 145,25
$BOX_Runtime.Location = New-Object Drawing.Point 373,248
$BOX_Runtime.Text = "Runtime Components"
$BOX_Runtime.ForeColor='#aaaaaa'
$BOX_Runtime.Checked = $true  
$BOX_WindowsCleanup = New-Object System.Windows.Forms.CheckBox
$BOX_WindowsCleanup.Size = New-Object Drawing.Point 135,25
$BOX_WindowsCleanup.Location = New-Object Drawing.Point 373,279
$BOX_WindowsCleanup.Text = "Windows Cleanup"
$BOX_WindowsCleanup.ForeColor='#aaaaaa'
$BOX_WindowsCleanup.Checked = $true
$BOX_Rename_HDD = New-Object System.Windows.Forms.CheckBox
$BOX_Rename_HDD.Size = New-Object Drawing.Point 135,25
$BOX_Rename_HDD.Location = New-Object Drawing.Point 373,310
$BOX_Rename_HDD.Text = "Rename C Drive"
$BOX_Rename_HDD.ForeColor='#aaaaaa'
$BOX_Rename_HDD.Checked = $true
$BOX_TakeOwnership = New-Object System.Windows.Forms.CheckBox
$BOX_TakeOwnership.Size = New-Object Drawing.Point 135,25
$BOX_TakeOwnership.Location = New-Object Drawing.Point 373,341
$BOX_TakeOwnership.Text = "Take Ownership" 
$BOX_TakeOwnership.ForeColor='#aaaaaa'
$BOX_TakeOwnership.Checked = $true
$BOX_Autoruns = New-Object System.Windows.Forms.CheckBox
$BOX_Autoruns.Size = New-Object Drawing.Point 135,25
$BOX_Autoruns.Location = New-Object Drawing.Point 373,373
$BOX_Autoruns.Text = "Autoruns" 
$BOX_Autoruns.ForeColor='#aaaaaa'
$BOX_Autoruns.Checked = $true
$BOX_Winrar = New-Object System.Windows.Forms.CheckBox
$BOX_Winrar.Size = New-Object Drawing.Point 135,25
$BOX_Winrar.Location = New-Object Drawing.Point 546,248
$BOX_Winrar.Text = "Winrar"
$BOX_Winrar.ForeColor='#aaaaaa'
$BOX_Winrar.Checked = $true
$BOX_Fan_Control = New-Object System.Windows.Forms.CheckBox
$BOX_Fan_Control.Size = New-Object Drawing.Point 135,25
$BOX_Fan_Control.Location = New-Object Drawing.Point 546,279
$BOX_Fan_Control.Text = "Fan Control"
$BOX_Fan_Control.ForeColor='#aaaaaa'
$BOX_Fan_Control.Checked = $false  
$BOX_AutoActions = New-Object System.Windows.Forms.CheckBox
$BOX_AutoActions.Size = New-Object Drawing.Point 135,25
$BOX_AutoActions.Location = New-Object Drawing.Point 546,310
$BOX_AutoActions.Text = "AutoActions"
$BOX_AutoActions.ForeColor='#aaaaaa'
$BOX_AutoActions.Checked = $false 
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
$form.controls.add($Titel_Install)
$form.Controls.Add($BOX_Checks)
$form.Controls.Add($BOX_SystemPoint)
$form.Controls.Add($BOX_SophiaScript)
$form.Controls.Add($BOX_ooShutup)
$form.Controls.Add($BOX_WindowsTweaks_Registry)
$form.Controls.Add($BOX_WindowsTweaks_Tasks)
$form.Controls.Add($BOX_WindowsTweaks_Features)
$form.Controls.Add($BOX_WindowsTweaks_Services)
$form.Controls.Add($BOX_WindowsTweaks_Index)
$form.Controls.Add($BOX_Runtime)
$form.Controls.Add($BOX_WindowsCleanup)
$form.Controls.Add($BOX_Rename_HDD)
$form.Controls.Add($BOX_TakeOwnership)
$form.Controls.Add($BOX_Autoruns)
$form.Controls.Add($BOX_Winrar)
$form.Controls.Add($BOX_Fan_Control)
$form.Controls.Add($BOX_AutoActions)
$form.Controls.Add($BOX_Process_Lasso)
$form.Controls.Add($BOX_Controller)
$form.Controls.Add($BOX_Reboot)
$form.Controls.Add($BUTTON_Start)
$form.Controls.Add($BUTTON_Cancel)
$form.ShowDialog() } Out-Null

function Choice { 
if($hash.Cancel){exit}
if($hash.Checks){Checks}
if($hash.SystemPoint){SystemPoint}
if($hash.SophiaScript){SophiaScript}
if($hash.ooShutup){ooShutup}
if($hash.WindowsTweaks_Registry){WindowsTweaks_Registry}
if($hash.WindowsTweaks_Tasks){WindowsTweaks_Tasks} 
if($hash.WindowsTweaks_Features){WindowsTweaks_Features} 
if($hash.WindowsTweaks_Services){WindowsTweaks_Services}
if($hash.WindowsTweaks_Index){WindowsTweaks_Index}
if($hash.Rename_HDD){Rename_HDD}
if($hash.Runtime){Runtime}   
if($hash.TakeOwnership){TakeOwnership}
if($hash.Autoruns){Autoruns}    
if($hash.Winrar){Winrar}    
if($hash.Fan_Control){Fan_Control}
if($hash.AutoActions){AutoActions}
if($hash.Controller){Controller} 
if($hash.Process_Lasso){Process_Lasso}
if($hash.WindowsCleanup){WindowsCleanup}}

GUI
Choice
Finish

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQULTMfmWswrPXCKt7t2M/YHJWA
# sgugggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUOcnyGYKltzny4SYK6sUCPts1l1IwDQYJ
# KoZIhvcNAQEBBQAEggEAGbEVuMAYEPrJfxqypKIvWa6CSSxFW5hh3mUDZDVt/dyo
# xOn9LEZlYHrVXCKxPAJOAH3O4hICeF8fJ0J1FMOBM5+L0wGrpcXw1HV6FMWd8NT3
# Y3eRS5wsVzSlJ93w9Tuyma6vUHtOSns+VpUFD0ox1fisEh9QlgB9tn5KomF5/GFY
# nE2Llpe93gKjOg29Yo/5EqfXYvvxTxxCkpaGnAYWeJq+nNMv/H/b4xq754VfnoTp
# Z+AFVGn9lL7vMQ4oeCj+3HkUs/v2BQ8pxVGyCPCqMzBIV7jBo3CIB6x9rEamkIcb
# LGsLiigTQVYtYdXiAD2KJRv1UzXDw0ADPMyFAEx5bw==
# SIG # End signature block
