# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

Clear-Host
ipconfig /flushdns
Clear-BCCache -Force -ErrorAction SilentlyContinue
$path = @("$env:windir\..\MSOCache\","$env:windir\Prefetch\","$env:SystemRoot\SoftwareDistribution\Download\","$env:ProgramData\Microsoft\Windows\RetailDemo\","$env:LOCALAPPDATA\CrashDumps\","$env:windir\Temp\"
"$env:LOCALAPPDATA\NVIDIA\DXCache\","$env:LOCALAPPDATA\NVIDIA\GLCache\","$env:APPDATA\..\locallow\Intel\ShaderCache\","$env:SystemDrive\AMD\","$env:LOCALAPPDATA\AMD\","$env:APPDATA\..\locallow\AMD\","$env:temp\")
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
Start-Process -FilePath "cmd.exe" -ArgumentList '/c title Windows_Optimisation_Pack && mode con cols=40 lines=12 && echo Background tasks are processed... && echo This Step can run up to 1 Hour && echo _ && echo You can continue with your stuff :) && %windir%\system32\rundll32.exe advapi32.dll,ProcessIdleTasks'