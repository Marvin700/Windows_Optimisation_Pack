@echo off
echo ====================================
echo Windows Optimization Pack Downloader
echo ====================================
echo Die neuste Version wird nun von Github geladen und ausgefuert
timeout 5
powershell -command Remove-Item -Path C:\Windows_Optimisation_Pack -Force -Recurse
cls
echo ====================================
echo Windows Optimization Pack Downloader
echo ====================================
powershell -command Invoke-WebRequest 'https://github.com/Marvin700/Windows_Optimisation_Pack/releases/download/1.2.1/Windows_Optimisation_Pack.zip' -OutFile .\Windows_Optimisation_Pack.zip
powershell -command Expand-Archive '.\Windows_Optimisation_Pack.zip' C:\
powershell -command Remove-Item .\Windows_Optimisation_Pack.zip
Powershell.exe -executionpolicy remotesigned -File "C:\Windows_Optimisation_Pack\_Files\install.ps1"
exit