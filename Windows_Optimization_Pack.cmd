@echo off
echo ==============================
echo Windows Optimization Pack
echo ==============================
echo Nun wird das Script von Github geladen und gestartet
echo ...
timeout 5
powershell -command Invoke-WebRequest 'https://github.com/Marvin700/Windows-Optimisation-Pack/archive/refs/heads/main.zip' -OutFile .\Windows-Optimisation-Pack-main.zip
powershell -command Expand-Archive '.\Windows-Optimisation-Pack-main.zip' ./
powershell -command Move-Item -Path .\Windows-Optimisation-Pack-main\ -Destination C:\Windows_Optimization_Pack"\
powershell -command Remove-Item .\Windows-Optimisation-Pack-main.zip
start C:\Windows_Optimization_Pack\_Files\install.cmd
exit