@echo off
cd "C:\Windows Optimization Pack"
echo ==============================
echo Windows Optimization Pack
echo ==============================
pause
cls

reg import "C:\Windows Optimization Pack\_Files\Registry.reg"

echo ---------------------------
echo Schritt 1 - C++ installieren
echo ---------------------------
echo Nun wird C++ installiert
winget source update
winget install --id=Microsoft.VC++2012Redist-x64 -e  && winget install --id=Microsoft.VC++2012Redist-x86 -e  && winget install --id=Microsoft.VC++2013Redist-x64 -e  && winget install --id=Microsoft.VC++2013Redist-x86 -e  && winget install --id=Microsoft.VC++2015Redist-x64 -e  && winget install --id=Microsoft.VC++2015Redist-x86 -e  && winget install --id=Microsoft.VC++2017Redist-x64 -e  && winget install --id=Microsoft.VC++2017Redist-x86 -e  && winget install --id=Microsoft.VC++2005Redist-x86 -e  && winget install --id=Microsoft.VC++2008Redist-x86 -e  && winget install --id=Microsoft.VC++2015-2019Redist-x64 -e  && winget install --id=Microsoft.VC++2015-2019Redist-x86 -e  && winget install --id=Microsoft.VC++2005Redist-x64 -e  && winget install --id=Microsoft.VC++2008Redist-x64 -e  && winget install --id=Microsoft.VC++2010Redist-x64 -e  && winget install --id=Microsoft.VC++2010Redist-x86 -e
echo ---------------------------
echo Schritt 2 - Direct X Installieren
echo ---------------------------
echo nun wird Direct X installiert
winget install --id=Microsoft.DirectX  -e
echo ---------------------------
echo Schritt 3 - Alle Programme Updaten
echo ---------------------------
echo Nun werden alle Programme auf den aktuellstens stand gebracht
winget upgrade --all --include-unknown
echo ---------------------------
echo Schritt 3 - Weitere Programme installieren
echo ---------------------------
winget winget install --id=RARLab.WinRAR -e && install --id=VideoLAN.VLC -e  && winget install --id=Notepad++.Notepad++ -e  && winget install --id=Discord.Discord -e  && winget install --id=Valve.Steam -e && winget install --id=BitSum.ProcessLasso && -e winget install --id=REALiX.HWiNFO -e 
cls

echo ---------------------------
echo Schritt 4 - Schnellstart deaktiveren
echo Nun wird der Schnellstart deaktiviert 
echo ---------------------------
powercfg -h off
cls

echo ---------------------------
echo Schritt 5 - Festplatten Indizierung ausschalten
echo ---------------------------
echo Dieser PC -> Festplatte -> Weitere Optionen anzeigen -> Eigenschaften -> indizierung deaktivieren
pause
cls

echo ---------------------------
echo Schritt 6 - Windows updaten
echo ---------------------------
echo Bitte Windows auf den aktuellsten stand bringen
start ms-settings:windowsupdate
pause
cls

echo ---------------------------
echo Schritt 7 - Update Microsoft Apps
echo ---------------------------
echo Bitte alle Microsoft Store Apps updaten
echo Dazu auf "Bibliothek" klicken und anschließend "Updates abrufen" klicken
start ms-windows-store:
pause
cls

echo ---------------------------
echo Schritt 8 - Maps Auto Update Off
echo ---------------------------
echo Automatische Maps Updates ausschalten
start ms-settings:maps
pause
cls

echo ---------------------------
echo Schritt 9 - Apps Autostart deaktivieren
echo ---------------------------
echo Apps Autostart deaktivieren
start ms-settings:startupapps
pause 
cls

echo ---------------------------
echo Schritt 10 - Einstellungs Synchronisierung Off
echo ---------------------------
echo Automatische Syncronisierung deaktivieren
start ms-settings:sync
pause
cls

echo ---------------------------
echo Schritt 11 - Programme Deinstallieren
echo ---------------------------
echo Bitte ungewollte Programme deinstallieren
start ms-settings:appsfeatures
pause
cls 

echo ---------------------------
echo Schritt 12 - Autostart bereinigen
echo ---------------------------
echo Hier bitte nur Aenderungen durchfüren, wenn das noetige Wissen vorhanden ist.
echo Ansonsten diesen Schritt bitte überspringen
start Autoruns.exe
pause
cls

echo ---------------------------
echo Schritt 13 o&oShutup
echo ---------------------------
cd "C:\Windows Optimization Pack\_Files\o&oShutup"
start OOSU10.exe
cd "C:\Windows Optimization Pack\"
echo Datei - Einstellungen importieren - ooshutup10.cfg
pause
cls
