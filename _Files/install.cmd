@echo off
cd "C:\Windows_Optimisation_Pack"
echo ...
echo --- WCHICHTIG --- 
echo Bitte erst Windows Updaten
echo Der Ornder Windows_Optimisation_Pack muss unter C liegen.
echo Muss als Admin ausgefuert werden
echo --- WCHICHTIG ---
echo ...

echo ===========================
echo Windows Optimization Pack
echo ===========================
echo Schritt 0   - Wiederherstellungspunkt erstellen
echo Schritt 1   - Apps Autostart deaktivieren
echo Schritt 2   - Autostart bereinigen
echo Schritt 3   - oShutup
echo Schritt 4   - Registry Werte aendern (Benutzerkontensteuerung deaktivieren)
echo Schritt 4   - Registry Werte aendern (Zeiger Beschleunigung deaktivieren)
echo Schritt 4   - Registry Werte aendern (Take Ownership)
echo Schritt 5   - Schnellstart deaktiveren
echo Schritt 6   - Performance Counter
echo Schritt 7   - Winget installieren
echo Schritt 7.1 - C++ 2008-2019 installieren 
echo Schritt 7.2 - Direct X Installieren
echo Schritt 7.3 - Net-Framework Installieren
echo Schritt 7.4 - Alle Programme Updaten
echo Schritt 7.5 - Nuetzliche Programme installieren
echo Schritt 8   - Sophia Script
echo ...
echo ...
echo Automatischer start in 30 Sekunden...
timeout 30
cls

echo ---------------------------
echo Schritt 0 - Wiederherstellungspunkt erstellen
echo ---------------------------
wmic.exe /Namespace:\\root\default Path SystemRestore Call CreateRestorePoint "Windows_Optimisation_Pack", 100, 7
cls

echo ---------------------------
echo Schritt 1 - Apps Autostart deaktivieren
echo ---------------------------
echo Apps Autostart deaktivieren
start ms-settings:startupapps
cls

echo ---------------------------
echo Schritt 2 - Autostart bereinigen
echo ---------------------------
echo Hier bitte nur Aenderungen durchfüren, wenn das noetige Wissen vorhanden ist.
echo Ansonsten diesen Schritt bitte überspringen
cd "C:\Windows_Optimisation_Pack\_Files\"
start Autoruns.exe
cls

echo ---------------------------
echo Schritt 3 - oShutup
echo ---------------------------
cd "C:\Windows_Optimisation_Pack\_Files\oShutup"
start OOSU10.exe
cls

echo ---------------------------
echo Schritt 4 Registry Werte ändern
echo ---------------------------
reg import "C:\Windows_Optimisation_Pack\_Files\Registry.reg"
cls

echo ---------------------------
echo Schritt 5 - Schnellstart deaktiveren
echo ---------------------------
echo Nun wird der Schnellstart deaktiviert 
powercfg -h off
cls

echo ---------------------------
echo Schritt 6 - Performance Counter
echo ---------------------------
lodctr /r
lodctr /r
cls

echo ---------------------------
echo Schritt 7 - Winget installieren
echo ---------------------------
powershell -command Add-AppxPackage "C:\Windows_Optimisation_Pack\_Files\WinGet.msixbundle"
echo ...
echo ---------------------------
echo Schritt 7.1 - C++ installieren
echo ---------------------------
echo Nun wird C++ installiert
winget source update
winget install --id=Microsoft.VC++2008Redist-x86  -e && winget install --id=Microsoft.VC++2008Redist-x64  -e && winget install --id=Microsoft.VC++2010Redist-x86  -e && winget install --id=Microsoft.VC++2010Redist-x64  -e && winget install --id=Microsoft.VC++2012Redist-x86  -e && winget install --id=Microsoft.VC++2012Redist-x64  -e && winget install --id=Microsoft.VC++2013Redist-x86  -e && winget install --id=Microsoft.VC++2013Redist-x64  -e && winget install --id=Microsoft.VC++2015-2019Redist-x86  -e && winget install --id=Microsoft.VC++2015-2019Redist-x64  -e
echo ...
echo ---------------------------
echo Schritt 7.2 - Direct X Installieren
echo ---------------------------
echo nun wird Direct X installiert
winget install --id=Microsoft.DirectX  -e
echo ...
echo ---------------------------
echo Schritt 7.3 - .Net-Framework Installieren
echo ---------------------------
echo nun wird .Net-Framework installiert
winget install --id=Microsoft.dotNetFramework -e 
echo ...
echo ---------------------------
echo Schritt 7.4 - Alle Programme Updaten
echo ---------------------------
echo Nun werden alle Programme auf den aktuellstens stand gebracht
winget upgrade --all --include-unknown
echo ...
echo ---------------------------
echo Schritt 7.5 - Nuetzliche Programme installieren
echo ---------------------------
winget install --id=RARLab.WinRAR -e && winget install --id=VideoLAN.VLC -e  && winget install --id=Notepad++.Notepad++ -e  && winget install --id=Discord.Discord -e  && winget install --id=Valve.Steam -e && winget install --id=REALiX.HWiNFO -e 
cls

echo ---------------------------
echo Schritt 8 - Sophia Script
echo ---------------------------
Powershell.exe -executionpolicy remotesigned -File "C:\Windows_Optimisation_Pack\_Files\Sophia Script\Sophia.ps1"
