# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

$Branch = "Beta"

# Download and Nvidia Profile Inspector
Start-BitsTransfer -Source "https://github.com/Marvin700/Windows_Optimisation_Pack/raw/$Branch/config/NvidiaProfileInspector.zip" -Destination "$env:temp\NvidiaProfileInspector.zip"
Expand-Archive $env:temp\NvidiaProfileInspector.zip $env:temp


Start-Process -wait "$env:TEMP\NvidiaProfileInspector\NvidiaProfileInspector.exe" -args "$env:TEMP\NvidiaProfileInspector\Settings.nip -silent"