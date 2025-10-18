# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

$Branch = "Beta"

Write-Host " Apply Optimal NVIDIA Settings"

# Download and Extract Nvidia Profile Inspector
Start-BitsTransfer -Source "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip" -Destination "$env:temp\NvidiaProfileInspector.zip"
Expand-Archive $env:temp\NvidiaProfileInspector.zip $env:temp\NvidiaProfileInspector

# Download Nvidia Profile Inspector Settings
Start-BitsTransfer -Source "https://github.com/Marvin700/Windows_Optimisation_Pack/raw/$Branch/config/NvidiaProfileInspector.nip" -Destination "$env:temp\NvidiaProfileInspector\Settings.nip"

Start-Process -wait "$env:TEMP\NvidiaProfileInspector\NvidiaProfileInspector.exe" -args "$env:TEMP\NvidiaProfileInspector\Settings.nip -silent"