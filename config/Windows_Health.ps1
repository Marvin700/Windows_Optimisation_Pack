# Windows_Optimisation_Pack @Marvin700
# windows-optimisation.de

$Branch = "Beta"

Dism /Online /Cleanup-Image /ScanHealth
Dism /Online /Cleanup-Image /RestoreHealth
sfc /SCANNOW
