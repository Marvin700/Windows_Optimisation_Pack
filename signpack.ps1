cd Cert:\CurrentUser\My\
$Cert = Get-ChildItem "7B29DE403EDBD036E73DA32BA83437090EC2CA16"
Set-AuthenticodeSignature -Certificate:$cert -FilePath:"C:\Windows_Optimisation_Pack\_Files\Windows-Cleaner.ps1"