$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack Cleaner | $([char]0x00A9) Marvin700" 
vssadmin delete shadows /all /quiet | Out-Null
Checkpoint-Computer -Description "Windows_Optimisation_Pack Cleaner" -RestorePointType MODIFY_SETTINGS 
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
Clear-Host
Write-Host "Datentraeger Bereinigung wird gestartet..."
Start-Process cleanmgr.exe /sagerun:1 -Wait
Write-Warning "The System has been cleaned"

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUvRbsZqB+rN2YMgUFyAWeRQnV
# Gm2gggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU39Og5ETyONA9vxyIwabOAmsVanswDQYJ
# KoZIhvcNAQEBBQAEggEAKWSKBL6XqPAt3o0y61Xr2SuYf/X7cL1ZPOaBNJZk4Um0
# WGPNApvuEeI2kNnmQ7RMwR42dBKT51kG3tPdlTU1iZQYbQIGrh8NZhpDFGSipeqX
# +Kh10LvC2yH9wwxF5WlGB/BV9R0nKYeBgmzO42qa9H5LyazKjt/1AZYMjxWgNy5S
# GxtFgQ1Dr9oSFhjeoDKffl/geaXVWQrGoyJl7xC12WtgizA5lNX2l3w+c+B5Tro9
# tgwDgY5Pw5+WNq77NWVFHIcP7Itcpd25pI1ltsW2iuLPeN8HFo/CzrEv+oNdY7Dy
# JZ7DsWFsxe+R3Jg8s/sq0zMPEPuHAN3COXIYfjC4QQ==
# SIG # End signature block
