$Host.UI.RawUI.WindowTitle = "Windows_Optimisation_Pack Cleaner | $([char]0x00A9) Marvin700"
$Key = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches
ForEach($result in $Key)
{If($result.name -eq "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\DownloadsFolder"){}Else{
$Regkey = 'HKLM:' + $result.Name.Substring( 18 )
New-ItemProperty -Path $Regkey -Name 'StateFlags0001' -Value 2 -PropertyType DWORD -Force -EA 0 | Out-Null}}
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
Dism.exe /Online /Cleanup-Image /spsuperseded
Dism.exe /online /Cleanup-Image /StartComponentCleanup
Clear-BCCache -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path $env:TEMP -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse 
Get-ChildItem -Path $env:windir\Temp\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse 
Get-ChildItem -Path $env:windir\Prefetch *.* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse 
Get-ChildItem -Path $env:SystemRoot\SoftwareDistribution\Download -Recurse -Force | Remove-Item -Recurse -Force
Get-ChildItem -Path $env:ProgramData\Microsoft\Windows\RetailDemo\* -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse
Clear-Host
Start-Process cleanmgr.exe /sagerun:1 -Wait
vssadmin delete shadows /all /quiet
Write-Host "The System has been cleaned"

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDe1BLj5Du07xjxVoD0/emQmC
# Jb2gggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUb70SU+m0VR4YHfk/SdLgK5ta9N8wDQYJ
# KoZIhvcNAQEBBQAEggEAlUqIsSN97qNyK6K8/6/PwsJHaYIw6ejc6V+ekNFLnm2P
# 71vLoC6ikONWymLX5xh8YPf+WA80SyqAMM9+22U/3eVSpvSafNvxPn4KAilwVgUx
# xssW64+35J/mTvMqiPnHGuDeIv32pHD0HTFJdaD3BcBrz/hJFQvAN0z3wHmy9CWf
# 01ci+MtvhpcxRtpdpI9XKyWfCUWeANSzTw8IDVTjjWEfCa+GmwIv1dZjiPQVES9d
# HOhhRofaprS2KaynBuDvPbky7QZrWRK2tKkMi5K69U8/Y3yjWmkjeeJp8zT8TsS/
# 26Lj7OXksoOVuobuWsBZgtXBVtvHCFijSbOLgWaV+Q==
# SIG # End signature block
