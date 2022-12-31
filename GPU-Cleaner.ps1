$Host.UI.RawUI.WindowTitle = "GPU Treiber Cleaner | $([char]0x00A9) Marvin700" 
Start-BitsTransfer -Source "https://github.com/Marvin700/Windows_Optimisation_Pack/raw/main/DDU.zip" -Destination $env:temp\DDU.zip
Expand-Archive $env:temp\DDU.zip $env:temp
Set-Location $env:temp\DDU\
& '.\Display Driver Uninstaller.exe' -silent -removemonitors -cleannvidia -cleanamd -cleanintel -removephysx -removegfe -removenvbroadcast -removenvcp -removeintelcp -removeamdcp -restart
# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxt7eaT1Z1Aq53x+HM2D4AHVD
# uASgggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU8O/j91pkGj7TIVLOwg2Z0PhdV2AwDQYJ
# KoZIhvcNAQEBBQAEggEAWFy7byG4Zwp/GbPMjEsIcmlTJ4CbACq+h6K1pMFPe4ny
# inSUO8F1CUGRkSScFM5yhggQuRi6umAjlniBt0EUMEtXkjg/lu+4+wrDzH7t/Q5m
# yCdf9xTQelSxuWrkabEYqWYE+TubqTuPY0s8Ub46NtSzmO3y5rte3AlX3PQ979mZ
# 1qevgxDyyJsADFGkqkowVITmZNTeBgevYG4n7Be5VjXmvRDPurzFPqzFUpNS+7fj
# wk1w+k5VR/He6IYC+rgMQdRaXka/q6+q39XObc/3MYUbKpaGeTIT6pR1U1V/r9jP
# IX0jrqxBVUC3EqgPxw3NrRoEa/dy05nLLBeSpzC0Mw==
# SIG # End signature block
