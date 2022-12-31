$Host.UI.RawUI.WindowTitle = "GPU Driver-Cleaner | $([char]0x00A9) Marvin700" 
Start-BitsTransfer -Source "https://github.com/Marvin700/Windows_Optimisation_Pack/raw/main/DDU.zip" -Destination $env:temp\DDU.zip
Expand-Archive $env:temp\DDU.zip $env:temp
Set-Location $env:temp\DDU\
& '.\Display Driver Uninstaller.exe' -silent -removemonitors -cleannvidia -cleanamd -cleanintel -removephysx -removegfe -removenvbroadcast -removenvcp -removeintelcp -removeamdcp -restart
Write-Warning "Please Wait..."
Write-Warning "The Driver Removal takes up to 10 Minutes"

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUq3rtFfgLLrJonoAHgAN5aAlQ
# Bw+gggMcMIIDGDCCAgCgAwIBAgIQJBEmIU6B/6pL+Icl+8AGsDANBgkqhkiG9w0B
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
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUjZIP7FLctevXKFqcJ/LKV7IjDUQwDQYJ
# KoZIhvcNAQEBBQAEggEAwEfq1vN4qkoanMCu1j0077k2rW0U1u5TwUntPrNIrQ2w
# pnhXqKCbIeUql7E8SqRCXntsyI6t7Rz6ZlFufWhDfb5d96EWVU8rwoBG+ESNsxkW
# n0Z02P7enQ1bwzF6K4TpXrQfvzn1OOvLBmUljrV4/A2jTuFidAFJpBReMNFFiVgK
# 2mA2+sGsR1pU0eFNl+8ox+Bs9mNf+xJos+QQlSPk03rgrRukjyw/HYVEZZKaMq3D
# jyGMh71ok04NA1TLV78Edeqyc1EueTRzNnfnhmtK1lqd73rKnJmpt0d0t/lDtbHD
# 4/QU3wT3U6b87PWi5bHC45fALQC4sa9FlgpzsDdcwQ==
# SIG # End signature block
