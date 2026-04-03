rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "Detects suspicious PowerShell downloader behavior"
        author = "OpenAI"
        severity = "high"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "Invoke-WebRequest" nocase
        $ps3 = "DownloadFile" nocase
        $ps4 = "http://" nocase
        $ps5 = "https://" nocase

    condition:
        $ps1 and any of ($ps2, $ps3) and any of ($ps4, $ps5)
}


rule Suspicious_CMD_Downloader
{
    meta:
        description = "Detects suspicious CMD downloader patterns"
        author = "OpenAI"
        severity = "medium"

    strings:
        $c1 = "cmd.exe" nocase
        $c2 = "curl" nocase
        $c3 = "wget" nocase
        $c4 = "http://" nocase
        $c5 = "https://" nocase

    condition:
        $c1 and any of ($c2, $c3) and any of ($c4, $c5)
}


rule Encoded_PowerShell_Command
{
    meta:
        description = "Detects encoded PowerShell command usage"
        author = "OpenAI"
        severity = "high"

    strings:
        $e1 = "-encodedcommand" nocase
        $e2 = "powershell" nocase
        $e3 = "base64" nocase

    condition:
        $e1 or ($e2 and $e3)
}


rule Suspicious_Process_Injection_APIs
{
    meta:
        description = "Detects suspicious process injection API names"
        author = "OpenAI"
        severity = "high"

    strings:
        $a1 = "CreateRemoteThread" ascii
        $a2 = "WriteProcessMemory" ascii
        $a3 = "VirtualAllocEx" ascii
        $a4 = "OpenProcess" ascii

    condition:
        2 of them
}
