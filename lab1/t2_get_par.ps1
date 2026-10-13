$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Script is running only with admin rights"
    Write-Host "Restart PowerShell ISE/Console with admin rights" -ForegroundColor Red
    Exit
}

$OutputFile = Join-Path $PSScriptRoot "paruser_2.txt"
$TempCfg = Join-Path $env:TEMP "sec_policy.cfg"

Write-Host "Exporting local group policy... Please wait..." -ForegroundColor Cyan
secedit /export /cfg $TempCfg /areas USER_RIGHTS SECURITYPOLICY | Out-Null
if (-not (Test-Path $TempCfg)) {
    Write-Error "Cannot export local group policy"
    Exit
}

$RawPolicy = Get-Content $TempCfg -Encoding Unicode

$GuestUser = Get-LocalUser -Name "Guest"

function Translate-SidString ($sidString) {
    if (-not $sidString) { return "Deny all" }
    $accounts = @()
    foreach ($part in $sidString.Split(',')) {
        $trimmed = $part.Trim().Replace('*', '')
        if ($trimmed -match "^S-1-") {
            try {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($trimmed)
                $accounts += $sid.Translate([Security.Principal.NTAccount]).Value
            } catch {
                $accounts += $trimmed
            }
        } else {
            $accounts += $trimmed
        }
    }
    return $accounts -join ", "
}

$OutputBlock = [System.Collections.Generic.List[string]]::new()

if ($GuestUser) {
    if ($GuestUser.Enabled) {
        $OutputBlock.add("Guest user: existing, enabled")
    } else {
        $OutputBlock.add("Guest user: existing, not enabled")
    }
} else {
    $OutputBlock.add("Guest user: not found")
}

$DenyNetLine = $RawPolicy | Select-String -Pattern "^SeDenyNetworkLogonRight"
if ($DenyNetLine) {
    $RawVal = ($DenyNetLine -split "=")[1].Trim()
    $OutputBlock.add("Deny network logon: $(Translate-SidString $RawVal)")
} else {
    $OutputBlock.add("Deny network logon: <not configured>")
}

$BackupLine = $RawPolicy | Select-String -Pattern "^SeBackupPrivilege"
if ($BackupLine) {
    $RawVal = ($BackupLine -split "=")[1].Trim()
    $OutputBlock.add("Backup right: $(Translate-SidString $RawVal)")
} else {
    $OutputBlock.add("Backup right: <not configured>")
}

$ShutdownLine = $RawPolicy | Select-String -Pattern "ShutdownWithoutLogon"
if ($ShutdownLine) {
    $RawVal = ($ShutdownLine -split "=")[1].Trim()
    if ($RawVal -eq "4,0") {
        $OutputBlock.add("Shutdown without logon: denied for all")
    } else {
        $OutputBlock.add("Shutdown without logon: allowed")
    }
} else {
    $OutputBlock.add("Shutdown without logon: <not configured>")
}

$DenyRemoteLine = $RawPolicy | Select-String -Pattern "^SeDenyRemoteInteractiveLogonRight"
if ($DenyRemoteLine) {
    $RawVal = ($DenyRemoteLine -split "=")[1].Trim()
    $OutputBlock.add("Deny RDP access: $(Translate-SidString $RawVal)")
} else {
    $OutputBlock.add("Deny RDP access: <not configured>")
}

$OutputBlock | Tee-Object -FilePath $OutputFile
