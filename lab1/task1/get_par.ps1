$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Script is running only with admin rights"
    Write-Host "Restart PowerShell ISE/Console with admin rights" -ForegroundColor Red
    Exit
}

$OutputFile = Join-Path $PSScriptRoot "paruser.txt"
$TempCfg = Join-Path $env:TEMP "sec_policy.cfg"

Write-Host "Exporting local group policy... Please wait..." -ForegroundColor Cyan
secedit /export /cfg $TempCfg /areas SECURITYPOLICY | Out-Null
if (-not (Test-Path $TempCfg)) {
    Write-Error "Cannot export local group policy"
    Exit
}

$RawPolicy = Get-Content $TempCfg -Encoding Unicode
$MinPassLen = ($RawPolicy | Select-String "MinimumPasswordLength")[0].ToString().Split('=')[1].Trim()
$PassComplexity = ($RawPolicy | Select-String "PasswordComplexity")[0].ToString().Split('=')[1].Trim()
$ComplexityStatus = if ($PassComplexity -eq "1") { "On" } else { "Off" }
$MaxPassAge = ($RawPolicy | Select-String "MaximumPasswordAge")[0].ToString().Split('=')[1].Trim()

$OutputBlock = @"
Local group policy
==================

Minimum password length: $MinPassLen
Password complexity: $ComplexityStatus
Maximum password age: $MaxPassAge
"@

Write-Host $OutputBlock -ForegroundColor Green

$OutputBlock | Out-File -FilePath $OutputFile -Encoding utf8 -Force
Write-Host "`nResult was saved on file: $OutputFile" -ForegroundColor Green
