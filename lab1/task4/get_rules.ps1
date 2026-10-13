$RuleNames = @("Block_http", "Allow_rdp", "Block_ftp", "Block_ping")

Get-NetFirewallRule -DisplayName $RuleNames | ForEach-Object {
    $PortFilter = $_ | Get-NetFirewallPortFilter
    [PSCustomObject]@{
        DisplayName  = $_.DisplayName
        Enabled      = $_.Enabled
        Protocol     = $PortFilter.Protocol
        LocalPort    = $PortFilter.LocalPort
        RemotePort   = $PortFilter.RemotePort
        Action       = $_.Action
        Profile      = $_.Profile
    }
} | Format-Table -AutoSize
