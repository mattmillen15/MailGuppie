# fix_relay_account.ps1
# Grant Send As to itsupport@ on all shared mailboxes + enable SMTP AUTH

$ErrorActionPreference = "Stop"

$Relay   = "itsupport@247supportsolutions.com"
$Admin   = "Matt.Millen@247supportsolutions.onmicrosoft.com"
$Domains = @(
    "247supportsolutions.com",
    "bchipfinancial.com",
    "crbanking.com",
    "memphisheartclinic.com",
    "omgresorts.com"
)

Write-Host "`n[*] Connecting to Exchange Online (device code)..." -ForegroundColor Cyan
Connect-ExchangeOnline -UserPrincipalName $Admin -Device -ShowBanner:$false
Write-Host "[+] Connected`n" -ForegroundColor Green

# Enable SMTP AUTH for relay account
Write-Host "[*] Enabling SMTP AUTH for $Relay..."
Set-CASMailbox -Identity $Relay -SmtpClientAuthenticationDisabled $false
Write-Host "[+] SMTP AUTH enabled`n"

foreach ($domain in $Domains) {
    $mbx = "noreply@$domain"
    Write-Host "  $mbx"

    # Grant Send As to itsupport@
    $already = Get-RecipientPermission -Identity $mbx -Trustee $Relay -ErrorAction SilentlyContinue |
               Where-Object { $_.AccessRights -contains "SendAs" }
    if ($already) {
        Write-Host "    [~] Send As already granted to $Relay"
    } else {
        Add-RecipientPermission -Identity $mbx -Trustee $Relay -AccessRights SendAs -Confirm:$false | Out-Null
        Write-Host "    [+] Send As granted: $Relay"
    }

    # Remove Matt.Millen Send As (clean up)
    $mattPerm = Get-RecipientPermission -Identity $mbx -Trustee $Admin -ErrorAction SilentlyContinue |
                Where-Object { $_.AccessRights -contains "SendAs" }
    if ($mattPerm) {
        Remove-RecipientPermission -Identity $mbx -Trustee $Admin -AccessRights SendAs -Confirm:$false
        Write-Host "    [+] Removed Send As for $Admin"
    }
}

Write-Host "`n[+] Done — $Relay is the relay account"
Disconnect-ExchangeOnline -Confirm:$false
