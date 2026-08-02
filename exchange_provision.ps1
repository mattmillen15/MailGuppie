# exchange_provision.ps1
# Device code auth to Exchange Online, then for each domain:
#   - create shared mailbox noreply@domain
#   - grant Matt.Millen Send As
#   - enable DKIM, output CNAME targets

$ErrorActionPreference = "Stop"

$Relay   = "Matt.Millen@247supportsolutions.onmicrosoft.com"
$Domains = @(
    "247supportsolutions.com",
    "bchipfinancial.com",
    "crbanking.com",
    "memphisheartclinic.com",
    "omgresorts.com"
)

Write-Host "`n[*] Connecting to Exchange Online (device code)..." -ForegroundColor Cyan
Connect-ExchangeOnline -UserPrincipalName $Relay -Device -ShowBanner:$false

Write-Host "[+] Connected`n" -ForegroundColor Green

# Collect DKIM results to print at end
$DkimResults = @{}

foreach ($domain in $Domains) {
    Write-Host ("─" * 56) -ForegroundColor DarkGray
    Write-Host "  $domain" -ForegroundColor Cyan
    Write-Host ("─" * 56) -ForegroundColor DarkGray

    $mbx = "noreply@$domain"

    # --- Shared Mailbox ---
    $existing = Get-Mailbox -Identity $mbx -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "  [~] Shared mailbox already exists: $mbx"
    } else {
        try {
            New-Mailbox -Shared -Name "noreply-$domain" -PrimarySmtpAddress $mbx | Out-Null
            Write-Host "  [+] Shared mailbox created: $mbx"
        } catch {
            Write-Host "  [-] Mailbox error: $_" -ForegroundColor Red
        }
    }

    # --- Send As ---
    $perm = Get-RecipientPermission -Identity $mbx -Trustee $Relay -ErrorAction SilentlyContinue |
            Where-Object { $_.AccessRights -contains "SendAs" }
    if ($perm) {
        Write-Host "  [~] Send As already granted to $Relay"
    } else {
        try {
            Add-RecipientPermission -Identity $mbx -Trustee $Relay -AccessRights SendAs -Confirm:$false | Out-Null
            Write-Host "  [+] Send As granted: $Relay -> $mbx"
        } catch {
            Write-Host "  [-] Send As error: $_" -ForegroundColor Red
        }
    }

    # --- DKIM ---
    $dkim = Get-DkimSigningConfig -Identity $domain -ErrorAction SilentlyContinue
    if ($null -eq $dkim) {
        try {
            New-DkimSigningConfig -DomainName $domain -Enabled $true | Out-Null
            Write-Host "  [+] DKIM signing config created"
            $dkim = Get-DkimSigningConfig -Identity $domain -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  [-] DKIM create error: $_" -ForegroundColor Red
        }
    } elseif (-not $dkim.Enabled) {
        try {
            Set-DkimSigningConfig -Identity $domain -Enabled $true | Out-Null
            Write-Host "  [+] DKIM enabled"
            $dkim = Get-DkimSigningConfig -Identity $domain
        } catch {
            Write-Host "  [-] DKIM enable error: $_" -ForegroundColor Red
        }
    } else {
        Write-Host "  [~] DKIM already enabled"
    }

    if ($dkim) {
        $s1 = $dkim.Selector1CNAME
        $s2 = $dkim.Selector2CNAME
        $DkimResults[$domain] = @{ S1 = $s1; S2 = $s2 }
        Write-Host "  [*] DKIM CNAMEs:"
        Write-Host "        selector1._domainkey.$domain"
        Write-Host "          -> $s1"
        Write-Host "        selector2._domainkey.$domain"
        Write-Host "          -> $s2"
    }

    Write-Host ""
}

# Summary of DKIM CNAMEs for Cloudflare
Write-Host ("=" * 56) -ForegroundColor Green
Write-Host "  DKIM CNAME SUMMARY (add to Cloudflare, proxied=off)" -ForegroundColor Green
Write-Host ("=" * 56) -ForegroundColor Green
foreach ($domain in $DkimResults.Keys) {
    Write-Host "`n  $domain"
    Write-Host "    selector1._domainkey.$domain  ->  $($DkimResults[$domain].S1)"
    Write-Host "    selector2._domainkey.$domain  ->  $($DkimResults[$domain].S2)"
}

# Write DKIM data to file for Python to pick up
$DkimResults | ConvertTo-Json -Depth 3 | Out-File -FilePath "/tmp/dkim_results.json" -Encoding utf8
Write-Host "`n[*] DKIM data saved to /tmp/dkim_results.json"

Disconnect-ExchangeOnline -Confirm:$false
Write-Host "[*] Done"
