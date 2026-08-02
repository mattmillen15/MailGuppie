#!/usr/bin/env python3
"""
m365_provision.py - Add/verify domains in M365 tenant via Graph API device code auth
Writes token to /tmp/m365_token for subsequent Exchange PowerShell use.
"""

import json
import sys
import time
import requests
from pathlib import Path

CF_TOKEN    = Path("~/.cloudflare/token").expanduser().read_text().strip()
CLIENT_ID   = "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph Command Line Tools
TENANT      = "247supportsolutions.onmicrosoft.com"
GRAPH       = "https://graph.microsoft.com/v1.0"
CF_API      = "https://api.cloudflare.com/client/v4"
TOKEN_FILE  = Path("/tmp/m365_token")

TARGET_DOMAINS = [
    "247supportsolutions.com",
    "bchipfinancial.com",
    "crbanking.com",
    "memphisheartclinic.com",
    "omgresorts.com",
]


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def device_code_auth():
    resp = requests.post(
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode",
        data={
            "client_id": CLIENT_ID,
            "scope": "https://graph.microsoft.com/Domain.ReadWrite.All "
                     "https://graph.microsoft.com/Directory.AccessAsUser.All "
                     "offline_access",
        },
    )
    d = resp.json()
    if "error" in d:
        print(f"[-] Device code error: {d}")
        sys.exit(1)

    print(f"\n{'='*58}")
    print(f"  Open on your phone: {d['verification_uri']}")
    print(f"  Enter code:         {d['user_code']}")
    print(f"{'='*58}\n")
    sys.stdout.flush()

    interval = d.get("interval", 5)
    deadline = time.time() + d["expires_in"]

    while time.time() < deadline:
        time.sleep(interval)
        tr = requests.post(
            f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": CLIENT_ID,
                "device_code": d["device_code"],
            },
        )
        td = tr.json()
        if "access_token" in td:
            print("[+] Authenticated via Graph API")
            TOKEN_FILE.write_text(td["access_token"])
            TOKEN_FILE.chmod(0o600)
            return td["access_token"]
        err = td.get("error", "")
        if err == "slow_down":
            interval += 5
        elif err != "authorization_pending":
            print(f"[-] Auth error: {td}")
            sys.exit(1)

    print("[-] Auth timed out")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Graph API helpers
# ---------------------------------------------------------------------------

def g(method, path, token, **kwargs):
    r = requests.request(
        method,
        f"{GRAPH}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        **kwargs,
    )
    return r.json()


# ---------------------------------------------------------------------------
# Cloudflare helpers
# ---------------------------------------------------------------------------

def cf_headers():
    return {"Authorization": f"Bearer {CF_TOKEN}", "Content-Type": "application/json"}


def cf_zone(domain):
    apex = ".".join(domain.split(".")[-2:])
    r = requests.get(f"{CF_API}/zones?name={apex}&per_page=5", headers=cf_headers())
    zones = r.json().get("result", [])
    return zones[0]["id"] if zones else None


def cf_upsert(zone_id, rtype, name, content):
    r = requests.get(
        f"{CF_API}/zones/{zone_id}/dns_records?type={rtype}&per_page=100",
        headers=cf_headers(),
    )
    existing = [x for x in r.json().get("result", []) if x["name"] == name]
    payload = {"type": rtype, "name": name, "content": content, "ttl": 1, "proxied": False}
    if existing:
        rid = existing[0]["id"]
        requests.put(f"{CF_API}/zones/{zone_id}/dns_records/{rid}", headers=cf_headers(), json=payload)
        return "updated"
    requests.post(f"{CF_API}/zones/{zone_id}/dns_records", headers=cf_headers(), json=payload)
    return "created"


def cf_set_mx(zone_id, domain, mx_target):
    r = requests.get(
        f"{CF_API}/zones/{zone_id}/dns_records?type=MX&per_page=100",
        headers=cf_headers(),
    )
    for rec in r.json().get("result", []):
        requests.delete(f"{CF_API}/zones/{zone_id}/dns_records/{rec['id']}", headers=cf_headers())

    payload = {"type": "MX", "name": domain, "content": mx_target, "priority": 0, "ttl": 1, "proxied": False}
    requests.post(f"{CF_API}/zones/{zone_id}/dns_records", headers=cf_headers(), json=payload)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    token = device_code_auth()

    # List existing tenant domains
    existing = {d["id"]: d for d in g("GET", "/domains", token).get("value", [])}
    print("\n[*] Current tenant domains:")
    for d in existing.values():
        status = "verified" if d["isVerified"] else "UNVERIFIED"
        default = "  ← primary" if d.get("isDefault") else ""
        print(f"    {d['id']:40s}  {status}{default}")

    print()

    for domain in TARGET_DOMAINS:
        print(f"\n{'─'*56}")
        print(f"  {domain}")
        print(f"{'─'*56}")

        zone_id = cf_zone(domain)
        if not zone_id:
            print(f"  [-] No Cloudflare zone found — skipping")
            continue

        mx_target = domain.replace(".", "-") + ".mail.protection.outlook.com"

        if domain in existing and existing[domain]["isVerified"]:
            print(f"  [✓] Already verified in tenant")
        else:
            if domain not in existing:
                print(f"  [+] Adding to tenant...")
                result = g("POST", "/domains", token, json={"id": domain})
                if "error" in result:
                    print(f"  [-] Add failed: {result['error'].get('message', result['error'])}")
                    continue
                print(f"  [+] Domain added (unverified)")
            else:
                print(f"  [~] In tenant but unverified")

            # Get verification TXT
            vr = g("GET", f"/domains/{domain}/verificationDnsRecords", token)
            txt_value = None
            for rec in vr.get("value", []):
                if rec.get("recordType") == "Txt":
                    txt_value = rec.get("text", "")
                    break

            if not txt_value:
                print(f"  [-] No verification TXT in response: {json.dumps(vr)}")
                continue

            action = cf_upsert(zone_id, "TXT", domain, txt_value)
            print(f"  [+] Verification TXT {action}: {txt_value}")
            print(f"  [*] Waiting 15s for DNS...")
            sys.stdout.flush()
            time.sleep(15)

            vresult = g("POST", f"/domains/{domain}/verify", token, json={})
            if vresult.get("isVerified"):
                print(f"  [✓] Domain verified!")
            else:
                errs = vresult.get("error", {})
                print(f"  [!] Verify response: {json.dumps(vresult)}")
                print(f"      (DNS may need longer to propagate — re-run if needed)")

        # SPF
        spf = "v=spf1 include:spf.protection.outlook.com -all"
        action = cf_upsert(zone_id, "TXT", domain, spf)
        print(f"  [+] SPF {action}")

        # MX  — skip primary 247supportsolutions.com, it's already correct
        if domain != "247supportsolutions.com":
            cf_set_mx(zone_id, domain, mx_target)
            print(f"  [+] MX set: {mx_target}")

        # DMARC (set if not already present or using non-M365 value)
        dmarc_name  = f"_dmarc.{domain}"
        dmarc_value = f"v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}; fo=1"
        action = cf_upsert(zone_id, "TXT", dmarc_name, dmarc_value)
        print(f"  [+] DMARC {action}")

    print(f"\n{'='*56}")
    print(f"  Graph phase complete.")
    print(f"  Next: run exchange_provision.ps1 for mailboxes + DKIM")
    print(f"{'='*56}\n")


if __name__ == "__main__":
    main()
