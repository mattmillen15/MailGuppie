#!/usr/bin/env python3
"""
dkim_to_cloudflare.py - Read /tmp/dkim_results.json from exchange_provision.ps1
and add DKIM CNAMEs to Cloudflare with proxied=False.
"""

import json
import sys
import requests
from pathlib import Path

CF_TOKEN = Path("~/.cloudflare/token").expanduser().read_text().strip()
CF_API   = "https://api.cloudflare.com/client/v4"
SRC      = Path("/tmp/dkim_results.json")


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
    payload  = {"type": rtype, "name": name, "content": content, "ttl": 1, "proxied": False}
    if existing:
        rid = existing[0]["id"]
        requests.put(f"{CF_API}/zones/{zone_id}/dns_records/{rid}", headers=cf_headers(), json=payload)
        return "updated"
    requests.post(f"{CF_API}/zones/{zone_id}/dns_records", headers=cf_headers(), json=payload)
    return "created"


def main():
    if not SRC.exists():
        print(f"[-] {SRC} not found — run exchange_provision.ps1 first")
        sys.exit(1)

    data = json.loads(SRC.read_text())
    print(f"[*] Adding DKIM CNAMEs for {len(data)} domain(s)\n")

    for domain, cnames in data.items():
        zone_id = cf_zone(domain)
        if not zone_id:
            print(f"[-] No zone for {domain} — skipping")
            continue

        apex = ".".join(domain.split(".")[-2:])
        s1_name = f"selector1._domainkey.{apex}"
        s2_name = f"selector2._domainkey.{apex}"
        s1_val  = cnames.get("S1", "")
        s2_val  = cnames.get("S2", "")

        if s1_val:
            action = cf_upsert(zone_id, "CNAME", s1_name, s1_val)
            print(f"[+] {domain}  selector1 CNAME {action}")
            print(f"    {s1_name}  ->  {s1_val}")
        if s2_val:
            action = cf_upsert(zone_id, "CNAME", s2_name, s2_val)
            print(f"[+] {domain}  selector2 CNAME {action}")
            print(f"    {s2_name}  ->  {s2_val}")
        print()

    print("[*] Done — run dns_provision.py status <domain> to verify")


if __name__ == "__main__":
    main()
