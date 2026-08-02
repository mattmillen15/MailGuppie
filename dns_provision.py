#!/usr/bin/env python3
"""
dns_provision.py - Provision Cloudflare DNS for M365 engagement domains

Commands:
  status   <domain>                          Show current SPF/DKIM/DMARC/MX
  verify   <domain> <MS=msXXXXXXXX>         Add M365 domain verification TXT
  spf      <domain>                          Set SPF for M365
  dkim     <domain> <cname1> <cname2>        Add DKIM CNAMEs from M365 Defender
  dmarc    <domain> [--rua <email>]          Set DMARC policy
  full     <domain>                          Interactive guided setup (all steps)

Token:  set CF_TOKEN env var  or  store in ~/.cloudflare/token
"""

import argparse
import json
import os
import sys
import requests
from textwrap import indent

CF_API   = "https://api.cloudflare.com/client/v4"
TOKEN_FILE = os.path.expanduser("~/.cloudflare/token")

BANNER = """
╔════════════════════════════════════════════════╗
║           dns_provision  (M365+CF)             ║
╚════════════════════════════════════════════════╝
"""

SPF_VALUE   = "v=spf1 include:spf.protection.outlook.com -all"
DMARC_FMT   = "v=DMARC1; p=quarantine; rua=mailto:{rua}; ruf=mailto:{rua}; fo=1"


# ---------------------------------------------------------------------------
# Cloudflare API helpers
# ---------------------------------------------------------------------------

def get_token():
    token = os.environ.get("CF_TOKEN", "").strip()
    if token:
        return token
    if os.path.exists(TOKEN_FILE):
        return open(TOKEN_FILE).read().strip()
    print("[-] No token found. Set CF_TOKEN or create ~/.cloudflare/token")
    sys.exit(1)


def cf(method, path, token, **kwargs):
    resp = requests.request(
        method,
        f"{CF_API}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        **kwargs,
    )
    data = resp.json()
    if not data.get("success"):
        errors = data.get("errors", [])
        raise RuntimeError(f"Cloudflare API error: {errors}")
    return data.get("result")


def get_zone(domain, token):
    apex = ".".join(domain.strip().split(".")[-2:])
    zones = cf("GET", f"/zones?name={apex}&per_page=5", token)
    if zones:
        return zones[0]
    zones = cf("GET", f"/zones?name={domain}&per_page=5", token)
    if zones:
        return zones[0]
    return None


def list_records(zone_id, token, rtype=None):
    path = f"/zones/{zone_id}/dns_records?per_page=100"
    if rtype:
        path += f"&type={rtype}"
    return cf("GET", path, token)


def upsert(zone_id, token, rtype, name, content, ttl=1, proxied=False):
    existing = [r for r in list_records(zone_id, token, rtype) if r["name"] == name]
    payload  = {"type": rtype, "name": name, "content": content, "ttl": ttl, "proxied": proxied}
    if existing:
        cf("PUT", f"/zones/{zone_id}/dns_records/{existing[0]['id']}", token, json=payload)
        return "updated"
    cf("POST", f"/zones/{zone_id}/dns_records", token, json=payload)
    return "created"


def delete_record(zone_id, token, record_id):
    cf("DELETE", f"/zones/{zone_id}/dns_records/{record_id}", token)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_status(domain, token):
    zone = get_zone(domain, token)
    if not zone:
        print(f"[-] Zone not found for {domain}")
        sys.exit(1)

    print(f"\n  Domain : {domain}")
    print(f"  Zone   : {zone['id']}  [{zone['status']}]\n")

    for rtype, label in [("TXT", "TXT"), ("CNAME", "CNAME"), ("MX", "MX")]:
        records = list_records(zone["id"], token, rtype)
        relevant = []
        for r in records:
            name = r["name"]
            val  = r["content"]
            if rtype == "TXT" and any(k in val for k in ("v=spf1", "v=DMARC1", "MS=ms", "v=DKIM")):
                relevant.append((name, val))
            elif rtype == "CNAME" and "_domainkey" in name:
                relevant.append((name, val))
            elif rtype == "MX":
                relevant.append((name, f"priority={r.get('priority','')}  {val}"))
        if relevant:
            print(f"  {label}:")
            for name, val in relevant:
                print(f"    {name}")
                print(f"      {val}")
            print()


def cmd_verify(domain, txt_value, token):
    if not txt_value.startswith("MS="):
        print(f"[-] Verification value should start with MS=  (got: {txt_value})")
        sys.exit(1)
    zone = _require_zone(domain, token)
    action = upsert(zone["id"], token, "TXT", domain, txt_value)
    print(f"[+] TXT {action}: {domain}  →  {txt_value}")
    print(f"\n    Go verify in Entra Admin now, then come back to run:")
    print(f"    python3 dns_provision.py dkim {domain} <selector1-cname> <selector2-cname>")


def cmd_spf(domain, token):
    zone = _require_zone(domain, token)
    action = upsert(zone["id"], token, "TXT", domain, SPF_VALUE)
    print(f"[+] SPF {action}: {domain}")
    print(f"    {SPF_VALUE}")


def cmd_dkim(domain, cname1, cname2, token):
    """
    M365 provides two CNAME values in the format:
      selector1._domainkey.domain.com  →  selector1-domain-com._domainkey.tenant.onmicrosoft.com
      selector2._domainkey.domain.com  →  selector2-domain-com._domainkey.tenant.onmicrosoft.com

    Pass the *target* (right-hand side) values; we derive the record names.
    Or pass full  name=value  pairs if the names differ.
    """
    zone   = _require_zone(domain, token)
    apex   = ".".join(domain.split(".")[-2:])

    entries = []
    for i, val in enumerate([cname1, cname2], 1):
        if "=" in val:
            name, _, target = val.partition("=")
            entries.append((name.strip(), target.strip()))
        else:
            sel  = f"selector{i}._domainkey.{apex}"
            entries.append((sel, val.strip()))

    for name, target in entries:
        action = upsert(zone["id"], token, "CNAME", name, target)
        print(f"[+] DKIM CNAME {action}:")
        print(f"    {name}  →  {target}")


def cmd_dmarc(domain, rua, token):
    zone  = _require_zone(domain, token)
    value = DMARC_FMT.format(rua=rua)
    name  = f"_dmarc.{domain}"
    action = upsert(zone["id"], token, "TXT", name, value)
    print(f"[+] DMARC {action}: {name}")
    print(f"    {value}")


def cmd_full(domain, token):
    """Interactive guided setup for a domain."""
    zone = _require_zone(domain, token)
    apex = ".".join(domain.split(".")[-2:])

    print(f"\n  Provisioning: {domain}  (zone {zone['id']})")
    print("  " + "-" * 50)

    # Step 1: M365 verification
    print("\n[1/4] M365 DOMAIN VERIFICATION")
    print("      Entra Admin → Custom domain names → Add domain → get TXT value")
    txt = input("      Paste MS=ms... value (or press Enter to skip): ").strip()
    if txt:
        if not txt.startswith("MS="):
            print(f"      [-] Expected MS=ms... format, got: {txt}")
        else:
            action = upsert(zone["id"], token, "TXT", domain, txt)
            print(f"      [+] TXT {action}: {txt}")
            print("      → Go verify in Entra Admin, then continue here.")
            input("      Press Enter when verified in M365...")

    # Step 2: SPF
    print("\n[2/4] SPF")
    action = upsert(zone["id"], token, "TXT", domain, SPF_VALUE)
    print(f"      [+] SPF {action}")
    print(f"          {SPF_VALUE}")

    # Step 3: DKIM
    print("\n[3/4] DKIM")
    print("      Defender → Email & collaboration → Policies & rules → DKIM")
    print(f"      Find {domain} → Enable → copy the two CNAME records")
    print()
    print("      Paste each CNAME target (right-hand value) from M365 Defender,")
    print(f"      or full  name=value  pairs. Leave blank to skip.")
    s1 = input(f"      selector1._domainkey.{apex}  →  ").strip()
    s2 = input(f"      selector2._domainkey.{apex}  →  ").strip()
    if s1 or s2:
        for i, val in enumerate(filter(None, [s1, s2]), 1):
            if "=" in val:
                name, _, target = val.partition("=")
                name, target = name.strip(), target.strip()
            else:
                name   = f"selector{i}._domainkey.{apex}"
                target = val
            action = upsert(zone["id"], token, "CNAME", name, target)
            print(f"      [+] DKIM CNAME {action}: {name}  →  {target}")

    # Step 4: DMARC
    print("\n[4/4] DMARC")
    default_rua = f"dmarc@{domain}"
    rua = input(f"      RUA report address [{default_rua}]: ").strip() or default_rua
    dmarc_value = DMARC_FMT.format(rua=rua)
    dmarc_name  = f"_dmarc.{domain}"
    action = upsert(zone["id"], token, "TXT", dmarc_name, dmarc_value)
    print(f"      [+] DMARC {action}: {dmarc_name}")
    print(f"          {dmarc_value}")

    print("\n  Done. Run  python3 dns_provision.py status " + domain + "  to verify.")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_zone(domain, token):
    zone = get_zone(domain, token)
    if not zone:
        print(f"[-] Zone not found in Cloudflare for {domain}")
        sys.exit(1)
    return zone


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        usage="%(prog)s <command> <domain> [args]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    sub = parser.add_subparsers(dest="cmd", metavar="command")

    p_status = sub.add_parser("status", help="Show SPF/DKIM/DMARC/MX records")
    p_status.add_argument("domain")

    p_verify = sub.add_parser("verify", help="Add M365 domain verification TXT")
    p_verify.add_argument("domain")
    p_verify.add_argument("txt", metavar="MS=msXXXXXXXX")

    p_spf = sub.add_parser("spf", help="Set SPF record for M365")
    p_spf.add_argument("domain")

    p_dkim = sub.add_parser("dkim", help="Add DKIM CNAMEs from M365 Defender")
    p_dkim.add_argument("domain")
    p_dkim.add_argument("cname1", metavar="selector1-target")
    p_dkim.add_argument("cname2", metavar="selector2-target")

    p_dmarc = sub.add_parser("dmarc", help="Set DMARC policy")
    p_dmarc.add_argument("domain")
    p_dmarc.add_argument("--rua", metavar="email", help="Report address (default: dmarc@<domain>)")

    p_full = sub.add_parser("full", help="Interactive guided full setup")
    p_full.add_argument("domain")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args   = parser.parse_args()
    token  = get_token()

    try:
        if args.cmd == "status":
            cmd_status(args.domain, token)
        elif args.cmd == "verify":
            cmd_verify(args.domain, args.txt, token)
        elif args.cmd == "spf":
            cmd_spf(args.domain, token)
        elif args.cmd == "dkim":
            cmd_dkim(args.domain, args.cname1, args.cname2, token)
        elif args.cmd == "dmarc":
            rua = args.rua or f"dmarc@{args.domain}"
            cmd_dmarc(args.domain, rua, token)
        elif args.cmd == "full":
            cmd_full(args.domain, token)
        else:
            parser.print_help()
    except RuntimeError as e:
        print(f"[-] {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
