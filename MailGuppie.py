#!/usr/bin/env python3
"""
MailGuppie - Cloudflare Email Sender
"""

import argparse
import hashlib
import re
import sys
import time
import random
import requests
from datetime import datetime
from pathlib import Path


BANNER = """
╔════════════════════════════════════════════════╗
║                  MailGuppie                    ║
╚════════════════════════════════════════════════╝

          ><((((º>   ><((((º>   ><((((º>
"""

CF_API = "https://api.cloudflare.com/client/v4"


def generate_sha3_hash(email):
    hasher = hashlib.sha3_256()
    hasher.update(email.encode("utf-8"))
    return hasher.hexdigest()[22:42]


def load_config(path):
    config = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and ":" in line:
                key, _, value = line.partition(":")
                config[key.strip()] = value.strip()
    return config


def parse_template(path):
    content = Path(path).read_text()
    lines = content.split("\n")
    variables = {}
    body_start = 0

    for i, line in enumerate(lines):
        if line.strip().startswith("#"):
            m = re.match(r"#\s*(\w+):\s*(.+)", line)
            if m:
                variables[m.group(1)] = m.group(2).strip()
        elif line.strip():
            body_start = i
            break

    return variables, "\n".join(lines[body_start:])


def render(html_body, variables, target, hash_value):
    replacements = {
        "<SHA3_HASH>":    hash_value,
        "<TARGET_EMAIL>": target,
        **{f"<{k}>": v for k, v in variables.items()},
    }
    for placeholder, value in replacements.items():
        html_body = html_body.replace(placeholder, value)
    return html_body


def html_to_text(html_body):
    text = re.sub(r"<[^>]+>", "", html_body)
    text = re.sub(r"\s+", " ", text).strip()
    return text


class CloudflareMailer:
    def __init__(self, account_id, token):
        self._url = f"{CF_API}/accounts/{account_id}/email/sending/send"
        self._headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }

    def send(self, sender_email, sender_name, reply_to, target, subject, html_body):
        from_addr = f"{sender_name} <{sender_email}>" if sender_name else sender_email
        payload = {
            "from":    from_addr,
            "to":      target,
            "subject": subject,
            "html":    html_body,
            "text":    html_to_text(html_body),
        }
        if reply_to:
            payload["replyTo"] = reply_to

        resp = requests.post(self._url, headers=self._headers, json=payload, timeout=30)
        data = resp.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            raise RuntimeError(f"Cloudflare API error: {errors}")

        result = data.get("result", {})
        bounces = result.get("permanent_bounces", [])
        if bounces:
            raise RuntimeError(f"Permanent bounce: {bounces}")

        return result


def load_sent(log_path):
    sent = set()
    if Path(log_path).exists():
        with open(log_path, "r") as f:
            for line in f:
                parts = line.strip().split("\t")
                if len(parts) >= 2 and parts[0] == "SENT":
                    sent.add(parts[1])
    return sent


def write_log(log_path, status, target, hash_value, note=""):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a") as f:
        f.write(f"{status}\t{target}\t{hash_value}\t{ts}\t{note}\n")


def parse_delay(delay_str):
    parts = delay_str.split("-")
    try:
        lo = float(parts[0])
        hi = float(parts[1]) if len(parts) > 1 else lo
        return lo, hi
    except (ValueError, IndexError):
        raise argparse.ArgumentTypeError(f"Invalid delay format '{delay_str}' — use seconds or min-max (e.g. 3-8)")


def build_parser():
    parser = argparse.ArgumentParser(
        usage="%(prog)s -s <sender@domain.com> -t <targets.txt> -r <responder> [options]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Cloudflare Email sender for authorized red team engagements",
    )
    parser.add_argument("-s", "--sender",    required=True, metavar="<sender@domain.com>",
                        help="Sender address (must be on a verified Cloudflare domain)")
    parser.add_argument("-n", "--name",      default=None, metavar="<display name>",
                        help="Sender display name (default: local part of -s address)")
    parser.add_argument("-t", "--targets",   required=True, metavar="<targets.txt>",
                        help="File containing one target email per line")
    parser.add_argument("-r", "--responder", required=True, metavar="<responder>",
                        help="Responder IP or hostname (substituted for <RESPONDER>)")
    parser.add_argument("-c", "--config",    default="config/template.conf", metavar="<template.conf>",
                        help="Email template file (default: config/template.conf)")
    parser.add_argument("-l", "--log",       default="send.log", metavar="<log>",
                        help="Append-only send log (default: send.log)")
    parser.add_argument("--delay",           default=None, metavar="<min-max>",
                        help="Seconds between sends, supports range (e.g. 3-8)")
    parser.add_argument("--dry-run",         action="store_true",
                        help="Render the first message and print it without sending")
    parser.add_argument("--resume",          action="store_true",
                        help="Skip targets already marked SENT in the log")
    return parser


def main():
    print(BANNER)

    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    delay_min, delay_max = 0, 0
    if args.delay:
        try:
            delay_min, delay_max = parse_delay(args.delay)
        except argparse.ArgumentTypeError as e:
            print(f"[-] {e}")
            sys.exit(1)

    # --- Credentials ---
    key_path = Path("config/key.conf")
    if not key_path.exists():
        print("[-] config/key.conf not found — see config/key.conf.example")
        sys.exit(1)

    keys       = load_config(key_path)
    account_id = keys.get("ACCOUNT_ID", "").strip()
    token      = keys.get("TOKEN", "").strip()

    for field, val in [("ACCOUNT_ID", account_id), ("TOKEN", token)]:
        if not val:
            print(f"[-] Missing '{field}' in config/key.conf")
            if field == "ACCOUNT_ID":
                print("    Find it: dash.cloudflare.com → any domain → right sidebar → API → Account ID")
            sys.exit(1)

    # --- Template ---
    template_path = Path(args.config)
    if not template_path.exists():
        print(f"[-] Template not found: {template_path}")
        sys.exit(1)

    variables, html_template = parse_template(template_path)
    sender_name = args.name or args.sender.split("@")[0]

    variables["RESPONDER"]   = args.responder
    variables["SENDER"]      = args.sender
    variables["SENDER_NAME"] = sender_name

    subject  = variables.get("SUBJECT", "No Subject").strip()
    reply_to = variables.get("REPLY_TO", "").strip()

    print(f"[*] Template  : {template_path}")
    print(f"[*] From      : {sender_name} <{args.sender}>")
    if reply_to:
        print(f"[*] Reply-To  : {reply_to}")
    print(f"[*] Subject   : {subject}")
    print(f"[*] Relay     : Cloudflare Email")

    # --- Targets ---
    with open(args.targets, "r") as f:
        targets = [line.strip() for line in f if line.strip() and "@" in line]

    if not targets:
        print("[-] No valid targets found")
        sys.exit(1)

    print(f"[*] Targets   : {len(targets)}")

    if args.resume:
        sent = load_sent(args.log)
        before = len(targets)
        targets = [t for t in targets if t not in sent]
        skipped = before - len(targets)
        if skipped:
            print(f"[*] Resume    : skipping {skipped} already sent")

    if not targets:
        print("[*] All targets already sent.")
        sys.exit(0)

    # --- Dry run ---
    if args.dry_run:
        t = targets[0]
        h = generate_sha3_hash(t)
        body = render(html_template, variables, t, h)
        print(f"\n[DRY RUN] Message preview for: {t}\n")
        print(f"From: {sender_name} <{args.sender}>")
        if reply_to:
            print(f"Reply-To: {reply_to}")
        print(f"To: {t}")
        print(f"Subject: {subject}")
        print(f"\n{body}")
        print(f"\n[DRY RUN] No emails sent.  ({len(targets)} target(s) queued)")
        sys.exit(0)

    if args.delay:
        print(f"[*] Delay     : {delay_min}-{delay_max}s")
    print()

    mailer = CloudflareMailer(account_id, token)

    success = 0
    failed  = 0

    for i, target in enumerate(targets):
        hash_value = generate_sha3_hash(target)
        body = render(html_template, variables, target, hash_value)

        try:
            mailer.send(args.sender, sender_name, reply_to, target, subject, body)
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[+] {target}\t{hash_value}\t{ts}")
            write_log(args.log, "SENT", target, hash_value)
            success += 1
        except Exception as e:
            print(f"[-] FAILED {target}: {e}")
            write_log(args.log, "FAIL", target, hash_value, str(e))
            failed += 1

        if args.delay and i < len(targets) - 1:
            time.sleep(random.uniform(delay_min, delay_max))

    print(f"\n[*] Done — Sent: {success}  Failed: {failed}  Log: {args.log}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
