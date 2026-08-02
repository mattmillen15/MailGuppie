#!/usr/bin/env python3
"""
MailGuppie - M365 SMTP Email Sender
"""

import argparse
import hashlib
import re
import smtplib
import ssl
import sys
import time
import random
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid
from pathlib import Path


BANNER = """
╔════════════════════════════════════════════════╗
║                  MailGuppie                    ║
╚════════════════════════════════════════════════╝

          ><((((º>   ><((((º>   ><((((º>
"""


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
        "<SHA3_HASH>": hash_value,
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


def build_message(target, sender_email, sender_name, reply_to, subject, html_body, sender_domain):
    msg = MIMEMultipart("alternative")
    msg["From"] = formataddr((sender_name, sender_email)) if sender_name else sender_email
    msg["To"] = target
    msg["Subject"] = subject
    msg["Message-ID"] = make_msgid(domain=sender_domain)
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    if reply_to:
        msg["Reply-To"] = reply_to

    msg.attach(MIMEText(html_to_text(html_body), "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))
    return msg


class SMTPRelay:
    def __init__(self, host, port, user, password):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self._conn = None

    def connect(self):
        self._conn = smtplib.SMTP(self.host, self.port, timeout=30)
        self._conn.ehlo()
        self._conn.starttls(context=ssl.create_default_context())
        self._conn.ehlo()
        self._conn.login(self.user, self.password)

    def send(self, msg, sender_email, target):
        try:
            self._conn.sendmail(sender_email, [target], msg.as_string())
        except smtplib.SMTPServerDisconnected:
            self.connect()
            self._conn.sendmail(sender_email, [target], msg.as_string())

    def quit(self):
        if self._conn:
            try:
                self._conn.quit()
            except Exception:
                pass


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
        usage="%(prog)s -t <targets.txt> -r <responder> [options]",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="M365 SMTP phishing relay for authorized red team engagements",
    )
    parser.add_argument("-t", "--targets",  required=True, metavar="<targets.txt>",
                        help="File containing one target email per line")
    parser.add_argument("-r", "--responder", required=True, metavar="<responder>",
                        help="Responder IP or hostname (substituted for <RESPONDER>)")
    parser.add_argument("-c", "--config",   default="config/template.conf", metavar="<template.conf>",
                        help="Email template file (default: config/template.conf)")
    parser.add_argument("-s", "--smtp",     default="config/smtp.conf", metavar="<smtp.conf>",
                        help="SMTP credentials file (default: config/smtp.conf)")
    parser.add_argument("-l", "--log",      default="send.log", metavar="<log>",
                        help="Append-only send log (default: send.log)")
    parser.add_argument("--delay",          default="3-8", metavar="<min-max>",
                        help="Seconds between sends, supports range (default: 3-8)")
    parser.add_argument("--dry-run",        action="store_true",
                        help="Render the first message and print it without sending")
    parser.add_argument("--resume",         action="store_true",
                        help="Skip targets already marked SENT in the log")
    return parser


def main():
    print(BANNER)

    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    try:
        delay_min, delay_max = parse_delay(args.delay)
    except argparse.ArgumentTypeError as e:
        print(f"[-] {e}")
        sys.exit(1)

    # --- SMTP config ---
    smtp_path = Path(args.smtp)
    if not smtp_path.exists():
        print(f"[-] SMTP config not found: {smtp_path}")
        print("    Create config/smtp.conf — see config/smtp.conf.example")
        sys.exit(1)

    smtp_cfg = load_config(smtp_path)
    for field in ("HOST", "PORT", "USER", "PASS"):
        if field not in smtp_cfg:
            print(f"[-] Missing '{field}' in {smtp_path}")
            sys.exit(1)

    # --- Template ---
    template_path = Path(args.config)
    if not template_path.exists():
        print(f"[-] Template not found: {template_path}")
        sys.exit(1)

    variables, html_template = parse_template(template_path)
    variables["RESPONDER"] = args.responder

    sender_email = variables.get("SENDER", "").strip()
    sender_name  = variables.get("SENDER_NAME", "").strip()
    subject      = variables.get("SUBJECT", "No Subject").strip()
    reply_to     = variables.get("REPLY_TO", "").strip()

    if not sender_email:
        print("[-] SENDER not set in template")
        sys.exit(1)

    sender_domain = sender_email.split("@")[1] if "@" in sender_email else "localhost"

    print(f"[*] Template  : {template_path}")
    print(f"[*] From      : {sender_name} <{sender_email}>" if sender_name else f"[*] From      : {sender_email}")
    if reply_to:
        print(f"[*] Reply-To  : {reply_to}")
    print(f"[*] Subject   : {subject}")
    print(f"[*] Relay     : {smtp_cfg['HOST']}:{smtp_cfg['PORT']}  ({smtp_cfg['USER']})")

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
        msg = build_message(t, sender_email, sender_name, reply_to, subject, body, sender_domain)
        print(f"\n[DRY RUN] Message preview for: {t}\n")
        print(msg.as_string())
        print(f"\n[DRY RUN] No emails sent.  ({len(targets)} target(s) queued)")
        sys.exit(0)

    print(f"[*] Delay     : {delay_min}-{delay_max}s\n")

    # --- Connect ---
    relay = SMTPRelay(smtp_cfg["HOST"], smtp_cfg["PORT"], smtp_cfg["USER"], smtp_cfg["PASS"])
    try:
        relay.connect()
        print(f"[*] Connected to {smtp_cfg['HOST']}\n")
    except Exception as e:
        print(f"[-] SMTP connection failed: {e}")
        sys.exit(1)

    success = 0
    failed  = 0

    try:
        for i, target in enumerate(targets):
            hash_value = generate_sha3_hash(target)
            body = render(html_template, variables, target, hash_value)
            msg  = build_message(target, sender_email, sender_name, reply_to, subject, body, sender_domain)

            try:
                relay.send(msg, sender_email, target)
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[+] {target}\t{hash_value}\t{ts}")
                write_log(args.log, "SENT", target, hash_value)
                success += 1
            except Exception as e:
                print(f"[-] FAILED {target}: {e}")
                write_log(args.log, "FAIL", target, hash_value, str(e))
                failed += 1

            if i < len(targets) - 1:
                time.sleep(random.uniform(delay_min, delay_max))

    finally:
        relay.quit()

    print(f"\n[*] Done — Sent: {success}  Failed: {failed}  Log: {args.log}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
