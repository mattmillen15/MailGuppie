#!/usr/bin/env python3
"""
send_all_domains.py - Send a template from all 5 engagement domains.

Usage:
    python3 send_all_domains.py -t matt.txt -r 35.87.210.244
    python3 send_all_domains.py -t matt.txt -r 35.87.210.244 -c config/sneaky-template.conf
    python3 send_all_domains.py -t matt.txt -r 35.87.210.244 --dry-run
"""

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def make_targets_file(email):
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tf.write(email + "\n")
    tf.flush()
    tf.close()
    return tf.name

DOMAINS = [
    "247supportsolutions.com",
    "bchipfinancial.com",
    "crbanking.com",
    "memphisheartclinic.com",
    "omgresorts.com",
]

SENDER_PLACEHOLDER = "noreply@<domain.com>"


def main():
    parser = argparse.ArgumentParser(description="Send template from all engagement domains")
    parser.add_argument("-t", "--targets", required=True)
    parser.add_argument("-r", "--responder", required=True)
    parser.add_argument("-c", "--config", default="config/sneaky-template.conf")
    parser.add_argument("--delay", default="5-10", help="Delay between sends (default: 5-10)")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    temp_targets = None
    if "@" in args.targets and not Path(args.targets).exists():
        temp_targets = make_targets_file(args.targets)
        args.targets = temp_targets

    template_text = Path(args.config).read_text()

    if SENDER_PLACEHOLDER not in template_text:
        print(f"[-] Template SENDER must be exactly:  {SENDER_PLACEHOLDER}")
        sys.exit(1)

    print(f"[*] Template  : {args.config}")
    print(f"[*] Targets   : {args.targets}")
    print(f"[*] Responder : {args.responder}")
    print(f"[*] Domains   : {len(DOMAINS)}")
    if args.dry_run:
        print("[*] DRY RUN")
    print()

    for i, domain in enumerate(DOMAINS, 1):
        sender = f"noreply@{domain}"
        domain_conf = template_text.replace(SENDER_PLACEHOLDER, sender)

        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False)
        tf.write(domain_conf)
        tf.flush()
        tf.close()

        print(f"[{i}/{len(DOMAINS)}] {sender}")
        cmd = [
            sys.executable, "MailGuppie.py",
            "-t", args.targets,
            "-r", args.responder,
            "-c", tf.name,
            "--delay", args.delay,
        ]
        if args.dry_run:
            cmd.append("--dry-run")

        try:
            subprocess.run(cmd)
        finally:
            os.unlink(tf.name)

        if i < len(DOMAINS) and not args.dry_run:
            time.sleep(5)

    if temp_targets:
        os.unlink(temp_targets)

    print("\n[*] Done")


if __name__ == "__main__":
    main()
