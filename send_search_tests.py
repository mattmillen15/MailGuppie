#!/usr/bin/env python3
"""
send_search_tests.py - Send all search: URI test templates via MailGuppie

Usage:
    python3 send_search_tests.py -t millen.matthew@gmail.com -r 10.0.1.100
    python3 send_search_tests.py -t targets.txt -r 10.0.1.100
    python3 send_search_tests.py -t millen.matthew@gmail.com -r 10.0.1.100 -d config/search-uri-tests
    python3 send_search_tests.py -t millen.matthew@gmail.com -r 10.0.1.100 --dry-run
"""

import argparse
import subprocess
import sys
import os
import tempfile
import time
from pathlib import Path


BANNER = """
╔════════════════════════════════════════════════════════════╗
║             MailGuppie - search: URI Test Runner           ║
╚════════════════════════════════════════════════════════════╝
"""


def is_email(value):
    return "@" in value and not Path(value).exists()


def make_targets_file(email):
    """Write a single email to a temp file and return the path."""
    tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tf.write(email + "\n")
    tf.flush()
    tf.close()
    return tf.name


def get_subject_from_conf(conf_path):
    """Read the # SUBJECT: line from a template conf file."""
    try:
        with open(conf_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("# SUBJECT:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return Path(conf_path).stem


def run_mailguppie(conf_path, targets_file, responder, dry_run=False):
    """Invoke MailGuppie.py for a single template."""
    cmd = [
        sys.executable,
        "MailGuppie.py",
        "-t", targets_file,
        "-r", responder,
        "-c", str(conf_path),
    ]

    if dry_run:
        print(f"    [dry-run] {' '.join(cmd)}")
        return True

    result = subprocess.run(cmd, capture_output=True, text=True)
    # Print MailGuppie output, stripping the banner/fish art to keep output compact
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("╔") and not stripped.startswith("╚") and not stripped.startswith("║") and not stripped.startswith("><("):
            print(f"    {stripped}")
    if result.returncode != 0 and result.stderr:
        print(f"    [stderr] {result.stderr.strip()}")
    return result.returncode == 0


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="Send all search: URI test templates via MailGuppie",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-t", "--targets", required=True,
                        help="Test email address OR path to targets .txt file")
    parser.add_argument("-r", "--responder", required=True,
                        help="Responder/listener IP or hostname (replaces <RESPONDER> in templates)")
    parser.add_argument("-d", "--dir", default="config/search-uri-tests",
                        help="Template directory (default: config/search-uri-tests)")
    parser.add_argument("--delay", type=float, default=3.0,
                        help="Seconds to wait between sends (default: 3)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print commands without sending")
    args = parser.parse_args()

    # Resolve targets file
    temp_file = None
    if is_email(args.targets):
        temp_file = make_targets_file(args.targets)
        targets_file = temp_file
        print(f"[*] Target:    {args.targets} (single address)")
    else:
        targets_file = args.targets
        print(f"[*] Targets:   {targets_file}")

    print(f"[*] Responder: {args.responder}")
    print(f"[*] Templates: {args.dir}")
    print(f"[*] Delay:     {args.delay}s between sends")
    if args.dry_run:
        print("[*] DRY RUN — no emails will be sent")
    print()

    # Collect and sort template files
    template_dir = Path(args.dir)
    if not template_dir.exists():
        print(f"[-] Template directory not found: {template_dir}")
        sys.exit(1)

    templates = sorted(template_dir.glob("*.conf"))
    if not templates:
        print(f"[-] No .conf files found in {template_dir}")
        sys.exit(1)

    print(f"[*] Found {len(templates)} template(s):\n")
    for t in templates:
        subj = get_subject_from_conf(t)
        print(f"    {t.name}")
        print(f"      Subject: {subj}")
    print()

    # Send loop
    success = 0
    failed = 0
    for i, conf in enumerate(templates, 1):
        subj = get_subject_from_conf(conf)
        print(f"[{i}/{len(templates)}] {conf.name}")
        print(f"    Subject: {subj}")

        ok = run_mailguppie(conf, targets_file, args.responder, dry_run=args.dry_run)
        if ok:
            success += 1
            print(f"    Status:  sent")
        else:
            failed += 1
            print(f"    Status:  FAILED")

        if i < len(templates):
            if not args.dry_run:
                time.sleep(args.delay)
        print()

    print(f"[*] Done — {success} sent, {failed} failed out of {len(templates)} templates")

    if temp_file:
        try:
            os.unlink(temp_file)
        except Exception:
            pass


if __name__ == "__main__":
    main()
