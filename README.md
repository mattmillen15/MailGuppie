# MailGuppie

Cloudflare Email sender for authorized red team engagements.

```
usage: MailGuppie.py -s <sender@domain.com> -t <targets.txt> -r <responder> [options]

  -s, --sender     Sender address (must be on a verified Cloudflare sending domain)
  -n, --name       Sender display name (default: local part of -s address)
  -t, --targets    File containing one target email per line
  -r, --responder  Responder IP or hostname (substituted for <RESPONDER>)
  -c, --config     Email template file (default: config/template.conf)
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

**3. Send**

```bash
python3 MailGuppie.py -s noreply@yourdomain.com -t targets.txt -r 10.0.1.100
python3 MailGuppie.py -s noreply@yourdomain.com -n "IT Support" -t targets.txt -r 10.0.1.100 -c config/template.conf
python3 MailGuppie.py -s noreply@yourdomain.com -t targets.txt -r 10.0.1.100 --resume
python3 MailGuppie.py -s noreply@yourdomain.com -t targets.txt -r 10.0.1.100 --dry-run
```

## Templates

Edit `config/template.conf` or create your own. Only `# SUBJECT:` is read from the file — sender is set via `-s`/`-n` flags.

**Placeholders:**

| Placeholder      | Value                                           |
|------------------|-------------------------------------------------|
| `<RESPONDER>`    | `-r` argument                                   |
| `<SENDER>`       | `-s` argument                                   |
| `<SENDER_NAME>`  | `-n` argument (or local part of `-s`)           |
| `<SHA3_HASH>`    | SHA3-256 of target email — unique per recipient |
| `<TARGET_EMAIL>` | Target email address                            |

## Send Log

```
SENT    target@corp.com    abc123hash    2026-08-10 14:30:00
FAIL    other@corp.com     def456hash    2026-08-10 14:30:05    [error]
```
