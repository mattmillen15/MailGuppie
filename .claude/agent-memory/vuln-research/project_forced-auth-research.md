---
name: forced-auth-research
description: Research into forced authentication (NTLM hash capture) techniques via email delivery for authorized penetration testing with MailGuppie tool
metadata:
  type: project
---

MailGuppie is a Cloudflare Email sender for red team engagements that uses file:// URIs in HTML email templates to trigger outbound SMB connections (forced authentication / NTLM hash capture). The enable-images template is the preferred pretext style. Some mail filters are catching these emails as spam/junk.

**Why:** The team needs to validate clients' egress SMB and SMB-over-QUIC protections. Current file:// URI approach works for most targets but is being flagged by some email security gateways.

**How to apply:** When working on templates or delivery mechanisms, focus on maximizing email deliverability while maintaining the forced authentication capability. The enable-images pretext requiring user to click "enable images" is the preferred approach unless zero-click alternatives are found.
