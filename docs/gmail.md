# Gmail delivery

Gmail delivery is opt-in. It sends a bounded, redacted report with a plain-text
fallback and an HTML view containing the Alert map; the dashboard remains
loopback-only and does not receive email.

## One-time setup

1. Enable Google two-step verification for the sending account.
2. Create a dedicated **App Password** in the Google Account security settings.
   Do not use the normal Google account password.
3. Copy `ai_module/gmail.local.env.example` to the ignored local file
   `ai_module/gmail.local.env`, then fill the values:

   ```text
   SIEM_GMAIL_ENABLED=true
   SIEM_GMAIL_SENDER_EMAIL=sender@example.com
   SIEM_GMAIL_APP_PASSWORD=<google-app-password>
   SIEM_GMAIL_RECIPIENT_EMAIL=recipient@example.com
   ```

   The sender and recipient can differ. Do not put these values in
   `config.yaml`, SQLite, exported reports, screenshots, or tracked docs.
4. Use the dashboard's **Cài đặt Gmail** form to write the same ignored file,
   then click **Gửi test Gmail**. The test sends fixed text, not a SIEM report.

The App Password may be entered with spaces as displayed by Google; the local
notifier removes the spaces before SMTP login. If this credential is exposed,
revoke it immediately and create a replacement.

## Sending reports

Choose **Gmail** in **Nhận báo cáo** for a manual job, or in **Gửi mỗi cửa sổ**
for the fixed-window schedule. Successful and partial jobs queue a Gmail
delivery. Empty, failed, and cancelled jobs are not sent automatically.

A completed job also exposes **Gửi Gmail** for an explicit one-off delivery.
Once sent, **Gửi lại Gmail** is available (up to three total attempts) so an
operator can deliberately regenerate the email with the current formatter.
The audit queue stores only channel, state, attempt count, hash, local message
ID, and safe error code. It never stores the email body, sender, recipient, or
App Password.

`sent` means Gmail SMTP accepted the message; check Inbox and Spam to confirm
final delivery. A timeout, network drop, or uncertain SMTP outcome is marked
`uncertain` and is not retried automatically because Gmail might have accepted
the message. Retry only after accepting the chance of a duplicate email.

## Content and safety

The email uses Gmail SMTP over implicit TLS on `smtp.gmail.com:465`. The SMTP
host is fixed and cannot be changed from the dashboard.

The report formatter selects job status/window, aggregate counts, de-duplicated
rule IDs, severity, confidence, summary, key findings, MITRE, next steps,
auditable assessment basis, warnings, and analysis hash. It also renders the
stored Alert map as an HTML bar chart (up to 48 visual bins) with a text map
fallback for email clients that do not render HTML. It excludes raw logs, alert
references, prompts, private reasoning, IP addresses, email addresses, and
inline secrets. The email has no external image, script, or attachment.

## Troubleshooting

- `configured: missing local secret`: check the three Gmail values in the local
  file, or check whether process environment variables override it.
- `gmail_auth_failed`: create a fresh App Password and confirm two-step
  verification is enabled; do not use the normal account password.
- `gmail_recipient_refused`: verify the sender/recipient addresses and Gmail
  account policy.
- `gmail_network_error` or `gmail_timeout`: check network/TLS access, then
  inspect the recipient inbox before manually retrying.
- App Passwords disabled by a Workspace administrator: contact the Workspace
  administrator. Gmail API/OAuth is not part of this local SMTP integration.
