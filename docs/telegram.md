# Telegram delivery

Telegram delivery is opt-in. Each delivery uses one `sendDocument` request: a
concise, redacted caption and a PDF attachment containing the complete
allow-listed AI review plus a graphical Alert map. The dashboard remains
loopback-only; it does not receive inbound Telegram webhooks.

## One-time setup

1. Rotate any bot token that has been pasted into a chat, terminal transcript,
   or tracked file. Do not reuse it.
2. Send `/start` to the bot from the intended private chat. For a group, add
   the bot and send one message; its chat ID is normally negative.
3. Fill the local, ignored file `ai_module/telegram.local.env`:

   ```text
   SIEM_TELEGRAM_ENABLED=true
   SIEM_TELEGRAM_BOT_TOKEN=<new bot token>
   SIEM_TELEGRAM_CHAT_ID=<numeric chat id>
   ```

   Do not put these values in `config.yaml`, tracked documentation, SQLite, or
   an exported report.
4. If the chat ID is unknown, leave it blank temporarily and run:

   ```powershell
   python scripts/telegram_setup.py --discover-chats
   ```

   Copy the intended numeric ID into the ignored local file. The helper reads
   only recent bot updates and never prints the token.
5. Verify basic bot/chat connectivity with either `python scripts/telegram_setup.py`
   or the dashboard's **Gửi test Telegram** button. This is a text-only test; a
   real report uses `sendDocument` and is verified separately.

## Dashboard settings

The **Cài đặt Telegram** button in the local dashboard opens a form for the
bot token and numeric chat ID. Saving it writes the same ignored
`ai_module/telegram.local.env` file; the API never returns either value and no
restart is needed. Close an editor that is locking the file before saving.

The settings form deliberately does not prefill saved values. Use the
**Gửi test Telegram** button after saving to verify the destination.

## Sending reports

For a manual job, select **Telegram bot** in **Nhận báo cáo** before creating
the job. A successful or partial job is then queued for delivery. Scheduled
windows have the same choice in **Gửi mỗi cửa sổ**. Empty, failed, and cancelled
jobs are not sent automatically.

Completed jobs also expose **Gửi Telegram** for an explicit one-off delivery.
The dashboard stores the channel, delivery status, attempt count, report hash,
and provider message ID only; it never stores the text sent to Telegram.

If a network timeout occurs, delivery becomes `uncertain` instead of retrying
automatically, because Telegram may already have accepted the document. An
analyst must check the chat, then explicitly retry and accept the duplicate
document risk.

The caption stays within Telegram's 1,024-character caption limit. The full
report is sent as `siem-ai-report-job-<id>.pdf`, generated locally with the same card and
table hierarchy as the Gmail HTML view, plus all redacted report sections. Its
Alert map is one scalable chart: up to 48 bars, a peak-based Y axis, and labels
only on the largest buckets; it never embeds the 48-line text fallback. Caption
and PDF share one provider request, so a successful standalone summary can no
longer be separated from a failed document upload. Legacy `telegram_partial_*`
rows remain visible and can be explicitly resent in the new format. PDF upload
has a 45-second minimum read timeout.

## Content and safety

The summary selects job status/window/model, metrics, severity, confidence,
grouped top rules, summary, next steps, warnings, and analysis hash. The PDF
uses the same rich allow-list as Gmail: findings, MITRE, observed facts,
inferences, uncertainties, limitations, and an **Alert map / Mật độ alert theo
thời gian** graphical timeline bounded to at most 48 buckets. The graph scales
to the maximum bucket count, so a report with thousands of alerts remains
legible without printing every time bucket.

It excludes alert references, raw logs, prompts, private reasoning, source IP
addresses, email addresses, and inline secret values. It deliberately keeps
`parse_mode` disabled for the caption and sends the PDF as an `application/pdf`
document. The PDF
is bounded to 12 MiB before upload.

Use a private chat or an explicitly approved group. The bot token and chat ID
are secrets/identifiers; revoke and replace the token immediately if either is
exposed.
