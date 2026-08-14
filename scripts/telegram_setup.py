"""List recent Telegram chat IDs or send a static connectivity test.

The script reads the gitignored ``ai_module/telegram.local.env`` file through
the notifier. It never prints the bot token or its configured destination.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ai_module"))

from telegram_notifier import TelegramConfigurationError, TelegramDeliveryError, TelegramNotifier  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Telegram setup helper for Local AI SIEM Analyzer")
    parser.add_argument(
        "--discover-chats", action="store_true",
        help="list recent numeric chat IDs after sending /start to the bot",
    )
    args = parser.parse_args()
    notifier = TelegramNotifier({"notifications": {"telegram": {"enabled": True}}})
    try:
        if args.discover_chats:
            chats = notifier.discover_chats()
            if not chats:
                print("No chat found. Send /start to the bot, then run this command again.")
                return 1
            for chat in chats:
                print(f"chat_id={chat['id']} type={chat['type']}")
            return 0
        result = notifier.send_test()
        print(f"Telegram test sent; message_id={result.get('message_id', '')}")
        return 0
    except (TelegramConfigurationError, TelegramDeliveryError) as exc:
        print(f"Telegram setup failed: {getattr(exc, 'code', str(exc))}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
