import logging
import os

import requests


logger = logging.getLogger(__name__)
TELEGRAM_TIMEOUT_SECONDS = 10
TELEGRAM_MESSAGE_LIMIT = 3800


def format_change_alert(
    hostname: str,
    added_lines: list[str],
    removed_lines: list[str],
    security_issues: list[str],
) -> str:
    """Summarize a configuration change and its current security findings."""
    message_lines = [f"Configuration changed: {hostname}"]
    message_lines.append(f"Added: {len(added_lines)} line(s); removed: {len(removed_lines)} line(s).")

    for label, changes, marker in (
        ("Added", added_lines, "+"),
        ("Removed", removed_lines, "-"),
    ):
        if changes:
            message_lines.append(f"{label} lines:")
            message_lines.extend(f"{marker} {line}" for line in changes[:10])
            if len(changes) > 10:
                message_lines.append(f"...and {len(changes) - 10} more")

    message_lines.append("Security findings:")
    if security_issues:
        message_lines.extend(f"- {issue}" for issue in security_issues[:10])
        if len(security_issues) > 10:
            message_lines.append(f"...and {len(security_issues) - 10} more")
    else:
        message_lines.append("None detected.")

    return "\n".join(message_lines)[:TELEGRAM_MESSAGE_LIMIT]


def send_telegram_alert(message: str) -> bool:
    """Send an alert when Telegram credentials are configured; never block backups."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        logger.info("Telegram alert skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is unset.")
        return False

    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": message},
            timeout=TELEGRAM_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.warning("Telegram alert delivery failed (%s).", type(exc).__name__)
        return False
