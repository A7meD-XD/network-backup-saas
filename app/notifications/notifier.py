import logging

from app.alerts import format_change_alert, send_telegram_alert
from app.notifications.slack import send_slack_alert
from app.notifications.teams import send_teams_alert


logger = logging.getLogger(__name__)


def _deliver(channel: str, sender, *args) -> bool:
    try:
        return bool(sender(*args))
    except Exception as exc:
        logger.warning(
            "Unexpected %s notification error (%s).", channel, type(exc).__name__
        )
        return False


def send_configuration_alert(
    hostname: str,
    added_lines: list[str],
    removed_lines: list[str],
    security_issues: list[str],
) -> dict[str, bool]:
    """Fan out a configuration-change/audit alert to configured channels."""
    message = format_change_alert(hostname, added_lines, removed_lines, security_issues)
    results = {
        "telegram": _deliver("Telegram", send_telegram_alert, message),
        "slack": _deliver("Slack", send_slack_alert, message),
        "teams": _deliver(
            "Teams", send_teams_alert, message, f"Configuration alert: {hostname}"
        ),
    }
    logger.info(
        "Notification delivery for %s: %s",
        hostname,
        ", ".join(f"{channel}={'sent' if sent else 'not sent'}" for channel, sent in results.items()),
    )
    return results
