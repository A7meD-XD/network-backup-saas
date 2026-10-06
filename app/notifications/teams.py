import logging

import requests

from app.settings import TEAMS_WEBHOOK_URL


logger = logging.getLogger(__name__)
REQUEST_TIMEOUT_SECONDS = 10


def send_teams_alert(message: str, title: str = "Network configuration alert") -> bool:
    """Post a MessageCard payload to a Microsoft Teams incoming webhook."""
    if not TEAMS_WEBHOOK_URL:
        return False
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": "C24132" if "Security findings:\nNone detected." not in message else "2F855A",
        "title": title,
        "text": message.replace("\n", "  \n"),
    }
    try:
        response = requests.post(
            TEAMS_WEBHOOK_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.warning("Teams notification delivery failed (%s).", type(exc).__name__)
        return False
