import logging

import requests

from app.settings import SLACK_WEBHOOK_URL


logger = logging.getLogger(__name__)
REQUEST_TIMEOUT_SECONDS = 10


def send_slack_alert(message: str) -> bool:
    """Post a plain-text incoming-webhook message to Slack."""
    if not SLACK_WEBHOOK_URL:
        return False
    try:
        response = requests.post(
            SLACK_WEBHOOK_URL,
            json={"text": message},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.warning("Slack notification delivery failed (%s).", type(exc).__name__)
        return False
