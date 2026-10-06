import logging
import smtplib
from email.message import EmailMessage

from app.settings import (
    SMTP_FROM_EMAIL,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_STARTTLS,
    SMTP_TO_EMAILS,
    SMTP_USE_SSL,
    SMTP_USERNAME,
)


logger = logging.getLogger(__name__)


def send_email_report(subject: str, body: str) -> bool:
    """Send a plain-text report to configured administrators over SMTP."""
    if not SMTP_HOST or not SMTP_FROM_EMAIL or not SMTP_TO_EMAILS:
        logger.info("Email report skipped: SMTP host, sender, or recipient list is not configured.")
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = SMTP_FROM_EMAIL
    message["To"] = ", ".join(SMTP_TO_EMAILS)
    message.set_content(body)

    try:
        smtp_class = smtplib.SMTP_SSL if SMTP_USE_SSL else smtplib.SMTP
        with smtp_class(SMTP_HOST, SMTP_PORT, timeout=20) as client:
            if not SMTP_USE_SSL:
                client.ehlo()
                if SMTP_STARTTLS:
                    client.starttls()
                    client.ehlo()
            if SMTP_USERNAME:
                client.login(SMTP_USERNAME, SMTP_PASSWORD or "")
            client.send_message(message)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        logger.warning("Email report delivery failed (%s).", type(exc).__name__)
        return False
