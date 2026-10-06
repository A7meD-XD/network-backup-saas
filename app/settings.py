import os

from dotenv import load_dotenv


load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./network_backup.db")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_REQUEST_TIMEOUT_SECONDS = 15
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")

SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").strip().lower() in {"1", "true", "yes", "on"}
SMTP_FROM_EMAIL = os.getenv("SMTP_FROM_EMAIL")
SMTP_TO_EMAILS = tuple(
    email.strip()
    for email in os.getenv("SMTP_TO_EMAILS", "").split(",")
    if email.strip()
)
SMTP_STARTTLS = os.getenv("SMTP_STARTTLS", "true").strip().lower() in {"1", "true", "yes", "on"}

REPORT_FREQUENCY = os.getenv("REPORT_FREQUENCY", "daily").strip().lower()
if REPORT_FREQUENCY not in {"daily", "weekly"}:
    raise ValueError("REPORT_FREQUENCY must be either 'daily' or 'weekly'.")
REPORT_DAY_OF_WEEK = os.getenv("REPORT_DAY_OF_WEEK", "mon").strip().lower()
if REPORT_DAY_OF_WEEK not in {"mon", "tue", "wed", "thu", "fri", "sat", "sun"}:
    raise ValueError("REPORT_DAY_OF_WEEK must be a three-letter weekday such as 'mon'.")
REPORT_HOUR = int(os.getenv("REPORT_HOUR", "8"))
REPORT_MINUTE = int(os.getenv("REPORT_MINUTE", "0"))
if not 0 <= REPORT_HOUR <= 23 or not 0 <= REPORT_MINUTE <= 59:
    raise ValueError("REPORT_HOUR must be 0-23 and REPORT_MINUTE must be 0-59.")

if not 1 <= SMTP_PORT <= 65535:
    raise ValueError("SMTP_PORT must be between 1 and 65535.")

try:
    BACKUP_INTERVAL_HOURS = float(os.getenv("BACKUP_INTERVAL_HOURS", "24"))
except ValueError as exc:
    raise ValueError("BACKUP_INTERVAL_HOURS must be a positive number.") from exc

if BACKUP_INTERVAL_HOURS <= 0:
    raise ValueError("BACKUP_INTERVAL_HOURS must be greater than zero.")
