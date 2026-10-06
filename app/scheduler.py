import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select

from app.backup_service import create_device_backup
from app.database import SessionLocal
from app.models import Device
from app.notifications.email_reports import send_email_report
from app.notifications.report import build_health_report
from app.settings import REPORT_DAY_OF_WEEK, REPORT_FREQUENCY, REPORT_HOUR, REPORT_MINUTE


logger = logging.getLogger(__name__)


def run_scheduled_backups() -> None:
    """Back up every currently registered device, isolating failures per device."""
    with SessionLocal() as db:
        device_ids = db.scalars(select(Device.id).order_by(Device.id)).all()

    if not device_ids:
        logger.info("Scheduled backup skipped: no devices are registered.")
        return

    logger.info("Starting scheduled backups for %d device(s).", len(device_ids))
    for device_id in device_ids:
        try:
            with SessionLocal() as db:
                device = db.get(Device, device_id)
                if device is None:
                    continue
                result = create_device_backup(db, device)
                logger.info(
                    "Scheduled backup completed for device %s (backup %s).",
                    device_id,
                    result["id"],
                )
        except Exception:
            logger.exception("Scheduled backup failed for device %s.", device_id)


def run_scheduled_email_report() -> None:
    """Build and send a fleet health summary to configured administrators."""
    try:
        with SessionLocal() as db:
            subject, body = build_health_report(db)
        if send_email_report(subject, body):
            logger.info("Scheduled fleet email report sent.")
        else:
            logger.info("Scheduled fleet email report was not sent; check SMTP settings.")
    except Exception:
        logger.exception("Scheduled fleet email report failed.")


def create_backup_scheduler(interval_hours: float) -> BackgroundScheduler:
    """Create a scheduler that runs the backup sweep at the configured interval."""
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        run_scheduled_backups,
        trigger="interval",
        hours=interval_hours,
        id="scheduled_device_backups",
        name="Back up all registered network devices",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    scheduler.add_job(
        run_scheduled_email_report,
        trigger=CronTrigger(
            day_of_week=REPORT_DAY_OF_WEEK if REPORT_FREQUENCY == "weekly" else "*",
            hour=REPORT_HOUR,
            minute=REPORT_MINUTE,
            timezone="UTC",
        ),
        id="scheduled_fleet_email_report",
        name=f"{REPORT_FREQUENCY.title()} network fleet health email",
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    return scheduler
