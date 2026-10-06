from sqlalchemy.orm import Session
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from app.config_diff import compare_configs
from app.models import Backup, Device
from app.network import fetch_running_config
from app.notifications.notifier import send_configuration_alert
from app.security import decrypt_password
from app.security_audit import security_check


def create_device_backup(db: Session, device: Device) -> dict[str, object]:
    """Fetch, audit, diff, alert on, and persist one device configuration."""
    previous_backup = (
        db.query(Backup)
        .filter(Backup.device_id == device.id, Backup.status == "success")
        .order_by(Backup.id.desc())
        .first()
    )
    password = decrypt_password(device.password_encrypted)
    config_text = fetch_running_config(device, password)

    security_issues = security_check(config_text, device.device_type)
    comparison = (
        compare_configs(previous_backup.config_text, config_text, device.device_type)
        if previous_backup
        else None
    )
    changes_detected = bool(
        comparison and (comparison["added_lines"] or comparison["removed_lines"])
    )

    backup = Backup(device_id=device.id, config_text=config_text, status="success")
    db.add(backup)
    db.commit()
    db.refresh(backup)

    notification_results = {"telegram": False, "slack": False, "teams": False}
    if changes_detected or security_issues:
        notification_results = send_configuration_alert(
            device.hostname,
            comparison["added_lines"] if comparison else [],
            comparison["removed_lines"] if comparison else [],
            security_issues,
        )

    return {
        "id": backup.id,
        "device_id": backup.device_id,
        "created_at": backup.created_at,
        "status": backup.status,
        "has_previous_backup": previous_backup is not None,
        "changes_detected": changes_detected,
        "security_issues": security_issues,
        "telegram_alert_sent": notification_results["telegram"],
        "notification_results": notification_results,
    }
