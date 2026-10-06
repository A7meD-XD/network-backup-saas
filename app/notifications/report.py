from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Backup, Device
from app.network import is_ssh_reachable
from app.security_audit import security_check


def build_health_report(db: Session) -> tuple[str, str]:
    """Build a plain-text daily/weekly fleet status report."""
    devices = db.query(Device).order_by(Device.hostname).all()
    latest_ids = (
        db.query(Backup.device_id, func.max(Backup.id).label("backup_id"))
        .group_by(Backup.device_id)
        .subquery()
    )
    latest_backups = {
        backup.device_id: backup
        for backup in db.query(Backup).join(
            latest_ids,
            (Backup.device_id == latest_ids.c.device_id)
            & (Backup.id == latest_ids.c.backup_id),
        )
    }

    lines = [
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Devices registered: {len(devices)}",
        "",
    ]
    healthy_count = 0
    finding_count = 0
    for device in devices:
        reachable = is_ssh_reachable(device.ip_address, device.ssh_port)
        backup = latest_backups.get(device.id)
        backup_status = backup.status if backup else "never backed up"
        backup_time = (
            backup.created_at.strftime("%Y-%m-%d %H:%M UTC") if backup else "n/a"
        )
        issues = (
            security_check(backup.config_text, device.device_type)
            if backup and backup.status == "success"
            else []
        )
        healthy_count += int(reachable and backup is not None and backup.status == "success")
        finding_count += len(issues)
        lines.append(
            f"{device.hostname} ({device.ip_address}:{device.ssh_port}, {device.device_type})"
        )
        lines.append(f"  SSH: {'reachable' if reachable else 'unreachable'}")
        lines.append(f"  Latest backup: {backup_status} at {backup_time}")
        if issues:
            lines.append("  Security findings:")
            lines.extend(f"    - {issue}" for issue in issues)
        else:
            lines.append("  Security findings: none detected")
        lines.append("")

    title = f"Network fleet report: {healthy_count}/{len(devices)} healthy, {finding_count} finding(s)"
    return title, "\n".join(lines).rstrip()
