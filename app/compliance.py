import re

from sqlalchemy.orm import Session

from app.models import Backup, ComplianceRule, Device


DEFAULT_RULES = (
    {
        "name": "central_logging_configured",
        "description": "A remote logging destination is configured.",
        "pattern": r"(?im)^\s*(?:logging\s+host\s+\S+|set\s+system\s+syslog\s+host\s+\S+|set\s+syslogd\s+server\s+\S+|.*\bremote=\d{1,3}(?:\.\d{1,3}){3}\b)",
        "remediation": "Configure a trusted central syslog destination, for example: logging host 192.0.2.10.",
        "severity": "high",
    },
    {
        "name": "ntp_server_configured",
        "description": "A network time source is configured.",
        "pattern": r"(?im)^\s*(?:ntp\s+server\s+\S+|set\s+system\s+ntp\s+server\s+\S+|server\s+\S+|.*\bservers?=\S+)",
        "remediation": "Configure an approved NTP server, for example: ntp server 192.0.2.20.",
        "severity": "medium",
    },
)


def seed_default_rules(db: Session) -> None:
    """Insert built-in checks once without overwriting administrator changes."""
    existing_names = {
        name for (name,) in db.query(ComplianceRule.name).all()
    }
    for rule in DEFAULT_RULES:
        if rule["name"] not in existing_names:
            db.add(ComplianceRule(**rule, enabled=True))
    db.commit()


def check_config_compliance(
    config_text: str,
    rules: list[ComplianceRule],
) -> list[dict[str, object]]:
    """Return failed enabled rules for a configuration snapshot."""
    findings = []
    for rule in rules:
        try:
            compliant = re.search(rule.pattern, config_text, re.IGNORECASE | re.MULTILINE) is not None
        except re.error:
            compliant = False
        if not compliant:
            findings.append(
                {
                    "rule_id": rule.id,
                    "name": rule.name,
                    "description": rule.description,
                    "severity": rule.severity,
                    "remediation": rule.remediation,
                    "status": "non_compliant",
                }
            )
    return findings


def latest_successful_backup(db: Session, device_id: int) -> Backup | None:
    return (
        db.query(Backup)
        .filter(Backup.device_id == device_id, Backup.status == "success")
        .order_by(Backup.id.desc())
        .first()
    )


def evaluate_device(
    db: Session,
    device: Device,
    rules: list[ComplianceRule] | None = None,
) -> dict[str, object]:
    """Evaluate enabled rules against the device's latest successful backup."""
    enabled_rules = rules if rules is not None else (
        db.query(ComplianceRule)
        .filter(ComplianceRule.enabled.is_(True))
        .order_by(ComplianceRule.id)
        .all()
    )
    backup = latest_successful_backup(db, device.id)
    if backup is None:
        findings = [
            {
                "rule_id": rule.id,
                "name": rule.name,
                "description": "No successful backup is available to verify this requirement.",
                "severity": rule.severity,
                "remediation": f"Run a successful backup, then verify: {rule.remediation}",
                "status": "not_evaluated",
            }
            for rule in enabled_rules
        ]
        return {"device_id": device.id, "hostname": device.hostname, "compliant": False, "findings": findings}

    findings = check_config_compliance(backup.config_text, enabled_rules)
    return {
        "device_id": device.id,
        "hostname": device.hostname,
        "backup_id": backup.id,
        "compliant": not findings,
        "findings": findings,
    }


def evaluate_fleet(db: Session) -> list[dict[str, object]]:
    rules = (
        db.query(ComplianceRule)
        .filter(ComplianceRule.enabled.is_(True))
        .order_by(ComplianceRule.id)
        .all()
    )
    devices = db.query(Device).order_by(Device.hostname).all()
    return [evaluate_device(db, device, rules) for device in devices]
