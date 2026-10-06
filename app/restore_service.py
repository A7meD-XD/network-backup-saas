import logging
import re

from app.models import Backup, Device
from app.network import push_config_set
from app.security import decrypt_password


logger = logging.getLogger(__name__)
_IGNORED_COMMANDS = {"!", "end", "exit", "configure terminal", "conf t"}
_IGNORED_OUTPUT = re.compile(r"^(?:building configuration\.{0,3}|current configuration\s*:)", re.IGNORECASE)
_SENSITIVE_VALUE = re.compile(
    r"\b(password|secret|community|key|string|pre-shared-key|authentication-key)\b\s+.+",
    re.IGNORECASE,
)
_CONFIG_REJECTION = re.compile(
    r"^\s*%\s*(?:invalid input|incomplete command|ambiguous command|authorization failed|error)\b",
    re.IGNORECASE | re.MULTILINE,
)


class EmptyBackupConfigurationError(ValueError):
    """Raised when a backup contains no config commands suitable for restore."""


class DeviceRejectedConfigurationError(RuntimeError):
    """Raised when the device CLI reports that a restore command was rejected."""


def configuration_commands(config_text: str) -> list[str]:
    """Extract config commands from show output, excluding terminal control lines."""
    commands = []
    for raw_line in config_text.splitlines():
        command = raw_line.strip()
        normalized = command.lower()
        if not command or normalized in _IGNORED_COMMANDS or _IGNORED_OUTPUT.match(command):
            continue
        commands.append(command)

    if not commands:
        raise EmptyBackupConfigurationError("Backup contains no configuration commands to restore.")
    return commands


def _redact_command(command: str) -> str:
    """Hide sensitive values from the API response while retaining the command name."""
    match = _SENSITIVE_VALUE.search(command)
    if match is None:
        return command
    return f"{command[:match.start()]}{match.group(1)} [REDACTED]"


def restore_device_backup(device: Device, backup: Backup) -> dict[str, object]:
    """Push a saved configuration to a device and log the restore outcome."""
    logger.info(
        "Configuration restore started for device %s from backup %s.",
        device.id,
        backup.id,
    )

    try:
        commands = configuration_commands(backup.config_text)
        password = decrypt_password(device.password_encrypted)
        output = push_config_set(device, password, commands)
        if _CONFIG_REJECTION.search(output):
            raise DeviceRejectedConfigurationError(
                "The device CLI rejected one or more configuration commands."
            )
    except Exception:
        logger.exception(
            "Configuration restore failed for device %s from backup %s.",
            device.id,
            backup.id,
        )
        raise

    logger.info(
        "Configuration restore succeeded for device %s from backup %s (%d commands).",
        device.id,
        backup.id,
        len(commands),
    )
    return {
        "status": "success",
        "device_id": device.id,
        "backup_id": backup.id,
        "command_count": len(commands),
        "commands_pushed": [_redact_command(command) for command in commands],
    }
