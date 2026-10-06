import socket

from netmiko import ConnectHandler

from app.models import Device


SSH_CONNECT_TIMEOUT_SECONDS = 10
SSH_PROBE_TIMEOUT_SECONDS = 0.75
BACKUP_COMMANDS = {
    "cisco_ios": "show running-config",
    "mikrotik_routeros": "export",
    "juniper_junos": "show configuration",
    "fortinet": "show full-configuration",
}


class UnsupportedBackupPlatformError(ValueError):
    """Raised when no backup command is defined for a Netmiko platform."""


def is_ssh_reachable(address: str, port: int) -> bool:
    """Check whether an SSH TCP port accepts connections within a short timeout."""
    try:
        with socket.create_connection((address, port), timeout=SSH_PROBE_TIMEOUT_SECONDS):
            return True
    except OSError:
        return False


def backup_command_for(device_type: str) -> str:
    """Return the platform-specific command used to retrieve configuration."""
    platform = device_type.strip().lower()
    try:
        return BACKUP_COMMANDS[platform]
    except KeyError as exc:
        supported = ", ".join(sorted(BACKUP_COMMANDS))
        raise UnsupportedBackupPlatformError(
            f"No backup command is configured for '{device_type}'. Supported types: {supported}."
        ) from exc


def fetch_running_config(device: Device, password: str) -> str:
    """Connect over SSH and retrieve configuration with a vendor-specific command."""
    command = backup_command_for(device.device_type)
    connection_parameters = {
        "device_type": device.device_type,
        "host": device.ip_address,
        "username": device.username,
        "password": password,
        "port": device.ssh_port,
        "conn_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "auth_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "banner_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "fast_cli": False,
    }

    with ConnectHandler(**connection_parameters) as connection:
        return connection.send_command(command)


def push_config_set(device: Device, password: str, commands: list[str]) -> str:
    """Connect over SSH and apply configuration commands using Netmiko."""
    connection_parameters = {
        "device_type": device.device_type,
        "host": device.ip_address,
        "username": device.username,
        "password": password,
        "port": device.ssh_port,
        "conn_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "auth_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "banner_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "fast_cli": False,
    }

    with ConnectHandler(**connection_parameters) as connection:
        return connection.send_config_set(commands)


def execute_cli_commands(device: Device, password: str, commands: list[str]) -> list[dict[str, str]]:
    """Run each command in exec mode over one Netmiko SSH session."""
    connection_parameters = {
        "device_type": device.device_type,
        "host": device.ip_address,
        "username": device.username,
        "password": password,
        "port": device.ssh_port,
        "conn_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "auth_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "banner_timeout": SSH_CONNECT_TIMEOUT_SECONDS,
        "fast_cli": False,
    }

    command_results = []
    with ConnectHandler(**connection_parameters) as connection:
        for command in commands:
            command_results.append(
                {"command": command, "output": connection.send_command(command)}
            )
    return command_results
