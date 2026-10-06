import os

from cryptography.fernet import Fernet, InvalidToken


KEY_ENV_VAR = "DEVICE_ENCRYPTION_KEY"


def _cipher() -> Fernet:
    """Build the Fernet cipher from the persistent application encryption key."""
    key = os.getenv(KEY_ENV_VAR)
    if not key:
        raise ValueError(
            f"{KEY_ENV_VAR} is not set. Generate a Fernet key and configure it before adding devices."
        )
    try:
        return Fernet(key.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise ValueError(f"{KEY_ENV_VAR} must contain a valid Fernet key.") from exc


def encrypt_password(password: str) -> str:
    """Encrypt a device password for storage in the database."""
    return _cipher().encrypt(password.encode("utf-8")).decode("utf-8")


def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a stored device password using the same application key."""
    try:
        return _cipher().decrypt(encrypted_password.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Password could not be decrypted with the configured key.") from exc
