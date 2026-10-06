import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import BulkCommandBatch, BulkCommandResult, Device
from app.network import execute_cli_commands
from app.security import decrypt_password


logger = logging.getLogger(__name__)
MAX_CONCURRENT_DEVICES = 10


def _execute_for_device(device_id: int, commands: list[str]) -> dict[str, object]:
    """Run commands for one device using an isolated database session."""
    with SessionLocal() as db:
        device = db.get(Device, device_id)
        if device is None:
            return {"device_id": device_id, "status": "failed", "error": "Device not found."}
        try:
            password = decrypt_password(device.password_encrypted)
            results = execute_cli_commands(device, password, commands)
            return {"device_id": device.id, "hostname": device.hostname, "status": "success", "commands": results}
        except NetmikoTimeoutException:
            return {"device_id": device.id, "hostname": device.hostname, "status": "failed", "error": "SSH connection timed out."}
        except NetmikoAuthenticationException:
            return {"device_id": device.id, "hostname": device.hostname, "status": "failed", "error": "SSH authentication failed."}
        except ValueError:
            return {"device_id": device.id, "hostname": device.hostname, "status": "failed", "error": "Stored device password could not be decrypted."}
        except Exception as exc:
            logger.warning("Bulk command execution failed for device %s (%s).", device.id, type(exc).__name__)
            return {"device_id": device.id, "hostname": device.hostname, "status": "failed", "error": "Command execution failed."}


def execute_bulk_commands(
    db: Session,
    device_ids: list[int],
    commands: list[str],
    requested_by_id: int,
) -> dict[str, object]:
    """Execute commands concurrently, recording per-device outcome metadata."""
    batch = BulkCommandBatch(
        batch_key=uuid.uuid4().hex,
        requested_by_id=requested_by_id,
        command_count=len(commands),
        status="running",
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)

    worker_count = min(len(device_ids), MAX_CONCURRENT_DEVICES)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        results = list(executor.map(lambda device_id: _execute_for_device(device_id, commands), device_ids))

    for result in results:
        db.add(
            BulkCommandResult(
                batch_id=batch.id,
                device_id=result["device_id"],
                status=result["status"],
                error_summary=result.get("error"),
                completed_at=datetime.now(timezone.utc),
            )
        )

    success_count = sum(result["status"] == "success" for result in results)
    if success_count == len(results):
        batch.status = "success"
    elif success_count:
        batch.status = "partial_failure"
    else:
        batch.status = "failed"
    db.commit()

    return {
        "batch_id": batch.batch_key,
        "status": batch.status,
        "device_count": len(results),
        "command_count": len(commands),
        "results": results,
    }
