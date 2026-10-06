from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import timezone
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from app.backup_service import create_device_backup as backup_device
from app.bulk_commands import execute_bulk_commands
from app.ai_summary import summarize_unified_diff
from app.auth import (
    create_access_token,
    hash_password,
    require_roles,
    valid_admin_registration_token,
    verify_password,
)
from app.compliance import (
    evaluate_fleet,
    evaluate_device,
    seed_default_rules,
)
from app.config_diff import compare_configs
from app.database import Base, SessionLocal, engine, get_db
from app.models import Backup, ComplianceRule, Device, User, UserRole
from app.network import UnsupportedBackupPlatformError, is_ssh_reachable
from app.scheduler import create_backup_scheduler
from app.settings import BACKUP_INTERVAL_HOURS
from app.restore_service import (
    DeviceRejectedConfigurationError,
    EmptyBackupConfigurationError,
    restore_device_backup,
)
from app.schemas import (
    BulkCommandRequest,
    ComplianceRuleCreate,
    ComplianceRuleRead,
    DeviceCreate,
    DeviceRead,
    RestoreRequest,
    TokenResponse,
    UserRead,
    UserRegister,
)
from app.security import encrypt_password
from app.security_audit import security_check


APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(APP_DIR / "templates"))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_default_rules(db)
    scheduler = create_backup_scheduler(BACKUP_INTERVAL_HOURS)
    scheduler.start()
    try:
        yield
    finally:
        scheduler.shutdown(wait=True)


app = FastAPI(
    title="Network Configuration Backup & Audit API",
    version="0.1.0",
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(APP_DIR / "static")), name="static")


@app.get("/healthz")
def health_check() -> dict[str, str]:
    """Report readiness only when the configured database accepts a query."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except SQLAlchemyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is unavailable.",
        ) from exc
    return {"status": "ok", "database": "ok"}


@app.post("/auth/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register_user(
    registration: UserRegister,
    db: Session = Depends(get_db),
    admin_registration_token: str | None = Header(default=None, alias="X-Admin-Registration-Token"),
) -> User:
    """Create a Viewer account; Admin creation requires the bootstrap token."""
    email = str(registration.email).lower()
    if db.query(User).filter(User.email == email).first() is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered.")

    role = registration.role
    if role == UserRole.ADMIN.value and not valid_admin_registration_token(admin_registration_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin registration requires a valid bootstrap token.",
        )

    user = User(email=email, password_hash=hash_password(registration.password), role=role)
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered.",
        ) from exc
    db.refresh(user)
    return user


@app.post("/auth/login", response_model=TokenResponse)
def login_user(
    credentials: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
) -> TokenResponse:
    """Validate email/password credentials and return an OAuth2 bearer token."""
    email = credentials.username.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if user is None or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        access_token = create_access_token(user.id)
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT signing is not configured.",
        ) from exc
    return TokenResponse(access_token=access_token, role=user.role)


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    """Render the dashboard shell without embedding protected device data."""
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={},
    )


@app.get("/api/dashboard")
def dashboard_data(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN.value, UserRole.VIEWER.value)),
) -> dict[str, object]:
    """Return device status, backup metadata, and security findings for the UI."""
    devices = db.query(Device).order_by(Device.id).all()
    enabled_rules = (
        db.query(ComplianceRule)
        .filter(ComplianceRule.enabled.is_(True))
        .order_by(ComplianceRule.id)
        .all()
    )
    latest_backups: dict[int, Backup] = {}
    for backup in (
        db.query(Backup)
        .filter(Backup.status == "success")
        .order_by(Backup.id.desc())
        .all()
    ):
        latest_backups.setdefault(backup.device_id, backup)

    backup_counts = dict(
        db.query(Backup.device_id, func.count(Backup.id))
        .filter(Backup.status == "success")
        .group_by(Backup.device_id)
        .all()
    )
    targets = [(device.ip_address, device.ssh_port) for device in devices]
    if targets:
        with ThreadPoolExecutor(max_workers=min(len(targets), 16)) as executor:
            reachability = list(executor.map(lambda target: is_ssh_reachable(*target), targets))
    else:
        reachability = []

    dashboard_devices = []
    for device, ssh_reachable in zip(devices, reachability):
        latest_backup = latest_backups.get(device.id)
        compliance = evaluate_device(db, device, enabled_rules)
        backup_at = latest_backup.created_at if latest_backup else None
        if backup_at is not None and backup_at.tzinfo is None:
            backup_at = backup_at.replace(tzinfo=timezone.utc)
        dashboard_devices.append(
            {
                "id": device.id,
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "device_type": device.device_type,
                "ssh_port": device.ssh_port,
                "ssh_reachable": ssh_reachable,
                "latest_backup_at": backup_at.isoformat() if backup_at else None,
                "backup_count": backup_counts.get(device.id, 0),
                "security_issues": (
                    security_check(latest_backup.config_text, device.device_type)
                    if latest_backup
                    else []
                ),
                "compliance_findings": compliance["findings"],
                "compliant": compliance["compliant"],
            }
        )

    return {"role": current_user.role, "devices": dashboard_devices}


@app.get("/api/compliance")
def read_compliance_status(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_roles(UserRole.ADMIN.value, UserRole.VIEWER.value)),
) -> dict[str, object]:
    """Evaluate enabled rules against the latest successful backups."""
    devices = evaluate_fleet(db)
    return {
        "devices": devices,
        "non_compliant_devices": [device for device in devices if not device["compliant"]],
    }


@app.get("/api/compliance/rules", response_model=list[ComplianceRuleRead])
def list_compliance_rules(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_roles(UserRole.ADMIN.value, UserRole.VIEWER.value)),
) -> list[ComplianceRule]:
    return db.query(ComplianceRule).order_by(ComplianceRule.id).all()


@app.post("/api/compliance/rules", response_model=ComplianceRuleRead, status_code=status.HTTP_201_CREATED)
def create_compliance_rule(
    rule_data: ComplianceRuleCreate,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_roles(UserRole.ADMIN.value)),
) -> ComplianceRule:
    """Add a regex-based compliance rule for latest-backup evaluation."""
    rule = ComplianceRule(**rule_data.model_dump(), enabled=True)
    db.add(rule)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A compliance rule with that name already exists.",
        ) from exc
    db.refresh(rule)
    return rule


@app.post("/api/devices/bulk-exec")
def bulk_execute_commands(
    execution: BulkCommandRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles(UserRole.ADMIN.value)),
) -> dict[str, object]:
    """Execute up to 20 CLI commands concurrently on up to 50 selected devices."""
    found_ids = {
        device_id
        for (device_id,) in db.query(Device.id).filter(Device.id.in_(execution.device_ids)).all()
    }
    missing_ids = sorted(set(execution.device_ids) - found_ids)
    if missing_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"message": "Some devices were not found.", "device_ids": missing_ids},
        )
    return execute_bulk_commands(db, execution.device_ids, execution.commands, current_user.id)


@app.post("/devices", response_model=DeviceRead, status_code=status.HTTP_201_CREATED)
def add_device(
    device: DeviceCreate,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_roles(UserRole.ADMIN.value)),
) -> Device:
    """Register a network device, storing its password only as ciphertext."""
    try:
        encrypted_password = encrypt_password(device.password)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    new_device = Device(
        hostname=device.hostname,
        ip_address=device.ip_address,
        device_type=device.device_type,
        username=device.username,
        password_encrypted=encrypted_password,
        ssh_port=device.ssh_port,
    )
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    return new_device


@app.get("/devices", response_model=list[DeviceRead])
def list_devices(
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_roles(UserRole.ADMIN.value, UserRole.VIEWER.value)),
) -> list[Device]:
    """Return registered devices without exposing their stored credentials."""
    return db.query(Device).order_by(Device.id).all()


@app.post("/api/devices/{device_id}/backup", status_code=status.HTTP_201_CREATED)
def create_device_backup(
    device_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_roles(UserRole.ADMIN.value)),
) -> dict:
    """Fetch and persist a device's current running configuration."""
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    try:
        return backup_device(db, device)
    except UnsupportedBackupPlatformError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The device password could not be decrypted.",
        ) from exc
    except NetmikoTimeoutException as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="SSH connection to the device timed out.",
        ) from exc
    except NetmikoAuthenticationException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSH authentication failed for the device.",
        ) from exc


@app.post("/api/devices/{device_id}/restore")
def restore_device_configuration(
    device_id: int,
    restore_request: RestoreRequest | None = None,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_roles(UserRole.ADMIN.value)),
) -> dict[str, object]:
    """Push a selected successful backup, or the latest one, to the device."""
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    backup_query = db.query(Backup).filter(
        Backup.device_id == device_id,
        Backup.status == "success",
    )
    if restore_request and restore_request.backup_id is not None:
        backup_query = backup_query.filter(Backup.id == restore_request.backup_id)
        backup = backup_query.first()
    else:
        backup = backup_query.order_by(Backup.id.desc()).first()

    if backup is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No matching successful backup was found for this device.",
        )

    try:
        return restore_device_backup(device, backup)
    except EmptyBackupConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The device password could not be decrypted.",
        ) from exc
    except NetmikoTimeoutException as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="SSH connection to the device timed out during restore.",
        ) from exc
    except NetmikoAuthenticationException as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SSH authentication failed during restore.",
        ) from exc
    except DeviceRejectedConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The device rejected or could not apply the configuration restore.",
        ) from exc


@app.get("/api/devices/{device_id}/diff")
def diff_device_backups(
    device_id: int,
    db: Session = Depends(get_db),
    _current_user: User = Depends(require_roles(UserRole.ADMIN.value, UserRole.VIEWER.value)),
) -> dict:
    """Compare the latest successful backup with the one immediately before it."""
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found.")

    backups = (
        db.query(Backup)
        .filter(Backup.device_id == device_id, Backup.status == "success")
        .order_by(Backup.id.desc())
        .limit(2)
        .all()
    )
    if len(backups) < 2:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="At least two successful backups are required to generate a diff.",
        )

    latest, previous = backups[0], backups[1]
    comparison = compare_configs(previous.config_text, latest.config_text, device.device_type)
    ai_summary = summarize_unified_diff(comparison["diff"])
    return {
        "device_id": device_id,
        "previous_backup_id": previous.id,
        "latest_backup_id": latest.id,
        **comparison,
        "ai_summary": ai_summary,
        "security_issues": security_check(latest.config_text, device.device_type),
    }
