import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User


JWT_SECRET_ENV = "JWT_SECRET_KEY"
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_MINUTES = 30
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def hash_password(password: str) -> str:
    """Hash a plaintext password before it is persisted."""
    return password_context.hash(password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Check a login password against its stored bcrypt hash."""
    return password_context.verify(plain_password, password_hash)


def _jwt_secret() -> str:
    secret = os.getenv(JWT_SECRET_ENV)
    if not secret or len(secret) < 32:
        raise RuntimeError(f"Set {JWT_SECRET_ENV} to a secret containing at least 32 characters.")
    return secret


def create_access_token(user_id: int) -> str:
    """Create a short-lived JWT whose subject is the database user ID."""
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(user_id),
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES),
    }
    return jwt.encode(claims, _jwt_secret(), algorithm=JWT_ALGORITHM)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validate a bearer token and load its active user record."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = jwt.decode(token, _jwt_secret(), algorithms=[JWT_ALGORITHM])
    except RuntimeError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT signing is not configured.",
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise unauthorized from exc

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.isdecimal():
        raise unauthorized
    user = db.get(User, int(subject))
    if user is None:
        raise unauthorized
    return user


def require_roles(*allowed_roles: str) -> Callable:
    """Create a dependency that restricts an endpoint to the given roles."""
    def role_guard(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to perform this action.",
            )
        return current_user

    return role_guard


def valid_admin_registration_token(supplied_token: str | None) -> bool:
    """Validate the bootstrap token used to register an Admin account."""
    expected_token = os.getenv("ADMIN_REGISTRATION_TOKEN")
    return bool(
        expected_token
        and supplied_token
        and hmac.compare_digest(supplied_token, expected_token)
    )
