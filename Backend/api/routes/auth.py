import logging
from datetime import timedelta
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.deps import CurrentUser, DBSession
from config import settings
from core.security import (
    TokenExpiredError,
    TokenInvalidError,
    create_access_token,
    create_refresh_token,
    hash_password,
    verify_password,
    verify_refresh_token,
)
from models.user import User
from schemas.auth import (
    LoginRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter()
logger = logging.getLogger(__name__)


def _raise_internal_error(exc: Exception, context: str) -> None:
    logger.error("Database operation failed during %s: %s", context, exc, exc_info=True)
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="An internal error occurred. Please try again.",
    ) from exc


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Creates a new ASRE user account and returns JWT tokens.",
)
async def register(
    payload: RegisterRequest,
    db: DBSession,
) -> TokenResponse:
    _db: AsyncSession = db
    normalized_email = payload.email.strip().lower()
    new_user: User | None = None

    try:
        result = await _db.execute(select(User).where(func.lower(User.email) == normalized_email))
        existing_user = result.scalar_one_or_none()
        if existing_user is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists",
            )

        hashed = hash_password(payload.password)
        new_user = User(
            email=normalized_email,
            password_hash=hashed,
            full_name=payload.full_name,
        )
        _db.add(new_user)
        await _db.flush()
    except HTTPException:
        raise
    except Exception as exc:
        _raise_internal_error(exc, "register")

    if new_user is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An internal error occurred. Please try again.",
        )

    access_token = create_access_token(
        subject=str(new_user.id),
        email=str(new_user.email),
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(
        subject=str(new_user.id),
        expires_delta=timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    )

    logger.info("New user registered: %s (%s)", new_user.email, new_user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Login with email and password",
    description="Authenticates a user and returns JWT access + refresh tokens.",
)
async def login(
    payload: LoginRequest,
    request: Request,
    db: DBSession,
) -> TokenResponse:
    _db: AsyncSession = db
    normalized_email = payload.email.strip().lower()
    user: User | None = None

    try:
        result = await _db.execute(select(User).where(func.lower(User.email) == normalized_email))
        user = result.scalar_one_or_none()
    except Exception as exc:
        _raise_internal_error(exc, "login")

    if not user or not verify_password(payload.password, str(user.password_hash)):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        subject=str(user.id),
        email=str(user.email),
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    refresh_token = create_refresh_token(
        subject=str(user.id),
        expires_delta=timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
    )

    client_ip = request.client.host if request.client else "unknown"
    logger.info("User logged in: %s from IP %s", user.email, client_ip)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description="Issues a new access token using a valid refresh token.",
)
async def refresh_token(
    payload: RefreshRequest,
    db: DBSession,
) -> TokenResponse:
    try:
        token_payload = verify_refresh_token(payload.refresh_token)
    except TokenExpiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired — please log in again",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except TokenInvalidError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user_id = token_payload.get("sub")
    try:
        user_uuid = UUID(str(user_id))
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    _db: AsyncSession = db
    user: User | None = None
    try:
        result = await _db.execute(select(User).where(User.id == user_uuid))
        user = result.scalar_one_or_none()
    except Exception as exc:
        _raise_internal_error(exc, "refresh token")

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )

    new_access_token = create_access_token(
        subject=str(user.id),
        email=str(user.email),
        expires_delta=timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=payload.refresh_token,
        token_type="bearer",
        expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get(
    "/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile",
    description="Returns the profile of the currently authenticated user.",
)
async def get_me(
    current_user: CurrentUser,
) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Logout (client-side token discard)",
    description=(
        "ASRE uses stateless JWTs — logout is handled client-side by discarding "
        "the token. This endpoint exists as a clean API contract and logs the "
        "logout event server-side. Future versions will add token blocklisting via Redis."
    ),
)
async def logout(
    current_user: CurrentUser,
) -> dict[str, str]:
    logger.info("User logged out: %s", current_user.email)
    # TODO: Implement server-side token blocklisting (Redis jti tracking).
    return {"message": "Logged out successfully"}
