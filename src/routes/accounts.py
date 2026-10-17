from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    UserBase,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    TokenRefreshRequestSchema, UserLoginRequestSchema, TokenRefreshResponseSchema,
)
from security.interfaces import JWTAuthManagerInterface
from security.passwords import verify_password

router = APIRouter()


async def get_user_by_email(db: AsyncSession, email: str):
    stmt = select(UserModel).filter(UserModel.email == email)
    db_email = await db.scalar(stmt)
    return db_email


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    user: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):

    db_user = await get_user_by_email(db, user.email)
    if db_user:
        raise HTTPException(
            status_code=409,
            detail=f"A user with this email {user.email} already exists.",
        )
    try:
        user = UserModel(
            email=user.email,
            password=user.password,
            group_id=1,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        stmt = select(UserModel).filter(UserModel.id == user.id)
        db_user = await db.scalar(stmt)
        if db_user.is_active is False:
            activation_token = ActivationTokenModel(user_id=db_user.id)
            db.add(activation_token)
        await db.commit()
    except:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )
    return db_user


@router.post("/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def activate_account(
    user: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(UserModel)
        .filter(UserModel.email == user.email)
        .options(selectinload(UserModel.activation_token))
    )
    db_user = await db.scalar(stmt)
    if db_user is not None:
        if db_user.is_active is True:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User account is already active.",
            )

        elif db_user.activation_token is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        expires_at = cast(datetime, db_user.activation_token.expires_at).replace(
            tzinfo=timezone.utc
        )
        if expires_at < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        db_user.is_active = True
        db_user.activation_token = None
        await db.commit()
        await db.refresh(db_user)
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK)
async def request_password_reset_token(
    user: UserBase, db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(UserModel)
        .filter(UserModel.email == user.email)
        .options(selectinload(UserModel.password_reset_token))
    )
    db_user = await db.scalar(stmt)
    if db_user and db_user.is_active is True:
        if db_user.password_reset_token is not None:
            db.delete(db_user.password_reset_token)
        new_token = PasswordResetTokenModel(user_id=db_user.id)
        db_user.password_reset_token = new_token
        await db.commit()
    return {
        "message": "If you are registered, you will receive an email with instructions."
    }


@router.post(
    "/reset-password/complete/", response_model=MessageResponseSchema
)
async def reset_password_complete(
    payload_user: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    stmt = (
        select(UserModel)
        .filter(UserModel.email == payload_user.email)
        .options(selectinload(UserModel.password_reset_token))
    )
    db_user = await db.scalar(stmt)
    if (
        db_user is None
        or db_user.password_reset_token is None
        or db_user.is_active is False
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid email or token.",
        )

    expires_at = cast(datetime, db_user.password_reset_token.expires_at).replace(
        tzinfo=timezone.utc
    )
    if (
        expires_at < datetime.now(timezone.utc)
        or payload_user.token != db_user.password_reset_token.token
    ):
        db_user.password_reset_token = None
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )
    try:
        db_user.password = payload_user.password
        await db.commit()
        await db.refresh(db_user)
        return {"message": "Password reset successfully."}
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post("/login/", response_model=TokenRefreshResponseSchema , status_code=status.HTTP_200_OK)
async def login_user(
    payload_user: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    stmt = (
        select(UserModel)
        .filter(UserModel.email == payload_user.email)
        .options(selectinload(UserModel.refresh_tokens))
    )
    db_user = await db.scalar(stmt)
    if (
        db_user is None
        or verify_password(payload_user.password, db_user._hashed_password) is False
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if db_user.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )
    try:
        data = {"user_id": db_user.id, "email": db_user.email}

        refresh_token = jwt_manager.create_refresh_token(data)
        access_token = jwt_manager.create_access_token(data)

        if not db_user.refresh_tokens:
            one_login_user = RefreshTokenModel.create(
                user_id=db_user.id,
                days_valid=settings.LOGIN_TIME_DAYS,
                token=refresh_token,
            )
            db.add(one_login_user)
        else:
            db_user.refresh_tokens[0].token = refresh_token

        await db.commit()
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
        }
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )


@router.post("/api/v1/accounts/refresh/")
async def refresh_user_token(
    refresh_token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    stmt_token = select(RefreshTokenModel).filter(
        RefreshTokenModel.token == refresh_token.refresh_token
    )
    db_token = await db.scalar(stmt_token)

    try:
        data = jwt_manager.decode_refresh_token(refresh_token.refresh_token)
    except (TokenExpiredError, InvalidTokenError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Token has expired."
        )

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found.",
        )
    stmt_user = select(UserModel).filter(UserModel.id == db_token.user_id)
    db_user = await db.scalar(stmt_user)

    if not db_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    data_new_token = {
        "user_id": data.get("user_id"),
        "email": data.get("sub"),
    }
    new_token = jwt_manager.create_access_token(data_new_token)
    return {
        "access_token": new_token,
    }
