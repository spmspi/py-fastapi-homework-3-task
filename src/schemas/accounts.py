from pydantic import BaseModel, EmailStr, field_validator
from database.validators.accounts import validate_password_strength

from database import accounts_validators


class UserBase(BaseModel):
    email: EmailStr


class UserRegistrationRequestSchema(UserBase):
    password: str

    @field_validator("password")
    def password_validator(cls, password: str) -> str:
        validate_password_strength(password)
        return password


class UserRegistrationResponseSchema(UserBase):
    id: int

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str


class UserActivationRequestSchema(UserBase):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    def password_validator(cls, password: str) -> str:
        validate_password_strength(password)
        return password


class PasswordResetCompleteRequestSchema(BaseModel):
    message: str


class UserLoginResponseSchema(BaseModel):
    massage: str


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
