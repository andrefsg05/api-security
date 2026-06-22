from pydantic import BaseModel, ConfigDict


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserSafeOut(BaseModel):
    id: int
    name: str
    email: str

    model_config = ConfigDict(from_attributes=True)


class UserVulnerableOut(BaseModel):
    id: int
    name: str
    email: str
    role: str
    is_admin: bool
    password_hash: str
    internal_notes: str | None
    account_status: str

    model_config = ConfigDict(from_attributes=True)


class AdminUserSafeOut(BaseModel):
    id: int
    name: str
    email: str
    role: str
    is_admin: bool
    account_status: str

    model_config = ConfigDict(from_attributes=True)


class UserUpdateSafe(BaseModel):
    name: str | None = None
    email: str | None = None

    model_config = ConfigDict(extra="forbid")


class OrderOut(BaseModel):
    id: int
    product: str
    price: float
    status: str
    shipping_address: str
    user_id: int

    model_config = ConfigDict(from_attributes=True)
