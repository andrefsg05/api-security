from __future__ import annotations

import strawberry
from graphql import GraphQLError
from strawberry.types import Info

from app.graphql.context import get_db_from_info
from app.models import Order, User
from app.services import get_order_by_id, list_user_orders


@strawberry.type
class OrderVulnerable:
    id: int
    product: str
    price: float
    status: str
    shipping_address: str
    user_id: int

    @classmethod
    def from_model(cls, order: Order) -> OrderVulnerable:
        return cls(
            id=order.id,
            product=order.product,
            price=order.price,
            status=order.status,
            shipping_address=order.shipping_address,
            user_id=order.user_id,
        )

    @strawberry.field
    def user(self, info: Info) -> UserVulnerable:
        user = get_db_from_info(info).get(User, self.user_id)
        if user is None:
            raise GraphQLError("Utilizador nao encontrado")
        return UserVulnerable.from_model(user)


@strawberry.type
class UserVulnerable:
    id: int
    name: str
    email: str
    role: str
    is_admin: bool
    password_hash: str
    internal_notes: str | None
    account_status: str

    @classmethod
    def from_model(cls, user: User) -> UserVulnerable:
        return cls(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            is_admin=user.is_admin,
            password_hash=user.password_hash,
            internal_notes=user.internal_notes,
            account_status=user.account_status,
        )

    @strawberry.field
    def orders(self, info: Info) -> list[OrderVulnerable]:
        orders = list_user_orders(get_db_from_info(info), self.id)
        return [OrderVulnerable.from_model(order) for order in orders]


@strawberry.type
class OrderSafe:
    id: int
    product: str
    price: float
    status: str
    shipping_address: str
    user_id: int

    @classmethod
    def from_model(cls, order: Order) -> OrderSafe:
        return cls(
            id=order.id,
            product=order.product,
            price=order.price,
            status=order.status,
            shipping_address=order.shipping_address,
            user_id=order.user_id,
        )


@strawberry.type
class UserSafe:
    id: int
    name: str
    email: str

    @classmethod
    def from_model(cls, user: User) -> UserSafe:
        return cls(id=user.id, name=user.name, email=user.email)


@strawberry.type
class AdminUserSafe:
    id: int
    name: str
    email: str
    role: str
    is_admin: bool
    account_status: str

    @classmethod
    def from_model(cls, user: User) -> AdminUserSafe:
        return cls(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            is_admin=user.is_admin,
            account_status=user.account_status,
        )


@strawberry.input
class VulnerableUserUpdateInput:
    name: str | None = None
    email: str | None = None
    role: str | None = None
    is_admin: bool | None = None
    password_hash: str | None = None
    internal_notes: str | None = None
    account_status: str | None = None

    def to_updates(self) -> dict[str, object]:
        fields = {
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "is_admin": self.is_admin,
            "password_hash": self.password_hash,
            "internal_notes": self.internal_notes,
            "account_status": self.account_status,
        }
        return {key: value for key, value in fields.items() if value is not None}


@strawberry.input
class UserUpdateSafeInput:
    name: str | None = None
    email: str | None = None


def get_order_or_graphql_error(order_id: int, info: Info) -> Order:
    order = get_order_by_id(get_db_from_info(info), order_id)
    if order is None:
        raise GraphQLError("Encomenda nao encontrada")
    return order
