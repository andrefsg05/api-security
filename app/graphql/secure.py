import strawberry
from graphql import GraphQLError
from strawberry.extensions import DisableIntrospection
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info

from app.graphql.context import get_context, get_db_from_info, require_graphql_user
from app.graphql.types import (
    AdminUserSafe,
    OrderSafe,
    UserSafe,
    UserUpdateSafeInput,
    get_order_or_graphql_error,
)
from app.services import list_all_users, list_user_orders, update_user_secure


@strawberry.type
class Query:
    @strawberry.field
    def me(self, info: Info) -> UserSafe:
        return UserSafe.from_model(require_graphql_user(info))

    @strawberry.field
    def order(self, id: int, info: Info) -> OrderSafe:
        current_user = require_graphql_user(info)
        order = get_order_or_graphql_error(id, info)
        if order.user_id != current_user.id:
            raise GraphQLError("Esta encomenda pertence a outro utilizador")
        return OrderSafe.from_model(order)

    @strawberry.field
    def my_orders(
        self,
        info: Info,
        limit: int = 10,
        offset: int = 0,
    ) -> list[OrderSafe]:
        current_user = require_graphql_user(info)
        if limit < 1 or limit > 20:
            raise GraphQLError("O limite deve estar entre 1 e 20")
        if offset < 0:
            raise GraphQLError("O offset nao pode ser negativo")

        orders = list_user_orders(get_db_from_info(info), current_user.id)
        return [OrderSafe.from_model(order) for order in orders[offset : offset + limit]]

    @strawberry.field
    def admin_users(self, info: Info) -> list[AdminUserSafe]:
        current_user = require_graphql_user(info)
        if current_user.role != "admin" and not current_user.is_admin:
            raise GraphQLError("Acesso reservado a administradores")

        users = list_all_users(get_db_from_info(info))
        return [AdminUserSafe.from_model(user) for user in users]


@strawberry.type
class Mutation:
    @strawberry.mutation
    def update_me(
        self,
        input: UserUpdateSafeInput,
        info: Info,
    ) -> UserSafe:
        current_user = require_graphql_user(info)
        updated_user = update_user_secure(
            get_db_from_info(info),
            current_user,
            input.name,
            input.email,
        )
        return UserSafe.from_model(updated_user)


schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    extensions=[DisableIntrospection],
)
router = GraphQLRouter(
    schema,
    context_getter=get_context,
    graphql_ide=None,
)
