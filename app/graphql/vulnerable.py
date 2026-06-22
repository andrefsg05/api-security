import strawberry
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info

from app.graphql.context import get_context, get_db_from_info, require_graphql_user
from app.graphql.types import (
    OrderVulnerable,
    UserVulnerable,
    VulnerableUserUpdateInput,
    get_order_or_graphql_error,
)
from app.services import (
    list_all_users,
    list_user_orders,
    update_user_vulnerable,
)


@strawberry.type
class Query:
    @strawberry.field
    def me(self, info: Info) -> UserVulnerable:
        return UserVulnerable.from_model(require_graphql_user(info))

    @strawberry.field
    def order(self, id: int, info: Info) -> OrderVulnerable:
        require_graphql_user(info)
        order = get_order_or_graphql_error(id, info)
        return OrderVulnerable.from_model(order)

    @strawberry.field
    def orders(self, info: Info) -> list[OrderVulnerable]:
        current_user = require_graphql_user(info)
        orders = list_user_orders(get_db_from_info(info), current_user.id)
        return [OrderVulnerable.from_model(order) for order in orders]

    @strawberry.field
    def users(self, info: Info) -> list[UserVulnerable]:
        require_graphql_user(info)
        users = list_all_users(get_db_from_info(info))
        return [UserVulnerable.from_model(user) for user in users]


@strawberry.type
class Mutation:
    @strawberry.mutation
    def update_me(
        self,
        input: VulnerableUserUpdateInput,
        info: Info,
    ) -> UserVulnerable:
        current_user = require_graphql_user(info)
        updated_user = update_user_vulnerable(
            get_db_from_info(info),
            current_user,
            input.to_updates(),
        )
        return UserVulnerable.from_model(updated_user)


schema = strawberry.Schema(query=Query, mutation=Mutation)
router = GraphQLRouter(
    schema,
    context_getter=get_context,
    graphql_ide="graphiql",
)
