from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from graphql import GraphQLError
from sqlalchemy.orm import Session
from strawberry.types import Info

from app.database import get_db
from app.models import User
from app.security import get_user_from_authorization_header


@dataclass
class GraphQLContext:
    request: Request
    db: Session


def get_context(
    request: Request,
    db: Session = Depends(get_db),
) -> GraphQLContext:
    return GraphQLContext(request=request, db=db)


def get_db_from_info(info: Info) -> Session:
    return info.context.db


def require_graphql_user(info: Info) -> User:
    try:
        return get_user_from_authorization_header(
            info.context.request.headers.get("Authorization"),
            info.context.db,
        )
    except HTTPException as exc:
        raise GraphQLError(str(exc.detail)) from None
