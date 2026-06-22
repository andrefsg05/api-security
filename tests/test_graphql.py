import os
import sys
from pathlib import Path

import pytest

ROOT_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT_DIR))

os.environ["INSECURESHOP_DATABASE_URL"] = "sqlite:////tmp/insecureshop_graphql_test.db"

from app.database import Base, SessionLocal, engine
from app.graphql.context import GraphQLContext
from app.graphql.secure import schema as secure_schema
from app.graphql.vulnerable import schema as vulnerable_schema
from app.security import create_access_token
from app.seed import seed_database
from app.services import get_user_by_email


class RequestStub:
    def __init__(self, token: str):
        self.headers = {"Authorization": f"Bearer {token}"}


def reset_database() -> None:
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()


@pytest.fixture()
def db():
    reset_database()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def token_for(db, email: str = "andre@example.com") -> str:
    user = get_user_by_email(db, email)
    assert user is not None
    return create_access_token(str(user.id))


def execute_graphql(schema, query: str, token: str, db) -> dict:
    result = schema.execute_sync(
        query,
        context_value=GraphQLContext(request=RequestStub(token), db=db),
    )
    payload: dict = {}
    if result.data is not None:
        payload["data"] = result.data
    if result.errors:
        payload["errors"] = [{"message": error.message} for error in result.errors]
    return payload


def test_vulnerable_me_exposes_sensitive_fields(db):
    data = execute_graphql(
        vulnerable_schema,
        """
        query {
          me {
            email
            passwordHash
            internalNotes
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" not in data
    assert data["data"]["me"]["email"] == "andre@example.com"
    assert data["data"]["me"]["passwordHash"].startswith("$2b$")
    assert data["data"]["me"]["internalNotes"] is not None


def test_vulnerable_order_allows_bola(db):
    data = execute_graphql(
        vulnerable_schema,
        """
        query {
          order(id: 3) {
            id
            product
            userId
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" not in data
    assert data["data"]["order"]["id"] == 3
    assert data["data"]["order"]["userId"] == 2


def test_vulnerable_users_allows_non_admin_listing(db):
    data = execute_graphql(
        vulnerable_schema,
        """
        query {
          users {
            email
            role
            passwordHash
          }
        }
        """,
        token_for(db, "maria@example.com"),
        db,
    )

    assert "errors" not in data
    assert len(data["data"]["users"]) == 3
    assert data["data"]["users"][0]["passwordHash"].startswith("$2b$")


def test_vulnerable_update_me_allows_mass_assignment(db):
    data = execute_graphql(
        vulnerable_schema,
        """
        mutation {
          updateMe(input: {role: "admin", isAdmin: true}) {
            email
            role
            isAdmin
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" not in data
    assert data["data"]["updateMe"]["role"] == "admin"
    assert data["data"]["updateMe"]["isAdmin"] is True


def test_vulnerable_recursive_query_is_allowed(db):
    data = execute_graphql(
        vulnerable_schema,
        """
        query {
          me {
            orders {
              id
              user {
                orders {
                  id
                }
              }
            }
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" not in data
    assert data["data"]["me"]["orders"][0]["user"]["orders"][0]["id"] == 1


def test_secure_me_rejects_sensitive_field(db):
    data = execute_graphql(
        secure_schema,
        """
        query {
          me {
            id
            passwordHash
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" in data


def test_secure_order_blocks_bola(db):
    data = execute_graphql(
        secure_schema,
        """
        query {
          order(id: 3) {
            id
            userId
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" in data
    assert "outro utilizador" in data["errors"][0]["message"]


def test_secure_admin_users_requires_admin(db):
    data = execute_graphql(
        secure_schema,
        """
        query {
          adminUsers {
            email
          }
        }
        """,
        token_for(db, "maria@example.com"),
        db,
    )

    assert "errors" in data
    assert "administradores" in data["errors"][0]["message"]


def test_secure_update_me_rejects_privileged_fields(db):
    data = execute_graphql(
        secure_schema,
        """
        mutation {
          updateMe(input: {role: "admin", isAdmin: true}) {
            id
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" in data


def test_secure_my_orders_rejects_invalid_limit(db):
    data = execute_graphql(
        secure_schema,
        """
        query {
          myOrders(limit: 50) {
            id
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" in data
    assert "limite" in data["errors"][0]["message"].lower()


def test_secure_introspection_is_disabled(db):
    data = execute_graphql(
        secure_schema,
        """
        query {
          __schema {
            queryType {
              name
            }
          }
        }
        """,
        token_for(db),
        db,
    )

    assert "errors" in data
