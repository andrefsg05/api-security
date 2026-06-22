from typing import Any

from sqlalchemy.orm import Session

from app.models import Order, User
from app.security import verify_password


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.query(User).filter(User.email == email.lower()).first()


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    user = get_user_by_email(db, email)
    if user is None:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def expose_user(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "is_admin": user.is_admin,
        "password_hash": user.password_hash,
        "internal_notes": user.internal_notes,
        "account_status": user.account_status,
    }


def update_user_vulnerable(
    db: Session,
    user: User,
    updates: dict[str, Any],
) -> User:
    writable_columns = {column.name for column in User.__table__.columns}
    writable_columns.discard("id")

    # Deliberately vulnerable: trusts any user column supplied by the client.
    for key, value in updates.items():
        if key in writable_columns:
            setattr(user, key, value)

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_user_secure(db: Session, user: User, name: str | None, email: str | None) -> User:
    if name is not None:
        user.name = name
    if email is not None:
        user.email = email.lower()

    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def list_user_orders(db: Session, user_id: int) -> list[Order]:
    return (
        db.query(Order)
        .filter(Order.user_id == user_id)
        .order_by(Order.id.asc())
        .all()
    )


def get_order_by_id(db: Session, order_id: int) -> Order | None:
    return db.get(Order, order_id)


def list_all_users(db: Session) -> list[User]:
    return db.query(User).order_by(User.id.asc()).all()
