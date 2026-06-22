from sqlalchemy.orm import Session

from app.models import Order, User
from app.security import hash_password


def seed_database(db: Session) -> None:
    if db.query(User).first() is not None:
        return

    andre = User(
        name="André",
        email="andre@example.com",
        password_hash=hash_password("password123"),
        role="user",
        is_admin=False,
        internal_notes="Cliente normal. Prefere entregas ao fim da tarde.",
        account_status="active",
    )
    maria = User(
        name="Maria",
        email="maria@example.com",
        password_hash=hash_password("password123"),
        role="user",
        is_admin=False,
        internal_notes="Cliente frequente com morada validada.",
        account_status="active",
    )
    admin = User(
        name="Admin",
        email="admin@example.com",
        password_hash=hash_password("admin123"),
        role="admin",
        is_admin=True,
        internal_notes="Conta interna de administracao.",
        account_status="active",
    )

    db.add_all([andre, maria, admin])
    db.flush()

    db.add_all(
        [
            Order(
                product="Teclado mecanico",
                price=89.9,
                status="Em preparacao",
                shipping_address="Rua das Flores 12, Lisboa",
                user_id=andre.id,
            ),
            Order(
                product="Monitor 27 polegadas",
                price=229.0,
                status="Enviado",
                shipping_address="Rua das Flores 12, Lisboa",
                user_id=andre.id,
            ),
            Order(
                product="Cadeira ergonomica",
                price=179.5,
                status="Entregue",
                shipping_address="Avenida Central 45, Porto",
                user_id=maria.id,
            ),
            Order(
                product="Auscultadores sem fios",
                price=59.99,
                status="Em transporte",
                shipping_address="Avenida Central 45, Porto",
                user_id=maria.id,
            ),
        ]
    )
    db.commit()
