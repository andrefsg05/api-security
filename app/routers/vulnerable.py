from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import OrderOut, UserVulnerableOut
from app.security import get_current_user
from app.services import (
    expose_user,
    get_order_by_id,
    list_all_users,
    list_user_orders,
    update_user_vulnerable,
)


router = APIRouter(prefix="/api/vulnerable", tags=["vulnerable"])


# Vulnerabilidade: Excessive Data Exposure.
# Existe porque a resposta usa UserVulnerableOut/expose_user e devolve campos internos.
@router.get("/me", response_model=UserVulnerableOut)
def read_me_vulnerable(current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    return expose_user(current_user)


# Vulnerabilidade: Mass Assignment.
# Existe porque o corpo eh aceite como dict livre e campos extra podem ser aplicados ao utilizador.
@router.patch("/me", response_model=UserVulnerableOut)
def update_me_vulnerable(
    updates: dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    updated_user = update_user_vulnerable(db, current_user, updates)
    return expose_user(updated_user)


# Endpoint de apoio a BOLA/IDOR.
# Mostra no frontend apenas as encomendas do utilizador; o ID manipulado eh explorado no endpoint seguinte.
@router.get("/orders", response_model=list[OrderOut])
def list_orders_vulnerable(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return list_user_orders(db, current_user.id)


# Vulnerabilidade: BOLA/IDOR.
# Existe porque o utilizador eh autenticado, mas a API nao confirma que a encomenda lhe pertence.
@router.get("/orders/{order_id}", response_model=OrderOut)
def read_order_vulnerable(
    order_id: int,
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    order = get_order_by_id(db, order_id)
    if order is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Encomenda nao encontrada",
        )
    return order


# Vulnerabilidade: Broken Function Level Authorization.
# Existe porque basta estar autenticado; nao ha verificacao de role/admin antes de listar utilizadores.
@router.get("/admin/users", response_model=list[UserVulnerableOut])
def list_users_vulnerable(
    _: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return [expose_user(user) for user in list_all_users(db)]
