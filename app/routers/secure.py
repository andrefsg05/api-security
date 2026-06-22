from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.schemas import (
    AdminUserSafeOut,
    LoginRequest,
    OrderOut,
    TokenResponse,
    UserSafeOut,
    UserUpdateSafe,
)
from app.security import create_access_token, get_current_user, require_admin
from app.services import (
    authenticate_user,
    get_order_by_id,
    list_all_users,
    update_user_secure,
)


router = APIRouter(prefix="/api/secure", tags=["secure"])

MAX_FAILED_ATTEMPTS = 5
RATE_LIMIT_WINDOW = timedelta(minutes=1)
failed_attempts: dict[str, list[datetime]] = {}


def _rate_limit_key(request: Request, email: str) -> str:
    client_host = request.client.host if request.client else "unknown"
    return f"{client_host}:{email.lower()}"


def _recent_failures(key: str, now: datetime) -> list[datetime]:
    recent = [
        attempt
        for attempt in failed_attempts.get(key, [])
        if now - attempt < RATE_LIMIT_WINDOW
    ]
    failed_attempts[key] = recent
    return recent


# Vulnerabilidade corrigida: Falta de Rate Limiting.
@router.post("/auth/login", response_model=TokenResponse)
def login_secure(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    now = datetime.now(timezone.utc)
    key = _rate_limit_key(request, payload.email)
    recent = _recent_failures(key, now)

    # Correcao: bloqueia novas tentativas quando o limite de falhas recentes eh atingido.
    if len(recent) >= MAX_FAILED_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Demasiadas tentativas falhadas. Tente novamente mais tarde.",
        )

    user = authenticate_user(db, payload.email, payload.password)
    if user is None:
        # Correcao: regista a falha para contar contra o limite por IP/email.
        failed_attempts.setdefault(key, []).append(now)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou password invalidos",
        )

    failed_attempts.pop(key, None)
    return TokenResponse(access_token=create_access_token(str(user.id)))


# Vulnerabilidade corrigida: Excessive Data Exposure.
@router.get(
    "/me",
    # Correcao: UserSafeOut limita a resposta aos campos publicos.
    response_model=UserSafeOut,
)
def read_me_secure(current_user: User = Depends(get_current_user)):
    return current_user


# Vulnerabilidade corrigida: Mass Assignment.
@router.patch("/me", response_model=UserSafeOut)
def update_me_secure(
    # Correcao: UserUpdateSafe so aceita campos permitidos e rejeita propriedades extra.
    payload: UserUpdateSafe,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Correcao: a atualizacao aplica apenas name/email recebidos pelo schema seguro.
    return update_user_secure(db, current_user, payload.name, payload.email)


# Vulnerabilidade corrigida: BOLA/IDOR.
@router.get("/orders/{order_id}", response_model=OrderOut)
def read_order_secure(
    order_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    order = get_order_by_id(db, order_id)
    if order is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Encomenda nao encontrada",
        )
    # Correcao: valida ownership antes de devolver a encomenda.
    if order.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Esta encomenda pertence a outro utilizador",
        )
    return order


# Vulnerabilidade corrigida: Broken Function Level Authorization.
@router.get("/admin/users", response_model=list[AdminUserSafeOut])
def list_users_secure(
    # Correcao: require_admin verifica privilegios antes de executar a funcao administrativa.
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return list_all_users(db)
