from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.graphql import secure_router as secure_graphql_router
from app.graphql import vulnerable_router as vulnerable_graphql_router
from app.database import Base, SessionLocal, engine
from app.routers import auth, secure, vulnerable
from app.seed import seed_database


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_database(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title="InsecureShop",
    description="Demo academica de vulnerabilidades em APIs modernas.",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(auth.router)
app.include_router(vulnerable.router)
app.include_router(secure.router)
app.include_router(vulnerable_graphql_router, prefix="/graphql/vulnerable")
app.include_router(secure_graphql_router, prefix="/graphql/secure")

static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
def index():
    return RedirectResponse(url="/static/login.html")


@app.get("/health", tags=["system"])
def health():
    return {"status": "ok"}
