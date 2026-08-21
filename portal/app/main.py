import asyncio
import logging
import logging.config
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from config import settings
from database import AsyncSessionLocal
from deps import MustChangePassword
from routers.admin import router as admin_router
from routers.auth import router as auth_router
from routers.checkout import router as checkout_router
from routers.pages import router as pages_router
from routers.peers import router as peers_router
from routers.webhooks import router as webhooks_router
from services import scheduler as sched

# ── Logging JSON estruturado ──────────────────────────────────────────────────

_LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
            "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
        },
        "plain": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        },
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
            "formatter": "json" if settings.APP_ENV == "production" else "plain",
        },
    },
    "root": {
        "level": "INFO",
        "handlers": ["stdout"],
    },
    "loggers": {
        "uvicorn.access": {"propagate": True},
        "uvicorn.error": {"propagate": True},
        "apscheduler": {"level": "WARNING"},
    },
}
logging.config.dictConfig(_LOG_CONFIG)
log = logging.getLogger("main")

# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("startup: iniciando scheduler")
    sched.start()
    yield
    log.info("shutdown: encerrando scheduler")
    sched.stop()

# ── App ───────────────────────────────────────────────────────────────────────

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="VPN Concentrator API",
    version="0.4.0",
    docs_url="/docs" if settings.APP_ENV != "production" else None,
    redoc_url="/redoc" if settings.APP_ENV != "production" else None,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(MustChangePassword)
async def _must_change_password(request: Request, exc: MustChangePassword) -> Response:
    """Senha resetada pelo admin: prende o usuário em /account/password."""
    # Num parcial HTMX um 303 seria seguido e a página inteira injetada dentro
    # do target; HX-Redirect navega a janela.
    if request.headers.get("hx-request") == "true":
        return Response(status_code=204, headers={"HX-Redirect": "/account/password"})
    return RedirectResponse("/account/password", status_code=303)

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(admin_router)
app.include_router(auth_router)
app.include_router(checkout_router)
app.include_router(webhooks_router)
app.include_router(peers_router)
app.include_router(pages_router)


# ── /health ───────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    t0 = time.monotonic()
    checks: dict[str, str] = {}

    # DB
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(__import__("sqlalchemy").text("SELECT 1"))
        checks["db"] = "ok"
    except Exception as e:
        checks["db"] = f"error: {e}"

    # Bridge
    try:
        from services import vpn_bridge
        await asyncio.wait_for(vpn_bridge.genkeys(), timeout=3.0)
        checks["bridge"] = "ok"
    except asyncio.TimeoutError:
        checks["bridge"] = "error: timeout"
    except Exception as e:
        checks["bridge"] = f"error: {e}"

    # WireGuard — inferido via bridge (bridge chama wg no host)
    # Se o bridge respondeu ok, o wg0 está acessível
    checks["wireguard"] = "ok" if checks["bridge"] == "ok" else "unknown"

    elapsed_ms = round((time.monotonic() - t0) * 1000)
    overall = "ok" if all(v == "ok" for v in checks.values()) else "degraded"

    return {
        "status": overall,
        "checks": checks,
        "elapsed_ms": elapsed_ms,
        "scheduler_jobs": len(sched.scheduler.get_jobs()) if sched.scheduler.running else 0,
    }
