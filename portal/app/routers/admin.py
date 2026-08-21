"""
Painel de administração — rotas HTML + ações HTMX.
Requer is_admin=True. Autenticação por cookie.
"""
import logging
import uuid
from datetime import datetime, timedelta, timezone

log = logging.getLogger("admin")

import stripe
from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from deps import MustChangePassword
from models.bandwidth import AuditLog, BandwidthUsage, CustomDomain
from models.peer import VpnPeer
from models.plan import Plan
from models.subscription import Subscription
from models.user import User
from services import temp_password, vpn_bridge
from services.mailer import send_quota_alert
from services.provisioner import _provision_peer
from templates_env import templates

router = APIRouter(prefix="/admin", tags=["admin"])
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _client_ip(request: Request) -> str | None:
    """IP real do cliente. A app só escuta em 127.0.0.1, então o único
    caminho até aqui é o nginx — o X-Forwarded-For dele é confiável."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def _fmt_bytes(b: int) -> str:
    if b >= 1024 ** 3:
        return f"{b / 1024**3:.1f} GB"
    if b >= 1024 ** 2:
        return f"{b / 1024**2:.0f} MB"
    return f"{b / 1024:.0f} KB"


def _fmt_date(dt) -> str:
    if dt is None:
        return "—"
    if isinstance(dt, str):
        return dt[:10]
    return dt.strftime("%d/%m/%Y")


templates.env.filters["fmt_bytes"] = _fmt_bytes
templates.env.filters["fmt_date"] = _fmt_date


# ── Auth helper ───────────────────────────────────────────────────────────────

async def _get_admin(request: Request, db: AsyncSession) -> User | None:
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("kind") != "access":
            return None
        user_id = payload["sub"]
    except JWTError:
        return None
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not (user and user.is_active and user.is_admin):
        return None
    if user.must_change_password:
        raise MustChangePassword()
    return user


async def require_admin(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    user = await _get_admin(request, db)
    if user is None:
        raise Exception("redirect:/login")  # handled below
    return user


# Wrapper para todas as rotas HTML de admin — redireciona se não autenticado
async def _admin_or_redirect(request: Request, db: AsyncSession) -> User | None:
    user = await _get_admin(request, db)
    return user


# ── Dashboard / Stats ─────────────────────────────────────────────────────────

@router.get("", response_class=HTMLResponse)
async def admin_index(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)

    period = datetime.now(timezone.utc).strftime("%Y-%m")

    total_users = (await db.execute(
        select(func.count()).select_from(User)
    )).scalar() or 0

    active_subs = (await db.execute(
        select(func.count()).select_from(Subscription)
        .where(Subscription.status.in_(["active", "trialing"]))
    )).scalar() or 0

    active_peers = (await db.execute(
        select(func.count()).select_from(VpnPeer)
        .where(VpnPeer.is_active.is_(True))
    )).scalar() or 0

    bw_month_bytes = (await db.execute(
        select(func.coalesce(
            func.sum(BandwidthUsage.bytes_rx + BandwidthUsage.bytes_tx), 0
        )).where(BandwidthUsage.period == period)
    )).scalar() or 0

    recent_users_res = await db.execute(
        select(User).order_by(User.created_at.desc()).limit(8)
    )
    recent_users = recent_users_res.scalars().all()

    return templates.TemplateResponse("admin/index.html", {
        "request": request,
        "user": admin,
        "stats": {
            "total_users": total_users,
            "active_subs": active_subs,
            "active_peers": active_peers,
            "bw_month": bw_month_bytes,
        },
        "recent_users": recent_users,
        "period": period,
    })


# ── Usuários ──────────────────────────────────────────────────────────────────

@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    q: str = "",
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)

    stmt = select(User, Subscription).outerjoin(
        Subscription,
        (Subscription.user_id == User.id) &
        Subscription.status.in_(["active", "trialing", "past_due"]),
    ).order_by(User.created_at.desc())

    if q:
        stmt = stmt.where(User.email.ilike(f"%{q}%") | User.name.ilike(f"%{q}%"))

    rows = (await db.execute(stmt)).all()
    users_data = [{"user": r.User, "sub": r.Subscription} for r in rows]

    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "user": admin,
        "users_data": users_data,
        "q": q,
    })


@router.post("/users/{user_id}/toggle", response_class=HTMLResponse)
async def admin_toggle_user(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    res = await db.execute(select(User).where(User.id == user_id))
    target = res.scalar_one_or_none()
    if not target:
        return HTMLResponse("", status_code=404)

    new_active = not target.is_active
    await db.execute(update(User).where(User.id == user_id).values(is_active=new_active))
    await db.commit()
    await db.refresh(target)

    sub_res = await db.execute(
        select(Subscription).where(
            Subscription.user_id == user_id,
            Subscription.status.in_(["active", "trialing", "past_due"]),
        )
    )
    sub = sub_res.scalar_one_or_none()

    return templates.TemplateResponse("admin/_user_row.html", {
        "request": request,
        "item": {"user": target, "sub": sub},
    })


@router.post("/users/{user_id}/verify-email", response_class=HTMLResponse)
async def admin_verify_email(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    res = await db.execute(select(User).where(User.id == user_id))
    target = res.scalar_one_or_none()
    if not target:
        return HTMLResponse("", status_code=404)

    await db.execute(
        update(User).where(User.id == user_id).values(
            email_verified_at=datetime.now(timezone.utc),
            email_verification_token=None,
        )
    )
    await db.commit()
    await db.refresh(target)

    sub_res = await db.execute(
        select(Subscription).where(
            Subscription.user_id == user_id,
            Subscription.status.in_(["active", "trialing", "past_due"]),
        )
    )
    sub = sub_res.scalar_one_or_none()

    return templates.TemplateResponse("admin/_user_row.html", {
        "request": request,
        "item": {"user": target, "sub": sub},
    })


@router.get("/users/new", response_class=HTMLResponse)
async def admin_user_new_page(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse("admin/user_new.html", {
        "request": request, "user": admin, "error": None, "form": {"name": "", "email": ""},
    })


@router.post("/users/new", response_class=HTMLResponse)
async def admin_user_new_save(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    is_admin: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)

    name  = name.strip()
    email = email.strip().lower()

    def _error(msg: str):
        return templates.TemplateResponse("admin/user_new.html", {
            "request": request, "user": admin,
            "error": msg, "form": {"name": name, "email": email},
        }, status_code=400)

    if not name:
        return _error("Nome não pode ser vazio.")
    if not email:
        return _error("E-mail não pode ser vazio.")
    if len(password) < 8:
        return _error("Senha deve ter no mínimo 8 caracteres.")

    existing = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing:
        return _error("Este e-mail já está cadastrado.")

    new_user = User(
        email=email,
        password_hash=_pwd.hash(password),
        name=name,
        is_admin=is_admin == "1",
        # O admin digitou o endereço e definiu a senha — não há e-mail de
        # verificação a enviar. Sem isto a conta nascia com email_verified_at
        # NULL e sem token, ou seja, sem nenhuma forma de fazer login.
        email_verified_at=datetime.now(timezone.utc),
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return RedirectResponse(f"/admin/users/{new_user.id}/edit?success=true", status_code=303)


async def _get_edit_context(user_id: uuid.UUID, db: AsyncSession) -> dict:
    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not target:
        return {}
    plans = (await db.execute(select(Plan).order_by(Plan.price_cents))).scalars().all()
    sub = (await db.execute(
        select(Subscription).where(
            Subscription.user_id == user_id,
            Subscription.status.in_(["active", "trialing", "past_due"]),
        ).order_by(Subscription.created_at.desc())
    )).scalar_one_or_none()
    peer = None
    if sub and sub.peer_id:
        peer = (await db.execute(
            select(VpnPeer).where(VpnPeer.id == sub.peer_id, VpnPeer.is_active.is_(True))
        )).scalar_one_or_none()
    return {"target": target, "plans": plans, "sub": sub, "peer": peer}


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
async def admin_user_edit_page(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    success: bool = False,
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)
    ctx = await _get_edit_context(user_id, db)
    if not ctx:
        return RedirectResponse("/admin/users", status_code=303)
    return templates.TemplateResponse("admin/user_edit.html", {
        "request": request, "user": admin, "error": None, "success": success, **ctx,
    })


@router.post("/users/{user_id}/edit", response_class=HTMLResponse)
async def admin_user_edit_save(
    user_id: uuid.UUID,
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    is_active: str = Form(default=""),
    is_admin: str = Form(default=""),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)

    ctx = await _get_edit_context(user_id, db)
    if not ctx:
        return RedirectResponse("/admin/users", status_code=303)
    target = ctx["target"]

    def _error(msg: str):
        return templates.TemplateResponse("admin/user_edit.html", {
            "request": request, "user": admin, "error": msg, "success": False, **ctx,
        }, status_code=400)

    name = name.strip()
    email = email.strip().lower()
    if not name:
        return _error("Nome não pode ser vazio.")
    if not email:
        return _error("E-mail não pode ser vazio.")

    # Verifica duplicidade de e-mail (ignorando o próprio usuário)
    dup = (await db.execute(
        select(User).where(User.email == email, User.id != user_id)
    )).scalar_one_or_none()
    if dup:
        return _error("Este e-mail já está em uso por outro usuário.")

    await db.execute(
        update(User).where(User.id == user_id).values(
            name=name,
            email=email,
            is_active=is_active == "1",
            is_admin=is_admin == "1",
        )
    )
    await db.commit()
    return RedirectResponse(f"/admin/users/{user_id}/edit?success=true", status_code=303)


@router.post("/users/{user_id}/set-plan", response_class=HTMLResponse)
async def admin_set_plan(
    user_id: uuid.UUID,
    request: Request,
    plan_id: str = Form(...),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    target = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    plan   = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
    if not target or not plan:
        return RedirectResponse("/admin/users", status_code=303)

    # Assinatura ativa existente?
    sub = (await db.execute(
        select(Subscription).where(
            Subscription.user_id == user_id,
            Subscription.status.in_(["active", "trialing", "past_due"]),
        ).order_by(Subscription.created_at.desc())
    )).scalar_one_or_none()

    if sub is None:
        # Cria assinatura manual + provisiona peer
        sub = Subscription(
            user_id=user_id,
            plan_id=plan_id,
            stripe_subscription_id=f"manual_{uuid.uuid4().hex}",
            status="active",
            current_period_start=datetime.now(timezone.utc),
            current_period_end=datetime.now(timezone.utc) + timedelta(days=30),
        )
        db.add(sub)
        await db.flush()
        await _provision_peer(db, target, sub)
    else:
        old_plan_id = sub.plan_id

        # Atualiza plano na subscription
        await db.execute(
            update(Subscription).where(Subscription.id == sub.id).values(plan_id=plan_id)
        )

        # Peer existe?
        peer = None
        if sub.peer_id:
            peer = (await db.execute(
                select(VpnPeer).where(VpnPeer.id == sub.peer_id, VpnPeer.is_active.is_(True))
            )).scalar_one_or_none()

        if peer is None:
            # Sub existe mas peer não foi provisionado ainda — provisiona agora
            await db.flush()
            sub.plan_id = plan_id
            await _provision_peer(db, target, sub)
        elif old_plan_id != plan_id:
            # Muda plano no peer e atualiza TC
            await db.execute(
                update(VpnPeer).where(VpnPeer.id == peer.id).values(plan_id=plan_id)
            )
            try:
                await vpn_bridge.update_bandwidth(str(peer.ip_address), plan.bandwidth_mbps)
            except Exception as exc:
                log.warning("update_bandwidth falhou ip=%s: %s", peer.ip_address, exc)

    await db.commit()
    return RedirectResponse(f"/admin/users/{user_id}/edit?success=true", status_code=303)


@router.post("/users/{user_id}/delete")
async def admin_delete_user(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)
    if str(user_id) == str(admin.id):
        return RedirectResponse(f"/admin/users/{user_id}/edit?error=self", status_code=303)

    # Peers ativos → remove do WireGuard
    peers = (await db.execute(
        select(VpnPeer).where(VpnPeer.user_id == user_id)
    )).scalars().all()

    for peer in peers:
        if peer.is_active:
            try:
                await vpn_bridge.remove_peer(peer.public_key)
            except Exception as exc:
                log.warning("remove_peer falhou ao deletar user %s: %s", user_id, exc)

    # Deleta dependentes em ordem (FK)
    peer_ids = [p.id for p in peers]
    if peer_ids:
        await db.execute(
            __import__("sqlalchemy").delete(BandwidthUsage).where(BandwidthUsage.peer_id.in_(peer_ids))
        )
        await db.execute(
            __import__("sqlalchemy").delete(CustomDomain).where(CustomDomain.peer_id.in_(peer_ids))
        )

    await db.execute(
        __import__("sqlalchemy").delete(Subscription).where(Subscription.user_id == user_id)
    )
    await db.execute(
        __import__("sqlalchemy").delete(VpnPeer).where(VpnPeer.user_id == user_id)
    )
    await db.execute(
        __import__("sqlalchemy").delete(User).where(User.id == user_id)
    )
    await db.commit()

    log.info("Usuário %s deletado pelo admin %s", user_id, admin.id)
    return RedirectResponse("/admin/users", status_code=303)


@router.post("/users/{user_id}/reset-password", response_class=HTMLResponse)
async def admin_reset_password(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    res = await db.execute(select(User).where(User.id == user_id))
    target = res.scalar_one_or_none()
    if not target:
        return HTMLResponse("", status_code=404)

    # Senha aleatória por reset, exibida uma única vez na resposta HTMX.
    # Só o hash é persistido.
    temp = temp_password.generate()
    await db.execute(
        update(User).where(User.id == user_id)
        .values(
            password_hash=_pwd.hash(temp),
            must_change_password=True,
            password_reset_at=datetime.now(timezone.utc),
        )
    )
    db.add(AuditLog(
        user_id=admin.id,
        action="admin.reset_password",
        details={
            "target_user_id": str(target.id),
            "target_email": target.email,
            "ttl_hours": temp_password.TTL_HOURS,
        },
        ip_address=_client_ip(request),
    ))
    await db.commit()
    await db.refresh(target)

    log.info("Senha de %s resetada pelo admin %s", target.email, admin.id)

    sub_res = await db.execute(
        select(Subscription).where(
            Subscription.user_id == user_id,
            Subscription.status.in_(["active", "trialing", "past_due"]),
        )
    )
    sub = sub_res.scalar_one_or_none()

    return templates.TemplateResponse("admin/_user_row.html", {
        "request": request,
        "item": {"user": target, "sub": sub},
        "temp_password": temp,
        "temp_password_ttl": temp_password.TTL_HOURS,
    })


# ── Peers ─────────────────────────────────────────────────────────────────────

@router.get("/peers", response_class=HTMLResponse)
async def admin_peers(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)

    period = datetime.now(timezone.utc).strftime("%Y-%m")

    rows = (await db.execute(
        select(VpnPeer, User, Plan, BandwidthUsage)
        .join(User, VpnPeer.user_id == User.id)
        .join(Plan, VpnPeer.plan_id == Plan.id)
        .outerjoin(
            BandwidthUsage,
            (BandwidthUsage.peer_id == VpnPeer.id) & (BandwidthUsage.period == period),
        )
        .where(VpnPeer.is_active.is_(True))
        .order_by(VpnPeer.created_at.desc())
    )).all()

    peers_data = [{"peer": r.VpnPeer, "user": r.User, "plan": r.Plan, "bw": r.BandwidthUsage}
                  for r in rows]

    return templates.TemplateResponse("admin/peers.html", {
        "request": request,
        "user": admin,
        "peers_data": peers_data,
        "period": period,
    })


@router.post("/peers/{peer_id}/suspend", response_class=HTMLResponse)
async def admin_suspend_peer(
    peer_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    period = datetime.now(timezone.utc).strftime("%Y-%m")
    res = await db.execute(
        select(VpnPeer, User, Plan, BandwidthUsage)
        .join(User, VpnPeer.user_id == User.id)
        .join(Plan, VpnPeer.plan_id == Plan.id)
        .outerjoin(BandwidthUsage,
            (BandwidthUsage.peer_id == VpnPeer.id) & (BandwidthUsage.period == period))
        .where(VpnPeer.id == peer_id)
    )
    row = res.first()
    if not row:
        return HTMLResponse("", status_code=404)

    try:
        await vpn_bridge.set_quota(str(row.VpnPeer.ip_address))
    except Exception:
        pass

    return templates.TemplateResponse("admin/_peer_row.html", {
        "request": request,
        "item": {"peer": row.VpnPeer, "user": row.User, "plan": row.Plan, "bw": row.BandwidthUsage},
        "throttled": True,
    })


@router.post("/peers/{peer_id}/unsuspend", response_class=HTMLResponse)
async def admin_unsuspend_peer(
    peer_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    period = datetime.now(timezone.utc).strftime("%Y-%m")
    res = await db.execute(
        select(VpnPeer, User, Plan, BandwidthUsage)
        .join(User, VpnPeer.user_id == User.id)
        .join(Plan, VpnPeer.plan_id == Plan.id)
        .outerjoin(BandwidthUsage,
            (BandwidthUsage.peer_id == VpnPeer.id) & (BandwidthUsage.period == period))
        .where(VpnPeer.id == peer_id)
    )
    row = res.first()
    if not row:
        return HTMLResponse("", status_code=404)

    try:
        await vpn_bridge.clear_quota(str(row.VpnPeer.ip_address))
    except Exception:
        pass

    return templates.TemplateResponse("admin/_peer_row.html", {
        "request": request,
        "item": {"peer": row.VpnPeer, "user": row.User, "plan": row.Plan, "bw": row.BandwidthUsage},
        "throttled": False,
    })


@router.delete("/peers/{peer_id}", response_class=HTMLResponse)
async def admin_remove_peer(
    peer_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    res = await db.execute(select(VpnPeer).where(VpnPeer.id == peer_id))
    peer = res.scalar_one_or_none()
    if not peer:
        return HTMLResponse("")

    try:
        await vpn_bridge.remove_peer(peer.public_key)
    except Exception:
        pass

    await db.execute(
        update(VpnPeer)
        .where(VpnPeer.id == peer_id)
        .values(is_active=False, revoked_at=datetime.now(timezone.utc))
    )
    await db.commit()
    return HTMLResponse("")  # HTMX remove a linha


# ── Configurações / Produção ──────────────────────────────────────────────────

@router.get("/settings", response_class=HTMLResponse)
async def admin_settings(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return RedirectResponse("/login", status_code=303)

    plans_res = await db.execute(select(Plan).order_by(Plan.price_cents))
    plans = plans_res.scalars().all()

    stripe_mode = "live" if settings.STRIPE_SECRET_KEY.startswith("sk_live_") else "test"
    smtp_ok = bool(settings.SMTP_HOST and settings.SMTP_USER)

    return templates.TemplateResponse("admin/settings.html", {
        "request": request,
        "user": admin,
        "plans": plans,
        "cfg": {
            "app_env": settings.APP_ENV,
            "app_base_url": settings.APP_BASE_URL,
            "server_ip": settings.SERVER_PUBLIC_IP,
            "wg_pubkey": settings.WG_SERVER_PUBLIC_KEY,
            "smtp_ok": smtp_ok,
            "smtp_host": settings.SMTP_HOST or "—",
            "stripe_mode": stripe_mode,
            "stripe_ok": bool(settings.STRIPE_SECRET_KEY and not settings.STRIPE_SECRET_KEY.endswith("placeholder")),
            "webhook_ok": bool(settings.STRIPE_WEBHOOK_SECRET),
        },
    })


@router.post("/plans/{plan_id}/price", response_class=HTMLResponse)
async def admin_update_price(
    plan_id: str,
    request: Request,
    price_id: str = Form(...),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    price_id = price_id.strip()
    if not price_id.startswith("price_"):
        return HTMLResponse(
            '<span class="text-red-500 text-xs">Deve começar com price_</span>'
        )

    await db.execute(
        update(Plan).where(Plan.id == plan_id).values(stripe_price_id=price_id)
    )
    await db.commit()
    return HTMLResponse(
        f'<span class="text-green-600 text-xs font-mono">✓ {price_id}</span>'
    )


@router.post("/smtp-test", response_class=HTMLResponse)
async def admin_smtp_test(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    admin = await _admin_or_redirect(request, db)
    if not admin:
        return HTMLResponse("", status_code=401)

    try:
        await send_quota_alert(admin.email, admin.name, "Teste", 42.0)
        return HTMLResponse(
            f'<span class="text-green-600 text-sm">✓ E-mail enviado para {admin.email}</span>'
        )
    except Exception as e:
        return HTMLResponse(
            f'<span class="text-red-500 text-sm">✗ Erro: {e}</span>'
        )
