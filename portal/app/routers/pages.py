"""
HTML page routes — renderizadas com Jinja2.
Autenticação por cookie HttpOnly (access_token).
"""
import logging
import secrets
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, Form, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import get_db
from deps import MustChangePassword
from i18n import get_lang, TRANSLATIONS
from models.bandwidth import BandwidthUsage
from models.peer import VpnPeer
from models.plan import Plan
from models.subscription import Subscription
from models.user import User
from routers.peers import _get_active_peer_full
from services import mailer, temp_password
from services.mailer import send_verification_email
from templates_env import render, templates

log = logging.getLogger("pages")

router = APIRouter(tags=["pages"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_COOKIE = "access_token"
_COOKIE_MAX_AGE = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
_REFRESH_COOKIE = "refresh_token"
_REFRESH_MAX_AGE = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400


# ── auth helpers ──────────────────────────────────────────────────────────────

def _make_access_token(user_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": user_id, "kind": "access", "exp": exp},
                      settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def _make_refresh_token(user_id: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": user_id, "kind": "refresh", "exp": exp},
                      settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def _set_auth_cookies(response, user_id: str) -> None:
    response.set_cookie(_COOKIE, _make_access_token(user_id),
                        max_age=_COOKIE_MAX_AGE, httponly=True, samesite="lax")
    response.set_cookie(_REFRESH_COOKIE, _make_refresh_token(user_id),
                        max_age=_REFRESH_MAX_AGE, httponly=True, samesite="lax")


async def _auth_user(
    request: Request,
    db: AsyncSession,
    *,
    allow_password_change: bool = False,
) -> User | None:
    """Tries access cookie, falls back to refresh cookie. Returns None if unauthenticated.

    Levanta MustChangePassword quando o admin resetou a senha e ela ainda não
    foi trocada — só /account/password passa allow_password_change=True, senão
    o próprio gate impediria a troca.
    """
    token = request.cookies.get(_COOKIE)
    refresh = request.cookies.get(_REFRESH_COOKIE)

    user_id = None
    if token:
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            if payload.get("kind") == "access":
                user_id = payload["sub"]
        except JWTError:
            pass

    if user_id is None and refresh:
        try:
            payload = jwt.decode(refresh, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
            if payload.get("kind") == "refresh":
                user_id = payload["sub"]
        except JWTError:
            pass

    if user_id is None:
        return None

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None or user.email_verified_at is None:
        return None
    if user.must_change_password and not allow_password_change:
        raise MustChangePassword()
    return user



# ── language switcher ─────────────────────────────────────────────────────────

@router.get("/set-lang")
async def set_lang(request: Request, lang: str = "pt") -> RedirectResponse:
    if lang not in ("pt", "en"):
        lang = "pt"
    ref = request.headers.get("referer", "/")
    response = RedirectResponse(ref, status_code=303)
    response.set_cookie("lang", lang, max_age=365 * 86400, samesite="lax")
    return response


# ── public pages ──────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def index(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    user = await _auth_user(request, db)
    plans_res = await db.execute(select(Plan).order_by(Plan.price_cents))
    plans = plans_res.scalars().all()
    return render(request, "index.html", {"request": request, "user": user, "plans": plans})


# ── auth pages ────────────────────────────────────────────────────────────────

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> HTMLResponse:
    return render(request, "auth/login.html", {"request": request, "error": None})


@router.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    t = TRANSLATIONS[get_lang(request)]
    res = await db.execute(select(User).where(User.email == email))
    user = res.scalar_one_or_none()
    if user is None or not pwd_context.verify(password, user.password_hash):
        return render(request, "auth/login.html",
                      {"request": request, "error": t["err_invalid_credentials"]},
                      status_code=401)
    if user.email_verified_at is None:
        return render(request, "auth/login.html",
                      {"request": request, "error": t["err_email_not_verified"]},
                      status_code=403)
    if user.must_change_password and temp_password.is_expired(user.password_reset_at):
        return render(request, "auth/login.html",
                      {"request": request, "error": t["err_temp_pass_expired"]},
                      status_code=403)

    await db.execute(
        update(User).where(User.id == user.id)
        .values(last_login=datetime.now(timezone.utc))
    )
    await db.commit()

    if user.must_change_password:
        dest = "/account/password"
    else:
        # is_active=False = aguardando pagamento → redireciona para planos
        dest = "/dashboard" if user.is_active else "/plans"
    response = RedirectResponse(dest, status_code=303)
    _set_auth_cookies(response, str(user.id))
    return response


@router.get("/register", response_class=HTMLResponse)
async def register_page(request: Request) -> HTMLResponse:
    return render(request, "auth/register.html", {"request": request, "error": None})


@router.post("/register")
async def register_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    t = TRANSLATIONS[get_lang(request)]
    if len(password) < 8:
        return render(request, "auth/register.html",
                      {"request": request, "error": t["err_pass_too_short"]},
                      status_code=400)

    res = await db.execute(select(User).where(User.email == email))
    if res.scalar_one_or_none():
        return render(request, "auth/register.html",
                      {"request": request, "error": t["err_email_taken"]},
                      status_code=409)

    # Sem SMTP não há como entregar o link de verificação, e a conta nasceria
    # inacessível (o login exige email_verified_at). Nesse caso a conta já é
    # criada verificada — ou seja, enquanto o SMTP estiver vazio não há prova
    # de posse do endereço informado.
    smtp_ok = mailer.is_configured()
    token = secrets.token_urlsafe(32) if smtp_ok else None
    user = User(
        email=email,
        password_hash=pwd_context.hash(password),
        name=name.strip(),
        is_active=False,
        email_verification_token=token,
        email_verified_at=None if smtp_ok else datetime.now(timezone.utc),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    if not smtp_ok:
        log.warning(
            "SMTP não configurado — conta %s criada já verificada, sem confirmação de e-mail",
            email,
        )
        # Já verificada: manda direto para os planos em vez da tela de "confira
        # sua caixa de entrada", que não faria sentido aqui.
        response = RedirectResponse("/plans", status_code=303)
        _set_auth_cookies(response, str(user.id))
        return response

    verify_url = f"{settings.APP_BASE_URL}/verify-email?token={token}"
    import asyncio
    asyncio.create_task(send_verification_email(email, name.strip(), verify_url))

    response = RedirectResponse(f"/register/pending?email={email}", status_code=303)
    return response


@router.get("/register/pending", response_class=HTMLResponse)
async def register_pending(request: Request, email: str = "") -> HTMLResponse:
    return render(request, "auth/pending_verification.html", {
        "request": request,
        "email": email,
        "smtp_configured": mailer.is_configured(),
    })


@router.get("/verify-email", response_class=HTMLResponse)
async def verify_email(
    request: Request,
    token: str = "",
    db: AsyncSession = Depends(get_db),
):
    t = TRANSLATIONS[get_lang(request)]
    if not token:
        return render(request, "auth/login.html",
                      {"request": request, "error": t["err_verify_invalid"]},
                      status_code=400)

    res = await db.execute(select(User).where(User.email_verification_token == token))
    user = res.scalar_one_or_none()
    if user is None:
        return render(request, "auth/login.html",
                      {"request": request, "error": t["err_verify_invalid"]},
                      status_code=400)

    await db.execute(
        update(User).where(User.id == user.id).values(
            email_verified_at=datetime.now(timezone.utc),
            email_verification_token=None,
        )
    )
    await db.commit()

    return RedirectResponse(f"/login?verified=1", status_code=303)


@router.post("/logout")
async def logout() -> RedirectResponse:
    response = RedirectResponse("/", status_code=303)
    response.delete_cookie(_COOKIE)
    response.delete_cookie(_REFRESH_COOKIE)
    return response


# ── plans page (post-register) ────────────────────────────────────────────────

@router.get("/plans", response_class=HTMLResponse)
async def plans_page(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    user = await _auth_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    plans_res = await db.execute(select(Plan).order_by(Plan.price_cents))
    plans = plans_res.scalars().all()
    return render(request, "plans.html", {"request": request, "user": user, "plans": plans})


# ── dashboard ────────────────────────────────────────────────────────────────

@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    user = await _auth_user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    data = await _get_active_peer_full(user, db)

    response = render(request, "dashboard/index.html", {
        "request": request,
        "user": user,
        "subscription": data["subscription"] if data else None,
        "plan": data["plan"] if data else None,
        "peer": data["peer"] if data else None,
        "bandwidth": data["bandwidth"] if data else None,
    })

    # Always refresh the access token cookie on dashboard load
    response.set_cookie(_COOKIE, _make_access_token(str(user.id)),
                        max_age=_COOKIE_MAX_AGE, httponly=True, samesite="lax")
    return response


# ── HTMX partials ─────────────────────────────────────────────────────────────

@router.get("/account/password", response_class=HTMLResponse)
async def change_password_page(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    user = await _auth_user(request, db, allow_password_change=True)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return render(request, "account/password.html", {
        "request": request,
        "user": user,
        "error": None,
        "forced": user.must_change_password,
    })


@router.post("/account/password")
async def change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    user = await _auth_user(request, db, allow_password_change=True)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    t = TRANSLATIONS[get_lang(request)]

    def _error(msg: str):
        return render(request, "account/password.html",
                      {"request": request, "user": user, "error": msg,
                       "forced": user.must_change_password},
                      status_code=400)

    if not pwd_context.verify(current_password, user.password_hash):
        return _error(t["err_wrong_current_pass"])
    if len(new_password) < 8:
        return _error(t["err_new_pass_too_short"])
    if new_password != confirm_password:
        return _error(t["err_pass_mismatch"])
    # Sem isto, o usuário sairia do gate de troca obrigatória reenviando a
    # própria senha temporária como "nova".
    if new_password == current_password:
        return _error(t["err_pass_same"])

    await db.execute(
        update(User).where(User.id == user.id)
        .values(
            password_hash=pwd_context.hash(new_password),
            must_change_password=False,
            password_reset_at=None,
        )
    )
    await db.commit()

    # Invalida a sessão: apaga cookies e redireciona para login
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(_COOKIE)
    response.delete_cookie(_REFRESH_COOKIE)
    return response


@router.get("/dashboard/_qr", response_class=HTMLResponse)
async def dashboard_qr(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    """Returns inline <img> tag for the QR code."""
    import base64
    user = await _auth_user(request, db)
    if user is None:
        return HTMLResponse('<p class="text-red-500">Sessão expirada</p>')

    data = await _get_active_peer_full(user, db)
    t = TRANSLATIONS[get_lang(request)]
    if not data or not data["peer"] or not data["peer"].private_key:
        return HTMLResponse(f'<p class="text-gray-500">{t["qr_unavailable"]}</p>')

    from services.wg_config import build_conf, build_qr_png
    conf = build_conf(data["peer"].private_key, str(data["peer"].ip_address), data["plan"].gateway)
    png = build_qr_png(conf)
    b64 = base64.b64encode(png).decode()
    return HTMLResponse(
        f'<img src="data:image/png;base64,{b64}" class="mx-auto rounded-lg shadow" '
        f'alt="QR Code WireGuard" style="max-width:280px"/>'
    )


@router.get("/dashboard/_chart", response_class=HTMLResponse)
async def dashboard_chart(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    """Retorna partial com dados dos últimos 3 meses de bandwidth para Chart.js."""
    user = await _auth_user(request, db)
    if user is None:
        return HTMLResponse("")

    data = await _get_active_peer_full(user, db)
    t = TRANSLATIONS[get_lang(request)]
    if not data or not data["peer"]:
        return HTMLResponse(f'<p class="text-gray-400 text-sm italic">{t["bw_no_data"]}</p>')

    peer = data["peer"]
    from datetime import date, timedelta

    # Últimos 3 meses
    months = []
    d = date.today().replace(day=1)
    for _ in range(3):
        months.insert(0, d.strftime("%Y-%m"))
        d = (d - timedelta(days=1)).replace(day=1)

    bw_res = await db.execute(
        select(BandwidthUsage).where(
            BandwidthUsage.peer_id == peer.id,
            BandwidthUsage.period.in_(months),
        )
    )
    bw_rows = {b.period: b for b in bw_res.scalars().all()}

    labels = []
    rx_data = []
    tx_data = []
    for m in months:
        bw = bw_rows.get(m)
        labels.append(m[5:] + "/" + m[:4])  # MM/YYYY
        rx_data.append(round((bw.bytes_rx if bw else 0) / 1024**3, 2))
        tx_data.append(round((bw.bytes_tx if bw else 0) / 1024**3, 2))

    import json
    return render(request, "dashboard/_chart.html", {
        "request": request,
        "labels": json.dumps(labels),
        "rx_data": json.dumps(rx_data),
        "tx_data": json.dumps(tx_data),
    })


@router.get("/dashboard/_invoices", response_class=HTMLResponse)
async def dashboard_invoices(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    """Retorna partial com histórico de faturas do Stripe."""
    user = await _auth_user(request, db)
    if user is None:
        return HTMLResponse("")

    if not settings.STRIPE_SECRET_KEY or not user.stripe_customer_id:
        return HTMLResponse('<p class="text-gray-400 text-sm italic">Sem faturas disponíveis.</p>')

    import stripe as _stripe
    _stripe.api_key = settings.STRIPE_SECRET_KEY
    try:
        invoices = _stripe.Invoice.list(customer=user.stripe_customer_id, limit=6)
        inv_list = list(invoices.auto_paging_iter())
    except Exception:
        inv_list = []

    return render(request, "dashboard/_invoices.html", {
        "request": request,
        "invoices": inv_list,
    })


@router.get("/dashboard/_domains", response_class=HTMLResponse)
async def dashboard_domains(request: Request, db: AsyncSession = Depends(get_db)) -> HTMLResponse:
    user = await _auth_user(request, db)
    if user is None:
        return HTMLResponse("")

    data = await _get_active_peer_full(user, db)
    if not data or not data["peer"]:
        return HTMLResponse("")

    from models.bandwidth import CustomDomain
    dom_res = await db.execute(
        select(CustomDomain).where(CustomDomain.peer_id == data["peer"].id)
    )
    domains = dom_res.scalars().all()
    return render(request, "dashboard/_domains.html", {
        "request": request,
        "domains": domains,
        "plan": data["plan"],
    })


@router.post("/dashboard/_domains", response_class=HTMLResponse)
async def dashboard_add_domain(
    request: Request,
    domain: str = Form(...),
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    user = await _auth_user(request, db)
    if user is None:
        return HTMLResponse("")

    data = await _get_active_peer_full(user, db)
    if not data or not data["peer"]:
        return HTMLResponse("")

    plan, peer = data["plan"], data["peer"]

    from models.bandwidth import CustomDomain
    res = await db.execute(select(CustomDomain).where(CustomDomain.peer_id == peer.id))
    existing = res.scalars().all()

    if plan.custom_domains_limit > 0 and len(existing) < plan.custom_domains_limit:
        if not any(d.domain == domain for d in existing):
            db.add(CustomDomain(peer_id=peer.id, domain=domain))
            peer.config_stale = True
            await db.commit()
            res = await db.execute(select(CustomDomain).where(CustomDomain.peer_id == peer.id))
            existing = res.scalars().all()

    return render(request, "dashboard/_domains.html", {
        "request": request,
        "domains": existing,
        "plan": plan,
    })


@router.delete("/dashboard/_domains/{domain_id}", response_class=HTMLResponse)
async def dashboard_remove_domain(
    request: Request,
    domain_id: str,
    db: AsyncSession = Depends(get_db),
) -> HTMLResponse:
    import uuid as _uuid
    user = await _auth_user(request, db)
    if user is None:
        return HTMLResponse("")

    data = await _get_active_peer_full(user, db)
    if not data or not data["peer"]:
        return HTMLResponse("")

    from models.bandwidth import CustomDomain
    try:
        did = _uuid.UUID(domain_id)
    except ValueError:
        return HTMLResponse("")

    res = await db.execute(
        select(CustomDomain)
        .join(VpnPeer, CustomDomain.peer_id == VpnPeer.id)
        .where(CustomDomain.id == did, VpnPeer.user_id == user.id)
    )
    domain = res.scalar_one_or_none()
    if domain:
        await db.delete(domain)
        data["peer"].config_stale = True
        await db.commit()

    res = await db.execute(select(CustomDomain).where(CustomDomain.peer_id == data["peer"].id))
    return render(request, "dashboard/_domains.html", {
        "request": request,
        "domains": res.scalars().all(),
        "plan": data["plan"],
    })
