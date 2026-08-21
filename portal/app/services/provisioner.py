"""
Provisionamento e desprovisionamento de peers VPN via eventos Stripe.
"""
import logging
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models.peer import VpnPeer
from models.plan import Plan
from models.subscription import Subscription
from models.bandwidth import BandwidthUsage
from models.user import User
from services import ip_allocator, vpn_bridge
from services.wg_config import build_conf, build_qr_png
from services.mailer import send_vpn_credentials, send_subscription_cancelled

log = logging.getLogger("provisioner")


async def _find_user_by_customer(db: AsyncSession, customer_id: str) -> User | None:
    result = await db.execute(
        select(User).where(User.stripe_customer_id == customer_id)
    )
    return result.scalar_one_or_none()


async def _find_plan_by_price(db: AsyncSession, price_id: str) -> Plan | None:
    result = await db.execute(
        select(Plan).where(Plan.stripe_price_id == price_id)
    )
    return result.scalar_one_or_none()


async def _find_sub(db: AsyncSession, stripe_sub_id: str) -> Subscription | None:
    result = await db.execute(
        select(Subscription).where(
            Subscription.stripe_subscription_id == stripe_sub_id
        )
    )
    return result.scalar_one_or_none()


async def _active_peer_for_sub(db: AsyncSession, sub: Subscription) -> VpnPeer | None:
    if sub.peer_id is None:
        return None
    result = await db.execute(
        select(VpnPeer).where(VpnPeer.id == sub.peer_id, VpnPeer.is_active.is_(True))
    )
    return result.scalar_one_or_none()


# ── Handlers públicos ─────────────────────────────────────────────────────────

async def handle_checkout_completed(event_data: dict, db: AsyncSession) -> None:
    """
    checkout.session.completed — registra customer_id no usuário e cria
    o registro de Subscription (status inicial = incomplete até invoice.paid).
    """
    session = event_data["object"]
    meta = session.get("metadata") or {}
    user_id = meta.get("user_id")
    stripe_sub_id = session.get("subscription")
    stripe_customer_id = session.get("customer")

    if not user_id or not stripe_sub_id:
        log.warning("checkout.session.completed sem user_id ou subscription: %s", session.get("id"))
        return

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        log.error("Usuário não encontrado: %s", user_id)
        return

    # Salva stripe_customer_id no usuário (pode já estar setado)
    if user.stripe_customer_id != stripe_customer_id:
        await db.execute(
            update(User)
            .where(User.id == user.id)
            .values(stripe_customer_id=stripe_customer_id)
        )

    # Determina o plan_id a partir dos line_items — usa metadata como fallback
    plan_id = meta.get("plan_id", "")

    # Cria ou actualiza o registro de Subscription
    existing = await _find_sub(db, stripe_sub_id)
    if existing is None:
        sub = Subscription(
            user_id=user.id,
            plan_id=plan_id,
            stripe_subscription_id=stripe_sub_id,
            status="incomplete",
        )
        db.add(sub)

    await db.flush()
    log.info("checkout.session.completed registrado para user %s", user_id)


async def handle_invoice_paid(event_data: dict, db: AsyncSession) -> None:
    """
    invoice.paid — provisiona peer na primeira cobrança ou renova quota/bandwidth
    para cobranças recorrentes.
    """
    invoice = event_data["object"]
    stripe_sub_id = invoice.get("subscription")
    stripe_customer_id = invoice.get("customer")

    if not stripe_sub_id:
        return  # invoice avulsa, não de assinatura

    user = await _find_user_by_customer(db, stripe_customer_id)
    if user is None:
        log.error("Usuário não encontrado para customer %s", stripe_customer_id)
        return

    sub = await _find_sub(db, stripe_sub_id)

    # Determina o plano a partir dos line_items da invoice
    plan_id = None
    for line in (invoice.get("lines", {}).get("data") or []):
        price_id = (line.get("price") or {}).get("id")
        if price_id:
            plan = await _find_plan_by_price(db, price_id)
            if plan:
                plan_id = plan.id
                break

    # Cria Subscription se ainda não existir (webhook fora de ordem)
    if sub is None:
        if not plan_id:
            log.error("Não foi possível determinar plano para invoice %s", invoice.get("id"))
            return
        sub = Subscription(
            user_id=user.id,
            plan_id=plan_id,
            stripe_subscription_id=stripe_sub_id,
            status="incomplete",
        )
        db.add(sub)
        await db.flush()

    # Atualiza datas do período e status
    period_start = invoice.get("period_start")
    period_end = invoice.get("period_end")
    await db.execute(
        update(Subscription)
        .where(Subscription.id == sub.id)
        .values(
            status="active",
            current_period_start=datetime.fromtimestamp(period_start, tz=timezone.utc) if period_start else None,
            current_period_end=datetime.fromtimestamp(period_end, tz=timezone.utc) if period_end else None,
        )
    )
    await db.refresh(sub)

    # Garante que o usuário está ativo após pagamento confirmado
    if not user.is_active:
        await db.execute(update(User).where(User.id == user.id).values(is_active=True))

    peer = await _active_peer_for_sub(db, sub)

    if peer is None:
        # Primeira cobrança — provisiona peer
        await _provision_peer(db, user, sub)
    else:
        # Renovação — libera quota e reseta bandwidth
        await _renew_peer(db, peer)


async def handle_subscription_deleted(event_data: dict, db: AsyncSession) -> None:
    """
    customer.subscription.deleted — revoga o peer e cancela a assinatura.
    """
    stripe_sub = event_data["object"]
    stripe_sub_id = stripe_sub["id"]

    sub = await _find_sub(db, stripe_sub_id)
    if sub is None:
        log.warning("Subscription não encontrada para cancelamento: %s", stripe_sub_id)
        return

    peer = await _active_peer_for_sub(db, sub)
    if peer is not None:
        try:
            await vpn_bridge.remove_peer(peer.public_key)
        except Exception as exc:
            log.error("Erro ao remover peer %s: %s", peer.public_key[:10], exc)

        await db.execute(
            update(VpnPeer)
            .where(VpnPeer.id == peer.id)
            .values(is_active=False, revoked_at=datetime.now(timezone.utc))
        )

        # Envia e-mail de cancelamento
        result = await db.execute(select(User).where(User.id == sub.user_id))
        user = result.scalar_one_or_none()
        result2 = await db.execute(select(Plan).where(Plan.id == sub.plan_id))
        plan = result2.scalar_one_or_none()
        if user and plan:
            try:
                await send_subscription_cancelled(user.email, user.name, plan.name)
            except Exception as exc:
                log.error("Erro ao enviar e-mail de cancelamento: %s", exc)

    await db.execute(
        update(Subscription)
        .where(Subscription.id == sub.id)
        .values(status="canceled")
    )
    log.info("Subscription %s cancelada", stripe_sub_id)


async def handle_invoice_payment_failed(event_data: dict, db: AsyncSession) -> None:
    """
    invoice.payment_failed — na segunda falha, aplica throttling de quota ao peer.
    """
    invoice = event_data["object"]
    attempt_count = invoice.get("attempt_count", 1)
    if attempt_count < 2:
        return

    stripe_sub_id = invoice.get("subscription")
    if not stripe_sub_id:
        return

    sub = await _find_sub(db, stripe_sub_id)
    if sub is None:
        return

    peer = await _active_peer_for_sub(db, sub)
    if peer is None:
        return

    try:
        await vpn_bridge.set_quota(str(peer.ip_address))
        log.info("Quota aplicada ao peer %s (2ª falha de pagamento)", peer.ip_address)
    except Exception as exc:
        log.error("Erro ao aplicar quota: %s", exc)


# ── helpers internos ──────────────────────────────────────────────────────────

async def _provision_peer(db: AsyncSession, user: User, sub: Subscription) -> None:
    plan_id = sub.plan_id

    result = await db.execute(select(Plan).where(Plan.id == plan_id))
    plan = result.scalar_one_or_none()
    if plan is None:
        log.error("Plano não encontrado: %s", plan_id)
        return

    # Gera keypair
    try:
        keys = await vpn_bridge.genkeys()
    except Exception as exc:
        log.error("Erro ao gerar chaves: %s", exc)
        return

    public_key = keys["pubkey"]
    private_key = keys["privkey"]

    # Aloca IP
    try:
        client_ip = await ip_allocator.allocate_ip(db, plan_id)
    except Exception as exc:
        log.error("Erro ao alocar IP (plano %s): %s", plan_id, exc)
        return

    # Adiciona peer ao WireGuard com limite de banda do plano
    try:
        await vpn_bridge.add_peer(
            public_key, client_ip,
            label=str(user.id),
            bandwidth_mbps=plan.bandwidth_mbps,
        )
    except Exception as exc:
        log.error("Erro ao adicionar peer ao WireGuard: %s", exc)
        return

    # Persiste peer (private_key armazenada para re-download do .conf no dashboard)
    peer = VpnPeer(
        user_id=user.id,
        plan_id=plan_id,
        public_key=public_key,
        private_key=private_key,
        ip_address=client_ip,
    )
    db.add(peer)
    await db.flush()

    # Vincula peer à subscription
    await db.execute(
        update(Subscription).where(Subscription.id == sub.id).values(peer_id=peer.id)
    )

    # Cria registro de bandwidth para o período atual
    from datetime import date
    period = date.today().strftime("%Y-%m")
    db.add(BandwidthUsage(peer_id=peer.id, period=period))
    await db.flush()

    log.info("Peer provisionado: ip=%s user=%s plan=%s", client_ip, user.id, plan_id)

    # Gera .conf e envia e-mail (private_key não é armazenada)
    try:
        conf = build_conf(private_key, client_ip, plan.gateway)
        qr = build_qr_png(conf)
        await send_vpn_credentials(user.email, user.name, plan.name, client_ip, conf, qr)
    except Exception as exc:
        log.error("Erro ao enviar credenciais por e-mail: %s", exc)


async def _renew_peer(db: AsyncSession, peer: VpnPeer) -> None:
    from datetime import date
    try:
        await vpn_bridge.clear_quota(str(peer.ip_address))
    except Exception as exc:
        log.error("Erro ao limpar quota: %s", exc)

    # Reseta bandwidth para o novo período
    period = date.today().strftime("%Y-%m")
    existing = await db.execute(
        select(BandwidthUsage).where(
            BandwidthUsage.peer_id == peer.id,
            BandwidthUsage.period == period,
        )
    )
    if existing.scalar_one_or_none() is None:
        db.add(BandwidthUsage(peer_id=peer.id, period=period))
    else:
        await db.execute(
            update(BandwidthUsage)
            .where(BandwidthUsage.peer_id == peer.id, BandwidthUsage.period == period)
            .values(
                bytes_rx=0, bytes_tx=0,
                quota_notified_80=False, quota_notified_100=False,
            )
        )

    log.info("Peer renovado: ip=%s", peer.ip_address)
