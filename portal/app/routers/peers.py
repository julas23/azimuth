"""
Peer management — conf download, QR, key regeneration, custom domains.
"""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from deps import get_current_user
from models.bandwidth import BandwidthUsage, CustomDomain
from models.peer import VpnPeer
from models.plan import Plan
from models.subscription import Subscription
from models.user import User
from services import vpn_bridge
from services.ip_allocator import allocate_ip
from services.mailer import send_vpn_credentials
from services.wg_config import build_conf, build_qr_png

router = APIRouter(prefix="/peers", tags=["peers"])


# ── helpers ──────────────────────────────────────────────────────────────────

async def _get_active_peer_full(user: User, db: AsyncSession) -> dict | None:
    """Returns peer + subscription + plan + bandwidth or None if no active subscription."""
    sub_res = await db.execute(
        select(Subscription).where(
            Subscription.user_id == user.id,
            Subscription.status.in_(["active", "trialing", "past_due"]),
        ).order_by(Subscription.created_at.desc())
    )
    sub = sub_res.scalar_one_or_none()
    if sub is None:
        return None

    plan_res = await db.execute(select(Plan).where(Plan.id == sub.plan_id))
    plan = plan_res.scalar_one_or_none()

    peer = None
    if sub.peer_id:
        peer_res = await db.execute(
            select(VpnPeer).where(VpnPeer.id == sub.peer_id, VpnPeer.is_active.is_(True))
        )
        peer = peer_res.scalar_one_or_none()

    bw = None
    if peer:
        period = datetime.now(timezone.utc).strftime("%Y-%m")
        bw_res = await db.execute(
            select(BandwidthUsage).where(
                BandwidthUsage.peer_id == peer.id,
                BandwidthUsage.period == period,
            )
        )
        bw = bw_res.scalar_one_or_none()

    return {"subscription": sub, "plan": plan, "peer": peer, "bandwidth": bw}


# ── endpoints ────────────────────────────────────────────────────────────────

@router.get("/me")
async def get_my_peer(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    data = await _get_active_peer_full(current_user, db)
    if data is None:
        return {"subscription": None, "peer": None, "bandwidth": None, "plan": None}

    sub, plan, peer, bw = data["subscription"], data["plan"], data["peer"], data["bandwidth"]

    def _bytes_to_gb(b: int) -> float:
        return round(b / (1024 ** 3), 2)

    return {
        "subscription": {
            "id": str(sub.id),
            "status": sub.status,
            "plan_id": sub.plan_id,
            "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
            "cancel_at_period_end": sub.cancel_at_period_end,
        },
        "plan": {
            "id": plan.id,
            "name": plan.name,
            "bandwidth_mbps": plan.bandwidth_mbps,
            "quota_gb": plan.quota_gb,
            "custom_domains_limit": plan.custom_domains_limit,
        } if plan else None,
        "peer": {
            "id": str(peer.id),
            "ip_address": str(peer.ip_address),
            "public_key": peer.public_key,
            "created_at": peer.created_at.isoformat(),
            "has_conf": bool(peer.private_key),
        } if peer else None,
        "bandwidth": {
            "rx_gb": _bytes_to_gb(bw.bytes_rx),
            "tx_gb": _bytes_to_gb(bw.bytes_tx),
            "total_gb": _bytes_to_gb(bw.bytes_rx + bw.bytes_tx),
            "period": bw.period,
        } if bw else {"rx_gb": 0, "tx_gb": 0, "total_gb": 0, "period": ""},
    }


@router.get("/conf")
async def download_conf(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    data = await _get_active_peer_full(current_user, db)
    if data is None or data["peer"] is None:
        raise HTTPException(404, "Nenhum peer ativo")

    peer, plan = data["peer"], data["plan"]
    if not peer.private_key:
        raise HTTPException(409, "Chave privada não disponível — regenere as chaves")

    conf = build_conf(peer.private_key, str(peer.ip_address), plan.gateway)
    await db.execute(update(VpnPeer).where(VpnPeer.id == peer.id).values(config_stale=False))
    await db.commit()
    return Response(
        content=conf,
        media_type="text/plain",
        headers={"Content-Disposition": "attachment; filename=vpn.conf"},
    )


@router.get("/qr")
async def get_qr(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    data = await _get_active_peer_full(current_user, db)
    if data is None or data["peer"] is None:
        raise HTTPException(404, "Nenhum peer ativo")

    peer, plan = data["peer"], data["plan"]
    if not peer.private_key:
        raise HTTPException(409, "Chave privada não disponível — regenere as chaves")

    conf = build_conf(peer.private_key, str(peer.ip_address), plan.gateway)
    png = build_qr_png(conf)
    await db.execute(update(VpnPeer).where(VpnPeer.id == peer.id).values(config_stale=False))
    await db.commit()
    return Response(content=png, media_type="image/png")


@router.post("/regenerate")
async def regenerate_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    data = await _get_active_peer_full(current_user, db)
    if data is None or data["peer"] is None:
        raise HTTPException(404, "Nenhum peer ativo")

    old_peer, sub, plan = data["peer"], data["subscription"], data["plan"]
    old_ip = str(old_peer.ip_address)

    # Gera novas chaves
    keys = await vpn_bridge.genkeys()
    new_pubkey = keys["pubkey"]
    new_privkey = keys["privkey"]

    # Remove chave antiga, adiciona nova com mesmo IP
    try:
        await vpn_bridge.remove_peer(old_peer.public_key)
    except Exception:
        pass

    await vpn_bridge.add_peer(new_pubkey, old_ip, label=str(current_user.id))

    # Atualiza as chaves no peer existente (mantém mesmo IP — sem conflito de UNIQUE)
    await db.execute(
        update(VpnPeer)
        .where(VpnPeer.id == old_peer.id)
        .values(public_key=new_pubkey, private_key=new_privkey)
    )
    await db.commit()

    conf = build_conf(new_privkey, old_ip, plan.gateway)
    try:
        qr = build_qr_png(conf)
        await send_vpn_credentials(
            current_user.email, current_user.name, plan.name, old_ip, conf, qr
        )
    except Exception:
        pass

    return {
        "ok": True,
        "ip_address": old_ip,
        "public_key": new_pubkey,
        "conf": conf,
    }


# ── Custom Domains ────────────────────────────────────────────────────────────

class DomainRequest(BaseModel):
    domain: str


@router.get("/domains")
async def list_domains(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list:
    data = await _get_active_peer_full(current_user, db)
    if data is None or data["peer"] is None:
        return []

    res = await db.execute(
        select(CustomDomain).where(CustomDomain.peer_id == data["peer"].id)
    )
    return [{"id": str(d.id), "domain": d.domain} for d in res.scalars()]


@router.post("/domains", status_code=201)
async def add_domain(
    body: DomainRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    data = await _get_active_peer_full(current_user, db)
    if data is None or data["peer"] is None:
        raise HTTPException(404, "Nenhum peer ativo")

    plan, peer = data["plan"], data["peer"]
    if plan.custom_domains_limit == 0:
        raise HTTPException(403, "Seu plano não suporta domínios customizados")

    res = await db.execute(
        select(CustomDomain).where(CustomDomain.peer_id == peer.id)
    )
    existing = res.scalars().all()
    if len(existing) >= plan.custom_domains_limit:
        raise HTTPException(409, f"Limite de {plan.custom_domains_limit} domínio(s) atingido")

    # Verifica duplicata
    for d in existing:
        if d.domain == body.domain:
            raise HTTPException(409, "Domínio já cadastrado")

    new_domain = CustomDomain(peer_id=peer.id, domain=body.domain)
    db.add(new_domain)
    await db.commit()
    await db.refresh(new_domain)
    return {"id": str(new_domain.id), "domain": new_domain.domain}


@router.delete("/domains/{domain_id}", status_code=204)
async def remove_domain(
    domain_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    res = await db.execute(
        select(CustomDomain)
        .join(VpnPeer, CustomDomain.peer_id == VpnPeer.id)
        .where(CustomDomain.id == domain_id, VpnPeer.user_id == current_user.id)
    )
    domain = res.scalar_one_or_none()
    if domain is None:
        raise HTTPException(404, "Domínio não encontrado")
    await db.delete(domain)
    await db.commit()
