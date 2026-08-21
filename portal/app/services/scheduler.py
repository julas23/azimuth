"""
Jobs periódicos via APScheduler (AsyncIOScheduler).
Registrado no lifespan do FastAPI — roda no mesmo event loop do uvicorn.

Jobs:
  collect_bandwidth     — 60s  — wg show dump → delta mensal em bandwidth_usage
  check_quota_alerts    —  5m  — 80%/100%, envia email, throttle TC
  resolve_custom_domains—  4h  — DNS → basic-whitelist NFTables
  update_brazil_cidrs   —  4h  — resolve domínios brasileiros → split-tunnel cache
"""
import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select, update

from database import AsyncSessionLocal
from models.bandwidth import BandwidthUsage, CustomDomain
from models.peer import VpnPeer
from models.plan import Plan
from models.user import User
from services import vpn_bridge
from services.brazil_cidrs import get_cached_cidrs, get_fingerprint, resolve_and_cache
from services.mailer import send_quota_alert

log = logging.getLogger("scheduler")

scheduler = AsyncIOScheduler(timezone="UTC")


async def collect_bandwidth() -> None:
    """
    Coleta rx/tx de todos os peers ativos via bridge e acumula o delta mensal.

    wg show dump retorna bytes ACUMULADOS desde criação do peer (não reseta por mês).
    A coluna raw_rx/raw_tx guarda o último valor do contador wg.
    bytes_rx/bytes_tx acumulam apenas o delta do mês corrente.
    """
    period = datetime.now(timezone.utc).strftime("%Y-%m")
    updated = 0

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(VpnPeer).where(VpnPeer.is_active.is_(True))
        )
        peers = result.scalars().all()

        for peer in peers:
            try:
                stats = await vpn_bridge.get_stats(peer.public_key)
            except Exception:
                continue

            current_rx: int = stats.get("rx_bytes", 0)
            current_tx: int = stats.get("tx_bytes", 0)

            bw_res = await db.execute(
                select(BandwidthUsage).where(
                    BandwidthUsage.peer_id == peer.id,
                    BandwidthUsage.period == period,
                )
            )
            bw = bw_res.scalar_one_or_none()

            if bw is None:
                # Novo período: cria linha com baseline = contador atual.
                # bytes_rx/tx começam em 0 (nenhum tráfego contabilizado ainda este mês).
                db.add(BandwidthUsage(
                    peer_id=peer.id,
                    period=period,
                    bytes_rx=0,
                    bytes_tx=0,
                    raw_rx=current_rx,
                    raw_tx=current_tx,
                ))
            else:
                # Calcula delta desde a última leitura.
                # Se current < raw houve reset do contador (reinício do wg) — conta a partir de 0.
                delta_rx = current_rx - bw.raw_rx if current_rx >= bw.raw_rx else current_rx
                delta_tx = current_tx - bw.raw_tx if current_tx >= bw.raw_tx else current_tx

                await db.execute(
                    update(BandwidthUsage)
                    .where(BandwidthUsage.id == bw.id)
                    .values(
                        bytes_rx=BandwidthUsage.bytes_rx + delta_rx,
                        bytes_tx=BandwidthUsage.bytes_tx + delta_tx,
                        raw_rx=current_rx,
                        raw_tx=current_tx,
                    )
                )

            updated += 1

        await db.commit()

    if updated:
        log.debug("collect_bandwidth: %d peers (período %s)", updated, period)


async def check_quota_alerts() -> None:
    """Verifica consumo mensal vs franquia; envia alertas e throttle ao atingir limite."""
    period = datetime.now(timezone.utc).strftime("%Y-%m")

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(BandwidthUsage, VpnPeer, Plan, User)
            .join(VpnPeer, BandwidthUsage.peer_id == VpnPeer.id)
            .join(Plan, VpnPeer.plan_id == Plan.id)
            .join(User, VpnPeer.user_id == User.id)
            .where(
                BandwidthUsage.period == period,
                VpnPeer.is_active.is_(True),
                Plan.quota_gb > 0,
            )
        )
        rows = result.all()

        for bw, peer, plan, user in rows:
            total_bytes = bw.bytes_rx + bw.bytes_tx
            quota_bytes = plan.quota_gb * 1_073_741_824
            pct = total_bytes / quota_bytes * 100

            if pct >= 100 and not bw.quota_notified_100:
                try:
                    await vpn_bridge.set_quota(str(peer.ip_address))
                except Exception as e:
                    log.warning("set_quota %s falhou: %s", peer.ip_address, e)
                try:
                    await send_quota_alert(user.email, user.name, plan.name, pct)
                except Exception as e:
                    log.warning("send_quota_alert 100%% %s: %s", user.email, e)
                await db.execute(
                    update(BandwidthUsage)
                    .where(BandwidthUsage.id == bw.id)
                    .values(quota_notified_100=True)
                )
                log.info("quota 100%%: peer=%s user=%s plano=%s", peer.ip_address, user.email, plan.id)

            elif pct >= 80 and not bw.quota_notified_80:
                try:
                    await send_quota_alert(user.email, user.name, plan.name, pct)
                except Exception as e:
                    log.warning("send_quota_alert 80%% %s: %s", user.email, e)
                await db.execute(
                    update(BandwidthUsage)
                    .where(BandwidthUsage.id == bw.id)
                    .values(quota_notified_80=True)
                )
                log.info("quota 80%%: peer=%s user=%s plano=%s", peer.ip_address, user.email, plan.id)

        await db.commit()


async def resolve_custom_domains() -> None:
    """Resolve DNS dos domínios custom de peers basic e atualiza basic-whitelist via bridge."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(CustomDomain.domain)
            .join(VpnPeer, CustomDomain.peer_id == VpnPeer.id)
            .where(VpnPeer.plan_id == "basic", VpnPeer.is_active.is_(True))
        )
        domains = [row[0] for row in result.all()]

    if not domains:
        return

    for i in range(0, len(domains), 10):
        chunk = domains[i : i + 10]
        try:
            r = await vpn_bridge.resolve_whitelist(chunk)
            log.info(
                "resolve_custom_domains: resolvidos=%d falhos=%d",
                len(r.get("resolved", {})),
                len(r.get("failed", [])),
            )
        except Exception as e:
            log.warning("resolve_custom_domains chunk falhou: %s", e)


async def sync_split_tunnel_set() -> None:
    """Empurra a allowlist do split tunnel para o set NFTables via bridge.

    Obrigatório para o plano Basic: a plan-policy descarta tudo que não estiver
    em @split-tunnel ou @basic-whitelist. O arquivo /etc/nftables.d/wg-plans.nft
    dá flush na tabela, então o set nasce vazio em todo reload/reboot — por isso
    isto roda no startup, além do job de 4h.
    """
    try:
        r = await vpn_bridge.sync_split_tunnel(get_cached_cidrs())
        log.info(
            "sync_split_tunnel_set: %d CIDRs aplicados no set NFTables",
            r.get("applied", 0),
        )
    except Exception as e:
        log.error("sync_split_tunnel_set falhou: %s", e)


async def update_brazil_cidrs() -> None:
    """Resolve a allowlist e mantém o set NFTables em sincronia.

    NÃO marca mais os peers como config_stale: desde a migração para full tunnel
    o .conf do cliente é sempre `AllowedIPs = 0.0.0.0/0` e não depende desta
    lista, então marcar mostraria ao cliente um banner de "rebaixe seu config"
    a cada oscilação de DNS, sem nada ter mudado para ele.
    """
    old_fp = get_fingerprint()
    cidrs = await resolve_and_cache()
    new_fp = get_fingerprint()

    try:
        r = await vpn_bridge.sync_split_tunnel(cidrs)
        log.info("update_brazil_cidrs: %d CIDRs sincronizados no set NFTables", r.get("applied", 0))
    except Exception as e:
        log.error("update_brazil_cidrs: sync do set NFTables falhou: %s", e)

    if new_fp and new_fp != old_fp:
        log.info("update_brazil_cidrs: allowlist mudou (fp %s→%s)", old_fp, new_fp)


def start() -> None:
    scheduler.add_job(
        collect_bandwidth, "interval", seconds=60,
        id="collect_bandwidth", replace_existing=True,
        max_instances=1, misfire_grace_time=30,
    )
    scheduler.add_job(
        check_quota_alerts, "interval", minutes=5,
        id="check_quota_alerts", replace_existing=True,
        max_instances=1, misfire_grace_time=60,
    )
    scheduler.add_job(
        resolve_custom_domains, "interval", hours=4,
        id="resolve_custom_domains", replace_existing=True,
        max_instances=1, misfire_grace_time=300,
    )
    scheduler.add_job(
        update_brazil_cidrs, "interval", hours=4,
        id="update_brazil_cidrs", replace_existing=True,
        max_instances=1, misfire_grace_time=300,
    )
    # Uma vez, logo após o boot: o flush em wg-plans.nft deixa @split-tunnel
    # vazio, e sem ele a plan-policy bloqueia todo tráfego dos peers basic.
    scheduler.add_job(
        sync_split_tunnel_set, "date",
        run_date=datetime.now(timezone.utc) + timedelta(seconds=15),
        id="sync_split_tunnel_boot", replace_existing=True,
        misfire_grace_time=300,
    )
    scheduler.start()
    log.info("scheduler iniciado: %d jobs ativos", len(scheduler.get_jobs()))


def stop() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
        log.info("scheduler encerrado")
