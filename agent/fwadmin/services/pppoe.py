"""Os peers de PPPoE: um arquivo em /etc/ppp/peers por WAN discada."""

from __future__ import annotations

from fwadmin import secretstore, status
from fwadmin.models import Config
from fwadmin.services.base import Prova, Reload, ServiceModule, until

PREFIX = "ppp-peers-"
SECRET_PREFIX = "ppp-secret-"


def targets(cfg: Config) -> dict[str, str]:
    return {
        f"{PREFIX}{w.pppoe.peer}": f"/etc/ppp/peers/{w.pppoe.peer}"
        for w in cfg.wans
        if w.pppoe
    }


def secret_targets(cfg: Config) -> dict[str, str]:
    """O arquivo de senha de cada peer que o motor cuida (password_file)."""
    return {
        f"{SECRET_PREFIX}{w.pppoe.peer}": f"/etc/ppp/azimuth-{w.pppoe.peer}.secret"
        for w in cfg.wans
        if w.pppoe and w.pppoe.password_file
    }


def render_secrets(cfg: Config) -> tuple[dict[str, str], list[str]]:
    """(conteudo de cada arquivo de senha, peers sem senha conhecida).

    So o fwctl chama, como root. Na adocao, a senha que esta dentro do peer
    vivo vai antes para o secrets.yaml (secretstore.adopt_from_peer).
    """
    out, missing = {}, []
    for w in cfg.wans:
        if not (w.pppoe and w.pppoe.password_file):
            continue
        ppp = w.pppoe
        secretstore.adopt_from_peer(ppp.password_ref, ppp.peer)
        value = secretstore.current().get(ppp.password_ref)
        if value is None:
            missing.append(ppp.peer)
            continue
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        out[f"{SECRET_PREFIX}{ppp.peer}"] = (
            "# gerado pelo fwadmin a partir de /etc/fwadmin/secrets.yaml\n"
            f'password "{escaped}"\n'
        )
    return out, missing


def units(cfg: Config) -> frozenset[str]:
    # Sem pppoe.unit, quem sobe o link e' o 'pon', chamado pelo ifup da
    # interface fisica, e nao ha unidade para reivindicar — a linha do
    # inventario e' do interfaces. Com ela (ppp@provider no Debian), o link
    # e' do systemd, e a unidade e' deste modulo.
    return frozenset(w.pppoe.unit for w in cfg.wans if w.pppoe and w.pppoe.unit)


def _peers(files: list[str]) -> list[str]:
    """Peers tocados, pelo arquivo do peer ou pelo da senha — cada um uma vez."""
    out: list[str] = []
    for n in files:
        for prefix in (PREFIX, SECRET_PREFIX):
            if n.startswith(prefix) and n.removeprefix(prefix) not in out:
                out.append(n.removeprefix(prefix))
    return out


def _interface(cfg: Config | None, peer: str):
    if cfg is None:
        return None
    for iface in cfg.interfaces:
        if iface.pppoe is not None and iface.pppoe.peer == peer:
            return iface
    return None


def _restart(peer: str, device: str | None, unit: str | None = None) -> Reload:
    """Derruba e resobe um peer.

    A espera pela interface de baixo cobre o caminho do rollback, onde as
    interfaces sao mesmo derrubadas e resubidas antes do PPPoE: o rp-pppoe
    recusa o nome com 'unrecognized option <dev>' se ela nao estiver up na
    hora do parse.

    A confirmacao de que o ppp0 subiu NAO esta mais aqui — virou a prova de
    funcao deste modulo. O motivo e' o incidente de 2026-08-21: 'pon' devolve
    zero porque quem morre e' o pppd que ele lanca, entao a recarga reportava
    sucesso com a WAN caida. Como prova, a mesma verificacao passa a disparar
    rollback em vez de virar uma linha de FALHOU que ninguem le.
    """
    wait = (
        [
            f"for i in $(seq 1 20); do "
            f"ip link show {device} 2>/dev/null | grep -q LOWER_UP && break; sleep 1; done"
        ]
        if device
        else []
    )
    if unit:
        # pon/poff ao lado de um ppp@ do systemd subiria um segundo pppd na
        # mesma placa: com a unidade, quem reinicia e' o systemctl.
        steps = [*wait, f"systemctl restart {unit}"]
    else:
        steps = [f"poff {peer} || true", *wait, f"pon {peer}"]
    return Reload(f"PPPoE {peer}", ["sh", "-c", "; ".join(steps)], disruptive=True)


def context(cfg: Config, name: str) -> dict:
    """Cada peer renderiza com a propria interface — um arquivo por WAN discada."""
    iface = _interface(cfg, name.removeprefix(PREFIX))
    return {"iface": iface, "ppp": iface.pppoe if iface else None}


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    out = []
    for peer in _peers(changed):
        iface = _interface(cfg, peer)
        out.append(
            _restart(
                peer,
                iface.device if iface else None,
                iface.pppoe.unit if iface else None,
            )
        )
    return out


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    out = []
    for peer in _peers(files):
        iface = _interface(cfg, peer)
        out.append(
            _restart(
                peer,
                iface.device if iface else None,
                iface.pppoe.unit if iface else None,
            )
        )
    return out


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """O link discado subiu e tem endereco.

    Esta e' a prova que faltou em 2026-08-21: o 'pon' devolveu zero, o apply
    reportou sucesso e a WAN primaria estava caida. So o failover, um minuto
    depois, denunciou.
    """
    peers = _peers(changed)
    if not peers:
        return None

    alvos = {}
    for peer in peers:
        iface = _interface(cfg, peer)
        if iface is not None:
            alvos[peer] = iface.ppp_device
    if not alvos:
        return None

    esperado = "endereco no link discado: " + ", ".join(
        f"{p} ({d})" for p, d in alvos.items()
    )

    def olhar() -> Prova:
        vivos = status.links()
        if not vivos:
            return Prova.inconclusiva(
                "pppoe", esperado, "nao consegui ler o estado das interfaces"
            )
        quebrados = []
        vistos = []
        for peer, device in alvos.items():
            estado = vivos.get(device)
            if estado is None or not estado.address:
                quebrados.append(f"{peer}: {device} sem endereco")
            else:
                vistos.append(f"{peer}: {device} {estado.address}")
        if quebrados:
            return Prova.falhou("pppoe", esperado, "; ".join(quebrados))
        return Prova.passou("pppoe", esperado, "; ".join(vistos))

    return until(30, olhar)


SERVICE = ServiceModule(
    name="pppoe",
    order=40,
    section="interfaces[].pppoe",
    targets=targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    template_for=lambda name: "ppp-peer.j2",
    context_for=context,
)
