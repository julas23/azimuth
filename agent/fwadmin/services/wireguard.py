"""O tunel de acesso remoto — a unica porta que responde na internet."""

from __future__ import annotations

from fwadmin import status
from fwadmin.models import Config, WireGuard
from fwadmin.services.base import Prova, Reload, ServiceModule, until


def _wg(cfg: Config | None) -> WireGuard | None:
    if cfg is None:
        return None
    return cfg.wireguard if cfg.wireguard.enabled else None


def targets(cfg: Config) -> dict[str, str]:
    wg = _wg(cfg)
    if wg is None:
        return {}
    return {f"{wg.device}.conf": f"/etc/wireguard/{wg.device}.conf"}


def units(cfg: Config) -> frozenset[str]:
    wg = _wg(cfg)
    return frozenset() if wg is None else frozenset({f"wg-quick@{wg.device}.service"})


def context(cfg: Config, name: str) -> dict:
    return {"wg": cfg.wireguard}


def _recreate(device: str) -> Reload:
    """Derruba e resobe. Unica forma de mudar endereco, porta ou MTU."""
    return Reload(
        f"WireGuard {device} (recriar)",
        # O enable e' so para o boot: quem sobe agora e' o wg-quick.
        ["sh", "-c", f"systemctl enable -q wg-quick@{device}; wg-quick down {device} || true; wg-quick up {device}"],
        disruptive=True,
    )


def _sync(device: str, key_file: str) -> Reload:
    """Aplica mudanca de peers sem derrubar quem esta conectado.

    'wg syncconf' compara e muda so o que difere, entao trocar a lista de
    peers nao derruba as sessoes dos que continuam. O strip tira o PostUp e,
    com ele, a linha da chave privada. E o syncconf trata a ausencia de
    PrivateKey como "sem chave": APAGA a do dispositivo. O tunel fica de pe,
    na porta certa, com os peers certos, e recusando todo handshake. Por isso
    a chave volta logo em seguida, do mesmo arquivo que o PostUp usa, e a
    prova confere que ela esta la.

    Se a interface ainda nao existe, nao ha o que sincronizar: sobe.
    """
    sync = (
        "umask 077; t=$(mktemp) || exit 1; "
        f"wg-quick strip {device} > \"$t\" && wg syncconf {device} \"$t\" "
        f"&& wg set {device} private-key {key_file}; "
        "rc=$?; rm -f \"$t\"; exit $rc"
    )
    return Reload(
        f"WireGuard {device} (syncconf)",
        [
            "sh",
            "-c",
            f"if ip link show {device} >/dev/null 2>&1; then {sync}; "
            f"else systemctl enable -q wg-quick@{device}; wg-quick up {device}; fi",
        ],
    )


def _interface_mudou(atual: WireGuard, anterior: WireGuard | None) -> bool:
    """Mudou algo que o syncconf nao alcanca?

    O syncconf mexe em chave, porta e peers do dispositivo; endereco, MTU e
    rotas sao trabalho do wg-quick, e nao existem para ele. Trocar endereco e
    so sincronizar deixaria o tunel de pe com o endereco velho — divergencia
    silenciosa entre o declarado e o real, que e' o que este motor existe
    para nao ter.
    """
    if anterior is None:
        return True
    return (
        atual.device != anterior.device
        or atual.address != anterior.address
        or atual.mtu != anterior.mtu
        or atual.private_key_file != anterior.private_key_file
    )


def reloads(cfg: Config, previous: Config | None, changed: list[str]) -> list[Reload]:
    wg = _wg(cfg)
    if wg is None or f"{wg.device}.conf" not in changed:
        return []
    if _interface_mudou(wg, _wg(previous)):
        return [_recreate(wg.device)]
    return [_sync(wg.device, wg.private_key_file)]


def rollback(cfg: Config | None, files: list[str]) -> list[Reload]:
    """No caminho de volta nao ha diff em que confiar: recria."""
    wg = _wg(cfg)
    if wg is None or f"{wg.device}.conf" not in files:
        return []
    return [_recreate(wg.device)]


def probe(cfg: Config, previous: Config | None, changed: list[str]) -> Prova | None:
    """O tunel esta no ar, na porta declarada, com os peers declarados.

    O handshake entra como observacao, nao como criterio. Numa caixa recem
    configurada ninguem conectou ainda, e reprovar por isso reverteria uma
    configuracao correta — pior, reverteria justamente a que o usuario acabou
    de criar para poder conectar.
    """
    wg = _wg(cfg)
    if wg is None or f"{wg.device}.conf" not in changed:
        return None

    esperados = len(wg.active_peers)
    esperado = f"{wg.device} no ar na porta {wg.listen_port} com {esperados} peer(s)"

    def olhar() -> Prova:
        estado = status.wireguard(wg.device)
        if estado is None:
            return Prova.falhou("wireguard", esperado, f"{wg.device} nao respondeu ao 'wg show'")
        problemas = []
        if not estado.has_key:
            problemas.append("dispositivo sem chave privada: recusa todo handshake")
        if estado.listen_port != wg.listen_port:
            problemas.append(f"porta {estado.listen_port}, declarada {wg.listen_port}")
        if estado.peers != esperados:
            problemas.append(f"{estado.peers} peer(s) no dispositivo, declarados {esperados}")
        if problemas:
            return Prova.falhou("wireguard", esperado, "; ".join(problemas))

        visto = f"porta {estado.listen_port}, {estado.peers} peer(s)"
        if estado.last_handshake >= 0:
            visto += f", handshake ha {estado.last_handshake}s"
        elif esperados:
            visto += ", nenhum peer conectado ainda"
        return Prova.passou("wireguard", esperado, visto)

    return until(15, olhar)


SERVICE = ServiceModule(
    name="wireguard",
    order=45,  # depois do nftables (porta liberada) e da WAN (endpoint alcancavel)
    section="wireguard",
    targets=targets,
    units=units,
    reloads=reloads,
    rollback=rollback,
    probe=probe,
    # Checagem de leitura, NAO o portao de sintaxe. Verificado em 28/08/2026:
    # 'wg-quick strip' devolve zero para um arquivo com 'Address = isso-nao-e-
    # um-ip', 'ListenPort = 999999' e 'PublicKey = lixo' — ele filtra texto,
    # nao valida. Quem valida de verdade e' o 'wg setconf', e ele exige um
    # dispositivo: no arquivo absurdo ele responde 'Configuration parsing
    # error' e no valido 'Unable to modify interface', ambos com rc=1, o que
    # so daria para distinguir casando string de stderr. Frágil demais para
    # ser rede de seguranca.
    #
    # O portao real deste servico e' o SCHEMA: chave em base64 de 32 bytes,
    # endereco em CIDR, porta em faixa, MTU em faixa, endpoint em host:porta.
    # Nada chega ao template sem passar por la, entao o arquivo gerado nao tem
    # como sair malformado.
    validator=("wg-quick", "strip"),
    template_for=lambda name: "wireguard.conf.j2",
    context_for=context,
)
