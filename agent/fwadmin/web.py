"""A interface web. Roda sem privilegio nenhum.

Este processo nunca escreve em /etc nem executa nada como root. Quando o
usuario muda alguma coisa, o resultado e' gravado em config.pending.yaml e o
trabalho de verdade fica com o fwctl, chamado via sudo com uma lista fechada
de subcomandos.

Consequencia pratica: um bug aqui — ou alguem que consiga falar com este
processo — nao consegue escrever uma regra de firewall arbitraria. So consegue
propor uma config, que ainda passa pelo modelo e pelo nft -c antes de valer.

Modo somente leitura (FWADMIN_READONLY, ligado por padrao): o painel mostra o
sistema vivo, lido pelo importador a partir da fotografia do `fwctl observe`,
e recusa qualquer POST que mude alguma coisa. As rotas de escrita continuam
aqui, prontas para quando o modo for desligado.
"""

from __future__ import annotations

import asyncio
import difflib
import fcntl
import ipaddress
import json
import os
import pty
import signal
import struct
import termios
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any, Callable
from urllib.parse import parse_qs, urlencode

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from fwadmin import acks, agentes, db, dismissed, i18n, ia, importer, live, observe, ownership, paths, secretstore, status
from fwadmin.models import (
    BlockedDomain,
    Config,
    Failover,
    Forwarder,
    ForwardZone,
    Host,
    IPv4Mode,
    PPPoE,
    PortForward,
    Reservation,
    Rule,
    Resolver,
    Service,
    WGPeer,
)
from fwadmin.render import base_input, dump, load

TEMPLATES = Path(__file__).parent / "templates"
STATIC = Path(__file__).parent / "static"
HTMX = Path("/usr/share/javascript/htmx")

SESSION_COOKIE = "fwadmin_session"

MAX_BODY = 256 * 1024
"""Nenhum formulario daqui chega perto disso; o limite corta abuso."""


class FormData(dict):
    """Campos de um formulario, com leitura tolerante.

    Formulario que nao veio (checkbox desmarcado, campo ausente) devolve o
    default em vez de estourar — a validacao de verdade e' do modelo Pydantic,
    nao daqui.
    """

    def text(self, key: str, default: str = "") -> str:
        return self.get(key, default).strip()

    def number(self, key: str, default: int = 0) -> int:
        try:
            return int(self.get(key, "").strip())
        except ValueError:
            return default

    def flag(self, key: str) -> bool:
        return bool(self.get(key, "").strip())

    def csv(self, key: str) -> list[str]:
        return [part.strip() for part in self.get(key, "").split(",") if part.strip()]


async def form(request: Request) -> FormData:
    """Le o corpo do POST como urlencoded.

    Nao usamos o Form() do FastAPI de proposito: ele exige o python-multipart,
    e o pacote de mesmo nome no Debian e' de outro projeto, sem a API que o
    FastAPI espera. Como nenhum formulario daqui envia arquivo, urlencoded
    resolve — e o firewall fica sem depender de um pacote descasado.
    """
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(status_code=413, detail="formulário grande demais")
    parsed = parse_qs(raw.decode("utf-8", "replace"), keep_blank_values=True)
    return FormData({key: values[-1] for key, values in parsed.items()})


Fields = Annotated[FormData, Depends(form)]

FWCTL = "/usr/local/sbin/fwctl"
ALLOWED_FWCTL = {"check", "apply", "confirm", "rollback", "status", "diff", "observe", "f2b", "agente"}

READONLY = os.environ.get("FWADMIN_READONLY", "1") != "0"
"""Ligado por padrao: desligar e' decisao explicita de quem instala."""

READONLY_ALLOWED = {
    "/login",
    "/logout",
    "/system/diag",
    "/system/ack",
    "/system/unack",
    "/alerts/clear",
    "/alerts/restore",
    "/ia/settings",
    "/ia/ask",
}
"""POSTs que nao mudam nada no firewall e por isso valem no somente leitura.
Marcar uma mudanca como intencional, dispensar notificacoes ou configurar e
perguntar a IA so grava em /var/lib/fwadmin. Salvar a proposta da IA nao esta
aqui: aquilo e' edicao."""

ALLOW = [
    ipaddress.ip_network(cidr.strip(), strict=False)
    for cidr in os.environ.get("FWADMIN_ALLOW", "").split(",")
    if cidr.strip()
]
"""Redes de onde o painel aceita conexao. Vazio = qualquer uma.

Atras do nginx quem filtra a origem e' ele, e isto fica vazio. O instalador
enxuto nao toca no nginx: o uvicorn atende direto no IP da LAN, e esta lista
passa a ser o allow/deny que o nginx faria."""

app = FastAPI(title="fwadmin", docs_url=None, redoc_url=None, openapi_url=None)
templates = Jinja2Templates(directory=str(TEMPLATES))
templates.env.filters["timestamp"] = lambda value: datetime.fromtimestamp(value).strftime(
    "%d/%m %H:%M"
)


def _size(value: int | float) -> str:
    """Bytes em unidade de gente: 1536 -> '1,5 KB'."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            text = f"{value:.0f}" if unit == "B" else f"{value:.1f}"
            return f"{text.replace('.', ',')} {unit}"
        value /= 1024
    return ""


def _ago(seconds: int | float) -> str:
    """Segundos -> 'ha 3 min'. Negativo ou zero e' 'nunca'."""
    seconds = int(seconds)
    if seconds < 0:
        return "nunca"
    for size, unit in ((86400, "d"), (3600, "h"), (60, "min")):
        if seconds >= size:
            return f"há {seconds // size} {unit}"
    return f"há {seconds} s"


templates.env.filters["size"] = _size
templates.env.filters["ago"] = _ago


# ---------------------------------------------------------------------------
# chamada ao fwctl — a unica ponte para o privilegio
# ---------------------------------------------------------------------------


def fwctl(*args: str, timeout: int = 180) -> tuple[bool, str]:
    """Executa um subcomando do fwctl via sudo.

    A lista de subcomandos e' fechada aqui e tambem no sudoers: mesmo que este
    processo seja comprometido, ele nao consegue rodar outra coisa como root.
    """
    if not args or args[0] not in ALLOWED_FWCTL:
        return False, f"subcomando nao permitido: {args[0] if args else '(vazio)'}"
    try:
        proc = subprocess.run(
            ["sudo", "-n", FWCTL, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"nao consegui chamar o fwctl: {exc}"
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


# ---------------------------------------------------------------------------
# configuracao em edicao
# ---------------------------------------------------------------------------


class Unavailable(Exception):
    """Nao ha modelo para mostrar: a pagina vira a explicacao do porque."""


def snap() -> live.Snapshot:
    """A fotografia do sistema vivo. Tambem serve ao modo de edicao, que tira
    dela o estado de execucao (handshakes, banidos, contadores)."""
    return live.snapshot(fwctl)


def current() -> Config:
    """A config que a UI mostra.

    Somente leitura: o sistema vivo, pelo importador. Edicao: a proposta
    pendente, se houver, senao a config aplicada pelo motor.
    """
    if READONLY:
        snapshot = snap()
        if snapshot.cfg is None:
            raise Unavailable(snapshot.error)
        return snapshot.cfg
    source = paths.PENDING if paths.PENDING.exists() else paths.CONFIG
    if not source.exists():
        raise Unavailable(f"o motor ainda nao tem config em {source}")
    return load(source)


def save_pending(cfg: Config) -> None:
    """Grava a proposta. Nada e' aplicado ate alguem pedir."""
    paths.PENDING.parent.mkdir(parents=True, exist_ok=True)
    paths.PENDING.write_text(
        dump(cfg, header="# Proposta pela interface web, ainda NAO aplicada.\n")
    )


VERSION_KEEP = 200
"""Versoes guardadas; as mais antigas saem. Cada uma tem poucos KB."""


def keep_version(action: str, user: str) -> None:
    """Guarda a proposta como estava antes deste Salvar.

    E' o que o 'Restaurar' oferece: voltar a qualquer ponto anterior, aplicado
    ou nao. O backup do /etc continua sendo do apply (paths.BACKUPS); este e'
    o historico das edicoes.
    """
    source = paths.PENDING if paths.PENDING.exists() else paths.CONFIG
    if not source.exists():
        return
    paths.VERSIONS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    slug = re.sub(r"[^a-z0-9]+", "-", action.lower()).strip("-")[:40] or "edicao"
    header = (
        f"# versao de {datetime.now():%d/%m %H:%M}, antes de '{action}' por {user or '?'}\n"
        f"# origem: {'proposta pendente' if source == paths.PENDING else 'config aplicada'}\n"
    )
    (paths.VERSIONS / f"{stamp}-{slug}.yaml").write_text(header + source.read_text())
    for old in sorted(paths.VERSIONS.glob("*.yaml"))[:-VERSION_KEEP]:
        old.unlink(missing_ok=True)


def versions() -> list[dict[str, str]]:
    """Mais recentes primeiro: arquivo, quando, antes de que, por quem."""
    out = []
    for path in sorted(paths.VERSIONS.glob("*.yaml"), reverse=True):
        first = path.read_text().split("\n", 2)
        m = re.match(r"# versao de (.+), antes de '(.*)' por (.*)$", first[0])
        out.append(
            {
                "name": path.name,
                "when": m.group(1) if m else path.name[:15],
                "action": m.group(2) if m else "",
                "user": m.group(3) if m else "",
                "origin": first[1].removeprefix("# origem: ") if len(first) > 1 else "",
            }
        )
    return out


def has_pending() -> bool:
    return paths.PENDING.exists()


def adopting() -> bool:
    """Maquina adotada que o motor ainda nao selou: a config importada e' a
    viva, mas o /etc ainda e' o de antes. O primeiro apply e' o que falta, e
    ele nao depende de haver proposta salva."""
    return paths.CONFIG.exists() and not ownership.read_seal()


def applicable() -> bool:
    return not READONLY and (has_pending() or adopting())


def edit(request: Request, mutate: Callable[[Config], Any], action: str) -> str | None:
    """Aplica uma mudanca no modelo, valida e grava como pendente.

    Devolve None em caso de sucesso, ou a mensagem de erro. Como a validacao
    roda antes de gravar, uma edicao invalida nao chega nem a virar proposta.
    """
    cfg = current()
    try:
        mutate(cfg)
        validated = Config.model_validate(cfg.model_dump())
    except ValidationError as exc:
        return format_validation_error(exc)
    except (ValueError, KeyError) as exc:
        return str(exc)

    keep_version(action, user_of(request))
    save_pending(validated)
    db.log(action, username=user_of(request), address=client_ip(request))
    return None


def format_validation_error(exc: ValidationError) -> str:
    """Transforma o erro do Pydantic em algo legivel num formulario."""
    parts = []
    for error in exc.errors():
        location = ".".join(str(p) for p in error["loc"] if p != "__root__")
        message = error["msg"].removeprefix("Value error, ")
        parts.append(f"{location}: {message}" if location else message)
    return " · ".join(parts)


# ---------------------------------------------------------------------------
# autenticacao
# ---------------------------------------------------------------------------


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


def user_of(request: Request) -> str:
    session = db.get_session(request.cookies.get(SESSION_COOKIE, ""))
    return session.username if session else ""


def session_of(request: Request) -> db.Session | None:
    return db.get_session(request.cookies.get(SESSION_COOKIE, ""))


async def require_login(request: Request) -> str:
    session = db.get_session(request.cookies.get(SESSION_COOKIE, ""))
    if session is None:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return session.username


User = Annotated[str, Depends(require_login)]


@app.exception_handler(HTTPException)
async def redirect_unauthenticated(request: Request, exc: HTTPException) -> Response:
    if exc.status_code == 303 and "Location" in (exc.headers or {}):
        return RedirectResponse(exc.headers["Location"], status_code=303)
    return HTMLResponse(f"<h1>{exc.status_code}</h1><p>{exc.detail}</p>", status_code=exc.status_code)


@app.exception_handler(Unavailable)
async def show_unavailable(request: Request, exc: Unavailable) -> Response:
    return page(request, "unavailable.html", nav="", reason=str(exc), status_code=503)


@app.middleware("http")
async def source_guard(request: Request, call_next: Callable) -> Response:
    if ALLOW:
        try:
            origin = ipaddress.ip_address(client_ip(request))
        except ValueError:
            origin = None
        if origin is None or not any(origin in net for net in ALLOW):
            return PlainTextResponse("origem nao autorizada", status_code=403)
    return await call_next(request)


@app.middleware("http")
async def readonly_guard(request: Request, call_next: Callable) -> Response:
    """No somente leitura, nenhum POST que mude algo chega a uma rota.

    O bloqueio e' aqui, e nao no template: botao desabilitado e' conforto,
    quem garante e' o servidor.
    """
    if (
        READONLY
        and request.method not in ("GET", "HEAD")
        and request.url.path not in READONLY_ALLOWED
    ):
        return HTMLResponse(
            "<h1>403</h1><p>painel em modo somente leitura: nada foi alterado</p>",
            status_code=403,
        )
    return await call_next(request)


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------


NAV = [
    # (chave do texto, endereco, servico por baixo, recuado)
    ("status", "/", "", False),
    ("services", "/services", "", False),
    None,
    ("network", "/network", "WAN · LAN", False),
    ("firewall", "/firewall", "nftables", False),
    ("fail2ban", "/fail2ban", "", True),
    ("dhcp", "/dhcp", "dnsmasq", False),
    ("domain", "/domain", "dnsmasq", False),
    ("dns", "/dns", "unbound", False),
    ("vpn", "/vpn", "WireGuard", False),
    None,
    ("storage", "/storage", "LVM · SMB · NFS", False),
    ("ai", "/ia", "BYOK · local", False),
    ("agents", "/agentes", "terminal", False),
]
"""O menu da esquerda, de cima para baixo. None e' o separador; Sistema fica
preso no fundo e por isso esta fora da lista."""

LANG_COOKIE = "fwadmin_lang"
THEME_COOKIE = "fwadmin_theme"
THEMES = ("auto", "dark", "light")
"""Na ordem em que o botao do cabecalho alterna."""


def version() -> str:
    """O que o instalador gravou em VERSION; 'dev' rodando do repositorio."""
    try:
        return (paths.CODE / "VERSION").read_text().strip() or "dev"
    except OSError:
        return "dev"


def page(
    request: Request, template: str, nav: str = "", status_code: int = 200, **ctx: Any
) -> HTMLResponse:
    lang = i18n.pick(request.cookies.get(LANG_COOKIE))
    session = session_of(request)
    base = {
        "request": request,
        "user": session.username if session else "",
        "session_until": datetime.fromtimestamp(session.expires_at).strftime("%H:%M")
        if session
        else "",
        "client": client_ip(request),
        "pending": has_pending(),
        "applicable": applicable(),
        "adopting": not READONLY and adopting(),
        "readonly": READONLY,
        "nav": NAV,
        "here": nav,
        "lang": lang,
        "theme": theme if (theme := request.cookies.get(THEME_COOKIE)) in THEMES else "auto",
        "langs": i18n.LANGS,
        "t": i18n.TEXT[lang],
        "version": version(),
        "path": request.url.path,
    }
    if session:
        base["snapshot_age"] = snap().age
        try:
            every = alerts(current(), snap())
        except Unavailable:
            every = []
        for a in every:
            a["id"] = dismissed.alert_id(a)
        hidden = dismissed.prune([a["id"] for a in every])
        for a in every:
            a["dismissed"] = a["id"] in hidden
        # O sino mostra so as nao dispensadas; o Status, todas.
        base["alerts"] = [a for a in every if not a["dismissed"]]
        base["alerts_all"] = every
    return templates.TemplateResponse(request, template, base | ctx, status_code=status_code)


def alerts(cfg: Config, snapshot: live.Snapshot) -> list[dict[str, str]]:
    """O que pede atencao, do mais grave para o menos. Vai para o sino do
    cabecalho e para o topo do Status."""
    out: list[dict[str, str]] = []
    # So os servicos da stack, e so os instalados: o que nao esta na maquina e'
    # assunto da tela de Servicos, nao um alarme.
    down = [i.unit for i in stack_state(cfg) if i.installed and not i.running]
    if len(down) == 1:
        out.append(
            {"level": "bad", "title": f"{down[0]} não está rodando", "detail": "", "href": "/system"}
        )
    elif down:
        out.append(
            {
                "level": "bad",
                "title": f"{len(down)} serviços parados",
                "detail": ", ".join(down),
                "href": "/system",
            }
        )
    for wan in status.wans(cfg):
        if not wan.up:
            out.append(
                {
                    "level": "bad",
                    "title": f"{wan.description or wan.name} sem link",
                    "detail": f"interface {wan.device}",
                    "href": "/network",
                }
            )
    if READONLY and "accept" in snapshot.policies.values():
        out.append(
            {
                "level": "bad",
                "title": "Firewall em lista negra",
                "detail": "a política viva é accept: o que escuta e não tem bloqueio está aberto para a internet",
                "href": "/firewall",
            }
        )
    if not READONLY and has_pending():
        out.append(
            {
                "level": "warn",
                "title": "Alterações aguardando aplicação",
                "detail": "a proposta está gravada e ainda não vale no firewall",
                "href": "/system",
            }
        )
    for conflict in domain_conflicts(cfg):
        out.append(
            {
                "level": "warn",
                "title": f"{conflict['name']} aponta para o IP errado",
                "detail": f"o domínio diz {conflict['dns']}; o DHCP entrega {conflict['dhcp']}",
                "href": "/domain",
            }
        )
    if snapshot.missing:
        out.append(
            {
                "level": "warn",
                "title": (
                    "1 arquivo de config não foi lido"
                    if len(snapshot.missing) == 1
                    else f"{len(snapshot.missing)} arquivos de config não foram lidos"
                ),
                "detail": ", ".join(snapshot.missing),
                "href": "/system",
            }
        )
    # A lista da adocao trava so o primeiro apply. Depois do selo ela compara
    # o importador com uma caixa que o motor ja escreve, e so gera ruido.
    pending, _ = acks.split(snapshot.changes) if not ownership.read_seal() else ([], [])
    if pending:
        out.append(
            {
                "level": "info",
                "title": f"{len(pending)} mudanças da adoção sem marcação",
                "detail": "o primeiro apply fica travado até cada uma ser marcada como intencional",
                "href": "/system#mudancas",
            }
        )
    for peer in vpn_peers(cfg, snapshot):
        if peer["stale"]:
            out.append(
                {
                    "level": "mute",
                    "title": (
                        f"{peer['name']} nunca se conectou à VPN"
                        if peer["seen"] == "nunca"
                        else f"{peer['name']} sem contato na VPN {peer['seen']}"
                    ),
                    "detail": "se o aparelho foi perdido, revogue o peer",
                    "href": "/vpn",
                }
            )
    return out


def stack(cfg: Config) -> list[dict[str, str]]:
    """Os servicos que o portal administra, na ordem da tela de Servicos.

    So a stack do Azimuth: o que mais roda na maquina (zabbix, ssh, nginx)
    nao e' do portal e nao aparece aqui.
    """
    wg = cfg.wireguard.device if cfg.wireguard.enabled else "wg0"
    return [
        {"key": "nftables", "name": "Firewall", "role": "filtra o que entra e o que atravessa",
         "unit": "nftables.service", "package": "nftables", "href": "/firewall"},
        {"key": "fail2ban", "name": "Fail2Ban", "role": "bane quem erra a senha demais",
         "unit": "fail2ban.service", "package": "fail2ban", "href": "/fail2ban"},
        {"key": "dnsmasq", "name": "DHCP e domínio", "role": "entrega IPs e responde os nomes da LAN",
         "unit": "dnsmasq.service", "package": "dnsmasq", "href": "/dhcp"},
        {"key": "unbound", "name": "DNS", "role": "resolve na internet o que não é da LAN",
         "unit": "unbound.service", "package": "unbound", "href": "/dns"},
        {"key": "wireguard", "name": "VPN", "role": f"túnel WireGuard {wg}",
         "unit": f"wg-quick@{wg}.service", "package": "wireguard-tools", "href": "/vpn"},
    ]


def service_buttons(info: status.UnitInfo) -> dict[str, str]:
    """Para cada acao, o motivo de ela estar desligada; '' = pode.

    Nao instalado so deixa instalar. Durante uma transicao (subindo,
    parando, recarregando) nada vale, para nao empilhar comando em cima de
    comando.
    """
    if not info.installed:
        off = "não está instalado"
        return {"install": "", "start": off, "restart": off, "reload": off, "stop": off}
    if info.busy:
        off = "aguarde: o serviço está mudando de estado"
        return {"install": "já instalado", "start": off, "restart": off, "reload": off, "stop": off}
    stopped = "o serviço está parado"
    return {
        "install": "já instalado",
        "start": "já está rodando" if info.running else "",
        "restart": stopped if info.stopped else "",
        "reload": stopped if info.stopped else ("" if info.can_reload else "o serviço não sabe recarregar"),
        "stop": stopped if info.stopped else "",
    }


def stack_state(cfg: Config) -> list[status.UnitInfo]:
    """Estado de cada servico da stack, na ordem de stack()."""
    return [status.unit_info(svc["unit"], svc["package"]) for svc in stack(cfg)]


def domain_conflicts(cfg: Config) -> list[dict[str, str]]:
    """Nome que o DNS local resolve para um IP e o DHCP reserva para outro."""
    reserved = {r.name: r.ip for r in cfg.dhcp.reservations if r.enabled}
    out = []
    for host in cfg.hosts:
        if host.dns and host.name in reserved and reserved[host.name] != host.ip:
            out.append(
                {
                    "name": host.fqdn(cfg.dns.domain),
                    "dns": host.ip,
                    "dhcp": reserved[host.name],
                }
            )
    return out


STALE_PEER = 3 * 86400
"""Peer sem handshake ha mais que isso vira alerta."""


def vpn_peers(cfg: Config, snapshot: live.Snapshot) -> list[dict[str, Any]]:
    """Peers do modelo com o que o 'wg show' diz deles agora."""
    if not cfg.wireguard.enabled:
        return []
    seen = {
        p["public_key"]: p
        for p in snapshot.wireguard.get(cfg.wireguard.device, {}).get("peers", [])
    }
    now = time.time()
    out = []
    for peer in cfg.wireguard.peers:
        state = seen.get(peer.public_key, {})
        handshake = state.get("handshake", 0)
        age = int(now - handshake) if handshake else -1
        out.append(
            {
                "name": peer.description or peer.name,
                "ip": ", ".join(peer.allowed_ips),
                "enabled": peer.enabled,
                "known": bool(state),
                "online": 0 <= age < 180,
                "stale": peer.enabled and bool(snapshot.wireguard) and (age < 0 or age > STALE_PEER),
                "seen": _ago(age),
                "endpoint": state.get("endpoint", ""),
                "rx": state.get("rx", 0),
                "tx": state.get("tx", 0),
                "key": peer.public_key,
            }
        )
    return out


def back(path: str, error: str | None = None) -> RedirectResponse:
    target = f"{path}?erro={error}" if error else f"{path}?ok=1"
    return RedirectResponse(target, status_code=303)


def done(path: str, message: str) -> RedirectResponse:
    """Para acao que vale na hora, sem proposta: o aviso diz o que aconteceu."""
    return RedirectResponse(f"{path}?{urlencode({'feito': message})}", status_code=303)


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request) -> Response:
    if db.user_count() == 0:
        return page(request, "setup.html")
    return page(request, "login.html")


@app.post("/login")
async def login(request: Request, fields: Fields) -> Response:
    username = fields.text("username")
    password = fields.get("password", "")

    if db.user_count() == 0:
        if len(password) < 10:
            return page(request, "setup.html", error="a senha precisa de ao menos 10 caracteres")
        db.create_user(username, password)
        db.log("setup", username=username, address=client_ip(request))

    user_id = db.verify(username, password)
    if user_id is None:
        db.log("login-negado", username=username, address=client_ip(request))
        # A linha que o jail azimuth-panel le no journal. So o IP: o usuario e'
        # texto digitado por quem tenta, e numa linha que o fail2ban casa por
        # regex ele poderia forjar o endereco de outra pessoa.
        print(f"fwadmin: login recusado de {client_ip(request)}", file=sys.stderr, flush=True)
        time.sleep(1)  # desacelera tentativa em massa; o fail2ban cuida do resto
        return page(request, "login.html", error="usuário ou senha inválidos")

    token = db.open_session(user_id, client_ip(request))
    db.log("login", username=username, address=client_ip(request))
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        max_age=db.SESSION_TTL,
        path="/",
    )
    return response


@app.post("/logout")
async def logout(request: Request) -> Response:
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        db.close_session(token)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# ---------------------------------------------------------------------------
# telas — uma por item do menu; as rotas de escrita vem depois, por assunto
# ---------------------------------------------------------------------------


@app.get("/lang/{code}")
async def set_lang(code: str, back_to: str = "/") -> Response:
    """Troca o idioma da moldura. GET de proposito: vale no somente leitura."""
    if not back_to.startswith("/") or back_to.startswith("//"):
        back_to = "/"
    response = RedirectResponse(back_to, status_code=303)
    response.set_cookie(
        LANG_COOKIE, i18n.pick(code), max_age=365 * 86400, samesite="strict", path="/"
    )
    return response


@app.get("/theme/{mode}")
async def set_theme(mode: str, back_to: str = "/") -> Response:
    """Tema claro, escuro ou o do sistema. Como o idioma: cookie e GET."""
    if not back_to.startswith("/") or back_to.startswith("//"):
        back_to = "/"
    response = RedirectResponse(back_to, status_code=303)
    response.set_cookie(
        THEME_COOKIE, mode if mode in THEMES else "auto", max_age=365 * 86400, samesite="strict", path="/"
    )
    return response


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, user: User) -> Response:
    cfg = current()
    snapshot = snap()
    peers = vpn_peers(cfg, snapshot)
    jails = (snapshot.fail2ban or {}).get("jails", [])
    return page(
        request,
        "status.html",
        nav="status",
        cfg=cfg,
        snapshot=snapshot,
        wans=status.wans(cfg),
        leases=status.leases(cfg),
        services=stack_state(cfg),
        system=status.system(),
        peers=peers,
        online=sum(1 for p in peers if p["online"]),
        banned=sum(int(j["banned"] or 0) for j in jails),
        failover=status.failover_state(),
        audit=db.recent(6),
    )


@app.get("/services", response_class=HTMLResponse)
async def services_page(request: Request, user: User) -> Response:
    cfg = current()
    cards = []
    for svc in stack(cfg):
        info = status.unit_info(svc["unit"], svc["package"])
        buttons = service_buttons(info)
        if READONLY:
            buttons = {k: v or "somente leitura" for k, v in buttons.items()}
        else:
            # as acoes sobre servicos ainda nao existem no fwctl
            buttons = {k: v or "entra com as ações" for k, v in buttons.items()}
        cards.append(svc | {"info": info, "buttons": buttons})
    return page(request, "services.html", nav="services", cfg=cfg, cards=cards, now=time.time())


@app.get("/network", response_class=HTMLResponse)
async def network(request: Request, user: User) -> Response:
    cfg = current()
    return page(
        request,
        "network.html",
        nav="network",
        cfg=cfg,
        links=status.links(),
        wans=status.wans(cfg),
        failover=status.failover_state(),
        route=status.default_route(),
        routes=status.routes(),
    )


@app.get("/firewall", response_class=HTMLResponse)
async def firewall(request: Request, user: User) -> Response:
    cfg = current()
    return page(
        request,
        "firewall.html",
        nav="firewall",
        cfg=cfg,
        base=base_input(cfg),
        live_policy=snap().policies if READONLY else {},
    )


@app.get("/fail2ban", response_class=HTMLResponse)
async def fail2ban(request: Request, user: User) -> Response:
    return page(
        request, "fail2ban.html", nav="fail2ban", cfg=current(), f2b=snap().fail2ban
    )


@app.get("/dhcp", response_class=HTMLResponse)
async def dhcp(request: Request, user: User) -> Response:
    cfg = current()
    return page(request, "dhcp.html", nav="dhcp", cfg=cfg, leases=status.leases(cfg))


@app.get("/domain", response_class=HTMLResponse)
async def domain(request: Request, user: User) -> Response:
    cfg = current()
    return page(
        request, "domain.html", nav="domain", cfg=cfg, conflicts=domain_conflicts(cfg)
    )


@app.get("/dns", response_class=HTMLResponse)
async def dns(request: Request, user: User) -> Response:
    snapshot = snap()
    cfg = current()
    # Fora do modelo, a pagina mostra o que "trazer o unbound" faria, com o
    # mesmo tradutor da adocao, antes de alguem clicar.
    preview, preview_changes = (None, [])
    if not cfg.resolver.enabled:
        preview, _, preview_changes = importer.build_resolver(observe.LIVE)
    return page(
        request,
        "dns.html",
        nav="dns",
        cfg=cfg,
        unbound=snapshot.unbound,
        stats=snapshot.unbound_stats,
        preview=preview,
        preview_changes=preview_changes,
    )


@app.get("/storage", response_class=HTMLResponse)
async def storage(request: Request, user: User) -> Response:
    """So leitura: o modulo esta desenhado (STORAGE.md), falta a verificacao em
    VM antes de qualquer codigo que mexa em disco."""
    found = status.disks()
    free = [d for d in found if d.role == "livre"]
    system = [d for d in found if d.role == "sistema"]
    layout = status.storage_layout(len(free), bool(system))
    return page(
        request,
        "storage.html",
        nav="storage",
        cfg=current(),
        disks=found,
        free=free,
        layout=layout,
        lvm=bool(shutil.which("lvm") or Path("/sbin/lvm").exists()),
        volume=Path("/dev/aionas").exists(),
        mounted={m: os.path.ismount(m) for m in ("/srv/aionas", "/var/lib/aionas")},
        shares=[
            ("SMB", status.unit_info("smbd.service", "samba")),
            ("NFS", status.unit_info("nfs-server.service", "nfs-kernel-server")),
        ],
    )


def ai_view(request: Request, **extra: Any) -> HTMLResponse:
    settings = ia.load()
    return page(
        request,
        "ia.html",
        nav="ai",
        cfg=current(),
        settings=settings,
        has_key=bool(settings.key),
        providers=ia.PROVIDERS,
        default_model=ia.ANTHROPIC_DEFAULT_MODEL,
        local=[("Ollama", status.unit_info("ollama.service", "ollama"))],
        **extra,
    )


@app.get("/ia", response_class=HTMLResponse)
async def ai(request: Request, user: User) -> Response:
    return ai_view(request)


@app.post("/ia/settings")
async def ai_settings(request: Request, user: User, fields: Fields) -> Response:
    old = ia.load()
    provider = fields.text("provider")
    if provider not in ia.PROVIDERS:
        return back("/ia", "provedor desconhecido")
    base_url = fields.text("base_url")
    if provider == "openai" and not re.fullmatch(r"https?://[^\s/]+(/\S*)?", base_url):
        return back("/ia", "o endereço precisa começar com http:// ou https://")
    key = fields.text("key") or (old.key if provider == old.provider else "")
    model = fields.text("model") or (ia.ANTHROPIC_DEFAULT_MODEL if provider == "anthropic" else "")
    ia.save(ia.Settings(provider=provider, base_url=base_url if provider == "openai" else "", model=model, key=key))
    db.log("ia:configuracao", username=user, address=client_ip(request))
    return done("/ia", "configuração da IA salva")


def ai_context(cfg: Config) -> dict[str, Any]:
    """O que a IA ve. A config nao tem segredo (senha e chave moram em
    arquivos a parte); o estado e' o que o painel ja mostra."""
    snapshot = snap()
    return {
        "config": cfg.model_dump(mode="json"),
        "state": {
            "alertas": [f"{a['title']} — {a['detail']}".strip(" —") for a in alerts(cfg, snapshot)],
            "wans": [
                {"nome": w.name, "link": w.up, "em_uso": w.active, "endereco": w.address}
                for w in status.wans(cfg)
            ],
            "leases_dhcp": [
                {"nome": l.hostname, "ip": l.ip, "mac": l.mac, "reservado": l.reserved} for l in status.leases(cfg)
            ],
            "apply_aguardando_confirmacao": paths.STATE.exists(),
        },
    }


def _patched(cfg: Config, ops: list[dict[str, Any]]) -> Config:
    """A config com a proposta aplicada, ja validada pelo modelo."""
    try:
        doc = ia.apply_patch(cfg.model_dump(mode="json"), ops)
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(f"caminho que nao existe na config: {exc}") from exc
    return Config.model_validate(doc)


@app.post("/ia/ask", response_class=HTMLResponse)
async def ai_ask(request: Request, user: User, fields: Fields) -> Response:
    question = fields.text("question")[:2000]
    settings = ia.load()
    if not question:
        return back("/ia", "escreva a pergunta")
    if not settings.ready:
        return back("/ia", "configure o provedor primeiro")
    cfg = current()
    reply = ia.ask(settings, question, ai_context(cfg))
    db.log("ia:pergunta", username=user, address=client_ip(request), ok=reply.ok)
    diff, invalid = "", ""
    if reply.ok and reply.ops:
        try:
            proposed = _patched(cfg, reply.ops)
            diff = "".join(
                difflib.unified_diff(
                    dump(cfg).splitlines(keepends=True),
                    dump(proposed).splitlines(keepends=True),
                    "config atual", "com a proposta", n=2,
                )
            ) or "(a proposta nao muda nada)"
        except ValidationError as exc:
            invalid = format_validation_error(exc)
        except ValueError as exc:
            invalid = str(exc)
    return ai_view(
        request, question=question, reply=reply, diff=diff, invalid=invalid,
        ops_json=json.dumps(reply.ops, ensure_ascii=False) if reply.ops else "",
    )


@app.post("/ia/propose")
async def ai_propose(request: Request, user: User, fields: Fields) -> Response:
    """Transforma a proposta da IA em proposta pendente, como uma edicao a mao.

    As operacoes sao reaplicadas sobre a config de agora, e nao sobre a do
    momento da pergunta, e passam de novo pelo modelo.
    """
    try:
        ops = json.loads(fields.text("ops") or "[]")
    except ValueError:
        return back("/ia", "proposta ilegivel")
    summary = fields.text("summary")[:80] or "proposta da IA"

    def mutate(cfg: Config) -> None:
        proposed = _patched(cfg, ops)
        for name in Config.model_fields:
            setattr(cfg, name, getattr(proposed, name))

    error = edit(request, mutate, f"ia:{summary}")
    return back("/system", error) if not error else back("/ia", error)


@app.get("/vpn", response_class=HTMLResponse)
async def vpn(request: Request, user: User) -> Response:
    cfg = current()
    snapshot = snap()
    outside = [t for t in snapshot.tunnels if not (cfg.wireguard.enabled and t == cfg.wireguard.device)]
    return page(
        request,
        "vpn.html",
        nav="vpn",
        cfg=cfg,
        peers=vpn_peers(cfg, snapshot),
        runtime=snapshot.wireguard.get(cfg.wireguard.device) if cfg.wireguard.enabled else None,
        observed=bool(snapshot.wireguard),
        outside=outside,
        up=list(snapshot.wireguard),
    )


# ---------------------------------------------------------------------------
# reservas e registros — salvos linha a linha
# ---------------------------------------------------------------------------


def _reservation(fields: FormData, enabled: bool = True) -> Reservation:
    return Reservation(
        mac=fields.text("mac"),
        ip=fields.text("ip"),
        name=fields.text("name"),
        description=fields.text("description"),
        enabled=enabled,
    )


def _find(items: list, attr: str, key: str, what: str) -> int:
    """Indice da entrada cujo `attr` vale `key`, ou ValueError com o nome dela."""
    for i, item in enumerate(items):
        if getattr(item, attr) == key:
            return i
    raise ValueError(f"{what} inexistente: {key}")


@app.post("/dns/reservation")
async def add_reservation(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.dhcp.reservations.append(_reservation(fields))

    return back("/dhcp", edit(request, mutate, f"reserva+:{fields.text('name')}"))


@app.post("/dns/reservation/{mac}")
async def update_reservation(request: Request, user: User, mac: str, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        items = cfg.dhcp.reservations
        i = _find(items, "mac", mac, "reserva")
        items[i] = _reservation(fields, items[i].enabled)

    return back("/dhcp", edit(request, mutate, f"reserva~:{mac}"))


@app.post("/dns/reservation/{mac}/toggle")
async def toggle_reservation(request: Request, user: User, mac: str) -> Response:
    def mutate(cfg: Config) -> None:
        r = cfg.dhcp.reservations[_find(cfg.dhcp.reservations, "mac", mac, "reserva")]
        r.enabled = not r.enabled

    return back("/dhcp", edit(request, mutate, f"reserva!:{mac}"))


@app.post("/dns/reservation/{mac}/delete")
async def del_reservation(request: Request, user: User, mac: str) -> Response:
    def mutate(cfg: Config) -> None:
        remaining = [r for r in cfg.dhcp.reservations if r.mac != mac]
        if len(remaining) == len(cfg.dhcp.reservations):
            raise ValueError(f"reserva inexistente: {mac}")
        cfg.dhcp.reservations = remaining

    return back("/dhcp", edit(request, mutate, f"reserva-:{mac}"))


@app.post("/dns/host")
async def add_host(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.hosts.append(
            Host(
                name=fields.text("name"),
                ip=fields.text("ip"),
                group=fields.text("group") or None,
                description=fields.text("description"),
            )
        )

    return back("/domain", edit(request, mutate, f"host+:{fields.text('name')}"))


@app.post("/dns/host/{name}")
async def update_host(request: Request, user: User, name: str, fields: Fields) -> Response:
    """Edita nome, IP, grupo e descricao; os servicos do portal e o 'dns' ficam."""

    def mutate(cfg: Config) -> None:
        h = cfg.hosts[_find(cfg.hosts, "name", name, "host")]
        h.name = fields.text("name")
        h.ip = fields.text("ip")
        h.group = fields.text("group") or None
        h.description = fields.text("description")

    return back("/domain", edit(request, mutate, f"host~:{name}"))


@app.post("/dns/host/{name}/toggle")
async def toggle_host(request: Request, user: User, name: str) -> Response:
    """Desativar tira o registro do dnsmasq e deixa o host no modelo (dns=False)."""

    def mutate(cfg: Config) -> None:
        h = cfg.hosts[_find(cfg.hosts, "name", name, "host")]
        h.dns = not h.dns

    return back("/domain", edit(request, mutate, f"host!:{name}"))


@app.post("/dns/host/{name}/delete")
async def del_host(request: Request, user: User, name: str) -> Response:
    def mutate(cfg: Config) -> None:
        remaining = [h for h in cfg.hosts if h.name != name]
        if len(remaining) == len(cfg.hosts):
            raise ValueError(f"host inexistente: {name}")
        cfg.hosts = remaining

    return back("/domain", edit(request, mutate, f"host-:{name}"))


# ---------------------------------------------------------------------------
# DNS recursivo (unbound) — UNBOUND.md
# ---------------------------------------------------------------------------


@app.post("/dns/resolver/adopt")
async def adopt_resolver(request: Request, user: User) -> Response:
    """Traz o unbound vivo para o modelo, numa caixa ja adotada.

    O mesmo tradutor da adocao. Vira proposta como qualquer edicao: o diff do
    Sistema mostra os arquivos absorvidos virando aviso, e o Aplicar prova.
    """

    def mutate(cfg: Config) -> None:
        resolver, _, changes = importer.build_resolver(observe.LIVE)
        if resolver is None:
            raise ValueError("nao achei config do unbound nesta maquina")
        if not resolver["enabled"]:
            raise ValueError(" ".join(changes) or "o unbound desta maquina nao tem traducao completa")
        if cfg.dns.upstream not in ([], [f"{resolver['listen'].replace('@', '#')}"]):
            raise ValueError(
                f"o dnsmasq pergunta a {', '.join(cfg.dns.upstream)}, e nao so ao unbound: "
                "acerte o 'Encaminha para' do Dominio antes"
            )
        cfg.dns.upstream = []
        cfg.resolver = Resolver.model_validate(resolver)

    return back("/dns", edit(request, mutate, "unbound:adocao"))


def _forwarders(text: str) -> list[Forwarder]:
    """'1.1.1.1#cloudflare-dns.com, 9.9.9.9' -> servidores do modo forward."""
    out = []
    for item in (part.strip() for part in text.split(",")):
        if not item:
            continue
        main, _, tls_name = item.partition("#")
        ip, _, port = main.partition("@")
        out.append(Forwarder(address=ip, port=int(port) if port else None, tls_name=tls_name))
    return out


@app.post("/dns/resolver")
async def save_resolver(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        r = cfg.resolver
        if not r.enabled:
            raise ValueError("o unbound ainda nao e' do modelo: traga-o primeiro")
        r.mode = fields.text("mode") or "recursive"
        r.forwarders = _forwarders(fields.text("forwarders"))
        r.dnssec = fields.flag("dnssec")
        r.ipv6 = fields.flag("ipv6")
        r.privacy.qname_minimisation = fields.flag("qname_minimisation")
        r.privacy.hide_identity = fields.flag("hide_identity")
        r.cache.prefetch = fields.flag("prefetch")
        r.cache.min_ttl = fields.number("min_ttl", r.cache.min_ttl)
        r.cache.max_ttl = fields.number("max_ttl", r.cache.max_ttl)
        r.cache.msg_size = fields.text("msg_size") or r.cache.msg_size
        r.cache.rrset_size = fields.text("rrset_size") or r.cache.rrset_size
        r.threads = fields.number("threads", r.threads)

    return back("/dns", edit(request, mutate, "unbound"))


def _zone(fields: FormData, enabled: bool = True) -> ForwardZone:
    return ForwardZone(
        domain=fields.text("domain"),
        servers=fields.csv("servers"),
        description=fields.text("description"),
        enabled=enabled,
    )


def _block(fields: FormData, enabled: bool = True) -> BlockedDomain:
    return BlockedDomain(domain=fields.text("domain"), description=fields.text("description"), enabled=enabled)


@app.post("/dns/forward")
async def add_zone(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.resolver.forward_zones.append(_zone(fields))

    return back("/dns", edit(request, mutate, f"encaminha+:{fields.text('domain')}"))


@app.post("/dns/forward/{domain}")
async def update_zone(request: Request, user: User, domain: str, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        items = cfg.resolver.forward_zones
        i = _find(items, "domain", domain, "dominio encaminhado")
        items[i] = _zone(fields, items[i].enabled)

    return back("/dns", edit(request, mutate, f"encaminha~:{domain}"))


@app.post("/dns/forward/{domain}/toggle")
async def toggle_zone(request: Request, user: User, domain: str) -> Response:
    def mutate(cfg: Config) -> None:
        z = cfg.resolver.forward_zones[_find(cfg.resolver.forward_zones, "domain", domain, "dominio encaminhado")]
        z.enabled = not z.enabled

    return back("/dns", edit(request, mutate, f"encaminha!:{domain}"))


@app.post("/dns/forward/{domain}/delete")
async def del_zone(request: Request, user: User, domain: str) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.resolver.forward_zones.pop(_find(cfg.resolver.forward_zones, "domain", domain, "dominio encaminhado"))

    return back("/dns", edit(request, mutate, f"encaminha-:{domain}"))


@app.post("/dns/block")
async def add_block(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.resolver.blocked.append(_block(fields))

    return back("/dns", edit(request, mutate, f"bloqueio+:{fields.text('domain')}"))


@app.post("/dns/block/{domain}")
async def update_block(request: Request, user: User, domain: str, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        items = cfg.resolver.blocked
        i = _find(items, "domain", domain, "dominio bloqueado")
        items[i] = _block(fields, items[i].enabled)

    return back("/dns", edit(request, mutate, f"bloqueio~:{domain}"))


@app.post("/dns/block/{domain}/toggle")
async def toggle_block(request: Request, user: User, domain: str) -> Response:
    def mutate(cfg: Config) -> None:
        b = cfg.resolver.blocked[_find(cfg.resolver.blocked, "domain", domain, "dominio bloqueado")]
        b.enabled = not b.enabled

    return back("/dns", edit(request, mutate, f"bloqueio!:{domain}"))


@app.post("/dns/block/{domain}/delete")
async def del_block(request: Request, user: User, domain: str) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.resolver.blocked.pop(_find(cfg.resolver.blocked, "domain", domain, "dominio bloqueado"))

    return back("/dns", edit(request, mutate, f"bloqueio-:{domain}"))


# ---------------------------------------------------------------------------
# agentes no navegador (AGENTES.md)
# ---------------------------------------------------------------------------


def _agente(request: Request, user: str, action: str, **fields: str) -> Response:
    """Grava o pedido e chama o 'fwctl agente'. A validacao de verdade e' a do
    fwctl, como root."""
    pedido = {"action": action, **fields}
    tmp = agentes.REQUEST.with_name(f".{agentes.REQUEST.name}.{os.getpid()}")
    tmp.write_text(json.dumps(pedido))
    tmp.replace(agentes.REQUEST)
    # criar instala pacotes do Debian na primeira vez: pode levar minutos
    ok, out = fwctl("agente", timeout=900)
    if not ok:
        agentes.REQUEST.unlink(missing_ok=True)
        return back("/agentes", out.removeprefix("erro: ").strip() or "o fwctl recusou o pedido")
    db.log(f"agente-{action}:{fields.get('name', '')}:{fields.get('level', '')}", username=user, address=client_ip(request))
    return done("/agentes", out.strip().splitlines()[-1] if out.strip() else "feito")


def _agent_rows() -> list[dict[str, Any]]:
    rows = []
    for nome, info in sorted(agentes.load_state().items()):
        kind = agentes.CATALOG.get(info.get("kind", ""))
        rows.append(
            {
                "name": nome,
                "kind": kind.title if kind else info.get("kind", "?"),
                "level": info.get("level", "?"),
                "info": status.unit_info(agentes.UNIT.format(nome), "tmux"),
                "created": info.get("created", ""),
            }
        )
    return rows


@app.get("/agentes", response_class=HTMLResponse)
async def agents_page(request: Request, user: User) -> Response:
    return page(
        request,
        "agentes.html",
        nav="agents",
        cfg=current(),
        rows=_agent_rows(),
        catalog=agentes.CATALOG,
        levels=agentes.LEVELS,
        unavailable=agentes.UNAVAILABLE,
        default_level=agentes.DEFAULT_LEVEL,
    )


@app.get("/agentes/{nome}", response_class=HTMLResponse)
async def agent_terminal(request: Request, user: User, nome: str) -> Response:
    row = next((r for r in _agent_rows() if r["name"] == nome), None)
    if row is None:
        return back("/agentes", f"agente inexistente: {nome}")
    return page(request, "agente.html", nav="agents", cfg=current(), row=row, levels=agentes.LEVELS)


@app.post("/agentes/criar")
async def agent_create(request: Request, user: User, fields: Fields) -> Response:
    return _agente(
        request, user, "criar",
        name=fields.text("name"), kind=fields.text("kind"), level=fields.text("level") or agentes.DEFAULT_LEVEL,
    )


@app.post("/agentes/{nome}/nivel")
async def agent_level(request: Request, user: User, nome: str, fields: Fields) -> Response:
    return _agente(request, user, "nivel", name=nome, level=fields.text("level"))


@app.post("/agentes/{nome}/{acao}")
async def agent_action(request: Request, user: User, nome: str, acao: str) -> Response:
    if acao not in ("iniciar", "parar", "remover"):
        return back("/agentes", f"acao desconhecida: {acao}")
    return _agente(request, user, acao, name=nome)


def _ws_allowed(ws: WebSocket) -> str:
    """Os portoes das paginas, para o WebSocket, que nao passa pelos
    middlewares HTTP. Devolve o usuario, ou vazio se algum portao fechou."""
    if READONLY:
        return ""
    host = ws.client.host if ws.client else ""
    if ALLOW:
        try:
            origin_ip = ipaddress.ip_address(host)
        except ValueError:
            return ""
        if not any(origin_ip in net for net in ALLOW):
            return ""
    # um site de fora nao abre o terminal com o cookie de quem visita
    origin = ws.headers.get("origin", "")
    if not origin or origin.split("://", 1)[-1] != ws.headers.get("host", ""):
        return ""
    session = db.get_session(ws.cookies.get(SESSION_COOKIE, ""))
    return session.username if session else ""


@app.websocket("/agentes/{nome}/tty")
async def agent_tty(ws: WebSocket, nome: str) -> None:
    """Liga o xterm.js do navegador a sessao tmux do agente.

    O painel (netadm) entra no servidor tmux do usuario do agente pelo
    server-access, num pseudoterminal; fechar a aba so solta este cliente, e o
    agente continua. Entrada e redimensionamento chegam como JSON pequeno; a
    saida vai crua, em bytes, que o xterm.js decodifica.
    """
    user = _ws_allowed(ws)
    sock = agentes.socket_of(nome)
    if not user or nome not in agentes.load_state():
        await ws.close(code=4403)
        return
    await ws.accept()
    if not os.path.exists(sock):
        await ws.send_bytes("\r\n O agente está parado. Inicie-o na página Agentes.\r\n".encode())
        await ws.close()
        return
    db.log(f"agente-terminal:{nome}", username=user, address=ws.client.host if ws.client else "")

    pid, fd = pty.fork()
    if pid == 0:  # filho: vira o cliente tmux, e so isso
        os.environ["TERM"] = "xterm-256color"
        try:
            os.execvp("tmux", ["tmux", "-S", sock, "attach-session", "-t", "main"])
        finally:
            os._exit(127)

    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[bytes] = asyncio.Queue()

    def readable() -> None:
        try:
            data = os.read(fd, 65536)
        except OSError:
            data = b""
        queue.put_nowait(data)
        if not data:
            loop.remove_reader(fd)

    loop.add_reader(fd, readable)

    async def to_browser() -> None:
        while data := await queue.get():
            await ws.send_bytes(data)
        await ws.close()

    sender = asyncio.create_task(to_browser())
    try:
        while True:
            message = json.loads(await ws.receive_text())
            if message.get("t") == "i":
                os.write(fd, str(message.get("d", "")).encode())
            elif message.get("t") == "r":
                cols = max(20, min(int(message.get("c", 80)), 500))
                rows = max(5, min(int(message.get("r", 24)), 200))
                fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except (WebSocketDisconnect, ValueError, TypeError, OSError):
        pass
    finally:
        sender.cancel()
        loop.remove_reader(fd)
        os.close(fd)
        try:
            os.kill(pid, signal.SIGHUP)
            os.waitpid(pid, 0)
        except (ProcessLookupError, ChildProcessError):
            pass


# ---------------------------------------------------------------------------
# salvar por pagina — o "Salvar" da barra de baixo de cada tela
# ---------------------------------------------------------------------------


def _optional_int(fields: FormData, key: str, current: int | None) -> int | None:
    """Campo ausente mantem o atual; vazio vira None (o servico decide)."""
    if key not in fields:
        return current
    raw = fields.text(key)
    if raw and not raw.isdigit():
        raise ValueError(f"{key}: {raw!r} nao e' numero")
    return int(raw) if raw else None


@app.post("/network")
async def save_network(request: Request, user: User, fields: Fields) -> Response:
    """Interfaces, PPPoE e qual internet usar — a pagina Rede inteira.

    A senha do PPPoE nao entra na config: vai para secrets.pending.yaml, e so
    depois que a config validou. Campo de senha vazio mantem a atual.
    """
    passwords: dict[str, str] = {}

    def mutate(cfg: Config) -> None:
        for iface in cfg.interfaces:
            key = iface.name
            iface.description = fields.text(f"{key}.description", iface.description)
            if iface.role.value != "wan":
                continue
            mode = fields.text(f"{key}.mode") or iface.ipv4.mode.value
            if mode == "pppoe":
                if iface.pppoe is None:
                    iface.pppoe = PPPoE(peer=key.replace("_", "-"), username="-", password_ref=key.replace("_", "-"))
                ppp = iface.pppoe
                iface.ipv4.mode = IPv4Mode.pppoe
                iface.ipv4.address = iface.ipv4.gateway = None
                ppp.username = fields.text(f"{key}.username", ppp.username)
                ppp.mtu = _optional_int(fields, f"{key}.mtu", ppp.mtu)
                ppp.mru = _optional_int(fields, f"{key}.mru", ppp.mru)
                ppp.lcp_echo_interval = fields.number(f"{key}.lcp_interval", ppp.lcp_echo_interval)
                ppp.lcp_echo_failure = fields.number(f"{key}.lcp_failure", ppp.lcp_echo_failure)
                ppp.holdoff = fields.number(f"{key}.holdoff", ppp.holdoff)
                ppp.default_route = fields.flag(f"{key}.default_route")
                password = fields.get(f"{key}.password", "")
                if password:
                    if "\n" in password or "\r" in password:
                        raise ValueError("a senha do PPPoE nao pode ter quebra de linha")
                    ppp.password_file = True
                    passwords[ppp.password_ref] = password
            else:
                iface.pppoe = None
                iface.ipv4.mode = IPv4Mode(mode)
                iface.ipv4.address = fields.text(f"{key}.address") or None if mode == "static" else None
                iface.ipv4.gateway = fields.text(f"{key}.gateway") or None if mode == "static" else None
        cfg.routing.primary = fields.text("primary", cfg.routing.primary)
        cfg.routing.backup = fields.text("backup") or None
        cfg.routing.failover = Failover(
            enabled=fields.flag("failover"),
            interval_seconds=fields.number("interval_seconds", 60),
            threshold=fields.number("threshold", 3),
            ping_targets=fields.csv("ping_targets") or ["8.8.8.8"],
        )

    error = edit(request, mutate, "rede")
    if error is None:
        for ref, value in passwords.items():
            secretstore.propose(ref, value)
    return back("/network", error)


@app.post("/dhcp")
async def save_dhcp(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.dhcp.range.start = fields.text("range_start", cfg.dhcp.range.start)
        cfg.dhcp.range.end = fields.text("range_end", cfg.dhcp.range.end)
        cfg.dhcp.range.lease = fields.text("lease", cfg.dhcp.range.lease)
        cfg.dhcp.authoritative = fields.flag("authoritative")

    return back("/dhcp", edit(request, mutate, "dhcp"))


@app.post("/domain")
async def save_domain(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.dns.domain = fields.text("domain", cfg.dns.domain)
        cfg.dns.expand_hosts = fields.flag("expand_hosts")
        cfg.dns.local_only = fields.flag("local_only")
        cfg.dns.bind_interfaces = fields.flag("bind_interfaces")
        cfg.dns.upstream = fields.csv("upstream")
        cfg.dns.no_resolv = fields.flag("no_resolv")
        cfg.dns.proxy_dnssec = fields.flag("proxy_dnssec")

    return back("/domain", edit(request, mutate, "dominio"))


@app.post("/vpn")
async def save_vpn(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        wg = cfg.wireguard
        wg.address = fields.text("address", wg.address or "") or None
        wg.listen_port = fields.number("listen_port", wg.listen_port)
        wg.mtu = _optional_int(fields, "mtu", wg.mtu)
        wg.endpoint = fields.text("endpoint") or None

    return back("/vpn", edit(request, mutate, "vpn"))


def _wg(*args: str, stdin: str = "") -> str:
    """wg genkey / wg pubkey: so matematica, nao precisa de root."""
    proc = subprocess.run(
        ["wg", *args], input=stdin, capture_output=True, text=True, timeout=10, check=True
    )
    return proc.stdout.strip()


def _qr_svg(text: str) -> str:
    """QR do perfil em SVG, para o celular ler da tela. Vazio se nao houver qrencode."""
    try:
        proc = subprocess.run(
            ["qrencode", "-t", "SVG", "-o", "-", "-m", "2"],
            input=text, capture_output=True, text=True, timeout=10, check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    svg = proc.stdout
    return svg[svg.find("<svg"):] if "<svg" in svg else ""


def _next_tunnel_ip(cfg: Config) -> str:
    """O primeiro endereco livre da rede do tunel, fora o do servidor."""
    server = ipaddress.IPv4Interface(cfg.wireguard.address)
    taken = {server.ip}
    for peer in cfg.wireguard.peers:
        for net in map(ipaddress.ip_network, peer.allowed_ips):
            if net.version == 4 and net.overlaps(server.network):
                taken.update(net)
    for ip in server.network.hosts():
        if ip not in taken:
            return str(ip)
    raise ValueError(f"a rede do túnel {server.network} não tem mais endereço livre")


@app.post("/vpn/peer")
async def add_peer(request: Request, user: User, fields: Fields) -> Response:
    """Cria o aparelho e devolve o perfil dele, uma vez so.

    A chave privada nasce aqui, vai para a tela e nao e' gravada em lugar
    nenhum: o modelo guarda so a publica. Perdeu o perfil, cria outro peer e
    revoga este — e' o mesmo trato que o wg-quick faz com quem o usa a mao.
    """
    cfg = current()
    wg = cfg.wireguard
    if not wg.enabled:
        return back("/vpn", "não há túnel de acesso remoto no modelo")
    runtime = snap().wireguard.get(wg.device) or {}
    server_key = runtime.get("public_key", "")
    if not server_key:
        return back("/vpn", "a chave pública do servidor não foi lida: o túnel precisa estar no ar")
    endpoint = fields.text("endpoint") or wg.endpoint
    if not endpoint:
        return back("/vpn", "informe o endereço público pelo qual o aparelho chega")
    try:
        private = _wg("genkey")
        public = _wg("pubkey", stdin=private + "\n")
    except (OSError, subprocess.SubprocessError):
        return back("/vpn", "não consegui gerar a chave: o comando wg falhou")

    chosen: dict[str, str] = {}

    def mutate(cfg: Config) -> None:
        ip = _next_tunnel_ip(cfg)
        chosen["ip"] = ip
        cfg.wireguard.peers.append(
            WGPeer(
                name=fields.text("name"),
                public_key=public,
                allowed_ips=[f"{ip}/32"],
                description=fields.text("description"),
            )
        )
        if not cfg.wireguard.endpoint:
            cfg.wireguard.endpoint = endpoint

    error = edit(request, mutate, f"peer+:{fields.text('name')}")
    if error:
        return back("/vpn", error)

    tunnel = ipaddress.IPv4Interface(wg.address).network
    routes = "0.0.0.0/0" if fields.text("route") == "all" else f"{tunnel}, {cfg.lan.ipv4.network}"
    lines = [
        "[Interface]",
        f"PrivateKey = {private}",
        f"Address = {chosen['ip']}/32",
        f"DNS = {cfg.lan.ipv4.ip}",
    ]
    if wg.mtu:
        lines.append(f"MTU = {wg.mtu}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server_key}",
        f"Endpoint = {endpoint}:{wg.listen_port}",
        f"AllowedIPs = {routes}",
        "PersistentKeepalive = 25",
        "",
    ]
    profile = "\n".join(lines)
    response = page(
        request,
        "vpn_peer.html",
        nav="vpn",
        cfg=current(),
        name=fields.text("name"),
        ip=chosen["ip"],
        profile=profile,
        qr=_qr_svg(profile),
    )
    # A chave privada esta nesta resposta: nada de cache, nem do navegador.
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/vpn/peer/{name}/toggle")
async def toggle_peer(request: Request, user: User, name: str) -> Response:
    """Revoga ou reativa. Revogar tira o peer do arquivo gerado e mantem o
    registro no modelo, como o WGPeer.enabled pede."""

    def mutate(cfg: Config) -> None:
        peer = next((p for p in cfg.wireguard.peers if p.name == name), None)
        if peer is None:
            raise ValueError(f"peer inexistente: {name}")
        peer.enabled = not peer.enabled

    return back("/vpn", edit(request, mutate, f"peer~:{name}"))


# ---------------------------------------------------------------------------
# firewall
# ---------------------------------------------------------------------------


@app.post("/firewall/policy")
async def save_policy(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.firewall.input_policy = fields.text("input_policy")
        cfg.firewall.forward_policy = fields.text("forward_policy")

    return back("/firewall", edit(request, mutate, "firewall:policy"))


def _chain_of(cfg: Config, chain: str) -> list[Rule]:
    if chain not in ("input", "forward"):
        raise ValueError(f"cadeia desconhecida: {chain}")
    return getattr(cfg.firewall, f"{chain}_rules")


def _rule(fields: FormData, enabled: bool = True) -> Rule:
    return Rule(
        enabled=enabled,
        action=fields.text("action"),
        # Campo em branco chega como "", e nao ausente: o default do text()
        # nao cobriria.
        source=fields.text("source") or "any",
        destination=fields.text("destination") or "any",
        proto=fields.text("proto") or "any",
        dest_ports=fields.text("dest_ports"),
        description=fields.text("description"),
        log=fields.flag("log"),
    )


def _at(items: list, index: int, what: str) -> Any:
    if not 0 <= index < len(items):
        raise ValueError(f"{what} inexistente")
    return items[index]


@app.post("/firewall/rule/{chain}")
async def add_rule(request: Request, user: User, chain: str, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        _chain_of(cfg, chain).append(_rule(fields))

    return back("/firewall", edit(request, mutate, f"regra+:{chain}"))


@app.post("/firewall/rule/{chain}/{index}")
async def update_rule(
    request: Request, user: User, chain: str, index: int, fields: Fields
) -> Response:
    def mutate(cfg: Config) -> None:
        rules = _chain_of(cfg, chain)
        rules[index] = _rule(fields, _at(rules, index, "regra").enabled)

    return back("/firewall", edit(request, mutate, f"regra~:{chain}:{index}"))


@app.post("/firewall/rule/{chain}/{index}/toggle")
async def toggle_rule(request: Request, user: User, chain: str, index: int) -> Response:
    def mutate(cfg: Config) -> None:
        rule = _at(_chain_of(cfg, chain), index, "regra")
        rule.enabled = not rule.enabled

    return back("/firewall", edit(request, mutate, f"regra!:{chain}:{index}"))


@app.post("/firewall/rule/{chain}/{index}/delete")
async def del_rule(request: Request, user: User, chain: str, index: int) -> Response:
    def mutate(cfg: Config) -> None:
        rules = _chain_of(cfg, chain)
        if not 0 <= index < len(rules):
            raise ValueError("regra inexistente")
        rules.pop(index)

    return back("/firewall", edit(request, mutate, f"regra-:{chain}:{index}"))


@app.post("/firewall/rule/{chain}/{index}/move")
async def move_rule(
    request: Request, user: User, chain: str, index: int, fields: Fields
) -> Response:
    def mutate(cfg: Config) -> None:
        rules = _chain_of(cfg, chain)
        target = index - 1 if fields.text("direction") == "up" else index + 1
        if not (0 <= index < len(rules) and 0 <= target < len(rules)):
            raise ValueError("movimento fora da lista")
        rules[index], rules[target] = rules[target], rules[index]

    return back("/firewall", edit(request, mutate, f"regra~:{chain}:{index}"))


def _forward(fields: FormData, enabled: bool = True) -> PortForward:
    return PortForward(
        enabled=enabled,
        interface=fields.text("interface"),
        wan_port=fields.number("wan_port"),
        to_ip=fields.text("to_ip"),
        to_port=fields.number("to_port"),
        proto=fields.text("proto") or "tcp",
        description=fields.text("description"),
        source_filter=fields.text("source_filter"),
    )


@app.post("/firewall/forward")
async def add_forward(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        cfg.firewall.port_forwards.append(_forward(fields))

    return back("/firewall", edit(request, mutate, f"dnat+:{fields.text('wan_port')}"))


@app.post("/firewall/forward/{index}")
async def update_forward(request: Request, user: User, index: int, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        items = cfg.firewall.port_forwards
        items[index] = _forward(fields, _at(items, index, "port-forward").enabled)

    return back("/firewall", edit(request, mutate, f"dnat~:{index}"))


@app.post("/firewall/forward/{index}/toggle")
async def toggle_forward(request: Request, user: User, index: int) -> Response:
    def mutate(cfg: Config) -> None:
        pf = _at(cfg.firewall.port_forwards, index, "port-forward")
        pf.enabled = not pf.enabled

    return back("/firewall", edit(request, mutate, f"dnat!:{index}"))


@app.post("/firewall/forward/{index}/delete")
async def del_forward(request: Request, user: User, index: int) -> Response:
    def mutate(cfg: Config) -> None:
        if not 0 <= index < len(cfg.firewall.port_forwards):
            raise ValueError("port-forward inexistente")
        cfg.firewall.port_forwards.pop(index)

    return back("/firewall", edit(request, mutate, f"dnat-:{index}"))


# ---------------------------------------------------------------------------
# servicos — o portal, agora vindo do mesmo modelo do DNS
# ---------------------------------------------------------------------------


@app.post("/services/add")
async def add_service(request: Request, user: User, fields: Fields) -> Response:
    def mutate(cfg: Config) -> None:
        host = fields.text("host")
        target = next((h for h in cfg.hosts if h.name == host), None)
        if target is None:
            raise ValueError(f"host desconhecido: {host}")
        target.services.append(
            Service(
                name=fields.text("name"),
                url=fields.text("url"),
                description=fields.text("description"),
                icon=fields.text("icon"),
                tag=fields.text("tag"),
                tag_style=fields.text("tag_style"),
            )
        )

    return back("/domain", edit(request, mutate, f"servico+:{fields.text('name')}"))


@app.post("/services/{host}/{index}/delete")
async def del_service(request: Request, user: User, host: str, index: int) -> Response:
    def mutate(cfg: Config) -> None:
        target = next((h for h in cfg.hosts if h.name == host), None)
        if target is None or not 0 <= index < len(target.services):
            raise ValueError("serviço inexistente")
        target.services.pop(index)

    return back("/domain", edit(request, mutate, f"servico-:{host}:{index}"))


# ---------------------------------------------------------------------------
# diagnostico
# ---------------------------------------------------------------------------


@app.post("/system/diag", response_class=HTMLResponse)
async def run_diag(
    request: Request,
    user: User,
    fields: Fields,
) -> Response:
    tool = fields.text("tool")
    target = fields.text("target")
    iface = fields.text("iface")

    probes = {
        "ping": lambda: status.ping(target, iface),
        "traceroute": lambda: status.traceroute(target),
        "dns": lambda: status.dns_lookup(target),
    }
    if tool in probes:
        result = probes[tool]()
    elif tool == "nft":
        result = status.Probe(True, status.nft_ruleset(), "nft list ruleset")
    elif tool == "routes":
        result = status.Probe(True, status.routes(), "ip route show")
    elif tool == "journal":
        result = status.Probe(True, status.journal(target), f"journalctl -u {target or 'todos'}")
    else:
        result = status.Probe(False, f"ferramenta desconhecida: {tool}")

    db.log(f"diag:{tool}", username=user, address=client_ip(request))
    return system_view(request, result=result, tool=tool, target=target)


# ---------------------------------------------------------------------------
# sistema — aplicar, confirmar, reverter
# ---------------------------------------------------------------------------


@app.get("/system", response_class=HTMLResponse)
async def system_page(request: Request, user: User) -> Response:
    return system_view(request)


def system_view(request: Request, **extra: Any) -> HTMLResponse:
    cfg = current()
    ctx: dict[str, Any] = {}
    snapshot = snap()
    pending, accepted = acks.split(snapshot.changes)
    ctx = {"findings": snapshot.findings, "adopt_pending": pending, "adopt_accepted": accepted}
    if not READONLY:
        _, state = fwctl("status", timeout=20)
        _, diff = fwctl("diff", timeout=60) if applicable() else (True, "")
        # So ha o que confirmar com um apply gravado no state.json, o mesmo
        # arquivo que o 'fwctl confirm' consulta. Procurar texto na saida do
        # status nao serve: "nenhum apply aguardando confirmacao" contem a frase.
        ctx |= {"state": state, "diff": diff, "awaiting": paths.STATE.exists()}
    ctx["sealed"] = bool(ownership.read_seal())
    return page(
        request,
        "system.html",
        nav="system",
        cfg=cfg,
        saved=versions(),
        history=git_history(),
        audit=db.recent(30),
        system=status.system(),
        **ctx,
        **extra,
    )


@app.post("/system/ack")
async def ack_change(request: Request, user: User, fields: Fields) -> Response:
    """Marca como intencional uma mudanca que esta na lista agora.

    So aceita id de mudanca da fotografia atual: o texto gravado vem do
    importador, nunca do formulario.
    """
    cid = fields.text("id")
    by_id = dict(acks.split(snap().changes)[0])
    if cid not in by_id:
        return back("/system#mudancas", "essa mudança não está na lista atual")
    acks.mark(by_id[cid], by=user)
    db.log(f"intencional:{cid}", username=user, address=client_ip(request))
    return RedirectResponse("/system#mudancas", status_code=303)


@app.post("/system/unack")
async def unack_change(request: Request, user: User, fields: Fields) -> Response:
    cid = fields.text("id")
    acks.unmark(cid)
    db.log(f"intencional-desfeito:{cid}", username=user, address=client_ip(request))
    return RedirectResponse("/system#mudancas", status_code=303)


def _f2b(request: Request, user: str, action: str, jail: str, ip: str) -> Response:
    """Grava o pedido e chama 'fwctl f2b'. Validacao aqui e' conforto; a de
    verdade e' a do fwctl, como root."""
    try:
        ip = str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return back("/fail2ban", f"endereço inválido: {ip}")
    pedido = {"action": action, "jail": jail, "ip": ip}
    tmp = paths.F2B_REQUEST.with_name(f".{paths.F2B_REQUEST.name}.{os.getpid()}")
    tmp.write_text(json.dumps(pedido))
    tmp.replace(paths.F2B_REQUEST)
    ok, out = fwctl("f2b", timeout=30)
    if not ok:
        paths.F2B_REQUEST.unlink(missing_ok=True)
        return back("/fail2ban", out.removeprefix("erro: ").strip() or "o fwctl recusou o pedido")
    db.log(f"f2b-{action}:{jail}:{ip}", username=user, address=client_ip(request))
    return done("/fail2ban", f"{ip} {'banido' if action == 'ban' else 'desbanido'} em {jail}")


@app.post("/fail2ban/ban")
async def f2b_ban(request: Request, user: User, fields: Fields) -> Response:
    return _f2b(request, user, "ban", fields.text("jail"), fields.text("ip"))


@app.post("/fail2ban/unban")
async def f2b_unban(request: Request, user: User, fields: Fields) -> Response:
    return _f2b(request, user, "unban", fields.text("jail"), fields.text("ip"))


@app.post("/alerts/clear")
async def clear_alerts(request: Request, user: User, fields: Fields) -> Response:
    """Dispensa as notificacoes que estao no sino agora."""
    ids = [dismissed.alert_id(a) for a in alerts(current(), snap())]
    dismissed.dismiss(ids, by=user)
    db.log(f"notificacoes-limpas:{len(ids)}", username=user, address=client_ip(request))
    return RedirectResponse(_local(fields.text("back_to")), status_code=303)


@app.post("/alerts/restore")
async def restore_alerts(request: Request, user: User, fields: Fields) -> Response:
    dismissed.restore()
    return RedirectResponse(_local(fields.text("back_to")), status_code=303)


def _local(path: str) -> str:
    """So caminho do proprio painel, para o back_to nao virar redirecionamento aberto."""
    return path if path.startswith("/") and not path.startswith("//") else "/"


@app.post("/system/apply")
async def do_apply(request: Request, user: User, fields: Fields) -> Response:
    # A mensagem do commit vai por arquivo, nao por argumento: assim o sudoers
    # lista comandos exatos, sem curinga.
    note = fields.text("note") or f"alteração pela web · {user}"
    paths.NOTE.parent.mkdir(parents=True, exist_ok=True)
    paths.NOTE.write_text(note[:200])

    args = ["apply", "--yes"] if fields.flag("yes") else ["apply"]
    ok, output = fwctl(*args)
    db.log("apply", username=user, address=client_ip(request), ok=ok)
    return page(request, "result.html", nav="system", title="Aplicar", ok=ok, output=output, cfg=current())


@app.post("/system/confirm")
async def do_confirm(request: Request, user: User) -> Response:
    ok, output = fwctl("confirm")
    db.log("confirm", username=user, address=client_ip(request), ok=ok)
    return page(request, "result.html", nav="system", title="Confirmar", ok=ok, output=output, cfg=current())


@app.post("/system/rollback")
async def do_rollback(request: Request, user: User) -> Response:
    ok, output = fwctl("rollback")
    db.log("rollback", username=user, address=client_ip(request), ok=ok)
    return page(request, "result.html", nav="system", title="Reverter", ok=ok, output=output, cfg=current())


@app.post("/system/restore")
async def restore_version(request: Request, user: User, fields: Fields) -> Response:
    """Uma versao guardada vira a proposta pendente. Nao aplica nada."""
    name = fields.text("name")
    source = paths.VERSIONS / name
    if not re.fullmatch(r"[0-9-]+[a-z0-9-]*\.yaml", name) or not source.is_file():
        return back("/system#versoes", "versão inexistente")
    try:
        restored = load(source)
    except (ValidationError, ValueError, OSError) as exc:
        return back("/system#versoes", f"a versão não carrega mais: {exc}")
    keep_version(f"restaurar {name}", user)
    save_pending(restored)
    db.log(f"restaurar:{name}", username=user, address=client_ip(request))
    return back("/system")


@app.post("/system/discard")
async def discard_pending(request: Request, user: User) -> Response:
    keep_version("descartar", user)
    paths.PENDING.unlink(missing_ok=True)
    secretstore.discard()
    db.log("descartar-pendente", username=user, address=client_ip(request))
    return back("/system")


@app.get("/system/state", response_class=PlainTextResponse)
async def system_state(request: Request, user: User) -> str:
    """Consultado pelo htmx para o contador de confirmacao."""
    _, output = fwctl("status", timeout=20)
    return output


@app.get("/system/config", response_class=PlainTextResponse)
async def download_config(request: Request, user: User) -> Response:
    """O template da config em YAML. No somente leitura, e' o sistema vivo
    passado pelo importador: o config.yaml que o motor usaria se assumisse."""
    header = (
        "# Lido do sistema vivo pelo importador. O motor ainda NAO aplicou isto.\n"
        if READONLY
        else ""
    )
    return PlainTextResponse(
        dump(current(), header=header),
        headers={"Content-Disposition": 'attachment; filename="fwadmin-config.yaml"'},
    )


def git_history(limit: int = 20) -> list[dict[str, str]]:
    """Historico de commits da config — o rollback de longo prazo."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(paths.ETC), "log", f"-{limit}", "--format=%h%x1f%ar%x1f%s"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    entries = []
    for line in proc.stdout.splitlines():
        parts = line.split("\x1f")
        if len(parts) == 3:
            entries.append({"hash": parts[0], "when": parts[1], "subject": parts[2]})
    return entries


# ---------------------------------------------------------------------------
# arquivos estaticos e inicializacao
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
if HTMX.is_dir():
    app.mount("/vendor", StaticFiles(directory=str(HTMX)), name="vendor")


@app.on_event("startup")
async def startup() -> None:
    db.init()
